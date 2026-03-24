import 'dart:io';
import 'dart:convert';
import '../models/llm_settings.dart';
import '../models/command_log.dart';
import '../models/environment_info.dart';
import '../utils/json_parser.dart';
import '../utils/command_utils.dart';
import '../database/database_helper.dart';
import '../utils/device_utils.dart';
import 'command_executor.dart';
import 'environment_discovery.dart';
import 'llm_service.dart';
import 'storage_service.dart';

/// Phases of the structured recon pipeline.
enum ReconPhase { portScan, serviceBanner, webFingerprint, dnsEnum, osDetect }

/// Structured result from a recon run, convertible to device JSON.
class ReconResult {
  String ip;
  String hostname;
  List<Map<String, dynamic>> openPorts;
  String os;
  String osVersion;
  List<String> technologies;
  List<Map<String, dynamic>> dnsFindings;
  Map<String, String> httpHeaders;
  List<String> banners;
  List<String> hostnames;

  ReconResult({
    required this.ip,
    this.hostname = '',
    List<Map<String, dynamic>>? openPorts,
    this.os = '',
    this.osVersion = '',
    List<String>? technologies,
    List<Map<String, dynamic>>? dnsFindings,
    Map<String, String>? httpHeaders,
    List<String>? banners,
    List<String>? hostnames,
  })  : openPorts = openPorts ?? [],
        technologies = technologies ?? [],
        dnsFindings = dnsFindings ?? [],
        httpHeaders = httpHeaders ?? {},
        banners = banners ?? [],
        hostnames = hostnames ?? [];

  /// Merge this result into an existing device JSON map, enriching without overwriting.
  Map<String, dynamic> mergeInto(Map<String, dynamic> existing) {
    final device = (existing['device'] as Map<String, dynamic>?) ?? {};
    if (os.isNotEmpty && (device['os'] ?? '').toString().isEmpty) device['os'] = os;
    if (osVersion.isNotEmpty && (device['os_version'] ?? '').toString().isEmpty) device['os_version'] = osVersion;
    if (hostname.isNotEmpty && (device['name'] ?? '').toString().isEmpty) device['name'] = hostname;
    if (device['ip_address'] == null || device['ip_address'].toString().isEmpty) device['ip_address'] = ip;
    existing['device'] = device;

    // Merge open ports by port number
    final existingPorts = (existing['open_ports'] as List?) ?? [];
    for (final p in openPorts) {
      final portNum = p['port'];
      final idx = existingPorts.indexWhere((e) => (e as Map)['port'] == portNum);
      if (idx == -1) {
        existingPorts.add(Map<String, dynamic>.from(p));
      } else {
        final ep = existingPorts[idx] as Map<String, dynamic>;
        p.forEach((k, v) {
          if (v != null && v.toString().isNotEmpty &&
              (ep[k] == null || ep[k].toString().isEmpty)) {
            ep[k] = v;
          }
        });
      }
    }
    existing['open_ports'] = existingPorts;

    // Merge list fields
    final existingDns = ((existing['dns_findings'] as List?) ?? []).cast<Map<String, dynamic>>();
    existingDns.addAll(dnsFindings);
    existing['dns_findings'] = existingDns;

    // Merge technologies into web_findings
    if (technologies.isNotEmpty) {
      final webFindings = ((existing['web_findings'] as List?) ?? []).cast<Map<String, dynamic>>();
      if (webFindings.isNotEmpty) {
        final existingTechs = (webFindings.first['technologies'] as List?)?.cast<String>() ?? [];
        final merged = {...existingTechs, ...technologies}.toList();
        webFindings.first['technologies'] = merged;
      } else {
        webFindings.add({'technologies': technologies});
      }
      existing['web_findings'] = webFindings;
    }

    if (hostnames.isNotEmpty) existing['hostnames'] = hostnames;
    if (httpHeaders.isNotEmpty) existing['http_headers'] = httpHeaders;

    return existing;
  }

  /// Convert to standalone device JSON.
  Map<String, dynamic> toDeviceJson() => mergeInto({
    'device': {'ip_address': ip, 'name': hostname.isNotEmpty ? hostname : ip},
    'open_ports': <dynamic>[],
    'dns_findings': <dynamic>[],
    'web_findings': <dynamic>[],
  });
}

class _ExecEnv {
  final String osInfo;
  final bool isWsl;
  final bool isNativeWindows;
  final bool isMacOS;
  final bool isLinux;

  const _ExecEnv({
    required this.osInfo,
    required this.isWsl,
    required this.isNativeWindows,
    required this.isMacOS,
    required this.isLinux,
  });

  String get label {
    if (isWsl) return 'WSL (Windows Subsystem for Linux) - bash shell';
    if (isNativeWindows) return 'Native Windows - PowerShell/cmd only, NO bash';
    if (isMacOS) return 'macOS - bash/zsh shell';
    return 'Linux - bash shell';
  }

  String get shellRules {
    if (isNativeWindows) {
      return '''## PLATFORM RULES - Native Windows (NO WSL, NO bash):
- ALL commands must be valid PowerShell syntax
- Available: nmap (if installed), curl, Invoke-WebRequest, Test-NetConnection, Resolve-DnsName, net view
- NOT available: bash, sh, nc, dig, smbclient, enum4linux, grep, awk, sed, snmpwalk
- Port scan: nmap -sV -sC --open -T4 -p- TARGET (preferred if nmap installed)
- HTTP: curl -s -I http://TARGET  OR  Invoke-WebRequest -Uri http://TARGET -UseBasicParsing
- DNS: Resolve-DnsName TARGET
- SMB: net view \\\\TARGET /all
- Connectivity: Test-NetConnection TARGET -Port PORT
- Output files use backslash paths: temp\\recon\\
- Wrap multi-statement commands in: powershell -Command "..."''';
    }
    return '''## PLATFORM RULES - $label:
- Commands run in bash shell
- Available: nmap, curl, wget, nc, dig, smbclient, enum4linux, snmpwalk, python3, etc.
- Use: timeout 60 COMMAND  to prevent hangs
- Output files use forward slash paths: temp/recon/''';
  }

  String outputPath(String dir) =>
      isNativeWindows ? dir.replaceAll('/', '\\') : dir;

  static Future<_ExecEnv> detect() async {
    final osInfo = await CommandExecutor.getOsInfo();
    final isWindows = Platform.isWindows;
    final isWsl = isWindows && await CommandExecutor.isWslAvailable();
    return _ExecEnv(
      osInfo: osInfo,
      isWsl: isWsl,
      isNativeWindows: isWindows && !isWsl,
      isMacOS: Platform.isMacOS,
      isLinux: Platform.isLinux,
    );
  }
}

/// Result of the deterministic pre-LLM baseline scan.
class _BaselineResult {
  final bool isAlive;
  final bool hasWebPorts;
  final bool hasDnsData;
  final bool hasSmbPort;
  final List<String> commandsRun;

  const _BaselineResult({
    required this.isAlive,
    required this.hasWebPorts,
    required this.hasDnsData,
    required this.hasSmbPort,
    required this.commandsRun,
  });
}

class ReconService {
  final LLMSettings settings;
  final bool requireApproval;
  final String? adminPassword;
  final Future<String?> Function(String)? onApprovalNeeded;
  final Future<String?> Function(String)? onPasswordNeeded;
  final Function(String)? onProgress;
  final Function(String, String)? onPromptResponse;
  final Function(String, String)? onCommandExecuted;
  final Function(String)? onTargetDown;

  static const int _maxIterations = 100;
  static const int _maxIterationsExternal = 100;

  ReconService({
    required this.settings,
    this.requireApproval = false,
    this.adminPassword,
    this.onApprovalNeeded,
    this.onPasswordNeeded,
    this.onProgress,
    this.onPromptResponse,
    this.onCommandExecuted,
    this.onTargetDown,
  });

  // ---------------------------------------------------------------------------
  // Input parsing
  // ---------------------------------------------------------------------------

  static List<String> parseTargetInput(String input) {
    final trimmed = input.trim();
    if (trimmed.isEmpty) return [];

    final cidrMatch =
        RegExp(r'^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})/(\d+)$').firstMatch(trimmed);
    if (cidrMatch != null) {
      final prefix = cidrMatch.group(1)!;
      final hostStart = int.parse(cidrMatch.group(2)!);
      final mask = int.parse(cidrMatch.group(3)!);
      if (mask == 24) return List.generate(254, (i) => '$prefix.${i + 1}');
      if (mask > 24 && mask <= 30) {
        final size = (1 << (32 - mask)) - 2;
        return List.generate(size, (i) => '$prefix.${hostStart + i + 1}');
      }
      return [trimmed];
    }

    if (trimmed.contains(',') || trimmed.contains('\n')) {
      return trimmed
          .split(RegExp(r'[,\n]'))
          .map((s) => s.trim())
          .where((s) => s.isNotEmpty)
          .toList();
    }

    return [trimmed];
  }

  // ---------------------------------------------------------------------------
  // Main recon loop
  // ---------------------------------------------------------------------------

  Future<String?> reconTarget(String address, String projectName, {int projectId = 0, int targetId = 0}) async {
    final llmService = LLMService(onPromptResponse: onPromptResponse);
    final env = await _ExecEnv.detect();
    final scope = DeviceUtils.classifyTarget(address);
    final maxIter = scope == TargetScope.external ? _maxIterationsExternal : _maxIterations;
    final outputDir = await StorageService.getTargetPath(projectName, address);
    final outDir = StorageService.toShellPath(env.outputPath(outputDir));
    onProgress?.call('[$address] Target classified as ${scope.name.toUpperCase()}');

    final findings = <String, dynamic>{
      'device': {'ip_address': address, 'name': address},
      'open_ports': <dynamic>[],
      'nmap_scripts': <dynamic>[],
      'web_findings': <dynamic>[],
      'smb_findings': <dynamic>[],
      'dns_findings': <dynamic>[],
      'waf_findings': <dynamic>[],
      'other_findings': <dynamic>[],
    };

    String history = '';
    // Pre-load commands already run for this target from the DB so we never
    // repeat work across separate runs.
    final executedCommands = projectId > 0 && targetId > 0
        ? await DatabaseHelper.getExecutedCommands(projectId, targetId)
        : <String>{};
    final unavailableTools = <String>{};
    // Track per-port tool failures to enable fast fallback (e.g. gobuster → ffuf)
    final portToolFailures = <String, Set<String>>{}; // 'port:tool' → failed
    int consecutiveFailures = 0;
    bool exhaustedOptions = false;
    int connectivityFailures = 0;

    if (scope == TargetScope.external && ReconService._isDomainName(address)) {
      onProgress?.call('[$address] Running passive OSINT...');
      await _runPassiveOsint(
        address: address,
        env: env,
        outDir: outDir,
        findings: findings,
        executedCommands: executedCommands,
        projectId: projectId,
        targetId: targetId,
        llmService: llmService,
      );
    }

    onProgress?.call('[$address] Running baseline scan...');
    // Discover environment once (cached across targets)
    final envInfo = await EnvironmentDiscovery.discover();
    final baseline = await _runBaselineCommands(
      address: address,
      scope: scope,
      env: env,
      outDir: outDir,
      findings: findings,
      executedCommands: executedCommands,
      projectId: projectId,
      targetId: targetId,
      llmService: llmService,
      envInfo: envInfo,
    );
    if (!baseline.isAlive) {
      // Skip LLM evaluation entirely for down hosts — no token spend needed.
      onProgress?.call('[$address] Host is down — skipping (no LLM evaluation needed)');
      onTargetDown?.call(address);
      return null;
    }
    onProgress?.call('[$address] Baseline complete (${baseline.commandsRun.length} steps). Starting LLM-guided deep scan...');

    for (int iteration = 0; iteration < maxIter; iteration++) {
      onProgress?.call('[$address] Iteration ${iteration + 1}...');

      // Per-target command cap: warn at 50, hard stop at 80
      final cmdCount = executedCommands.length;
      if (cmdCount >= 80) {
        onProgress?.call('[$address] Command cap reached ($cmdCount commands) — stopping recon');
        break;
      }
      if (cmdCount == 50) {
        onProgress?.call('[$address] Warning: $cmdCount commands executed — approaching cap (80)');
      }

      String historyHint = '';
      {
        final parts = <String>[];
        if (executedCommands.isNotEmpty) {
          parts.add('## ALREADY EXECUTED - do NOT repeat:\n'
              '${executedCommands.map((c) => '- $c').join('\n')}');
        }
        if (unavailableTools.isNotEmpty) {
          parts.add('## UNAVAILABLE TOOLS - do NOT use:\n'
              '${unavailableTools.map((t) => '- $t').join('\n')}');
        }
        if (connectivityFailures >= 3) {
          parts.add('## ⚠ HOST UNREACHABLE ($connectivityFailures failures)\n'
              'DNS resolution and/or connectivity has failed $connectivityFailures times.\n'
              'Trying a different DNS resolver will NOT fix this — the host does not exist or is down.\n'
              'You MUST CONCLUDE now with host_useful=false.\n'
              'Do NOT run any more DNS or ping commands.');
        }
        if (parts.isNotEmpty) historyHint = '\n${parts.join('\n\n')}\n';
      }

      final prompt = _buildCommandPrompt(
        address: address,
        env: env,
        scope: scope,
        outDir: outDir,
        findings: findings,
        history: history,
        historyHint: historyHint,
        envInfo: envInfo,
      );

      String response;
      try {
        response = await llmService.sendMessage(settings, prompt);
      } catch (e) {
        onProgress?.call('[$address] LLM error: $e');
        history += 'Iteration ${iteration + 1}: LLM error: $e\n\n';
        consecutiveFailures++;
        if (consecutiveFailures >= 3) { exhaustedOptions = true; break; }
        continue;
      }

      final decision = _parseJson(response);

      if (decision['action'] == 'CONCLUDE') {
        final useful = decision['host_useful'] == true;
        final reason = decision['conclude_reason'] ?? 'Recon complete';
        // Don't conclude early if there are still unprobed ports/services
        final focusHints = _buildFocusHints(address, findings, env, scope);
        if (focusHints.isNotEmpty) {
          history += 'Iteration ${iteration + 1}: LLM tried to CONCLUDE but unprobed services remain — continuing.\n\n';
          onProgress?.call('[$address] Overriding early conclude — unprobed services remain');
          consecutiveFailures = 0;
          continue;
        }
        onProgress?.call('[$address] Concluded: $reason');
        if (!useful) {
          onProgress?.call('[$address] Excluded: no useful attack surface');
          return null;
        }
        return await _saveFindings(address, findings, outputDir);
      }

      if (decision['action'] != 'COMMAND') {
        consecutiveFailures++;
        if (consecutiveFailures >= 3) { exhaustedOptions = true; break; }
        continue;
      }

      final command = (decision['command'] as String? ?? '').trim();
      final purpose = decision['purpose'] as String? ?? '';
      final tool = (decision['tool'] as String? ?? '')
          .split(',').first.trim().split(' ').first.trim().toLowerCase();

      if (command.isEmpty) {
        consecutiveFailures++;
        if (consecutiveFailures >= 3) { exhaustedOptions = true; break; }
        continue;
      }

      if (CommandUtils.isSimilarCommand(command, executedCommands)) {
        history += 'Iteration ${iteration + 1}: SKIPPED duplicate: $command\n\n';
        consecutiveFailures++;
        if (consecutiveFailures >= 5) { exhaustedOptions = true; break; }
        continue;
      }

      // Also check DB for commands run in previous sessions — skip silently
      // (recon already merged the output into findings on the prior run)
      if (projectId > 0 && targetId > 0 &&
          await DatabaseHelper.wasCommandExecuted(projectId, targetId, command)) {
        history += 'Iteration ${iteration + 1}: SKIPPED (already run in prior session): $command\n\n';
        onProgress?.call('[$address] Skipping previously run command...');
        consecutiveFailures++;
        if (consecutiveFailures >= 5) { exhaustedOptions = true; break; }
        continue;
      }

      // Track timed-out commands so they are not retried
      bool commandTimedOut = false;

      // Check tool availability (skip for always-available tools)
      if (tool.isNotEmpty && !_isAlwaysAvailable(tool, env)) {
        if (unavailableTools.contains(tool)) {
          history += 'Iteration ${iteration + 1}: SKIPPED - $tool unavailable\n\n';
          consecutiveFailures++;
          continue;
        }
        final toolBinary = CommandExecutor.getToolBinary(tool);
        final exists = await CommandExecutor.checkToolExists(tool, settings, llmService);
        final checkLog = CommandLog(
          timestamp: DateTime.now(),
          command: 'which $toolBinary',
          output: exists ? '$toolBinary found' : '$toolBinary not found',
          exitCode: exists ? 0 : 1,
          vulnerabilityIndex: null,
          projectId: projectId,
          targetId: targetId,
        );
        await DatabaseHelper.insertCommandLog(checkLog);
        onCommandExecuted?.call(checkLog.command, checkLog.output);

        if (!exists) {
          onProgress?.call('[$address] $tool not found, attempting install...');
          final packageManager = await CommandExecutor.detectPackageManager();
          final installed = await CommandExecutor.installTool(tool, settings, llmService, adminPassword: adminPassword, onPasswordNeeded: onPasswordNeeded);
          final installLog = CommandLog(
            timestamp: DateTime.now(),
            command: '$packageManager install $tool',
            output: installed ? 'Successfully installed $tool' : 'Failed to install $tool',
            exitCode: installed ? 0 : 1,
            vulnerabilityIndex: null,
            projectId: projectId,
            targetId: targetId,
          );
          await DatabaseHelper.insertCommandLog(installLog);
          onCommandExecuted?.call(installLog.command, installLog.output);

          if (!installed) {
            unavailableTools.add(tool);
            history += 'Iteration ${iteration + 1}: $tool not found and install failed\n\n';
            onProgress?.call('[$address] $tool not available, skipping...');
            consecutiveFailures++;
            continue;
          }
          onProgress?.call('[$address] $tool installed successfully');
        }
      }

      executedCommands.add(command);
      consecutiveFailures = 0;
      onProgress?.call('[$address] Running: $purpose');

      Map<String, dynamic> result;
      try {
        result = await CommandExecutor.executeCommand(
          command,
          requireApproval,
          adminPassword: adminPassword,
          onApprovalNeeded: onApprovalNeeded,
        );
      } catch (e) {
        history += 'Iteration ${iteration + 1}:\nCommand: $command\nError: $e\n\n';
        if (e.toString().contains('timed out') || e.toString().contains('TimeoutException')) {
          commandTimedOut = true;
        }
        continue;
      }

      // Also detect timeout from output
      if ((result['output'] as String? ?? '').contains('Command timed out')) {
        commandTimedOut = true;
      }

      if (commandTimedOut) {
        history += 'Iteration ${iteration + 1}: TIMED OUT: $command — do NOT retry this command\n\n';
        onProgress?.call('[$address] Command timed out, skipping...');
        continue;
      }

      final output = (result['output'] as String? ?? '').trim();
      final exitCode = result['exitCode'] ?? -1;

      // Persist to DB now that we have the output
      if (projectId > 0 && targetId > 0) {
        await DatabaseHelper.recordExecutedCommand(projectId, targetId, command,
            output: output, exitCode: exitCode as int);
      }

      // Log to command log panel (same as exploit executor)
      final log = CommandLog(
        timestamp: DateTime.now(),
        command: '[RECON] $command',
        output: output.isEmpty ? '(no output)' : output,
        exitCode: exitCode as int,
        vulnerabilityIndex: null,
        projectId: projectId,
        targetId: targetId,
      );
      await DatabaseHelper.insertCommandLog(log);
      onCommandExecuted?.call(log.command, log.output);

      // Detect unavailable tools from output
      final notFoundMatch = RegExp(r"'?(\S+)'? is not recognized|(\S+): command not found|(\S+): not found")
          .firstMatch(output);
      if (notFoundMatch != null) {
        final missingTool = (notFoundMatch.group(1) ?? notFoundMatch.group(2) ?? notFoundMatch.group(3) ?? '').toLowerCase();
        if (missingTool.isNotEmpty) unavailableTools.add(missingTool);
      }

      // Track DNS/connectivity failures so the LLM is forced to conclude when the host is unreachable.
      // Patterns that reliably indicate the host cannot be reached:
      final connectivityFailurePatterns = [
        'could not resolve',
        'failed to resolve',
        'nxdomain',
        'name or service not known',
        'no such host',
        'connection refused',
        '0 hosts up',
        'network is unreachable',
      ];
      final lowerOutput = output.toLowerCase();
      // Also treat empty output from a DNS tool (dig/host/nslookup) with non-zero exit as a failure
      final isDnsTool = ['dig', 'host', 'nslookup', 'drill'].any((t) => command.contains(t));
      final hasConnectivityFailure = connectivityFailurePatterns.any((p) => lowerOutput.contains(p)) ||
          (isDnsTool && output.isEmpty && exitCode != 0);
      if (hasConnectivityFailure) {
        connectivityFailures++;
        if (connectivityFailures >= 3) {
          onProgress?.call('[$address] Connectivity failures: $connectivityFailures — host appears unreachable');
        }
      } else if (output.isNotEmpty) {
        // Successful output resets the connectivity failure streak
        connectivityFailures = 0;
      }

      // Track gobuster/ffuf/dirb failures per port for fast fallback
      if (exitCode != 0 && (command.contains('gobuster') || command.contains('ffuf') || command.contains('dirb'))) {
        final portMatch = RegExp(r':(\d+)').firstMatch(command);
        final portKey = portMatch?.group(1) ?? 'unknown';
        final toolName = command.contains('gobuster') ? 'gobuster'
            : command.contains('ffuf') ? 'ffuf' : 'dirb';
        portToolFailures.putIfAbsent(portKey, () => {}).add(toolName);
        // Inject hint into history so LLM knows to switch tools
        if (toolName == 'gobuster' && !portToolFailures[portKey]!.contains('ffuf')) {
          history += 'NOTE: gobuster failed on port $portKey — switch to ffuf immediately, do NOT retry gobuster.\n\n';
        }
      }

      history += 'Iteration ${iteration + 1}:\n'
          'Command: $command\n'
          'Purpose: $purpose\n'
          'Exit: $exitCode\n'
          'Output: ${CommandUtils.truncateOutput(output, 1500)}\n\n';

      if (output.isNotEmpty) {
        onProgress?.call('[$address] Parsing output...');
        await _mergeFindings(llmService, address, command, purpose, output, findings);
      }
    }

    if (exhaustedOptions) {
      onProgress?.call('[$address] Exhausted useful options, evaluating...');
    } else {
      onProgress?.call('[$address] Safety limit reached ($maxIter iterations), evaluating...');
    }
    return await _evaluateAndSave(llmService, address, findings, outputDir);
  }

  // ---------------------------------------------------------------------------
  // Prompt builder
  // ---------------------------------------------------------------------------

  String _buildCommandPrompt({
    required String address,
    required _ExecEnv env,
    required TargetScope scope,
    required String outDir,
    required Map<String, dynamic> findings,
    required String history,
    required String historyHint,
    EnvironmentInfo? envInfo,
  }) {
    final focusHints = _buildFocusHints(address, findings, env, scope);
    final baseline = scope == TargetScope.external
        ? _externalBaseline(address, env)
        : _internalBaseline(address, env);
    final scopeLabel = scope == TargetScope.external ? 'EXTERNAL (internet-facing)' : 'INTERNAL (LAN)';
    return '''You are an expert penetration tester performing RECONNAISSANCE ONLY on target: $address
Target scope: $scopeLabel
Your sole goal is to COLLECT DATA. Do NOT test exploits, do NOT attempt logins, do NOT modify anything on the target.
Every command must be read-only and purely informational.

## ATTACKER SYSTEM:
- OS: ${env.osInfo}
- Execution environment: ${env.label}
- Output directory: $outDir (ALL files MUST be saved here — use full absolute path)

${envInfo != null ? envInfo.toPromptBlock() : ''}
${env.shellRules}

## FILE OUTPUT RULES (CRITICAL):
- ALL tool output files MUST use the full absolute path: $outDir
- NEVER use relative paths like temp/, ./temp/, or just a filename

## OUTPUT VISIBILITY RULES (CRITICAL — read carefully):
When you redirect output to a file with `>`, the output is INVISIBLE to your context.
You will not be able to see what the command found, and cannot adapt based on the results.

RULE: For diagnostic/short-output commands, use `tee` so output goes BOTH to file AND to your context:
  * WRONG: dig a target.com > "$outDir/dig_a.txt"
  * RIGHT:  dig a target.com | tee "$outDir/dig_a.txt"
  * WRONG: curl -I https://target.com > "$outDir/headers.txt"
  * RIGHT:  curl -s -I https://target.com | tee "$outDir/headers.txt"
  * WRONG: whois target.com > "$outDir/whois.txt"
  * RIGHT:  whois target.com | tee "$outDir/whois.txt"

Use `tee` for: dig, host, nslookup, whois, curl headers, nmap short scans, any command where
you need to READ the results to decide what to do next.

Use `>` (not tee) ONLY for: large outputs like full nmap port scans, gobuster, ffuf, nikto —
where you are saving for later analysis and do not need to react to the output immediately.

Do NOT use command substitution like `\$(dig target.com +short)` inside another command's arguments.
If you need an IP from a DNS lookup, run the DNS lookup first in a separate command, read the result,
then use the IP directly in the next command.

## WHAT YOU HAVE FOUND SO FAR:
${json.encode(findings)}
${(findings['osint_dorks'] as List?)?.isNotEmpty == true ? '''
## GOOGLE DORK QUERIES (generated for manual use — do NOT re-generate these):
${(findings['osint_dorks'] as List).join('\n')}''' : ''}

## PREVIOUS COMMANDS RUN:
$history
$historyHint

$focusHints

$baseline

## TOOL SYNTAX NOTE — NUCLEI (if used):
- Use -id for specific CVEs: nuclei -u http://$address -id CVE-2021-41773
- Use -tags for technology scans: nuclei -u http://$address -tags drupal
- Do NOT use -t with file paths — template files are not present locally

## CONCLUDE when ALL of these are true:
- All open ports have been individually probed beyond the initial scan
- Every service has a version string, banner, or is confirmed unresponsive
- All web ports have been fingerprinted (headers, tech stack, path enumeration)
- No new information returned in the last 2 iterations
- OR: host is truly unreachable (DNS NXDOMAIN AND all ports filtered/timed out)

## host_useful field — CRITICAL:
- Set host_useful=true whenever port 80 or 443 is open, even if behind a WAF/CDN.
  Web application vulnerabilities are testable through Cloudflare/CDN at the public address.
- Set host_useful=false ONLY when: DNS NXDOMAIN AND no open ports AND all connections time out.
- WAF detected + no origin IP found → still host_useful=true

## RESPONSE (JSON only, no markdown):
{
  "thought": "what I found so far and exactly why I am choosing this next command",
  "action": "COMMAND or CONCLUDE",
  "command": "exact platform-appropriate read-only command",
  "tool": "primary tool name",
  "purpose": "what specific data this will collect",
  "conclude_reason": "why recon is complete (CONCLUDE only)",
  "host_useful": true or false
}

Respond ONLY with valid JSON.''';
  }

  String _internalBaseline(String address, _ExecEnv env) => '''
## RECON OBJECTIVES - INTERNAL TARGET:
Work through these objectives in order. Use whatever tools are available on the system.

### OBJECTIVE 1 — FULL PORT & SERVICE ENUMERATION
Collect: Every open TCP/UDP port, service name, product, exact version string, banner.
Why: Services on non-standard ports are common. Every open port is a potential entry point.
Approach: Scan all 65535 TCP ports with version detection, plus key UDP ports (161, 623, 2049).
Also attempt IPv6 discovery — internal hosts unreachable on IPv4 may respond on IPv6.
Timing: Use aggressive timing — internal hosts are local and won't rate-limit.

### OBJECTIVE 2 — OS & HOST IDENTIFICATION
Collect: OS name and version, hostname, domain membership, uptime, MAC/vendor.
Why: OS determines which exploit classes apply (EternalBlue = Windows, SambaCry = Linux,
AD attacks = domain-joined Windows). Domain membership is critical for scoping AD attacks.

### OBJECTIVE 3 — SERVICE DEEP-DIVE (per open port)
For each open port, collect everything available:
- Web (HTTP/HTTPS): headers, title, technology stack, CMS or application name+version,
  login portals, API endpoints, default credential exposure (admin panels, management UIs)
- SMB: share list, signing status, OS info, null session access, domain/workgroup, SMB version
- LDAP (389/636/3268/3269): domain name, naming context, base DN, supported LDAP features,
  any unauthenticated information disclosure (null bind query)
- Kerberos (88): domain name confirmation, user enumeration, pre-auth not required (AS-REP)
- WinRM (5985/5986): authentication methods, OS version
- FTP: anonymous access, banner, directory listing if accessible
- SSH: version string, supported algorithms, host key fingerprint, auth methods
- Databases (MySQL/MSSQL/PostgreSQL): version, accessible without credentials, exposed databases
- Redis (6379): unauthenticated access, version, keyspace listing
- MongoDB (27017): unauthenticated access, database listing
- Elasticsearch (9200): unauthenticated access, index listing, version, cluster health
- Memcached (11211): unauthenticated access, stats, cached key names
- NFS (2049): exported shares, mount permissions, root squash status
- IPMI (623 UDP): authentication type, cipher suite 0 (unauthenticated), version
- DNS: all record types, zone transfer attempt, recursion enabled
- SNMP: community strings (public/private/community), system info, interface table, ARP cache
- RDP: NLA status, encryption level, version, BlueKeep/DejaBlue indicators
- VNC: authentication required, version
- Any other service: banner grab, version, protocol fingerprint

### OBJECTIVE 4 — ACTIVE DIRECTORY DOMAIN ENUMERATION (when domain membership detected)
When the host is domain-joined or a domain controller is identified:
Collect: Domain name, domain controllers list, all domain users, groups, computers,
password policy, account lockout policy, GPO names, OU structure, trust relationships,
Kerberoastable accounts (users with SPNs), AS-REP-roastable accounts (no pre-auth),
AdminCount=1 accounts, privileged group membership (Domain Admins, Enterprise Admins).
Why: AD misconfigurations are the most common path to domain compromise. SPNs enable
offline password cracking. Accounts without Kerberos pre-auth leak crackable hashes passively.
Approach: Use LDAP queries and domain enumeration tools. Unauthenticated null sessions
may reveal partial data; authenticated sessions (if credentials found) reveal much more.

### OBJECTIVE 5 — VULNERABILITY SURFACE MAPPING
Collect: Version strings mapped to known CVE ranges, misconfigurations, weak default settings.
Why: Exact versions enable CVE matching in the analysis phase.
Approach: Use vulnerability scanning scripts/tools available on the system against each service.

### CONCLUDE when:
- All 65535 TCP ports scanned with version detection
- Every open service has a version string, banner, or is confirmed unresponsive
- All web ports have been fingerprinted (headers, tech stack, path enumeration)
- If domain-joined: AD enumeration attempted (users, groups, SPNs, pre-auth status)
- High-value unauthenticated services checked (Redis, MongoDB, Elasticsearch, NFS exports)
- UDP scan run for SNMP (161), IPMI (623), NFS (2049)
- No new data returned in last 3 iterations
- OR: host is down / all ports filtered''';

  String _externalBaseline(String address, _ExecEnv env) {
    final isWin = env.isNativeWindows;
    final winNote = isWin ? '\nNote: Windows — prefer PowerShell/curl equivalents where Unix tools are unavailable.' : '';
    return '''
## RECON OBJECTIVES - EXTERNAL TARGET:$winNote
External targets differ from internal: rate limiting, WAFs, and firewalls are common.
Use whatever tools are available. These are OBJECTIVES — not a fixed tool list.

### OBJECTIVE 1 — PASSIVE INTELLIGENCE (before any active scanning)
Collect: DNS records (A, MX, NS, TXT, AAAA, CNAME, SOA), subdomains via certificate
transparency logs and passive sources, WHOIS/ASN/org data, WAF/CDN presence,
hosting provider, email addresses, employee names.
Why: Expands attack surface beyond the single IP. Subdomains often have weaker security.
CT logs (crt.sh) and passive DNS are free and leave no trace on the target.
Timing: Do this BEFORE active scanning — it costs nothing and shapes the scan strategy.

### OBJECTIVE 2 — PORT & SERVICE ENUMERATION
Collect: Open ports, service names, product names, exact version strings, banners.
Why: Version strings are the primary input for CVE matching.
Approach: Begin with top-1000 ports, then follow with a full port scan (-p-) if initial
results are promising. Do not stop at only a handful of common ports.
Timing: Use moderate timing (not aggressive) — external hosts may block or rate-limit.

### OBJECTIVE 3 — SSL/TLS ANALYSIS (every HTTPS port)
Collect: Certificate CN, SANs (reveals additional hostnames/subdomains), issuer,
expiry, supported protocol versions, cipher suites, known protocol weaknesses.
Why: Weak TLS configs are directly exploitable. SANs frequently reveal internal hostnames.
Use any available tool that can enumerate TLS configuration.

### OBJECTIVE 4 — WEB APPLICATION FINGERPRINTING (every HTTP/HTTPS port)
Collect: Server/framework headers, technology stack, CMS name and version,
HTTP methods accepted, robots.txt, sitemap.xml, error page content,
login portals, admin interfaces, API endpoints, GraphQL, API docs.
Why: Technology identification maps directly to CVEs. Exposed admin panels are high value.
Approach: Fetch the root page and parse the HTML — look for generator meta tags, JS
framework hints, inline library names, and version strings in comments or script paths.
Use a technology identification tool to fingerprint the full stack beyond just HTTP headers.
For CMS: identify first, then use CMS-appropriate enumeration for plugins/themes/users.

### OBJECTIVE 5 — SUBDOMAIN ACTIVE ENUMERATION
Collect: Subdomains beyond what CT logs reveal, by actively brute-forcing DNS names.
Why: CT logs are passive and incomplete. Active DNS enumeration often finds internal,
staging, api, dev, and admin subdomains not listed in certificates.
Approach: Use a DNS brute-force or OSINT tool with a common subdomain wordlist.
Timing: Do this AFTER passive collection so duplicates are avoided.

### OBJECTIVE 6 — WAF/CDN ORIGIN IP DISCOVERY (CRITICAL when WAF/CDN is detected)
When a WAF or CDN (Cloudflare, Akamai, Fastly, Sucuri, Incapsula, etc.) is identified:
- All direct attack attempts against the WAF IP are WASTED EFFORT.
- FIRST priority: find the real origin server IP hiding behind the WAF.
Methods to try (in order):
  1. Historical DNS: look up pre-CDN A records via passive DNS history sources (SecurityTrails,
     ViewDNS, RiskIQ) — many operators set up CDN without changing DNS everywhere.
  2. SPF record: dig TXT $address — SPF often lists the real mail/web server IPs.
  3. MX record IPs: mail servers are frequently on the same subnet as the origin web server.
  4. Certificate SANs: additional hostnames in the certificate may resolve directly.
  5. Direct IP probe: if you find a candidate origin IP, verify with curl using Host header.
Why: Once the real IP is known, you bypass the WAF entirely and can test the raw application.

### OBJECTIVE 7 — API & ENDPOINT DISCOVERY
Collect: REST API versions, GraphQL schema (introspection query), OpenAPI/Swagger specs,
authentication mechanisms, debug/status/health endpoints, exposed internal paths.
Why: APIs frequently have weaker authentication and expose more functionality than the UI.

### OBJECTIVE 8 — DIRECTORY & PATH ENUMERATION (when web content is confirmed)
When a web port returns useful content (not just a WAF block page):
Collect: Common directories, hidden paths, backup files, config leaks, admin portals.
Why: Reveals unlinked functionality, exposed files, and entry points not visible from the UI.
Approach: Use a directory/path brute-force tool with a common wordlist, focused on the
confirmed technology stack. Use appropriate file extensions for the detected language.

### OBJECTIVE 9 — EMAIL & CONTACT HARVESTING
Collect: Email addresses, employee names, organisational structure hints.
Why: Provides phishing targets and username patterns for credential attacks.
Use passive sources — do not send emails or interact with mail servers.

### CONCLUDE when:
- Passive intelligence gathered (DNS, CT logs, WAF detection)
- Port scan completed (top-1000 minimum) with version strings or banners on all open ports
- Every web port has been fingerprinted (headers, tech stack, path enumeration)
- SSL/TLS analysed on all HTTPS ports
- If WAF/CDN detected: attempted origin IP discovery via passive DNS and SPF/MX methods
- Active subdomain enumeration attempted
- No new data returned in last 2 iterations
- OR: host is truly unreachable (DNS NXDOMAIN, all ports filtered, zero response)

### host_useful field (CRITICAL — read carefully):
- Set host_useful=true whenever port 80 or 443 is OPEN and responding, even through a WAF/CDN.
  REASON: Web application vulnerabilities (XSS, CSRF, injection, auth bypass, logic flaws) exist
  at the application layer and are fully testable through Cloudflare or any other CDN/WAF.
  Failing to find the origin IP does NOT make the target unreachable — it is accessible at its public address.
- Set host_useful=false ONLY when the host is completely unreachable:
  DNS does not resolve (NXDOMAIN) AND no ports are open AND all connection attempts time out.
- Do NOT set host_useful=false just because: origin IP unknown, WAF detected, or port scan timed out.''';
  }

  // ---------------------------------------------------------------------------
  // Findings-driven focus hints
  // ---------------------------------------------------------------------------

  String _buildFocusHints(String address, Map<String, dynamic> findings, _ExecEnv env, TargetScope scope) {
    final isExternal = scope == TargetScope.external;
    final ports = (findings['open_ports'] as List? ?? []).cast<Map<String, dynamic>>();
    final webFindings = (findings['web_findings'] as List? ?? []);
    final smbFindings = (findings['smb_findings'] as List? ?? []);
    final device = findings['device'] as Map<String, dynamic>? ?? {};

    if (ports.isEmpty) return '';

    final hints = <String>[];
    final isWin = env.isNativeWindows;

    // Group ports by service category
    final webPorts = <int>[];
    final smbPorts = <int>[];
    final ftpPorts = <int>[];
    final sshPorts = <int>[];
    final dnsPorts = <int>[];
    final snmpPorts = <int>[];
    final rdpPorts = <int>[];
    final telnetPorts = <int>[];
    final mysqlPorts = <int>[];
    final postgresPorts = <int>[];
    final mssqlPorts = <int>[];
    final ldapPorts = <int>[];
    final kerberosPorts = <int>[];
    final winrmPorts = <int>[];
    final redisPorts = <int>[];
    final mongoPorts = <int>[];
    final elasticPorts = <int>[];
    final nfsPorts = <int>[];
    final unknownPorts = <Map<String, dynamic>>[];

    for (final p in ports) {
      final port = (p['port'] as num?)?.toInt() ?? 0;
      final service = (p['service'] as String? ?? '').toLowerCase();
      final product = (p['product'] as String? ?? '').toLowerCase();
      final banner = (p['banner'] as String? ?? '').toLowerCase();

      // Classify by what the service actually is, not by port number.
      // Port numbers are only used as a last resort for 80/443 where nmap
      // may not populate the service field before any probing has run.
      final isHttp = service.contains('http') || product.contains('http') ||
          banner.contains('server:') || banner.contains('<html') ||
          (port == 80 || port == 443);

      if (isHttp) {
        webPorts.add(port);
      } else if (service.contains('smb') || service.contains('netbios') || service.contains('microsoft-ds')) {
        smbPorts.add(port);
      } else if (service.contains('ftp')) {
        ftpPorts.add(port);
      } else if (service.contains('ssh')) {
        sshPorts.add(port);
      } else if (service.contains('dns') || service.contains('domain')) {
        dnsPorts.add(port);
      } else if (service.contains('snmp')) {
        snmpPorts.add(port);
      } else if (service.contains('rdp') || service.contains('ms-wbt') || service.contains('msrdp')) {
        rdpPorts.add(port);
      } else if (service.contains('telnet')) {
        telnetPorts.add(port);
      } else if (service.contains('mysql')) {
        mysqlPorts.add(port);
      } else if (service.contains('postgres') || service.contains('postgresql')) {
        postgresPorts.add(port);
      } else if (service.contains('mssql') || service.contains('ms-sql') || service.contains('microsoft sql')) {
        mssqlPorts.add(port);
      } else if (service.contains('ldap') || port == 389 || port == 636 || port == 3268 || port == 3269) {
        ldapPorts.add(port);
      } else if (service.contains('kerberos') || port == 88) {
        kerberosPorts.add(port);
      } else if (service.contains('winrm') || service.contains('wsman') || port == 5985 || port == 5986) {
        winrmPorts.add(port);
      } else if (service.contains('redis') || port == 6379) {
        redisPorts.add(port);
      } else if (service.contains('mongo') || port == 27017 || port == 27018) {
        mongoPorts.add(port);
      } else if (service.contains('elastic') || port == 9200 || port == 9300) {
        elasticPorts.add(port);
      } else if (service.contains('nfs') || service.contains('mountd') || port == 2049) {
        nfsPorts.add(port);
      } else {
        // Anything not positively identified goes to unknown for banner grabbing
        unknownPorts.add(p);
      }
    }

    // OS fingerprint hint — skip for external (OS fingerprinting is noisy and often blocked)
    final os = device['os'] as String? ?? '';
    if (os.isEmpty && ports.isNotEmpty && !isExternal) {
      hints.add('- OS not yet identified — collect OS fingerprint and hostname');
    }

    // UDP scan guard: only suggest UDP if TCP baseline found at least one open port
    if (!isExternal && ports.isEmpty) {
      hints.add('- No TCP ports found yet — do NOT run UDP scans until at least one TCP port is confirmed open');
    }

    // External-only: WAF/CDN detection and origin IP discovery hint
    if (isExternal) {
      final wafKeywords = ['cloudflare', 'akamai', 'fastly', 'sucuri', 'incapsula',
                           'imperva', 'f5', 'waf', 'cdn', 'proxy'];
      final wafProduct = ports
          .map((p) => (p['product'] as String? ?? '').toLowerCase())
          .firstWhere((prod) => wafKeywords.any((kw) => prod.contains(kw)), orElse: () => '');
      final wafFindings = findings['waf_findings'] as List? ?? [];
      final wafDetected = wafProduct.isNotEmpty || wafFindings.isNotEmpty;

      if (wafDetected) {
        final wafName = wafProduct.isNotEmpty ? wafProduct : 'WAF/CDN';
        final hasOriginIp = (device['origin_ip'] as String? ?? '').isNotEmpty;
        if (!hasOriginIp) {
          hints.add('- $wafName DETECTED — direct attacks against this IP hit the WAF, not the app.');
          hints.add('  PRIORITY: find the REAL origin server IP before any further web testing:');
          hints.add('  1. Query historical/passive DNS sources for pre-CDN A records');
          hints.add('  2. Parse SPF TXT record — it often lists real mail/web server IPs');
          hints.add('  3. Resolve MX record IPs — mail servers are often on the same subnet');
          hints.add('  4. Check all SANs from the TLS certificate — some may resolve directly');
          hints.add('  5. If a candidate IP is found, verify: curl -H "Host: $address" http://CANDIDATE_IP/');
        } else {
          hints.add('  - Origin IP identified — test directly against the origin, bypassing the WAF');
        }
      }
    }

    // External-only: comprehensive port scan hint
    if (isExternal && ports.length < 20) {
      hints.add('- Only ${ports.length} open port(s) found — ensure a comprehensive port scan has been run (top-1000 minimum). If only a small set of common ports was scanned, run a broader scan now.');
    }

    // SSL/TLS hint for HTTPS ports not yet checked (internal and external)
    if (!isWin) {
      for (final p in ports) {
        final port = (p['port'] as num?)?.toInt() ?? 0;
        final svc = (p['service'] as String? ?? '').toLowerCase();
        final isHttps = svc.contains('https') || svc.contains('ssl') || port == 443 || port == 8443;
        if (isHttps) {
          final alreadyChecked = (findings['nmap_scripts'] as List? ?? [])
              .cast<Map<String, dynamic>>()
              .any((s) => s['port'] == port && (s['script_id'] as String? ?? '').contains('ssl'));
          if (!alreadyChecked) {
            hints.add('- SSL/TLS on port $port not yet analysed — run ONE comprehensive scan: '
                'nmap -p $port --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-dh-params,ssl-poodle $address '
                '(do NOT run multiple separate SSL nmap invocations on the same port)');
          }
        }
      }
    }

    // Web hints
    for (final port in webPorts) {
      final portEntry = ports.firstWhere((p) => (p['port'] as num?)?.toInt() == port, orElse: () => {});
      final svc = (portEntry['service'] as String? ?? '').toLowerCase();
      final scheme = svc.contains('https') || svc.contains('ssl') ? 'https' : 'http';
      final url = '$scheme://$address:$port';
      final existingFinding = webFindings.cast<Map<String, dynamic>>().firstWhere(
          (w) => (w['url'] as String? ?? '').contains(':$port'), orElse: () => {});
      final rootStatus = existingFinding['status'] as int? ?? 0;
      final hasUsefulContent = existingFinding.isNotEmpty && rootStatus == 200;
      final wasProbed = existingFinding.isNotEmpty;

      if (!wasProbed) {
        hints.add('- Web port $port not yet probed — collect: HTTP status, server header, technology stack, redirect chain');
      } else if (!hasUsefulContent) {
        hints.add('- Port $port root returned HTTP $rootStatus — application likely at a sub-path; enumerate paths and common locations (admin, login, api, console, manager, status, health, docs)');
      } else {
        final serverHeader = _findWebServer(webFindings, port);
        final techs = (webFindings.cast<Map<String, dynamic>>()
            .firstWhere((w) => (w['url'] as String? ?? '').contains(':$port'), orElse: () => {})
            ['technologies'] as List? ?? []).join(' ').toLowerCase();
        hints.add('- Port $port web service identified${serverHeader.isNotEmpty ? " ($serverHeader)" : ""} — collect more:');
        hints.add('  • Fetch robots.txt and sitemap.xml');
        hints.add('  • Enumerate directories and paths${isExternal ? " (use larger wordlist for external targets)" : ""}');
        hints.add('  • Identify full technology stack and exact versions (server, framework, CMS, JS libraries)');
        hints.add('  • Check common paths: admin, login, phpmyadmin, manager, api, console, dashboard');
        hints.add('  • Collect all HTTP response headers');
        if (isExternal) {
          hints.add('  • Check HTTP methods accepted (OPTIONS request)');
          hints.add('  • Probe API surface: /api, /api/v1, /graphql (introspection), /swagger, /openapi.json, /docs');
          if (techs.contains('wordpress') || techs.contains('wp-')) {
            hints.add('  • WordPress detected — enumerate plugins, themes, and users');
          } else if (techs.contains('drupal')) {
            hints.add('  • Drupal detected — enumerate modules and version');
          } else if (techs.contains('joomla')) {
            hints.add('  • Joomla detected — enumerate extensions and version');
          } else if (techs.isNotEmpty) {
            hints.add('  • CMS/framework identified — use appropriate enumeration tool');
          }
        }
      }
    }

    // External-only: HTTP method enumeration and API surface
    if (isExternal) {
      for (final port in webPorts) {
        final existingNotes = (findings['web_findings'] as List? ?? [])
            .cast<Map<String, dynamic>>()
            .firstWhere((w) => (w['url'] as String? ?? '').contains(':$port'), orElse: () => {})
            ['notes'] as String? ?? '';
        final hasApiData = existingNotes.toLowerCase().contains('graphql') ||
            existingNotes.toLowerCase().contains('/api');
        if (!hasApiData) {
          hints.add('- Port $port API surface not yet probed — check for REST API versions, GraphQL (introspection), OpenAPI/Swagger docs, and unauthenticated debug/status endpoints');
        }
      }
    }

    // SMB hints — internal only
    for (final port in smbPorts) {
      if (isExternal) continue;
      final alreadyProbed = smbFindings.isNotEmpty;
      if (!alreadyProbed) {
        hints.add('- SMB port $port not yet probed — collect: share list, null session access, signing status, OS info, domain/workgroup, SMB version, known vulnerabilities (MS17-010, CVE-2017-7494)');
      }
    }

    // FTP hints
    for (final port in ftpPorts) {
      hints.add('- FTP port $port — collect: banner/version, anonymous access status, directory listing if accessible');
    }

    // SSH hints
    for (final port in sshPorts) {
      hints.add('- SSH port $port — collect: exact version string, supported algorithms, host key fingerprint, authentication methods');
    }

    // DNS hints
    for (final port in dnsPorts) {
      hints.add('- DNS port $port — collect: all record types, zone transfer attempt, recursion status, version string');
    }

    // SNMP hints
    for (final port in snmpPorts) {
      hints.add('- SNMP port $port — collect: system info, interface table, running processes, installed software (try community strings: public, private, community)');
    }

    // RDP hints
    for (final port in rdpPorts) {
      hints.add('- RDP port $port — collect: NLA requirement, encryption level, version, known vulnerabilities (BlueKeep CVE-2019-0708, DejaBlue)');
    }

    // Telnet hints
    for (final port in telnetPorts) {
      hints.add('- Telnet port $port — collect: banner, device type, authentication prompt');
    }

    // Database hints
    for (final port in mysqlPorts) {
      hints.add('- MySQL port $port — collect: exact version, unauthenticated access, accessible databases');
    }
    for (final port in postgresPorts) {
      hints.add('- PostgreSQL port $port — collect: exact version, authentication method, accessible databases');
    }
    for (final port in mssqlPorts) {
      hints.add('- MSSQL port $port — collect: exact version, instance name, authentication method, sa account status');
    }

    // LDAP hints — internal only
    for (final port in ldapPorts) {
      if (isExternal) continue;
      hints.add('- LDAP port $port — collect: domain name, base DN, null bind (unauthenticated query), naming contexts, domain controllers list, password policy');
    }

    // Kerberos hints — internal only
    for (final port in kerberosPorts) {
      if (isExternal) continue;
      hints.add('- Kerberos port $port — collect: domain name, enumerate valid usernames, check for accounts with pre-auth disabled (AS-REP roasting candidates), list SPNs (Kerberoasting candidates)');
    }

    // WinRM hints — internal only
    for (final port in winrmPorts) {
      if (isExternal) continue;
      hints.add('- WinRM port $port — collect: authentication methods accepted, OS version, test for unauthenticated access or default/weak credentials');
    }

    // Redis hints — internal only
    for (final port in redisPorts) {
      if (isExternal) continue;
      hints.add('- Redis port $port — collect: unauthenticated access (try connecting with no password), server version, CONFIG GET, keyspace listing, check for write access (critical: can write SSH keys or cron jobs)');
    }

    // MongoDB hints — internal only
    for (final port in mongoPorts) {
      if (isExternal) continue;
      hints.add('- MongoDB port $port — collect: unauthenticated access, database and collection listing, version, check for sensitive data exposure');
    }

    // Elasticsearch hints — internal only
    for (final port in elasticPorts) {
      if (isExternal) continue;
      hints.add('- Elasticsearch port $port — collect: unauthenticated access (HTTP GET /), cluster info, index listing, version, check for sensitive data in indices');
    }

    // NFS hints — internal only
    for (final port in nfsPorts) {
      if (isExternal) continue;
      hints.add('- NFS port $port — collect: exported shares list, mount permissions per share, root squash status, check for world-readable or world-writable exports');
    }

    // Unknown ports
    for (final p in unknownPorts) {
      final port = (p['port'] as num?)?.toInt() ?? 0;
      hints.add('- Port $port has no banner or version yet — grab banner and identify service');
    }

    if (hints.isEmpty) return '';
    return '## PRIORITY TARGETS (act on these first, in order):\n${hints.join("\n")}';
  }

  String _findWebServer(List webFindings, int port) {
    for (final w in webFindings) {
      if ((w['url'] as String? ?? '').contains(':$port') ||
          (w['server'] as String? ?? '').isNotEmpty) {
        return (w['server'] as String? ?? '').toLowerCase();
      }
    }
    return '';
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  Future<void> _mergeFindings(
    LLMService llmService,
    String address,
    String command,
    String purpose,
    String output,
    Map<String, dynamic> findings,
  ) async {
    final prompt = '''You are a penetration tester extracting reconnaissance data from command output.
Target: $address
Command run: $command
Purpose: $purpose

Output to parse:
$output

Extract EVERY piece of information useful for later vulnerability analysis.
Be thorough — capture version numbers, banners, headers, paths, usernames, share names, record values, config details.
Only include keys that have real data from this output (omit empty arrays/objects).

CRITICAL FOR NMAP OUTPUT: The nmap output may contain 20+ open ports. You MUST extract ALL of them into open_ports[]. Do NOT stop after the first port. Scan the ENTIRE output for every line matching "PORT/tcp open" or "PORT/udp open" and include each one.

CRITICAL FOR VERSION EXTRACTION:
- Extract versions from URL query strings: e.g. "?v=10.6.3" or "?ver=8.2.1" in asset URLs → record as the app version
- Extract versions from HTML meta tags: <meta name="generator" content="WordPress 6.1">
- Extract versions from HTTP headers: X-Powered-By, X-Generator, X-Drupal-Cache, etc.
- Extract versions from JS/CSS asset filenames: e.g. jquery-3.6.0.min.js → jQuery 3.6.0
- If you see asset URLs like "/core/assets/vendor/jquery/jquery.min.js?v=10.6.3", the "v=" value is the CMS version

Schema:
{
  "device": {
    "os": "full OS string",
    "os_version": "version",
    "hostname": "hostname",
    "mac": "MAC address",
    "uptime": "uptime if shown"
  },
  "open_ports": [{
    "port": 80,
    "protocol": "tcp",
    "state": "open",
    "service": "http",
    "product": "Apache httpd",
    "version": "2.4.41",
    "extra_info": "(Ubuntu)",
    "banner": "raw banner text",
    "cpe": "cpe:/a:apache:http_server:2.4.41"
  }],
  "nmap_scripts": [{"port": 80, "script_id": "http-title", "output": "full script output"}],
  "web_findings": [{
    "url": "http://target:80",
    "status": 200,
    "server": "Apache/2.4.41",
    "content_type": "text/html",
    "powered_by": "PHP/7.4",
    "headers": {"X-Frame-Options": "SAMEORIGIN"},
    "title": "page title",
    "paths_found": ["/admin", "/login"],
    "technologies": ["WordPress 5.8", "jQuery 3.6"],
    "notes": "any other relevant observations"
  }],
  "smb_findings": [{
    "share": "ADMIN\$",
    "type": "Disk",
    "access": "NO ACCESS",
    "os": "Windows 10",
    "domain": "WORKGROUP",
    "signing": "disabled",
    "notes": ""
  }],
  "dns_findings": [{"record_type": "A", "name": "target", "value": "1.2.3.4", "ttl": 300}],
  "ftp_findings": [{"anonymous_allowed": false, "banner": "vsftpd 3.0.3", "files": []}],
  "ssh_findings": [{"version": "OpenSSH 8.2", "algorithms": [], "host_keys": []}],
  "db_findings": [{"type": "mysql", "version": "8.0.27", "databases": [], "notes": ""}],
  "waf_findings": [{"waf": "Cloudflare", "detected_by": "cf-ray header", "notes": "rate limiting likely"}],
  "other_findings": [{"type": "snmp", "data": "full extracted data"}]
}

Respond ONLY with valid JSON.''';

    try {
      final response = await llmService.sendMessage(settings, prompt);
      final parsed = JsonParser.tryParseJson(response);
      if (parsed != null) _deepMerge(findings, parsed);
    } catch (_) {}
  }

  Future<String?> _evaluateAndSave(
    LLMService llmService,
    String address,
    Map<String, dynamic> findings,
    String outputDir,
  ) async {
    final prompt = '''Evaluate these recon findings for target $address.

## FINDINGS:
${json.encode(findings)}

A host IS useful if ANY of these are true:
- Port 80 or 443 is open and responding (even through a WAF/CDN proxy — the web application is still testable)
- Any open port has an identified service, version number, or banner
- Any network service is confirmed reachable

A host is NOT useful only if ALL of these are true:
- No open ports found at all
- Host is down or DNS does not resolve (NXDOMAIN)
- All connection attempts timed out or were filtered

IMPORTANT: Do NOT mark a host as not useful simply because it is behind Cloudflare, a CDN, or a WAF.
Port 80/443 behind Cloudflare = web application is fully testable for XSS, CSRF, injection, authentication bypass, etc.

{"useful": true or false, "reason": "brief explanation"}

Respond ONLY with valid JSON.''';

    try {
      final response = await llmService.sendMessage(settings, prompt);
      final eval = JsonParser.tryParseJson(response);
      if (eval == null || eval['useful'] != true) {
        onProgress?.call('[$address] Excluded: ${eval?['reason'] ?? 'no useful data'}');
        return null;
      }
    } catch (_) {
      final ports = findings['open_ports'] as List?;
      if (ports == null || ports.isEmpty) {
        onProgress?.call('[$address] Excluded: no open ports found');
        return null;
      }
    }

    return await _saveFindings(address, findings, outputDir);
  }

  Future<String> _saveFindings(
    String address,
    Map<String, dynamic> findings,
    String outputDir,
  ) async {
    final safeAddr = address.replaceAll(RegExp(r'[/:\\*?"<>|]'), '_');
    final filePath = '$outputDir/$safeAddr.json';
    await File(filePath).writeAsString(const JsonEncoder.withIndent('  ').convert(findings));
    onProgress?.call('[$address] Saved findings to $filePath');
    return filePath;
  }

  void _deepMerge(Map<String, dynamic> target, Map<String, dynamic> source) {
    for (final key in source.keys) {
      final srcVal = source[key];
      final tgtVal = target[key];
      if (srcVal == null) continue;
      if (tgtVal is List && srcVal is List) {
        if (key == 'open_ports') {
          // Deduplicate by port number — merge new data into existing entry
          final existing = tgtVal.cast<Map<String, dynamic>>();
          for (final newPort in srcVal.cast<Map<String, dynamic>>()) {
            final portNum = newPort['port'];
            final idx = existing.indexWhere((e) => e['port'] == portNum);
            if (idx == -1) {
              existing.add(newPort);
            } else {
              // Merge new fields into existing entry without overwriting non-empty values
              newPort.forEach((k, v) {
                if (v != null && v.toString().isNotEmpty &&
                    (existing[idx][k] == null || existing[idx][k].toString().isEmpty)) {
                  existing[idx][k] = v;
                }
              });
            }
          }
        } else {
          tgtVal.addAll(srcVal);
        }
      } else if (tgtVal is Map<String, dynamic> && srcVal is Map<String, dynamic>) {
        _deepMerge(tgtVal, srcVal);
      } else {
        target[key] = srcVal;
      }
    }
  }

  Map<String, dynamic> _parseJson(String response) {
    return JsonParser.tryParseJson(response) ??
        {'action': 'CONCLUDE', 'host_useful': false, 'conclude_reason': 'Failed to parse LLM response'};
  }

  // Tools that are reliably available without installation on each platform
  static const _unixAlways = {
    'nmap', 'curl', 'wget', 'nc', 'netcat', 'cat', 'grep',
    'awk', 'sed', 'bash', 'sh', 'python', 'python3', 'dig', 'host', 'nslookup',
  };
  static const _windowsAlways = {'curl', 'powershell', 'cmd', 'nmap'};

  bool _isAlwaysAvailable(String tool, _ExecEnv env) {
    final t = tool.toLowerCase();
    if (env.isNativeWindows) return _windowsAlways.contains(t);
    return _unixAlways.contains(t);
  }

  // ---------------------------------------------------------------------------
  // Deterministic pre-LLM baseline runner (Phase 3.1)
  // Executes a fixed set of discovery commands before the LLM loop so the LLM
  // starts with real port and service data rather than an empty findings map.
  // ---------------------------------------------------------------------------

  Future<_BaselineResult> _runBaselineCommands({
    required String address,
    required TargetScope scope,
    required _ExecEnv env,
    required String outDir,
    required Map<String, dynamic> findings,
    required Set<String> executedCommands,
    required int projectId,
    required int targetId,
    required LLMService llmService,
    EnvironmentInfo? envInfo,
  }) async {
    final commandsRun = <String>[];
    bool isAlive = true;
    bool hasWebPorts = false;
    bool hasDnsData = false;
    bool hasSmbPort = false;
    final isInternal = scope == TargetScope.internal;
    final isWin = env.isNativeWindows;

    // Execute one baseline step: run command, log, merge findings. Returns raw
    // output on success, null on error/skip.
    Future<String?> runStep(String cmd, String purpose) async {
      if (executedCommands.contains(cmd)) return null;
      onProgress?.call('[$address] Baseline: $purpose');
      try {
        final result = await CommandExecutor.executeCommand(
          cmd, requireApproval,
          adminPassword: adminPassword,
          onApprovalNeeded: onApprovalNeeded,
        );
        final output = (result['output'] as String? ?? '').trim();
        final exitCode = (result['exitCode'] as int?) ?? -1;
        executedCommands.add(cmd);
        commandsRun.add(cmd);
        if (projectId > 0 && targetId > 0) {
          await DatabaseHelper.recordExecutedCommand(projectId, targetId, cmd,
              output: output, exitCode: exitCode);
        }
        final log = CommandLog(
          timestamp: DateTime.now(),
          command: '[RECON BASELINE] $cmd',
          output: output.isEmpty ? '(no output)' : output,
          exitCode: exitCode,
          vulnerabilityIndex: null,
          projectId: projectId,
          targetId: targetId,
        );
        await DatabaseHelper.insertCommandLog(log);
        onCommandExecuted?.call(log.command, log.output);
        if (output.isNotEmpty) {
          await _mergeFindings(llmService, address, cmd, purpose, output, findings);
        }
        return output;
      } catch (e) {
        onProgress?.call('[$address] Baseline step skipped ($purpose): $e');
        return null;
      }
    }

    // B1 — Host liveness check (ICMP ping, then TCP fallback for ICMP-blocking hosts)
    final pingCmd = isWin
        ? 'Test-NetConnection $address -Port 443 -InformationLevel Quiet'
        : 'ping -c 2 -W 2 $address';
    final pingOut = await runStep(pingCmd, 'host liveness check');
    bool icmpFailed = false;
    if (pingOut != null) {
      final lower = pingOut.toLowerCase();
      icmpFailed = lower.contains('0 received') ||
          lower.contains('100% packet loss') ||
          lower.contains('network is unreachable') ||
          lower.contains('false'); // Test-NetConnection False = unreachable
    }
    if (icmpFailed) {
      // TCP fallback: some hosts block ICMP but respond on common TCP ports
      onProgress?.call('[$address] ICMP failed — trying TCP fallback probe...');
      bool tcpAlive = false;
      if (!isWin) {
        final tcpOut = await runStep(
            'nmap -sn -PS22,80,443,445 --open -T4 $address',
            'TCP fallback probe (ICMP-blocking host)');
        if (tcpOut != null) {
          tcpAlive = tcpOut.toLowerCase().contains('host is up') ||
              tcpOut.toLowerCase().contains('1 host up');
        }
      } else {
        // Windows: try a few Test-NetConnection probes
        for (final port in [80, 443, 22, 445]) {
          final tcpOut = await runStep(
              'Test-NetConnection $address -Port $port -InformationLevel Quiet',
              'TCP fallback probe port $port');
          if (tcpOut != null && tcpOut.toLowerCase().contains('true')) {
            tcpAlive = true;
            break;
          }
        }
      }
      if (!tcpAlive) {
        onProgress?.call('[$address] Baseline: host is down (ICMP + TCP fallback failed) — skipping');
        return _BaselineResult(
          isAlive: false, hasWebPorts: false, hasDnsData: false,
          hasSmbPort: false, commandsRun: commandsRun,
        );
      }
      onProgress?.call('[$address] TCP fallback succeeded — host is up (blocks ICMP)');
    }

    // B2 — Top port scan
    final nmapXmlPath = '$outDir/nmap_baseline.xml';
    final nmapCmd = isInternal
        ? 'nmap -sV -sC --open -T4 --top-ports 1000 $address -oX "$nmapXmlPath"'
        : 'nmap -sV --open -T3 --top-ports 2000 $address -oX "$nmapXmlPath"';
    await runStep(nmapCmd, 'top port scan');

    // Parse the saved XML directly to update findings and detect web/SMB ports
    try {
      final xmlFile = File(nmapXmlPath);
      if (await xmlFile.exists()) {
        final xmlContent = await xmlFile.readAsString();
        if (xmlContent.isNotEmpty) {
          final parsedPorts = ReconService.parseNmapXml(xmlContent);
          if (parsedPorts.isEmpty) {
            onProgress?.call('[$address] nmap found 0 open ports — host may be filtered or down');
          }
          final existingPorts = (findings['open_ports'] as List)
              .map((p) => (p as Map)['port'])
              .toSet();
          for (final port in parsedPorts) {
            if (!existingPorts.contains(port['port'])) {
              (findings['open_ports'] as List).add(port);
            }
          }
          hasWebPorts = parsedPorts.any((p) {
            final portNum = p['port'] as int? ?? 0;
            final svc = (p['service'] as String? ?? '').toLowerCase();
            return portNum == 80 || portNum == 443 ||
                portNum == 8080 || portNum == 8443 ||
                svc.contains('http');
          });
          hasSmbPort = parsedPorts.any((p) => p['port'] == 445);
        }
      }
    } catch (_) {}

    // B3 — High-port second pass for web/API hosts (catches non-standard service ports)
    if (hasWebPorts && !isWin) {
      await runStep(
          'nmap -sV --open -T4 -p 8080,8443,8888,3000,3001,9000,9090,9200,5601,4848,7001,7002,8161,8500,8600,6443,2375,2376 $address',
          'high-port web/API scan');
    }

    // B4 — Web fingerprinting (if web ports found)
    if (hasWebPorts) {
      if (!isWin) {
        await runStep('curl -skL -I --max-time 10 http://$address',
            'HTTP header fingerprint');
        await runStep('curl -skL -I --max-time 10 https://$address',
            'HTTPS header fingerprint');
      } else {
        await runStep(
            'Invoke-WebRequest http://$address -Method Head -TimeoutSec 10 -SkipCertificateCheck -UseBasicParsing',
            'HTTP header fingerprint');
      }
    }

    // B4 — SSL/TLS certificate info (port 443 only, Unix)
    final has443 = (findings['open_ports'] as List)
        .any((p) => (p as Map)['port'] == 443);
    if (has443 && !isWin) {
      await runStep(
          'echo | openssl s_client -connect $address:443 -showcerts 2>&1 | head -60',
          'SSL/TLS certificate scan');
    }

    // B5 — DNS baseline (external targets or hostname inputs)
    final isHostname = !RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(address);
    if (!isInternal || isHostname) {
      if (!isWin) {
        await runStep('dig $address A +short', 'DNS A record');
        await runStep('dig $address MX +short', 'DNS MX record');
        await runStep('dig $address TXT +short', 'DNS TXT record');
        await runStep('dig $address NS +short', 'DNS NS record');
      } else {
        await runStep('Resolve-DnsName $address -Type ANY', 'DNS record enumeration');
      }
      hasDnsData = true;
    }

    // B6 — SMB security mode (internal + port 445, Unix only)
    if (isInternal && hasSmbPort && !isWin) {
      await runStep(
          'nmap -p 445 --script smb-security-mode,smb2-security-mode,smb-os-discovery $address',
          'SMB signing and OS discovery');
    }

    return _BaselineResult(
      isAlive: isAlive,
      hasWebPorts: hasWebPorts,
      hasDnsData: hasDnsData,
      hasSmbPort: hasSmbPort,
      commandsRun: commandsRun,
    );
  }

  // ---------------------------------------------------------------------------
  // Passive OSINT — external targets only (Phase 3.2)
  // Runs before the baseline and LLM loop. All steps are read-only and do
  // not touch the target directly.
  // ---------------------------------------------------------------------------

  /// Returns true when [address] looks like a domain name (contains a dot and
  /// is not a raw IPv4 address).
  static bool _isDomainName(String address) {
    final a = address.trim();
    return a.contains('.') &&
        !RegExp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').hasMatch(a);
  }

  Future<void> _runPassiveOsint({
    required String address,
    required _ExecEnv env,
    required String outDir,
    required Map<String, dynamic> findings,
    required Set<String> executedCommands,
    required int projectId,
    required int targetId,
    required LLMService llmService,
  }) async {
    // Ensure the osint bucket exists
    findings.putIfAbsent('osint_findings', () => <dynamic>[]);
    findings.putIfAbsent('osint_dorks', () => <dynamic>[]);
    final isWin = env.isNativeWindows;

    // Helper: run one OSINT step, log it, merge findings.
    Future<void> osintStep(String cmd, String purpose) async {
      if (executedCommands.contains(cmd)) return;
      onProgress?.call('[$address] OSINT: $purpose');
      try {
        final result = await CommandExecutor.executeCommand(
          cmd, requireApproval,
          adminPassword: adminPassword,
          onApprovalNeeded: onApprovalNeeded,
        );
        final output = (result['output'] as String? ?? '').trim();
        final exitCode = (result['exitCode'] as int?) ?? -1;
        executedCommands.add(cmd);
        if (projectId > 0 && targetId > 0) {
          await DatabaseHelper.recordExecutedCommand(projectId, targetId, cmd,
              output: output, exitCode: exitCode);
        }
        final log = CommandLog(
          timestamp: DateTime.now(),
          command: '[RECON OSINT] $cmd',
          output: output.isEmpty ? '(no output)' : output,
          exitCode: exitCode,
          vulnerabilityIndex: null,
          projectId: projectId,
          targetId: targetId,
        );
        await DatabaseHelper.insertCommandLog(log);
        onCommandExecuted?.call(log.command, log.output);
        if (output.isNotEmpty) {
          await _mergeFindings(llmService, address, cmd, purpose, output, findings);
        }
      } catch (e) {
        onProgress?.call('[$address] OSINT step skipped ($purpose): $e');
      }
    }

    // O1 — Certificate Transparency logs (crt.sh)
    await osintStep(
        'curl -s --max-time 15 "https://crt.sh/?q=$address&output=json"',
        'certificate transparency log — subdomain discovery');

    // O2 — WHOIS
    if (!isWin) {
      await osintStep('whois $address', 'WHOIS registrar and registration data');
    } else {
      await osintStep('Get-WinSystemInformation', 'WHOIS (whois not natively available on Windows — skip)');
    }

    // O3 — Shodan CLI (if installed)
    await osintStep('shodan host $address', 'Shodan historical port and vulnerability data');

    // O4 — GitHub search (if gh CLI is authenticated)
    await osintStep('gh search code "$address" --limit 10 --json path,repository,url',
        'GitHub public code search for domain references');

    // O5 — Google dork generation (always, no network required)
    final domain = address;
    final dorks = [
      'site:$domain filetype:pdf',
      'site:$domain intitle:"index of"',
      'site:$domain inurl:admin',
      'site:$domain inurl:login',
      'site:$domain intext:password',
      'site:$domain inurl:config OR inurl:env OR inurl:settings',
      'site:$domain ext:sql OR ext:bak OR ext:log',
      '"$domain" inurl:github.com',
    ];
    (findings['osint_dorks'] as List).addAll(dorks);
    onProgress?.call('[$address] OSINT: generated ${dorks.length} Google dork queries');
  }

  // ---------------------------------------------------------------------------
  // Phase 1.2 — Port scan command generation & nmap XML parsing
  // ---------------------------------------------------------------------------

  /// Generate an OS-appropriate nmap command for full TCP + high-value UDP scan.
  static String buildNmapCommand(String target, String outDir, {bool isWindows = false}) {
    final xmlPath = '$outDir/nmap_full.xml';
    return 'nmap -sV -O -T4 --open -p- -oX "$xmlPath" $target';
  }

  /// Generate a UDP scan command for high-value ports.
  static String buildUdpScanCommand(String target, String outDir) {
    final xmlPath = '$outDir/nmap_udp.xml';
    return 'sudo nmap -sU -sV -T4 --open -p 53,161,500,1194,4500 -oX "$xmlPath" $target';
  }

  /// Parse nmap XML output into the open_ports array format.
  static List<Map<String, dynamic>> parseNmapXml(String xmlContent) {
    final ports = <Map<String, dynamic>>[];
    // Match <port protocol="tcp" portid="80"> ... </port> blocks
    final portPattern = RegExp(
      r'<port\s+protocol="(\w+)"\s+portid="(\d+)">(.*?)</port>',
      dotAll: true,
    );
    for (final match in portPattern.allMatches(xmlContent)) {
      final protocol = match.group(1) ?? 'tcp';
      final portId = int.tryParse(match.group(2) ?? '') ?? 0;
      final block = match.group(3) ?? '';

      // State
      final stateMatch = RegExp(r'<state\s+state="(\w+)"').firstMatch(block);
      final state = stateMatch?.group(1) ?? 'unknown';
      if (state != 'open') continue;

      // Service
      final svcMatch = RegExp(
        r'<service\s+([^>]+)>',
      ).firstMatch(block);
      final svcAttrs = svcMatch?.group(1) ?? '';
      String attr(String name) {
        final m = RegExp('$name="([^"]*?)"').firstMatch(svcAttrs);
        return m?.group(1) ?? '';
      }

      final entry = <String, dynamic>{
        'port': portId,
        'protocol': protocol,
        'state': state,
        'service': attr('name'),
        'product': attr('product'),
        'version': attr('version'),
        'extra_info': attr('extrainfo'),
      };
      // CPE
      final cpeMatch = RegExp(r'<cpe>([^<]+)</cpe>').firstMatch(block);
      if (cpeMatch != null) entry['cpe'] = cpeMatch.group(1);

      ports.add(entry);
    }

    // OS detection
    // (parsed separately by parseNmapOs)
    return ports;
  }

  /// Parse OS detection from nmap XML.
  static Map<String, String> parseNmapOs(String xmlContent) {
    final osMatch = RegExp(r'<osmatch\s+name="([^"]+)"\s+accuracy="(\d+)"')
        .firstMatch(xmlContent);
    if (osMatch == null) return {};
    return {'os': osMatch.group(1) ?? '', 'accuracy': osMatch.group(2) ?? ''};
  }

  // ---------------------------------------------------------------------------
  // Phase 1.2 — Banner grabbing for unknown services
  // ---------------------------------------------------------------------------

  /// Generate a banner grab command for a port with unknown service.
  static String buildBannerGrabCommand(String target, int port, bool isTls) {
    if (isTls) {
      return 'timeout 10 openssl s_client -connect $target:$port </dev/null 2>/dev/null | head -20';
    }
    return 'echo "" | timeout 10 nc -w 5 $target $port 2>/dev/null | head -20';
  }

  // ---------------------------------------------------------------------------
  // Phase 1.3 — Web fingerprinting
  // ---------------------------------------------------------------------------

  /// Generate a whatweb command for a web port.
  static String buildWhatwebCommand(String target, int port, bool isTls) {
    final scheme = isTls ? 'https' : 'http';
    return 'whatweb -a 3 --color=never $scheme://$target:$port 2>/dev/null || '
        'curl -s -I -L --max-time 10 $scheme://$target:$port';
  }

  /// Generate curl commands to fetch headers and check common high-value paths.
  static List<String> buildWebProbeCommands(String target, int port, bool isTls, String outDir) {
    final scheme = isTls ? 'https' : 'http';
    final base = '$scheme://$target:$port';
    return [
      'curl -s -I -L --max-time 10 $base | tee "$outDir/headers_$port.txt"',
      for (final path in [
        '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
        '/crossdomain.xml', '/swagger.json', '/openapi.json', '/api/docs', '/graphql',
      ])
        'curl -s -o /dev/null -w "%{http_code} $path" --max-time 5 $base$path',
    ];
  }

  /// Detect WAF/CDN from response headers text.
  static String? detectWafFromHeaders(String headers) {
    final h = headers.toLowerCase();
    if (h.contains('cf-ray') || h.contains('cloudflare')) return 'Cloudflare';
    if (h.contains('x-sucuri')) return 'Sucuri';
    if (h.contains('x-akamai') || h.contains('akamai')) return 'Akamai';
    if (h.contains('x-cdn: fastly') || h.contains('fastly')) return 'Fastly';
    if (h.contains('x-amz-cf-id') || h.contains('cloudfront')) return 'CloudFront';
    if (h.contains('incapsula') || h.contains('imperva')) return 'Imperva';
    return null;
  }

  // ---------------------------------------------------------------------------
  // Phase 1.4 — DNS enumeration
  // ---------------------------------------------------------------------------

  /// Generate DNS lookup commands for a hostname target.
  static List<String> buildDnsCommands(String target, String outDir) {
    return [
      'dig A AAAA CNAME MX TXT NS SOA $target +noall +answer | tee "$outDir/dns_all.txt"',
      'dig AXFR $target 2>/dev/null | tee "$outDir/dns_axfr.txt"',
    ];
  }

  /// Generate reverse DNS command for an IP target.
  static String buildReverseDnsCommand(String ip) {
    return 'dig -x $ip +short';
  }

  /// Extract SPF, DKIM, DMARC from TXT records text.
  static Map<String, String> extractEmailSecurityRecords(String txtOutput) {
    final records = <String, String>{};
    for (final line in txtOutput.split('\n')) {
      final lower = line.toLowerCase();
      if (lower.contains('v=spf1')) records['spf'] = line.trim();
      if (lower.contains('v=dmarc1')) records['dmarc'] = line.trim();
      if (lower.contains('v=dkim1')) records['dkim'] = line.trim();
    }
    return records;
  }

  // ---------------------------------------------------------------------------
  // Phase 1.5 — OS and technology enrichment
  // ---------------------------------------------------------------------------

  /// Extract OS info from nmap OS detection and SSH/SMB banners.
  static String extractOsFromBanners(List<Map<String, dynamic>> ports) {
    for (final p in ports) {
      final product = (p['product'] ?? '').toString().toLowerCase();
      final version = (p['version'] ?? '').toString();
      final extra = (p['extra_info'] ?? '').toString();
      if (product.contains('openssh') && extra.toLowerCase().contains('ubuntu')) return 'Linux Ubuntu';
      if (product.contains('openssh') && extra.toLowerCase().contains('debian')) return 'Linux Debian';
      if (product.contains('microsoft') || product.contains('windows')) return 'Windows $version';
      if (extra.toLowerCase().contains('windows')) return 'Windows';
    }
    return '';
  }

  /// Parse SMB banners for Windows version, domain, signing status.
  static Map<String, String> parseSmbBanner(String smbOutput) {
    final result = <String, String>{};
    final osMatch = RegExp(r'OS:\s*(.+)', caseSensitive: false).firstMatch(smbOutput);
    if (osMatch != null) result['os'] = osMatch.group(1)!.trim();
    final domainMatch = RegExp(r'Domain:\s*(\S+)', caseSensitive: false).firstMatch(smbOutput);
    if (domainMatch != null) result['domain'] = domainMatch.group(1)!.trim();
    final signingMatch = RegExp(r'signing[:\s]+(\S+)', caseSensitive: false).firstMatch(smbOutput);
    if (signingMatch != null) result['signing'] = signingMatch.group(1)!.trim();
    return result;
  }

  /// Parse SSL/TLS certificate CN and SAN fields for hostname discovery.
  static List<String> parseCertHostnames(String certOutput) {
    final hostnames = <String>{};
    final cnMatch = RegExp(r'CN\s*=\s*([^\s/,]+)').firstMatch(certOutput);
    if (cnMatch != null) hostnames.add(cnMatch.group(1)!);
    final sanMatches = RegExp(r'DNS:([^\s,]+)').allMatches(certOutput);
    for (final m in sanMatches) {
      hostnames.add(m.group(1)!);
    }
    return hostnames.toList();
  }

  // ---------------------------------------------------------------------------
  // Host liveness pre-sweep
  // ---------------------------------------------------------------------------

  /// Quick single-packet ping to determine if a host is reachable.
  ///
  /// Used for a parallel pre-sweep before full recon so we don't waste time
  /// and tokens running nmap or LLM iterations against hosts that don't exist.
  /// Returns true if the host responded, false if it is down or unreachable.
  static Future<bool> quickHostAlive(String address) async {
    try {
      final isWindows = Platform.isWindows;
      final List<String> args = isWindows
          ? ['-n', '1', '-w', '2000', address]
          : ['-c', '1', '-W', '2', address];
      final result = await Process.run(
        isWindows ? 'ping' : 'ping',
        args,
      ).timeout(const Duration(seconds: 10));
      if (result.exitCode == 0) return true;
      // Some systems return exit 0 even on failure; parse output as fallback
      final out = (result.stdout as String).toLowerCase();
      if (out.contains('0 received') ||
          out.contains('100% packet loss') ||
          out.contains('host unreachable') ||
          out.contains('request timed out') ||
          out.contains('destination host unreachable')) {
        return false;
      }
      return result.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Phase 1.1 — Wire ReconService into analysis flow
  // ---------------------------------------------------------------------------

  /// Run structured recon and return a [ReconResult] that can be merged with
  /// user-supplied JSON before analysis. This is the integration point for
  /// VulnerabilityAnalyzer: call enrichWithRecon() then analyzeDevice().
  static Future<ReconResult?> enrichWithRecon({
    required String address,
    required String projectName,
    required LLMSettings settings,
    int projectId = 0,
    int targetId = 0,
    bool requireApproval = false,
    String? adminPassword,
    Future<String?> Function(String)? onApprovalNeeded,
    Future<String?> Function(String)? onPasswordNeeded,
    Function(String)? onProgress,
    Function(String, String)? onPromptResponse,
    Function(String, String)? onCommandExecuted,
  }) async {
    final recon = ReconService(
      settings: settings,
      requireApproval: requireApproval,
      adminPassword: adminPassword,
      onApprovalNeeded: onApprovalNeeded,
      onPasswordNeeded: onPasswordNeeded,
      onProgress: onProgress,
      onPromptResponse: onPromptResponse,
      onCommandExecuted: onCommandExecuted,
    );
    final filePath = await recon.reconTarget(
      address, projectName,
      projectId: projectId, targetId: targetId,
    );
    if (filePath == null) return null;
    try {
      final content = await File(filePath).readAsString();
      final parsed = json.decode(content) as Map<String, dynamic>;
      final device = (parsed['device'] as Map<String, dynamic>?) ?? {};
      final ports = ((parsed['open_ports'] as List?) ?? []).cast<Map<String, dynamic>>();
      return ReconResult(
        ip: device['ip_address']?.toString() ?? address,
        hostname: device['name']?.toString() ?? '',
        openPorts: ports,
        os: device['os']?.toString() ?? '',
        osVersion: device['os_version']?.toString() ?? '',
        technologies: ((parsed['web_findings'] as List?)?.firstOrNull
            as Map<String, dynamic>?)?['technologies']?.cast<String>() ?? [],
        dnsFindings: ((parsed['dns_findings'] as List?) ?? []).cast<Map<String, dynamic>>(),
        hostnames: (parsed['hostnames'] as List?)?.cast<String>() ?? [],
      );
    } catch (_) {
      return null;
    }
  }
}
