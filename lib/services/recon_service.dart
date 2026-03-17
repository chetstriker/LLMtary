import 'dart:io';
import 'dart:convert';
import '../models/llm_settings.dart';
import '../models/command_log.dart';
import '../utils/json_parser.dart';
import '../utils/command_utils.dart';
import '../database/database_helper.dart';
import '../utils/device_utils.dart';
import 'command_executor.dart';
import 'llm_service.dart';
import 'storage_service.dart';

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

class ReconService {
  final LLMSettings settings;
  final bool requireApproval;
  final String? adminPassword;
  final Future<String?> Function(String)? onApprovalNeeded;
  final Function(String)? onProgress;
  final Function(String, String)? onPromptResponse;
  final Function(String, String)? onCommandExecuted;

  static const int _maxIterations = 20;
  static const int _maxIterationsExternal = 25;

  ReconService({
    required this.settings,
    this.requireApproval = false,
    this.adminPassword,
    this.onApprovalNeeded,
    this.onProgress,
    this.onPromptResponse,
    this.onCommandExecuted,
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
    int consecutiveFailures = 0;

    onProgress?.call('[$address] Starting recon loop (${env.label})...');

    for (int iteration = 0; iteration < maxIter; iteration++) {
      onProgress?.call('[$address] Iteration ${iteration + 1}/$maxIter');

      String historyHint = '';
      if (executedCommands.isNotEmpty || unavailableTools.isNotEmpty) {
        final parts = <String>[];
        if (executedCommands.isNotEmpty) {
          parts.add('## ALREADY EXECUTED - do NOT repeat:\n'
              '${executedCommands.map((c) => '- $c').join('\n')}');
        }
        if (unavailableTools.isNotEmpty) {
          parts.add('## UNAVAILABLE TOOLS - do NOT use:\n'
              '${unavailableTools.map((t) => '- $t').join('\n')}');
        }
        historyHint = '\n${parts.join('\n\n')}\n';
      }

      final prompt = _buildCommandPrompt(
        address: address,
        env: env,
        scope: scope,
        outDir: outDir,
        findings: findings,
        history: history,
        historyHint: historyHint,
      );

      String response;
      try {
        response = await llmService.sendMessage(settings, prompt);
      } catch (e) {
        onProgress?.call('[$address] LLM error: $e');
        history += 'Iteration ${iteration + 1}: LLM error: $e\n\n';
        consecutiveFailures++;
        if (consecutiveFailures >= 3) break;
        continue;
      }

      final decision = _parseJson(response);

      if (decision['action'] == 'CONCLUDE') {
        final useful = decision['host_useful'] == true;
        final reason = decision['conclude_reason'] ?? 'Recon complete';
        // Don't conclude early if there are still unprobed ports/services
        final focusHints = _buildFocusHints(address, findings, env, scope);
        if (focusHints.isNotEmpty && iteration < maxIter - 3) {
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
        if (consecutiveFailures >= 3) break;
        continue;
      }

      final command = (decision['command'] as String? ?? '').trim();
      final purpose = decision['purpose'] as String? ?? '';
      final tool = (decision['tool'] as String? ?? '')
          .split(',').first.trim().split(' ').first.trim().toLowerCase();

      if (command.isEmpty) {
        consecutiveFailures++;
        if (consecutiveFailures >= 3) break;
        continue;
      }

      if (CommandUtils.isSimilarCommand(command, executedCommands)) {
        history += 'Iteration ${iteration + 1}: SKIPPED duplicate: $command\n\n';
        consecutiveFailures++;
        if (consecutiveFailures >= 2) break;
        continue;
      }

      // Also check DB for commands run in previous sessions — skip silently
      // (recon already merged the output into findings on the prior run)
      if (projectId > 0 && targetId > 0 &&
          await DatabaseHelper.wasCommandExecuted(projectId, targetId, command)) {
        history += 'Iteration ${iteration + 1}: SKIPPED (already run in prior session): $command\n\n';
        onProgress?.call('[$address] Skipping previously run command...');
        consecutiveFailures++;
        if (consecutiveFailures >= 2) break;
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
        final exists = await CommandExecutor.checkToolExists(tool, settings, llmService);
        if (!exists) {
          unavailableTools.add(tool);
          history += 'Iteration ${iteration + 1}: $tool not found\n\n';
          onProgress?.call('[$address] $tool not available, skipping...');
          consecutiveFailures++;
          continue;
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

    onProgress?.call('[$address] Max iterations reached, evaluating...');
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

${env.shellRules}

## FILE OUTPUT RULES (CRITICAL):
- ALL tool output files MUST use the full absolute path: $outDir
- NEVER use relative paths like temp/, ./temp/, or just a filename
- Examples:
  * gobuster -o output.txt → gobuster ... -o "$outDir/output.txt"
  * curl -o file.txt URL → curl -o "$outDir/file.txt" URL
  * wget URL → wget -P "$outDir" URL
  * command > file.txt → command > "$outDir/file.txt"

## WHAT YOU HAVE FOUND SO FAR:
${json.encode(findings)}

## PREVIOUS COMMANDS RUN:
$history
$historyHint

$focusHints

$baseline

## NUCLEI USAGE (CRITICAL — wrong syntax wastes iterations):
- CORRECT: nuclei -u http://$address -id CVE-2021-41773  (use -id for specific CVEs)
- CORRECT: nuclei -u http://$address -tags drupal  (use -tags for technology-based scans)
- CORRECT: nuclei -u http://$address -tags cve,drupal  (combine tags)
- WRONG: nuclei -u http://$address -t cves/2023/CVE-2023-1234.yaml  (file paths don't exist locally)
- WRONG: nuclei -u http://$address -t CVE-2023-1234  (not a valid flag value)
- If you don't know the exact CVE ID, use -tags with the technology name instead

## CONCLUDE when ALL of these are true:
- Port scan completed
- Every open port has been individually probed for banners/versions
- All web ports have had headers, robots.txt, and directory hints collected
- No new data has been returned in the last 2 commands
- OR: host is unreachable / all ports filtered

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
## BASELINE RECON - INTERNAL TARGET:
- First: FULL port scan across ALL 65535 ports with service/version detection
  Unix/WSL: nmap -sV -sC --open -T4 -p- $address
  Windows: Test-NetConnection $address -Port 80,443,22,21,445,3389,8080,8443,3306,5432
- CRITICAL: Always use -p- to scan all ports - services frequently run on non-standard ports.
- Then follow the PRIORITY TARGETS above based on what you find''';

  String _externalBaseline(String address, _ExecEnv env) {
    final isWin = env.isNativeWindows;
    final dnsCmd = isWin
        ? 'Resolve-DnsName $address -Type ANY'
        : 'dig ANY $address +noall +answer && dig MX $address +short && dig NS $address +short && dig TXT $address +short';
    final subdomainCmd = isWin
        ? ''
        : '- Subdomain hints (TWO separate commands):\n'
          '  Step 1: curl -s "https://crt.sh/?q=%25.$address&output=json" -o /tmp/crtsh_$address.json 2>/dev/null\n'
          '  Step 2: cat /tmp/crtsh_$address.json | python3 -c "import sys,json; [print(e[\'name_value\']) for e in json.load(sys.stdin)]" 2>/dev/null | sort -u | head -30';
    final sslCmd = isWin
        ? '- nmap --script ssl-cert,ssl-enum-ciphers -p 443 $address'
        : '- nmap --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle -p 443 $address\n- testssl.sh --fast $address 2>/dev/null | head -80  (if available)';
    final harvestCmd = isWin
        ? ''
        : '- theHarvester -d $address -b google,bing,crtsh -l 50 2>/dev/null | head -60  (if available)';
    return '''
## BASELINE RECON - EXTERNAL TARGET:
External targets require a different approach than internal hosts. Follow this order:

### STEP 1 - DNS & OSINT (do these before port scanning)
- DNS records: $dnsCmd
$subdomainCmd
- WAF/CDN detection: curl -sI https://$address | grep -iE 'cf-ray|x-amz|x-cache|via|server|x-powered'

### STEP 2 - Port scan (top ports first, then full)
- Fast top-1000 first (external hosts may rate-limit or block -p-):
  nmap -sV -sC --open -T3 $address
- Then full scan if top-1000 found interesting services:
  nmap -sV --open -T3 -p- $address
- NOTE: Use -T3 (not -T4) for external targets to avoid triggering rate limits or IDS.

### STEP 3 - SSL/TLS (for every HTTPS port found)
$sslCmd

### STEP 4 - Web enumeration (for every HTTP/HTTPS port)
- Use a larger wordlist for external targets:
  gobuster dir -u https://$address -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q -t 20 2>/dev/null
  (fallback: /usr/share/wordlists/dirb/common.txt if medium list not present)
- CMS detection: whatweb https://$address 2>/dev/null || curl -s https://$address | grep -iE '<meta|generator|powered|wp-content|drupal|joomla'
- If CMS identified from findings, run CMS-specific scanner:
  * WordPress: wpscan --url https://$address --enumerate p,t,u --no-banner 2>/dev/null
  * Drupal: droopescan scan drupal -u https://$address 2>/dev/null
  * Joomla: joomscan -u https://$address 2>/dev/null

### STEP 5 - Email/contact harvesting (for phishing context)
$harvestCmd''';
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
      } else {
        // Anything not positively identified goes to unknown for banner grabbing
        unknownPorts.add(p);
      }
    }

    // OS fingerprint hint — skip for external (OS fingerprinting is noisy and often blocked)
    final os = device['os'] as String? ?? '';
    if (os.isEmpty && ports.isNotEmpty && !isExternal) {
      hints.add('- OS not yet identified → run: nmap -O --osscan-guess $address');
    }

    // External-only: SSL/TLS hint for any HTTPS port not yet checked
    if (isExternal && !isWin) {
      for (final p in ports) {
        final port = (p['port'] as num?)?.toInt() ?? 0;
        final svc = (p['service'] as String? ?? '').toLowerCase();
        final isHttps = svc.contains('https') || svc.contains('ssl') || port == 443;
        if (isHttps) {
          final alreadyChecked = (findings['nmap_scripts'] as List? ?? [])
              .cast<Map<String, dynamic>>()
              .any((s) => s['port'] == port && (s['script_id'] as String? ?? '').contains('ssl'));
          if (!alreadyChecked) {
            hints.add('- SSL/TLS on port $port not yet checked → nmap --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed -p $port $address');
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
        if (isWin) {
          hints.add('- Web port $port not yet probed → Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object StatusCode,Headers');
        } else {
          hints.add('- Web port $port not yet probed → curl -sIL $url');
        }
      } else if (!hasUsefulContent) {
        // Got a non-200 at root (404, 403, redirect, etc.) — the app is likely at a sub-path
        hints.add('- Port $port root returned HTTP $rootStatus — application is likely at a sub-path, enumerate paths:');
        if (!isWin) {
          hints.add('  • nmap --script=http-enum -p $port $address  (discovers common app paths)');
          hints.add('  • gobuster dir -u $url -w /usr/share/wordlists/dirb/common.txt -q 2>/dev/null');
          hints.add('  • curl -s $url/robots.txt $url/sitemap.xml');
          hints.add('  • curl -s -o /dev/null -w "%{http_code} %{url_effective}\\n" $url/login $url/admin $url/app $url/api $url/console $url/manager $url/status $url/health');
        } else {
          hints.add('  • nmap --script=http-enum -p $port $address');
          hints.add('  • foreach (\$p in @("/login","/admin","/app","/api","/console","/manager","/status")) { try { \$r = Invoke-WebRequest "$url\$p" -UseBasicParsing -EA Stop; Write-Host "\$p \$(\$r.StatusCode)" } catch { Write-Host "\$p \$(\$_.Exception.Response.StatusCode.value__)" } }');
        }
      } else {
        // Got 200 at root — go deeper
        final serverHeader = _findWebServer(webFindings, port);
        // Check if CMS was already identified in findings
        final techs = (webFindings.cast<Map<String, dynamic>>()
            .firstWhere((w) => (w['url'] as String? ?? '').contains(':$port'), orElse: () => {})
            ['technologies'] as List? ?? []).join(' ').toLowerCase();
        hints.add('- Port $port web server identified${serverHeader.isNotEmpty ? " ($serverHeader)" : ""} → collect more:');
        if (!isWin) {
          hints.add('  • Fetch robots.txt: curl -s $url/robots.txt');
          hints.add('  • Fetch sitemap: curl -s $url/sitemap.xml');
          // External gets larger wordlist
          final wordlist = isExternal
              ? '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
              : '/usr/share/wordlists/dirb/common.txt';
          hints.add('  • Directory enum: gobuster dir -u $url -w $wordlist -q 2>/dev/null || dirb $url /usr/share/wordlists/dirb/common.txt -S 2>/dev/null');
          hints.add('  • Full headers + redirect chain: curl -sIL $url');
          if (serverHeader.contains('apache') || serverHeader.contains('nginx') ||
              serverHeader.contains('iis')) {
            hints.add('  • Server info page: curl -s $url/server-status 2>/dev/null || curl -s $url/server-info 2>/dev/null');
          }
          hints.add('  • Technology fingerprint: whatweb $url 2>/dev/null || curl -s $url | grep -iE \'<meta|generator|powered\'');
          hints.add('  • Common paths: curl -s -o /dev/null -w "%{http_code} %{url_effective}\\n" $url/admin $url/login $url/phpmyadmin $url/manager $url/api $url/console');
          // CMS-specific scanners (external only — too noisy for internal)
          if (isExternal) {
            if (techs.contains('wordpress') || techs.contains('wp-')) {
              hints.add('  • WordPress scan: wpscan --url $url --enumerate p,t,u --no-banner 2>/dev/null');
            } else if (techs.contains('drupal')) {
              hints.add('  • Drupal scan: droopescan scan drupal -u $url 2>/dev/null');
            } else if (techs.contains('joomla')) {
              hints.add('  • Joomla scan: joomscan -u $url 2>/dev/null');
            }
          }
        } else {
          hints.add('  • Fetch robots.txt: curl -s $url/robots.txt');
          hints.add('  • Common paths: foreach (\$p in @("/admin","/login","/manager","/phpmyadmin","/api","/console")) { \$r = try { Invoke-WebRequest "$url\$p" -UseBasicParsing -EA Stop } catch { \$_.Exception.Response }; Write-Host "\$p \$(\$r.StatusCode)" }');
        }
      }
    }

    // External-only: HTTP method enumeration for web ports
    if (isExternal && !isWin) {
      for (final port in webPorts) {
        final portEntry = ports.firstWhere((p) => (p['port'] as num?)?.toInt() == port, orElse: () => {});
        final svc = (portEntry['service'] as String? ?? '').toLowerCase();
        final scheme = svc.contains('https') || svc.contains('ssl') ? 'https' : 'http';
        final alreadyChecked = (findings['web_findings'] as List? ?? [])
            .cast<Map<String, dynamic>>()
            .any((w) => (w['notes'] as String? ?? '').toLowerCase().contains('options'));
        if (!alreadyChecked) {
          hints.add('- HTTP methods on port $port → curl -s -X OPTIONS -i $scheme://$address:$port/ | grep -i allow');
        }
      }
    }

    // External-only: API surface hints
    if (isExternal && !isWin) {
      for (final port in webPorts) {
        final portEntry = ports.firstWhere((p) => (p['port'] as num?)?.toInt() == port, orElse: () => {});
        final svc = (portEntry['service'] as String? ?? '').toLowerCase();
        final scheme = svc.contains('https') || svc.contains('ssl') ? 'https' : 'http';
        final existingNotes = (findings['web_findings'] as List? ?? [])
            .cast<Map<String, dynamic>>()
            .firstWhere((w) => (w['url'] as String? ?? '').contains(':$port'), orElse: () => {})
            ['notes'] as String? ?? '';
        if (!existingNotes.toLowerCase().contains('graphql') &&
            !existingNotes.toLowerCase().contains('/api')) {
          hints.add('- API surface on port $port → curl -s -o /dev/null -w "%{http_code} %{url_effective}\\n" '
              '$scheme://$address:$port/api $scheme://$address:$port/api/v1 '
              '$scheme://$address:$port/graphql $scheme://$address:$port/swagger '
              '$scheme://$address:$port/openapi.json $scheme://$address:$port/docs');
          hints.add('  • GraphQL introspection: curl -s -X POST -H "Content-Type: application/json" '
              '-d \'{"query":"{__schema{types{name}}}"}\'  $scheme://$address:$port/graphql');
        }
      }
    }

    // SMB hints — internal only (almost always firewalled on external targets)
    for (final port in smbPorts) {
      if (isExternal) continue;
      final alreadyProbed = smbFindings.isNotEmpty;
      if (!alreadyProbed) {
        if (isWin) {
          hints.add('- SMB port $port → net view \\\\$address /all');
          hints.add('- SMB details → nmap --script=smb-os-discovery,smb-security-mode,smb2-security-mode -p $port $address');
        } else {
          hints.add('- SMB port $port → smbclient -N -L //$address 2>/dev/null');
          hints.add('- SMB OS/security → nmap --script=smb-os-discovery,smb-security-mode,smb2-security-mode,smb-enum-shares -p $port $address');
          hints.add('- SMB full enum → enum4linux -a $address 2>/dev/null (if available)');
        }
      }
    }

    // FTP hints
    for (final port in ftpPorts) {
      hints.add('- FTP port $port → collect banner + check anonymous access:');
      if (isWin) {
        hints.add('  • nmap --script=ftp-anon,ftp-banner,ftp-syst -p $port $address');
      } else {
        hints.add('  • nmap --script=ftp-anon,ftp-banner,ftp-syst -p $port $address');
        hints.add('  • curl -s --connect-timeout 5 ftp://$address:$port/');
      }
    }

    // SSH hints
    for (final port in sshPorts) {
      hints.add('- SSH port $port → collect version + supported algorithms:');
      hints.add('  • nmap --script=ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p $port $address');
    }

    // DNS hints
    for (final port in dnsPorts) {
      hints.add('- DNS port $port → enumerate records:');
      if (isWin) {
        hints.add('  • Resolve-DnsName $address -Type ANY');
        hints.add('  • Resolve-DnsName $address -Type MX; Resolve-DnsName $address -Type NS');
      } else {
        hints.add('  • dig ANY $address @$address +noall +answer');
        hints.add('  • dig AXFR $address @$address 2>/dev/null (zone transfer attempt - read only)');
        hints.add('  • dig MX NS TXT $address @$address');
      }
    }

    // SNMP hints
    for (final port in snmpPorts) {
      if (!isWin) {
        hints.add('- SNMP port $port → snmpwalk -v2c -c public $address 2>/dev/null | head -50');
        hints.add('  • snmpwalk -v1 -c public $address 2>/dev/null | head -50');
      }
    }

    // RDP hints
    for (final port in rdpPorts) {
      hints.add('- RDP port $port → collect encryption/NLA info:');
      hints.add('  • nmap --script=rdp-enum-encryption,rdp-vuln-ms12-020 -p $port $address');
    }

    // Telnet hints
    for (final port in telnetPorts) {
      hints.add('- Telnet port $port → grab banner:');
      if (isWin) {
        hints.add('  • nmap --script=telnet-ntlm-info,banner -p $port $address');
      } else {
        hints.add('  • timeout 5 nc -w3 $address $port 2>/dev/null || nmap --script=telnet-ntlm-info,banner -p $port $address');
      }
    }

    // Database hints
    for (final port in mysqlPorts) {
      hints.add('- MySQL port $port → nmap --script=mysql-info,mysql-databases,mysql-empty-password -p $port $address');
    }
    for (final port in postgresPorts) {
      hints.add('- PostgreSQL port $port → nmap --script=pgsql-brute --script-args brute.mode=user -p $port $address');
    }
    for (final port in mssqlPorts) {
      hints.add('- MSSQL port $port → nmap --script=ms-sql-info,ms-sql-config,ms-sql-empty-password -p $port $address');
    }

    // Unknown ports — grab banners
    for (final p in unknownPorts) {
      final port = (p['port'] as num?)?.toInt() ?? 0;
      hints.add('- Port $port has no banner/version yet → nmap -sV --script=banner -p $port $address');
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

A host IS useful if it has open ports with identified services, version numbers, or banners.
A host is NOT useful if: no open ports, host down, all ports filtered.

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
}
