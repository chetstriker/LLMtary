import 'dart:io';
import 'dart:async';
import 'dart:convert';
import '../models/llm_settings.dart';
import '../utils/json_parser.dart';
import 'llm_service.dart';

/// Data classes for tool usage information.
class ToolUsageInfo {
  final String tool;
  final String? version;
  final String description;
  final String basicSyntax;
  final List<ToolOption> commonOptions;
  final List<ToolExample> exampleCommands;
  final List<String> requirements;
  final List<String> gotchas;
  final List<String> relatedTools;

  ToolUsageInfo({
    required this.tool,
    this.version,
    required this.description,
    required this.basicSyntax,
    required this.commonOptions,
    required this.exampleCommands,
    required this.requirements,
    required this.gotchas,
    required this.relatedTools,
  });

  @override
  String toString() => 'ToolUsageInfo($tool v$version)';
}

class ToolOption {
  final String option;
  final String description;
  final String example;

  ToolOption({
    required this.option,
    required this.description,
    this.example = '',
  });
}

class ToolExample {
  final String purpose;
  final String command;

  ToolExample({
    required this.purpose,
    required this.command,
  });
}

/// Manages tool detection, installation, versioning, and usage info.
///
/// Extracted from CommandExecutor to keep command execution focused.
class ToolManager {
  static String _timestamp() =>
      '[${DateTime.now().toIso8601String().substring(11, 23)}]';

  // Cache for tool usage information
  static final Map<String, ToolUsageInfo> _toolUsageCache = {};

  // Cache for tool setup verification results
  static final Map<String, Map<String, dynamic>> _toolSetupCache = {};

  // Track tools whose setup has failed
  static final Set<String> _toolSetupFailures = {};

  /// Mark a tool's setup as failed so we don't retry.
  static void markToolSetupFailed(String tool) {
    _toolSetupFailures.add(tool.toLowerCase());
  }

  /// Map tool names to their actual binary names.
  static const Map<String, String> toolBinaryMap = {
    'metasploit': 'msfconsole',
    'metasploit-framework': 'msfconsole',
    'msf': 'msfconsole',
    'msfconsole': 'msfconsole',
    'exploitdb': 'searchsploit',
    'exploit-db': 'searchsploit',
    'searchsploit': 'searchsploit',
    'sqlmap': 'sqlmap',
    'nikto': 'nikto',
    'hydra': 'hydra',
    'nuclei': 'nuclei',
    'scapy': 'scapy',
    'dirb': 'dirb',
    'gobuster': 'gobuster',
    'ffuf': 'ffuf',
    'smbclient': 'smbclient',
    'smbmap': 'smbmap',
    'enum4linux': 'enum4linux',
    'wfuzz': 'wfuzz',
    'john': 'john',
    'hashcat': 'hashcat',
    'masscan': 'masscan',
    'responder': 'responder',
    'crackmapexec': 'crackmapexec',
    'netexec': 'netexec',
    'wpscan': 'wpscan',
    'feroxbuster': 'feroxbuster',
    'testssl': 'testssl.sh',
    'testssl.sh': 'testssl.sh',
    'sslyze': 'sslyze',
    'nmap': 'nmap',
    'curl': 'curl',
    'wget': 'wget',
    'nc': 'nc',
    'netcat': 'nc',
    'python2': 'python2',
    'python3': 'python3',
    'python': 'python3',
    'perl': 'perl',
    'ruby': 'ruby',
    'dig': 'dig',
    'host': 'host',
    'nslookup': 'nslookup',
    'whois': 'whois',
    'tcpdump': 'tcpdump',
    'tshark': 'tshark',
    'arp-scan': 'arp-scan',
    'nbtscan': 'nbtscan',
    'snmpwalk': 'snmpwalk',
    'onesixtyone': 'onesixtyone',
    'dnsrecon': 'dnsrecon',
    'dnsenum': 'dnsenum',
    'fierce': 'fierce',
    'whatweb': 'whatweb',
    'wafw00f': 'wafw00f',
    'commix': 'commix',
    'xxd': 'xxd',
  };

  /// Get the actual binary name for a tool.
  static String getToolBinary(String tool) {
    final normalized = tool.toLowerCase().trim();
    return toolBinaryMap[normalized] ?? tool;
  }

  /// Get tool version string.
  static Future<String?> getToolVersion(String tool, Future<bool> Function() isWslAvailable) async {
    try {
      final primaryTool = tool.split(',').first.trim().split(' ').first.trim();
      if (primaryTool.isEmpty) return null;

      final binaryName = getToolBinary(primaryTool);
      final versionFlags = ['--version', '-version', '-v', '-V', 'version'];

      for (final flag in versionFlags) {
        try {
          ProcessResult result;
          if (Platform.isWindows && await isWslAvailable()) {
            result = await Process.run(
                    'wsl', ['bash', '-c', '$binaryName $flag 2>&1 | head -5'])
                .timeout(Duration(seconds: 10));
          } else {
            result = await Process.run(
                    'bash', ['-c', '$binaryName $flag 2>&1 | head -5'])
                .timeout(Duration(seconds: 10));
          }

          if (result.exitCode == 0 &&
              result.stdout.toString().trim().isNotEmpty) {
            final output = result.stdout.toString().trim();
            final versionMatch =
                RegExp(r'(\d+\.\d+(?:\.\d+)?(?:-\w+)?)').firstMatch(output);
            if (versionMatch != null) {
              print(
                  '${_timestamp()} DEBUG: $primaryTool ($binaryName) version: ${versionMatch.group(1)}');
              return versionMatch.group(1);
            }
            final firstLine = output.split('\n').first.trim();
            if (firstLine.isNotEmpty &&
                firstLine.length < 200 &&
                !firstLine.contains('command not found')) {
              print(
                  '${_timestamp()} DEBUG: $primaryTool ($binaryName) version info: $firstLine');
              return firstLine;
            }
          }
        } catch (e) {
          continue;
        }
      }

      print(
          '${_timestamp()} DEBUG: Could not determine version for $primaryTool ($binaryName)');
      return null;
    } catch (e) {
      print('${_timestamp()} DEBUG: getToolVersion error: $e');
      return null;
    }
  }

  /// Get comprehensive tool usage information via LLM.
  static Future<ToolUsageInfo> getToolUsageInfo(
      String tool,
      LLMSettings settings,
      LLMService llmService,
      Future<String> Function() getOsInfo,
      Future<bool> Function() isWslAvailable) async {
    final primaryTool = tool.split(',').first.trim().split(' ').first.trim();

    if (_toolUsageCache.containsKey(primaryTool)) {
      print('${_timestamp()} DEBUG: Using cached usage info for $primaryTool');
      return _toolUsageCache[primaryTool]!;
    }

    print('${_timestamp()} DEBUG: Looking up usage info for $primaryTool');

    final os = await getOsInfo();
    final isWsl = Platform.isWindows && await isWslAvailable();
    final executionEnv =
        isWsl ? 'WSL on Windows' : Platform.isMacOS ? 'macOS' : 'Native Linux';
    final version = await getToolVersion(primaryTool, isWslAvailable);
    final versionStr = version != null ? ' version $version' : '';

    final prompt =
        '''You are a penetration testing expert. Provide accurate usage information for "$primaryTool"$versionStr on $os (running via $executionEnv).

IMPORTANT: Search the web for current documentation if available, especially for:
- Official documentation for this specific version
- Common usage patterns and examples
- Known issues or gotchas with this version
- OS-specific differences for $os${isWsl ? ' (via WSL)' : ''}

Respond with JSON:
{
  "tool": "$primaryTool",
  "version": "${version ?? 'unknown'}",
  "description": "Brief description of what the tool does",
  "basicSyntax": "Basic command syntax pattern",
  "commonOptions": [
    {"option": "-x", "description": "What this option does", "example": "example usage"}
  ],
  "exampleCommands": [
    {"purpose": "What this example does", "command": "full example command"}
  ],
  "requirements": ["Any prerequisites or dependencies"],
  "gotchas": ["Common mistakes or version-specific issues to avoid"],
  "relatedTools": ["Similar or complementary tools"]
}

CRITICAL ACCURACY REQUIREMENTS:
1. Option flags must be EXACTLY correct (case-sensitive: -x vs -X matters!)
2. If this tool is a Metasploit module (.rb file), explain it MUST be run via msfconsole
3. For Python scripts, note if they require Python 2 vs Python 3
4. Include any OS-specific differences for $os

Respond ONLY with valid JSON.''';

    try {
      final response = await llmService
          .sendMessage(settings, prompt)
          .timeout(Duration(seconds: 45));
      final info = _parseToolUsageResponse(response, primaryTool, version);

      _toolUsageCache[primaryTool] = info;
      print('${_timestamp()} DEBUG: Cached usage info for $primaryTool');

      return info;
    } catch (e) {
      print('${_timestamp()} DEBUG: getToolUsageInfo error: $e');
      return ToolUsageInfo(
        tool: primaryTool,
        version: version,
        description: 'Usage information unavailable',
        basicSyntax: '$primaryTool [options]',
        commonOptions: [],
        exampleCommands: [],
        requirements: [],
        gotchas: [],
        relatedTools: [],
      );
    }
  }

  static ToolUsageInfo _parseToolUsageResponse(
      String response, String tool, String? version) {
    try {
      final data = JsonParser.tryParseJson(response);
      if (data == null) throw FormatException('No valid JSON in response');

      return ToolUsageInfo(
        tool: data['tool'] ?? tool,
        version: data['version'] ?? version,
        description: data['description'] ?? '',
        basicSyntax: data['basicSyntax'] ?? '$tool [options]',
        commonOptions: (data['commonOptions'] as List?)
                ?.map((o) => ToolOption(
                      option: o['option'] ?? '',
                      description: o['description'] ?? '',
                      example: o['example'] ?? '',
                    ))
                .toList() ??
            [],
        exampleCommands: (data['exampleCommands'] as List?)
                ?.map((e) => ToolExample(
                      purpose: e['purpose'] ?? '',
                      command: e['command'] ?? '',
                    ))
                .toList() ??
            [],
        requirements:
            (data['requirements'] as List?)?.cast<String>() ?? [],
        gotchas: (data['gotchas'] as List?)?.cast<String>() ?? [],
        relatedTools:
            (data['relatedTools'] as List?)?.cast<String>() ?? [],
      );
    } catch (e) {
      print('${_timestamp()} DEBUG: Failed to parse tool usage response: $e');
      return ToolUsageInfo(
        tool: tool,
        version: version,
        description: 'Parse error',
        basicSyntax: '$tool [options]',
        commonOptions: [],
        exampleCommands: [],
        requirements: [],
        gotchas: [],
        relatedTools: [],
      );
    }
  }

  /// Format tool usage info for inclusion in LLM prompts.
  static String formatToolUsageForPrompt(ToolUsageInfo info) {
    final buffer = StringBuffer();
    buffer.writeln(
        '## TOOL: ${info.tool}${info.version != null ? " v${info.version}" : ""}');
    buffer.writeln('Description: ${info.description}');
    buffer.writeln('Basic Syntax: ${info.basicSyntax}');

    if (info.commonOptions.isNotEmpty) {
      buffer.writeln('\nCommon Options:');
      for (final opt in info.commonOptions.take(8)) {
        buffer.writeln('  ${opt.option}: ${opt.description}');
        if (opt.example.isNotEmpty) {
          buffer.writeln('    Example: ${opt.example}');
        }
      }
    }

    if (info.exampleCommands.isNotEmpty) {
      buffer.writeln('\nExample Commands:');
      for (final ex in info.exampleCommands.take(5)) {
        buffer.writeln('  # ${ex.purpose}');
        buffer.writeln('  ${ex.command}');
      }
    }

    if (info.gotchas.isNotEmpty) {
      buffer.writeln('\nWARNINGS/GOTCHAS:');
      for (final gotcha in info.gotchas) {
        buffer.writeln('  \u26a0\ufe0f $gotcha');
      }
    }

    if (info.requirements.isNotEmpty) {
      buffer.writeln('\nRequirements: ${info.requirements.join(", ")}');
    }

    return buffer.toString();
  }

  /// Clear tool usage cache.
  static void clearToolUsageCache() {
    _toolUsageCache.clear();
  }

  /// Clear all caches.
  static void clearAllCaches() {
    _toolUsageCache.clear();
    _toolSetupCache.clear();
    _toolSetupFailures.clear();
  }

  /// Check if a tool exists on the system.
  static Future<bool> checkToolExists(
      String tool,
      LLMSettings settings,
      LLMService llmService,
      Future<bool> Function() isWslAvailable) async {
    try {
      final primaryTool = tool.split(',').first.trim().split(' ').first.trim();
      if (primaryTool.isEmpty) return false;

      final binaryName = getToolBinary(primaryTool);
      print(
          '${_timestamp()} DEBUG: Tool binary lookup: $primaryTool -> $binaryName');

      final checkCmd = 'which $binaryName';
      print('${_timestamp()} DEBUG: Checking with command: $checkCmd');

      if (Platform.isWindows && await isWslAvailable()) {
        final process =
            await Process.start('wsl', ['bash', '-c', checkCmd]);
        final stdoutBuffer = StringBuffer();
        process.stdout
            .transform(utf8.decoder)
            .listen((data) => stdoutBuffer.write(data));
        process.stderr.transform(utf8.decoder).listen((_) {});
        final exitCode = await process.exitCode;
        print('${_timestamp()} DEBUG: Exit code: $exitCode');
        return exitCode == 0;
      } else if (Platform.isLinux || Platform.isMacOS) {
        final process = await Process.start('bash', ['-c', checkCmd]);
        final stdoutBuffer = StringBuffer();
        process.stdout
            .transform(utf8.decoder)
            .listen((data) => stdoutBuffer.write(data));
        process.stderr.transform(utf8.decoder).listen((_) {});
        final exitCode = await process.exitCode;
        print('${_timestamp()} DEBUG: Exit code: $exitCode');
        return exitCode == 0;
      }
      return false;
    } catch (e) {
      print('${_timestamp()} DEBUG: checkToolExists error: $e');
      return false;
    }
  }

  /// Verify if a tool needs initialization/setup.
  static Future<Map<String, dynamic>> verifyToolSetup(
      String tool,
      LLMSettings settings,
      LLMService llmService,
      Future<String> Function() getOsInfo,
      Future<bool> Function() isWslAvailable) async {
    try {
      final noSetupTools = [
        'searchsploit', 'nmap', 'curl', 'wget', 'nc', 'netcat',
        'python', 'python2', 'python3', 'perl', 'ruby', 'nikto',
        'sqlmap', 'hydra', 'dirb', 'gobuster', 'ffuf', 'smbclient',
        'smbmap', 'nuclei', 'scapy'
      ];
      if (noSetupTools.contains(tool.toLowerCase())) {
        return {'needs_setup': false};
      }

      if (_toolSetupFailures.contains(tool.toLowerCase())) {
        return {
          'needs_setup': true,
          'setup_failed': true,
          'reason': 'Setup previously failed for $tool'
        };
      }

      if (_toolSetupCache.containsKey(tool.toLowerCase())) {
        return _toolSetupCache[tool.toLowerCase()]!;
      }

      final os = await getOsInfo();

      final prompt =
          '''Does "$tool" on $os require any initialization or setup after installation before it can be used effectively?

For example:
- Metasploit requires "msfdb init" to initialize the database
- Some tools need configuration files created
- Some need services started

Respond with JSON:
{
  "needs_setup": true/false,
  "reason": "explanation of what needs to be done",
  "check_command": "command to verify if setup is needed",
  "setup_command": "command to run if setup is needed"
}

IMPORTANT: check_command and setup_command must be non-interactive (no user prompts).
If no setup is needed, return {"needs_setup": false}.
Respond ONLY with valid JSON.''';

      final response = await llmService
          .sendMessage(settings, prompt)
          .timeout(Duration(seconds: 30));
      final decision = JsonParser.tryParseJson(response) ?? {};

      if (decision['needs_setup'] != true) {
        final result = <String, dynamic>{'needs_setup': false};
        _toolSetupCache[tool.toLowerCase()] = result;
        return result;
      }

      final checkCmd = decision['check_command'];
      if (checkCmd == null || checkCmd.isEmpty) {
        return decision;
      }

      try {
        Process process;
        if (Platform.isWindows && await isWslAvailable()) {
          process =
              await Process.start('wsl', ['bash', '-c', checkCmd]);
        } else {
          process = await Process.start('bash', ['-c', checkCmd]);
        }

        final stdoutBuffer = StringBuffer();
        process.stdout
            .transform(utf8.decoder)
            .listen((data) => stdoutBuffer.write(data));
        process.stderr.transform(utf8.decoder).listen((_) {});

        final exitCode =
            await process.exitCode.timeout(Duration(seconds: 60));
        final stdout = stdoutBuffer.toString();

        if (exitCode == 0 &&
            !stdout.toLowerCase().contains('disconnect') &&
            !stdout.toLowerCase().contains('failed')) {
          final result = <String, dynamic>{'needs_setup': false};
          _toolSetupCache[tool.toLowerCase()] = result;
          return result;
        }

        _toolSetupCache[tool.toLowerCase()] = decision;
        return decision;
      } on TimeoutException {
        return {'needs_setup': false};
      }
    } catch (e) {
      print('${_timestamp()} DEBUG: verifyToolSetup error: $e');
      return {'needs_setup': false};
    }
  }
}
