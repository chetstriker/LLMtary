import 'dart:io';
import 'dart:async';
import 'dart:convert';
import '../models/llm_settings.dart';
import '../database/database_helper.dart';
import 'llm_service.dart';

class CommandResult {
  final int exitCode;
  final String output;
  final String error;
  CommandResult(this.exitCode, this.output, this.error);
}

class CommandExecutor {
  static String _timestamp() => '[${DateTime.now().toIso8601String().substring(11, 23)}]';

  static String? _cachedOsInfo;

  // Cache for tool usage information to avoid repeated lookups
  static final Map<String, ToolUsageInfo> _toolUsageCache = {};

  // Map tool names to their actual binary names
  static const Map<String, String> _toolBinaryMap = {
    'metasploit': 'msfconsole',
    'metasploit-framework': 'msfconsole',
    'msf': 'msfconsole',
    'exploitdb': 'searchsploit',
    'exploit-db': 'searchsploit',
  };

  // Get the actual binary name for a tool
  static String _getToolBinary(String tool) {
    final normalized = tool.toLowerCase().trim();
    return _toolBinaryMap[normalized] ?? tool;
  }

  // Get tool version
  static Future<String?> getToolVersion(String tool) async {
    try {
      final primaryTool = tool.split(',').first.trim().split(' ').first.trim();
      if (primaryTool.isEmpty) return null;

      // Get the actual binary name (e.g., "metasploit" -> "msfconsole")
      final binaryName = _getToolBinary(primaryTool);

      // Common version flags to try
      final versionFlags = ['--version', '-version', '-v', '-V', 'version'];

      for (final flag in versionFlags) {
        try {
          ProcessResult result;
          if (Platform.isWindows && await isWslAvailable()) {
            result = await Process.run('wsl', ['bash', '-c', '$binaryName $flag 2>&1 | head -5'])
                .timeout(Duration(seconds: 10));
          } else {
            result = await Process.run('bash', ['-c', '$binaryName $flag 2>&1 | head -5'])
                .timeout(Duration(seconds: 10));
          }

          if (result.exitCode == 0 && result.stdout.toString().trim().isNotEmpty) {
            final output = result.stdout.toString().trim();
            // Extract version number pattern
            final versionMatch = RegExp(r'(\d+\.\d+(?:\.\d+)?(?:-\w+)?)').firstMatch(output);
            if (versionMatch != null) {
              print('${_timestamp()} DEBUG: $primaryTool ($binaryName) version: ${versionMatch.group(1)}');
              return versionMatch.group(1);
            }
            // Return first line if no version pattern found
            final firstLine = output.split('\n').first.trim();
            if (firstLine.isNotEmpty && firstLine.length < 200 && !firstLine.contains('command not found')) {
              print('${_timestamp()} DEBUG: $primaryTool ($binaryName) version info: $firstLine');
              return firstLine;
            }
          }
        } catch (e) {
          continue; // Try next flag
        }
      }

      print('${_timestamp()} DEBUG: Could not determine version for $primaryTool ($binaryName)');
      return null;
    } catch (e) {
      print('${_timestamp()} DEBUG: getToolVersion error: $e');
      return null;
    }
  }

  // Get comprehensive tool usage information
  static Future<ToolUsageInfo> getToolUsageInfo(String tool, LLMSettings settings, LLMService llmService) async {
    final primaryTool = tool.split(',').first.trim().split(' ').first.trim();

    // Check cache first
    if (_toolUsageCache.containsKey(primaryTool)) {
      print('${_timestamp()} DEBUG: Using cached usage info for $primaryTool');
      return _toolUsageCache[primaryTool]!;
    }

    print('${_timestamp()} DEBUG: Looking up usage info for $primaryTool');

    final os = await getOsInfo();
    final version = await getToolVersion(primaryTool);
    final versionStr = version != null ? ' version $version' : '';

    final prompt = '''You are a penetration testing expert. Provide accurate usage information for "$primaryTool"$versionStr on $os.

IMPORTANT: Search the web for current documentation if available, especially for:
- Official documentation for this specific version
- Common usage patterns and examples
- Known issues or gotchas with this version

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
      final response = await llmService.sendMessage(settings, prompt).timeout(Duration(seconds: 45));
      final info = _parseToolUsageResponse(response, primaryTool, version);

      // Cache the result
      _toolUsageCache[primaryTool] = info;
      print('${_timestamp()} DEBUG: Cached usage info for $primaryTool');

      return info;
    } catch (e) {
      print('${_timestamp()} DEBUG: getToolUsageInfo error: $e');
      // Return minimal info on error
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

  static ToolUsageInfo _parseToolUsageResponse(String response, String tool, String? version) {
    try {
      String cleaned = response.trim();
      if (cleaned.startsWith('```')) {
        cleaned = cleaned.replaceAll(RegExp(r'^```json\s*'), '');
        cleaned = cleaned.replaceAll(RegExp(r'^```\s*'), '');
        cleaned = cleaned.replaceAll(RegExp(r'```\s*$'), '');
      }

      final jsonStart = cleaned.indexOf('{');
      final jsonEnd = cleaned.lastIndexOf('}');
      if (jsonStart != -1 && jsonEnd != -1 && jsonEnd > jsonStart) {
        cleaned = cleaned.substring(jsonStart, jsonEnd + 1);
      }

      final data = json.decode(cleaned);

      return ToolUsageInfo(
        tool: data['tool'] ?? tool,
        version: data['version'] ?? version,
        description: data['description'] ?? '',
        basicSyntax: data['basicSyntax'] ?? '$tool [options]',
        commonOptions: (data['commonOptions'] as List?)?.map((o) => ToolOption(
          option: o['option'] ?? '',
          description: o['description'] ?? '',
          example: o['example'] ?? '',
        )).toList() ?? [],
        exampleCommands: (data['exampleCommands'] as List?)?.map((e) => ToolExample(
          purpose: e['purpose'] ?? '',
          command: e['command'] ?? '',
        )).toList() ?? [],
        requirements: (data['requirements'] as List?)?.cast<String>() ?? [],
        gotchas: (data['gotchas'] as List?)?.cast<String>() ?? [],
        relatedTools: (data['relatedTools'] as List?)?.cast<String>() ?? [],
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

  // Format tool usage info for inclusion in prompts
  static String formatToolUsageForPrompt(ToolUsageInfo info) {
    final buffer = StringBuffer();
    buffer.writeln('## TOOL: ${info.tool}${info.version != null ? " v${info.version}" : ""}');
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
        buffer.writeln('  ⚠️ $gotcha');
      }
    }

    if (info.requirements.isNotEmpty) {
      buffer.writeln('\nRequirements: ${info.requirements.join(", ")}');
    }

    return buffer.toString();
  }

  // Clear cache (useful for testing or when tools are updated)
  static void clearToolUsageCache() {
    _toolUsageCache.clear();
  }
  
  static Future<String> getOsInfo() async {
    if (_cachedOsInfo != null) return _cachedOsInfo!;
    
    try {
      if (Platform.isWindows && await isWslAvailable()) {
        final result = await Process.run('wsl', ['cat', '/etc/os-release']);
        if (result.exitCode == 0) {
          final output = result.stdout.toString();
          final nameMatch = RegExp(r'PRETTY_NAME="([^"]+)"').firstMatch(output);
          if (nameMatch != null) {
            _cachedOsInfo = nameMatch.group(1)!;
            return _cachedOsInfo!;
          }
        }
        _cachedOsInfo = 'Linux (WSL)';
      } else if (Platform.isLinux) {
        final result = await Process.run('cat', ['/etc/os-release']);
        if (result.exitCode == 0) {
          final output = result.stdout.toString();
          final nameMatch = RegExp(r'PRETTY_NAME="([^"]+)"').firstMatch(output);
          if (nameMatch != null) {
            _cachedOsInfo = nameMatch.group(1)!;
            return _cachedOsInfo!;
          }
        }
        _cachedOsInfo = 'Linux';
      } else if (Platform.isMacOS) {
        _cachedOsInfo = 'macOS';
      } else {
        _cachedOsInfo = 'Unknown';
      }
    } catch (e) {
      _cachedOsInfo = Platform.isWindows ? 'Linux (WSL)' : (Platform.isMacOS ? 'macOS' : 'Linux');
    }
    return _cachedOsInfo!;
  }
  
  static bool? _wslAvailable;
  
  static final _dangerousCommands = [
    'rm -rf /',
    'format',
    'del /f /q c:',
    'rmdir /s /q c:',
    'mkfs',
    'dd if=/dev/zero',
    ':(){:|:&};:',
  ];

  static Future<Map<String, dynamic>> verifyToolSetup(String tool, LLMSettings settings, LLMService llmService) async {
    try {
      // Skip setup verification for tools that don't need it
      final noSetupTools = ['searchsploit', 'nmap', 'curl', 'wget', 'nc', 'netcat'];
      if (noSetupTools.contains(tool.toLowerCase())) {
        print('${_timestamp()} DEBUG: $tool does not require setup');
        return {'needs_setup': false};
      }
      
      final os = await getOsInfo();
      
      final prompt = '''Does "$tool" on $os require any initialization or setup after installation before it can be used effectively?

For example:
- Metasploit requires "msfdb init" to initialize the database
- Some tools need configuration files created
- Some need services started

Respond with JSON:
{
  "needs_setup": true/false,
  "reason": "explanation of what needs to be done",
  "check_command": "command to verify if setup is needed (e.g., 'msfconsole -q -x \"db_status; exit\"' for metasploit)",
  "setup_command": "command to run if setup is needed (e.g., 'msfdb init' for metasploit)"
}

IMPORTANT: check_command and setup_command must be non-interactive (no user prompts).
If no setup is needed, return {"needs_setup": false}.
Respond ONLY with valid JSON.''';
      
      final response = await llmService.sendMessage(settings, prompt).timeout(Duration(seconds: 30));
      final decision = _parseJson(response);
      
      if (decision['needs_setup'] != true) {
        print('${_timestamp()} DEBUG: No setup needed for $tool');
        return {'needs_setup': false};
      }
      
      final checkCmd = decision['check_command'];
      if (checkCmd == null || checkCmd.isEmpty) {
        print('${_timestamp()} DEBUG: Setup needed but no check command provided');
        return decision;
      }
      
      print('${_timestamp()} DEBUG: Running setup check: $checkCmd');
      
      try {
        Process process;
        if (Platform.isWindows && await isWslAvailable()) {
          process = await Process.start('wsl', ['bash', '-c', checkCmd]);
        } else {
          process = await Process.start('bash', ['-c', checkCmd]);
        }
        
        final stdoutBuffer = StringBuffer();
        final stderrBuffer = StringBuffer();
        
        process.stdout.transform(utf8.decoder).listen((data) {
          print('${_timestamp()} [SETUP STDOUT] $data');
          stdoutBuffer.write(data);
        });
        
        process.stderr.transform(utf8.decoder).listen((data) {
          print('${_timestamp()} [SETUP STDERR] $data');
          stderrBuffer.write(data);
        });
        
        final exitCode = await process.exitCode.timeout(Duration(seconds: 60));
        final stdout = stdoutBuffer.toString();
        final stderr = stderrBuffer.toString();
        
        print('${_timestamp()} DEBUG: Setup check exit code: $exitCode');
        
        // If check command succeeds, setup is already done
        if (exitCode == 0 && !stdout.toLowerCase().contains('disconnect') && !stdout.toLowerCase().contains('failed')) {
          print('${_timestamp()} DEBUG: Setup already complete for $tool');
          return {'needs_setup': false};
        }
        
        print('${_timestamp()} DEBUG: Setup required for $tool: ${decision['reason']}');
        return decision;
      } on TimeoutException {
        print('${_timestamp()} DEBUG: Setup check timed out after 60s');
        return {'needs_setup': false};
      }
    } catch (e) {
      print('${_timestamp()} DEBUG: verifyToolSetup error: $e');
      return {'needs_setup': false};
    }
  }

  static Map<String, dynamic> _parseJson(String response) {
    try {
      String cleaned = response.trim();
      if (cleaned.startsWith('```')) {
        cleaned = cleaned.replaceAll(RegExp(r'^```json\s*'), '');
        cleaned = cleaned.replaceAll(RegExp(r'^```\s*'), '');
        cleaned = cleaned.replaceAll(RegExp(r'```\s*$'), '');
      }
      return json.decode(cleaned);
    } catch (e) {
      return {};
    }
  }

  static Future<bool> isWslAvailable() async {
    if (_wslAvailable != null) return _wslAvailable!;
    
    if (!Platform.isWindows) {
      _wslAvailable = false;
      return false;
    }
    
    try {
      final result = await Process.run('wsl', ['--status']).timeout(const Duration(seconds: 3));
      _wslAvailable = result.exitCode == 0;
    } catch (e) {
      _wslAvailable = false;
    }
    return _wslAvailable!;
  }

  static Future<String> getWslIp() async {
    if (await isWslAvailable()) {
      try {
        final result = await Process.run('wsl', ['hostname', '-I']);
        return result.stdout.toString().trim().split(' ')[0];
      } catch (e) {}
    }
    return "127.0.0.1";
  }

  static Future<bool> checkToolExists(String tool, LLMSettings settings, LLMService llmService) async {
    try {
      // Handle comma-separated tool names - check the PRIMARY tool only
      final primaryTool = tool.split(',').first.trim().split(' ').first.trim();
      if (primaryTool.isEmpty) return false;

      final os = await getOsInfo();
      print('${_timestamp()} DEBUG: Detected OS: $os');
      print('${_timestamp()} DEBUG: Checking for primary tool: $primaryTool (from "$tool")');

      final prompt = '''What is the exact binary/command name for "$primaryTool" on $os?

Respond with JSON:
{
  "binary": "exact binary name to check with 'which'",
  "explanation": "brief explanation"
}

IMPORTANT: Return ONLY the single primary binary name, not multiple tools.

Examples:
- For metasploit: {"binary": "msfconsole", "explanation": "msfconsole is the main Metasploit binary"}
- For nmap: {"binary": "nmap", "explanation": "nmap is the binary name"}
- For sqlmap: {"binary": "sqlmap", "explanation": "sqlmap is the binary name"}
- For searchsploit: {"binary": "searchsploit", "explanation": "searchsploit is part of exploitdb"}
- For hydra: {"binary": "hydra", "explanation": "hydra is the binary name"}
- For nikto: {"binary": "nikto", "explanation": "nikto is the binary name"}

Respond ONLY with valid JSON.''';

      final response = await llmService.sendMessage(settings, prompt).timeout(Duration(seconds: 30));
      final decision = _parseJson(response);
      final binaryName = decision['binary'] ?? primaryTool;

      // Use simple 'which' check for single binary
      final checkCmd = 'which $binaryName';
      print('${_timestamp()} DEBUG: Checking with command: $checkCmd');
      
      if (Platform.isWindows && await isWslAvailable()) {
        print('${_timestamp()} DEBUG: Running command: wsl bash -c "$checkCmd"');
        final process = await Process.start('wsl', ['bash', '-c', checkCmd]);
        
        final stdoutBuffer = StringBuffer();
        final stderrBuffer = StringBuffer();
        
        process.stdout.transform(utf8.decoder).listen((data) {
          print('${_timestamp()} [CHECK STDOUT] $data');
          stdoutBuffer.write(data);
        });
        
        process.stderr.transform(utf8.decoder).listen((data) {
          print('${_timestamp()} [CHECK STDERR] $data');
          stderrBuffer.write(data);
        });
        
        final exitCode = await process.exitCode;
        print('${_timestamp()} DEBUG: Exit code: $exitCode');
        return exitCode == 0;
      } else if (Platform.isLinux || Platform.isMacOS) {
        print('${_timestamp()} DEBUG: Running command: $checkCmd');
        final process = await Process.start('bash', ['-c', checkCmd]);
        
        final stdoutBuffer = StringBuffer();
        final stderrBuffer = StringBuffer();
        
        process.stdout.transform(utf8.decoder).listen((data) {
          print('${_timestamp()} [CHECK STDOUT] $data');
          stdoutBuffer.write(data);
        });
        
        process.stderr.transform(utf8.decoder).listen((data) {
          print('${_timestamp()} [CHECK STDERR] $data');
          stderrBuffer.write(data);
        });
        
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

  static Future<String> _detectPackageManager() async {
    final managers = ['apt-get', 'yum', 'dnf', 'pacman', 'zypper', 'apk'];
    
    for (final manager in managers) {
      try {
        final result = await Process.run('which', [manager]);
        if (result.exitCode == 0) return manager;
      } catch (e) {}
    }
    return 'apt-get';
  }

  static Future<bool> installTool(String tool, LLMSettings settings, LLMService llmService) async {
    try {
      // Handle comma-separated tool names - install the PRIMARY tool only
      final primaryTool = tool.split(',').first.trim().split(' ').first.trim();
      if (primaryTool.isEmpty) return false;

      print('${_timestamp()} DEBUG: Installing primary tool: $primaryTool (from "$tool")');

      // Check if already installed
      if (await checkToolExists(primaryTool, settings, llmService)) {
        print('${_timestamp()} DEBUG: Tool $primaryTool already installed');
        return true;
      }

      final os = await getOsInfo();
      print('${_timestamp()} DEBUG: Installing on OS: $os');

      final prompt = '''What is the SINGLE apt package name to install "$primaryTool" on $os?

Respond with JSON:
{
  "command": "sudo apt-get install -y PACKAGE_NAME",
  "package": "exact package name"
}

IMPORTANT RULES:
1. Return ONLY ONE package name, not multiple
2. Do NOT include 'apt-get update' - just the install command
3. Use the standard package name from apt repositories
4. Do NOT suggest git clone unless the tool is not in apt

Examples:
- For metasploit: {"command": "sudo apt-get install -y metasploit-framework", "package": "metasploit-framework"}
- For nmap: {"command": "sudo apt-get install -y nmap", "package": "nmap"}
- For smbmap: {"command": "sudo apt-get install -y smbmap", "package": "smbmap"}
- For sqlmap: {"command": "sudo apt-get install -y sqlmap", "package": "sqlmap"}
- For hydra: {"command": "sudo apt-get install -y hydra", "package": "hydra"}
- For nikto: {"command": "sudo apt-get install -y nikto", "package": "nikto"}
- For searchsploit: {"command": "sudo apt-get install -y exploitdb", "package": "exploitdb"}

Respond ONLY with valid JSON.''';
      
      final response = await llmService.sendMessage(settings, prompt).timeout(Duration(seconds: 30));
      final decision = _parseJson(response);
      String installCmd = decision['command'] ?? '';

      if (installCmd.isEmpty) {
        print('${_timestamp()} DEBUG: LLM did not provide install command');
        return false;
      }

      // Remove apt-get update from the command - it takes too long
      installCmd = installCmd.replaceAll(RegExp(r'sudo\s+apt-get\s+update\s*&&\s*'), '');
      installCmd = installCmd.replaceAll(RegExp(r'apt-get\s+update\s*&&\s*'), '');

      // Ensure -y flag is present
      if (installCmd.contains('apt-get install') && !installCmd.contains('-y')) {
        installCmd = installCmd.replaceAll('apt-get install', 'apt-get install -y');
      }

      // Use sudo -n (non-interactive) to fail fast if password required
      // instead of hanging forever waiting for password input
      if (installCmd.contains('sudo ') && !installCmd.contains('sudo -n') && !installCmd.contains('sudo -S')) {
        installCmd = installCmd.replaceAll('sudo ', 'sudo -n ');
      }

      // Check if sudo requires password (would cause hang)
      if (installCmd.contains('sudo')) {
        print('${_timestamp()} DEBUG: Checking sudo access...');
        try {
          ProcessResult sudoCheck;
          if (Platform.isWindows && await isWslAvailable()) {
            sudoCheck = await Process.run('wsl', ['sudo', '-n', 'true']).timeout(Duration(seconds: 5));
          } else {
            sudoCheck = await Process.run('sudo', ['-n', 'true']).timeout(Duration(seconds: 5));
          }
          if (sudoCheck.exitCode != 0) {
            print('${_timestamp()} DEBUG: sudo requires password - cannot install automatically');
            print('${_timestamp()} DEBUG: User should run: $installCmd');
            return false;
          }
          print('${_timestamp()} DEBUG: sudo access confirmed (no password needed)');
        } catch (e) {
          print('${_timestamp()} DEBUG: sudo check failed: $e - proceeding anyway');
        }
      }

      print('${_timestamp()} DEBUG: Running install command: $installCmd');

      Process process;
      if (Platform.isWindows && await isWslAvailable()) {
        print('${_timestamp()} DEBUG: Running install command in WSL');
        process = await Process.start('wsl', ['bash', '-c', installCmd]);
      } else if (Platform.isLinux || Platform.isMacOS) {
        print('${_timestamp()} DEBUG: Running install command');
        process = await Process.start('bash', ['-c', installCmd]);
      } else {
        return false;
      }

      final stdoutBuffer = StringBuffer();
      final stderrBuffer = StringBuffer();

      process.stdout.transform(utf8.decoder).listen((data) {
        print('${_timestamp()} [INSTALL STDOUT] $data');
        stdoutBuffer.write(data);
      });

      process.stderr.transform(utf8.decoder).listen((data) {
        print('${_timestamp()} [INSTALL STDERR] $data');
        stderrBuffer.write(data);
      });

      // Increased timeout to 3 minutes for package installation
      final exitCode = await process.exitCode.timeout(const Duration(minutes: 3));
      print('${_timestamp()} DEBUG: Install exit code: $exitCode');

      // Verify the tool was actually installed
      if (exitCode == 0) {
        final verified = await checkToolExists(primaryTool, settings, llmService);
        print('${_timestamp()} DEBUG: Post-install verification: ${verified ? "SUCCESS" : "FAILED"}');
        return verified;
      }
      return false;
    } catch (e) {
      print('${_timestamp()} DEBUG: installTool error: $e');
      return false;
    }
  }

  static String _getInstallCommand(String packageManager, String package) {
    switch (packageManager) {
      case 'apt-get':
        return 'sudo apt-get update && sudo apt-get install -y $package';
      case 'yum':
        return 'sudo yum install -y $package';
      case 'dnf':
        return 'sudo dnf install -y $package';
      case 'pacman':
        return 'sudo pacman -S --noconfirm $package';
      case 'zypper':
        return 'sudo zypper install -y $package';
      case 'apk':
        return 'sudo apk add $package';
      default:
        return 'sudo apt-get install -y $package';
    }
  }

  static Future<Map<String, dynamic>> executeCommand(String command, bool requireApproval, {String? adminPassword, Future<String?> Function(String)? onApprovalNeeded}) async {
    for (final dangerous in _dangerousCommands) {
      if (command.toLowerCase().contains(dangerous.toLowerCase())) {
        return {
          'exitCode': -1,
          'output': 'BLOCKED: Dangerous command detected',
          'error': 'Command contains dangerous pattern: $dangerous',
        };
      }
    }

    // Check if approval is required
    if (requireApproval && onApprovalNeeded != null) {
      final isWhitelisted = await DatabaseHelper.isCommandWhitelisted(command);
      if (!isWhitelisted) {
        final approval = await onApprovalNeeded(command);
        if (approval == null || approval == 'deny') {
          return {
            'exitCode': -2,
            'output': 'DENIED: User denied command execution',
            'error': 'Command execution denied by user',
          };
        } else if (approval == 'always') {
          await DatabaseHelper.addToWhitelist(command);
        }
        // 'once' approval continues without adding to whitelist
      }
    }

    try {
      // Prepend sudo with password if provided and command doesn't already have sudo
      String execCommand = command;
      if (adminPassword != null && adminPassword.isNotEmpty) {
        if (!command.trim().startsWith('sudo') && !command.contains('echo') && !command.contains('|')) {
          if (Platform.isWindows && await isWslAvailable()) {
            execCommand = 'echo "$adminPassword" | sudo -S bash -c "$command"';
          } else if (Platform.isLinux || Platform.isMacOS) {
            execCommand = 'echo "$adminPassword" | sudo -S bash -c "$command"';
          }
        } else if (command.trim().startsWith('sudo') && !command.contains('sudo -S')) {
          execCommand = command.replaceFirst('sudo', 'echo "$adminPassword" | sudo -S');
        }
      }

      CommandResult result;
      
      if (Platform.isWindows && await isWslAvailable()) {
        result = await _executeInWsl(execCommand);
      } else if (Platform.isLinux || Platform.isMacOS) {
        result = await _executeInShell(execCommand);
      } else {
        return {
          'exitCode': -1,
          'output': 'No execution environment available',
          'error': 'WSL not available on Windows',
        };
      }
      
      return {
        'exitCode': result.exitCode,
        'output': result.output.isEmpty ? result.error : result.output,
        'error': result.error,
      };
    } catch (e) {
      return {
        'exitCode': -1,
        'output': 'Error: $e',
        'error': e.toString(),
      };
    }
  }

  static Future<CommandResult> _executeInWsl(String command) async {
    try {
      final process = await Process.start('wsl', ['bash', '-c', command])
          .timeout(const Duration(minutes: 5));

      final stdoutBuffer = StringBuffer();
      final stderrBuffer = StringBuffer();

      // Use Utf8Decoder with allowMalformed to handle invalid UTF-8 sequences
      final decoder = Utf8Decoder(allowMalformed: true);

      process.stdout.transform(decoder).listen((data) {
        final sanitized = _sanitizeOutput(data);
        print('[STDOUT] $sanitized');
        stdoutBuffer.write(sanitized);
      });

      process.stderr.transform(decoder).listen((data) {
        final sanitized = _sanitizeOutput(data);
        print('[STDERR] $sanitized');
        stderrBuffer.write(sanitized);
      });

      final exitCode = await process.exitCode;
      return CommandResult(exitCode, stdoutBuffer.toString(), stderrBuffer.toString());
    } on TimeoutException {
      return CommandResult(-1, "", "Command timed out.");
    } catch (e) {
      return CommandResult(-1, "", "Error: $e");
    }
  }

  // Sanitize output to remove/replace non-printable and problematic characters
  static String _sanitizeOutput(String input) {
    // Remove control characters except newline, carriage return, and tab
    // Replace non-ASCII printable characters with ?
    final buffer = StringBuffer();
    for (int i = 0; i < input.length; i++) {
      final code = input.codeUnitAt(i);
      if (code == 0x0A || code == 0x0D || code == 0x09) {
        // Keep newline, carriage return, tab
        buffer.writeCharCode(code);
      } else if (code >= 0x20 && code <= 0x7E) {
        // Keep printable ASCII
        buffer.writeCharCode(code);
      } else if (code > 0x7E) {
        // Replace non-ASCII with ?
        buffer.write('?');
      }
      // Skip other control characters (0x00-0x1F except tab/newline/cr)
    }
    return buffer.toString();
  }

  static Future<CommandResult> _executeInShell(String command) async {
    try {
      final process = await Process.start('/bin/bash', ['-c', command])
          .timeout(const Duration(minutes: 5));

      final stdoutBuffer = StringBuffer();
      final stderrBuffer = StringBuffer();

      final decoder = Utf8Decoder(allowMalformed: true);

      process.stdout.transform(decoder).listen((data) {
        final sanitized = _sanitizeOutput(data);
        print('[STDOUT] $sanitized');
        stdoutBuffer.write(sanitized);
      });

      process.stderr.transform(decoder).listen((data) {
        final sanitized = _sanitizeOutput(data);
        print('[STDERR] $sanitized');
        stderrBuffer.write(sanitized);
      });

      final exitCode = await process.exitCode;
      return CommandResult(exitCode, stdoutBuffer.toString(), stderrBuffer.toString());
    } on TimeoutException {
      return CommandResult(-1, "", "Command timed out.");
    } catch (e) {
      return CommandResult(-1, "", "Error: $e");
    }
  }

  static Future<CommandResult> execute(String command) async {
    try {
      final process = await Process.start('powershell.exe', ['-Command', command])
          .timeout(const Duration(minutes: 5));
      final stdout = await process.stdout.transform(utf8.decoder).join();
      final stderr = await process.stderr.transform(utf8.decoder).join();
      return CommandResult(await process.exitCode, stdout, stderr);
    } on TimeoutException {
      return CommandResult(-1, "", "Command timed out.");
    } catch (e) {
      return CommandResult(-1, "", "Error: $e");
    }
  }
}

// Data classes for tool usage information
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
