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

  // Cache for tool setup verification results
  static final Map<String, Map<String, dynamic>> _toolSetupCache = {};

  // Track tools whose setup has failed (to avoid repeated attempts)
  static final Set<String> _toolSetupFailures = {};

  // Mark a tool's setup as failed so we don't retry
  static void markToolSetupFailed(String tool) {
    _toolSetupFailures.add(tool.toLowerCase());
  }

  // Map tool names to their actual binary names (avoids LLM calls for known tools)
  static const Map<String, String> _toolBinaryMap = {
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

  // Get the actual binary name for a tool
  static String getToolBinary(String tool) {
    final normalized = tool.toLowerCase().trim();
    return _toolBinaryMap[normalized] ?? tool;
  }

  // Get tool version
  static Future<String?> getToolVersion(String tool) async {
    try {
      final primaryTool = tool.split(',').first.trim().split(' ').first.trim();
      if (primaryTool.isEmpty) return null;

      // Get the actual binary name (e.g., "metasploit" -> "msfconsole")
      final binaryName = getToolBinary(primaryTool);

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
    final isWsl = Platform.isWindows && await isWslAvailable();
    final executionEnv = isWsl ? 'WSL on Windows' : Platform.isMacOS ? 'macOS' : 'Native Linux';
    final version = await getToolVersion(primaryTool);
    final versionStr = version != null ? ' version $version' : '';

    final prompt = '''You are a penetration testing expert. Provide accurate usage information for "$primaryTool"$versionStr on $os (running via $executionEnv).

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

  // Clear all caches (useful on app restart or new scan)
  static void clearAllCaches() {
    _toolUsageCache.clear();
    _toolSetupCache.clear();
    _toolSetupFailures.clear();
  }
  
  static Future<String> getOsInfo() async {
    if (_cachedOsInfo != null) return _cachedOsInfo!;
    
    try {
      if (Platform.isWindows) {
        if (await isWslAvailable()) {
          final result = await Process.run('wsl', ['cat', '/etc/os-release']);
          if (result.exitCode == 0) {
            final output = result.stdout.toString();
            final nameMatch = RegExp(r'PRETTY_NAME="([^"]+)"').firstMatch(output);
            if (nameMatch != null) {
              _cachedOsInfo = '${nameMatch.group(1)!} (via WSL on Windows)';
              return _cachedOsInfo!;
            }
          }
          _cachedOsInfo = 'Linux (WSL on Windows)';
        } else {
          // Native Windows without WSL
          final result = await Process.run('cmd', ['/c', 'ver']);
          if (result.exitCode == 0) {
            _cachedOsInfo = 'Windows (Native)';
          } else {
            _cachedOsInfo = 'Windows';
          }
        }
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
        final result = await Process.run('sw_vers', ['-productVersion']);
        if (result.exitCode == 0) {
          _cachedOsInfo = 'macOS ${result.stdout.toString().trim()}';
          return _cachedOsInfo!;
        }
        _cachedOsInfo = 'macOS';
      } else {
        _cachedOsInfo = 'Unknown';
      }
    } catch (e) {
      if (Platform.isWindows) {
        _cachedOsInfo = await isWslAvailable() ? 'Linux (WSL on Windows)' : 'Windows';
      } else {
        _cachedOsInfo = Platform.isMacOS ? 'macOS' : 'Linux';
      }
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
      final noSetupTools = ['searchsploit', 'nmap', 'curl', 'wget', 'nc', 'netcat', 'python', 'python2', 'python3', 'perl', 'ruby', 'nikto', 'sqlmap', 'hydra', 'dirb', 'gobuster', 'ffuf', 'smbclient', 'smbmap', 'nuclei', 'scapy'];
      if (noSetupTools.contains(tool.toLowerCase())) {
        print('${_timestamp()} DEBUG: $tool does not require setup');
        return {'needs_setup': false};
      }

      // Check if setup previously failed for this tool
      if (_toolSetupFailures.contains(tool.toLowerCase())) {
        print('${_timestamp()} DEBUG: $tool setup previously failed, skipping');
        return {'needs_setup': true, 'setup_failed': true, 'reason': 'Setup previously failed for $tool'};
      }

      // Check setup cache
      if (_toolSetupCache.containsKey(tool.toLowerCase())) {
        print('${_timestamp()} DEBUG: Using cached setup result for $tool');
        return _toolSetupCache[tool.toLowerCase()]!;
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
        final result = <String, dynamic>{'needs_setup': false};
        _toolSetupCache[tool.toLowerCase()] = result;
        return result;
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
          final result = <String, dynamic>{'needs_setup': false};
          _toolSetupCache[tool.toLowerCase()] = result;
          return result;
        }

        print('${_timestamp()} DEBUG: Setup required for $tool: ${decision['reason']}');
        _toolSetupCache[tool.toLowerCase()] = decision;
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

      // Use known binary mapping (avoids LLM call for common tools)
      final binaryName = getToolBinary(primaryTool);
      print('${_timestamp()} DEBUG: Tool binary lookup: $primaryTool -> $binaryName');

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
    // Check for macOS first
    if (Platform.isMacOS) {
      try {
        final result = await Process.run('which', ['brew']);
        if (result.exitCode == 0) return 'brew';
      } catch (e) {}
      return 'brew'; // Default for macOS
    }

    // Check for Windows native (without WSL)
    if (Platform.isWindows && !await isWslAvailable()) {
      // Windows uses chocolatey, scoop, or winget
      final managers = ['choco', 'scoop', 'winget'];
      for (final manager in managers) {
        try {
          final result = await Process.run('where', [manager]);
          if (result.exitCode == 0) return manager;
        } catch (e) {}
      }
      return 'choco'; // Default for Windows (most common)
    }

    // For Linux (native or WSL)
    final managers = ['apt-get', 'yum', 'dnf', 'pacman', 'zypper', 'apk'];
    
    if (Platform.isWindows && await isWslAvailable()) {
      // Check inside WSL
      for (final manager in managers) {
        try {
          final result = await Process.run('wsl', ['which', manager]);
          if (result.exitCode == 0) return manager;
        } catch (e) {}
      }
    } else {
      // Native Linux
      for (final manager in managers) {
        try {
          final result = await Process.run('which', [manager]);
          if (result.exitCode == 0) return manager;
        } catch (e) {}
      }
    }
    return 'apt-get'; // Default fallback
  }

  static Future<bool> installTool(String tool, LLMSettings settings, LLMService llmService, {String? adminPassword}) async {
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
      final packageManager = await _detectPackageManager();
      print('${_timestamp()} DEBUG: Installing on OS: $os (package manager: $packageManager)');

      // Build OS-specific prompt
      String packageManagerInfo;
      String exampleCommand;
      if (packageManager == 'brew') {
        packageManagerInfo = 'macOS using Homebrew';
        exampleCommand = 'brew install PACKAGE_NAME';
      } else if (packageManager == 'choco') {
        packageManagerInfo = 'Windows using Chocolatey';
        exampleCommand = 'choco install -y PACKAGE_NAME';
      } else if (packageManager == 'scoop') {
        packageManagerInfo = 'Windows using Scoop';
        exampleCommand = 'scoop install PACKAGE_NAME';
      } else if (packageManager == 'winget') {
        packageManagerInfo = 'Windows using winget';
        exampleCommand = 'winget install --id PACKAGE_NAME --silent';
      } else if (packageManager == 'apt-get') {
        packageManagerInfo = 'Debian/Ubuntu using apt-get';
        exampleCommand = 'sudo apt-get install -y PACKAGE_NAME';
      } else if (packageManager == 'yum' || packageManager == 'dnf') {
        packageManagerInfo = 'RedHat/CentOS/Fedora using $packageManager';
        exampleCommand = 'sudo $packageManager install -y PACKAGE_NAME';
      } else if (packageManager == 'pacman') {
        packageManagerInfo = 'Arch Linux using pacman';
        exampleCommand = 'sudo pacman -S --noconfirm PACKAGE_NAME';
      } else {
        packageManagerInfo = 'Linux using $packageManager';
        exampleCommand = 'sudo $packageManager install PACKAGE_NAME';
      }

      final isWsl = Platform.isWindows && await isWslAvailable();
      final wslInfo = isWsl ? 'WSL (Windows Subsystem for Linux)' : 
                      Platform.isWindows ? 'Native Windows' : 'Native';

      final prompt = '''What is the SINGLE package name to install "$primaryTool" on $os?

SYSTEM INFO:
- OS: $os
- Package Manager: $packageManagerInfo
- Running via: $wslInfo

Respond with JSON:
{
  "command": "$exampleCommand",
  "package": "exact package name"
}

IMPORTANT RULES:
1. Return ONLY ONE package name, not multiple
2. For apt-get: Do NOT include 'apt-get update' - just the install command
3. For brew: Use the standard Homebrew formula name (often different from Linux package names)
4. For Windows (choco/scoop/winget): Use Windows-compatible package names
5. Use the standard package name from the appropriate repository
6. Do NOT suggest git clone unless the tool is not available in the package manager

EXAMPLES FOR DIFFERENT SYSTEMS:

Debian/Ubuntu (apt-get):
- metasploit: {"command": "sudo apt-get install -y metasploit-framework", "package": "metasploit-framework"}
- nmap: {"command": "sudo apt-get install -y nmap", "package": "nmap"}
- searchsploit: {"command": "sudo apt-get install -y exploitdb", "package": "exploitdb"}

macOS (brew):
- metasploit: {"command": "brew install metasploit", "package": "metasploit"}
- nmap: {"command": "brew install nmap", "package": "nmap"}
- Note: searchsploit/exploitdb requires: {"command": "brew install exploitdb", "package": "exploitdb"}

Windows (choco):
- nmap: {"command": "choco install -y nmap", "package": "nmap"}
- curl: {"command": "choco install -y curl", "package": "curl"}
- Note: Many pentesting tools are not available on Windows - suggest WSL installation

RedHat/CentOS (yum/dnf):
- nmap: {"command": "sudo yum install -y nmap", "package": "nmap"}

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

      // Ensure -y flag is present for apt-get
      if (installCmd.contains('apt-get install') && !installCmd.contains('-y')) {
        installCmd = installCmd.replaceAll('apt-get install', 'apt-get install -y');
      }

      // For brew, no sudo needed (and it will fail with sudo)
      if (packageManager == 'brew' && installCmd.contains('sudo')) {
        installCmd = installCmd.replaceAll('sudo ', '');
      }

      // For Windows package managers, handle elevation differently
      final isWindowsNative = Platform.isWindows && !isWsl;
      if (isWindowsNative && (packageManager == 'choco' || packageManager == 'scoop' || packageManager == 'winget')) {
        // Windows package managers need to run elevated - will be handled by executeCommand
        // Remove any sudo that LLM might have added
        installCmd = installCmd.replaceAll('sudo ', '');
      }

      // Use sudo -n (non-interactive) to fail fast if password required
      // Skip for brew (doesn't use sudo), Windows (no sudo), and if adminPassword is provided
      if (packageManager != 'brew' && !isWindowsNative &&
          installCmd.contains('sudo ') && !installCmd.contains('sudo -n') && !installCmd.contains('sudo -S')) {
        installCmd = installCmd.replaceAll('sudo ', 'sudo -n ');
      }

      // Check if sudo requires password (would cause hang) - skip for Windows native
      if (installCmd.contains('sudo') && !isWindowsNative) {
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
      if (isWsl) {
        print('${_timestamp()} DEBUG: Running install command in WSL');
        // Use admin password if provided
        if (adminPassword != null && adminPassword.isNotEmpty && installCmd.contains('sudo')) {
          final sudoCmd = 'echo "$adminPassword" | sudo -S bash -c "${installCmd.replaceFirst('sudo', '')}"';
          process = await Process.start('wsl', ['bash', '-c', sudoCmd]);
        } else {
          process = await Process.start('wsl', ['bash', '-c', installCmd]);
        }
      } else if (isWindowsNative) {
        print('${_timestamp()} DEBUG: Running install command on Windows');
        // For Windows, use PowerShell with elevation if needed
        if (packageManager == 'choco' || packageManager == 'winget') {
          // These require elevation - use Start-Process with -Verb RunAs
          final psCommand = 'Start-Process powershell -ArgumentList "-Command","$installCmd" -Verb RunAs -Wait';
          process = await Process.start('powershell', ['-Command', psCommand]);
        } else {
          // Scoop doesn't require elevation
          process = await Process.start('powershell', ['-Command', installCmd]);
        }
      } else if (Platform.isLinux || Platform.isMacOS) {
        print('${_timestamp()} DEBUG: Running install command');
        // Never use sudo for brew on macOS
        if (packageManager == 'brew') {
          // For brew casks that need sudo, set SUDO_ASKPASS
          if (adminPassword != null && adminPassword.isNotEmpty) {
            // Create a temporary askpass script with restricted permissions
            final tempDir = Directory.systemTemp;
            final askpassScript = File('${tempDir.path}/.askpass_${DateTime.now().millisecondsSinceEpoch}.sh');
            await askpassScript.writeAsString('#!/bin/bash\necho "$adminPassword"');
            // Set permissions to 700 (owner read/write/execute only)
            await Process.run('chmod', ['700', askpassScript.path]);
            
            final envVars = Map<String, String>.from(Platform.environment);
            envVars['SUDO_ASKPASS'] = askpassScript.path;
            
            process = await Process.start('bash', ['-c', installCmd], environment: envVars);
            
            // Delete askpass script after installation completes (3 minutes timeout)
            Future.delayed(Duration(minutes: 3), () async {
              try {
                if (await askpassScript.exists()) {
                  await askpassScript.delete();
                }
              } catch (_) {}
            });
          } else {
            process = await Process.start('bash', ['-c', installCmd]);
          }
        } else if (adminPassword != null && adminPassword.isNotEmpty && installCmd.contains('sudo')) {
          final sudoCmd = 'echo "$adminPassword" | sudo -S bash -c "${installCmd.replaceFirst('sudo', '')}"';
          process = await Process.start('bash', ['-c', sudoCmd]);
        } else {
          process = await Process.start('bash', ['-c', installCmd]);
        }
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
      final stdout = stdoutBuffer.toString();
      final stderr = stderrBuffer.toString();
      print('${_timestamp()} DEBUG: Install exit code: $exitCode');

      // Check for missing dependencies in output
      if (exitCode != 0 || stdout.contains('requires') || stderr.contains('requires')) {
        // Check for Rosetta 2 requirement on Apple Silicon
        if ((stdout.contains('Rosetta 2') || stderr.contains('Rosetta 2')) && 
            (stdout.contains('softwareupdate --install-rosetta') || stderr.contains('softwareupdate --install-rosetta'))) {
          print('${_timestamp()} DEBUG: Rosetta 2 required, installing...');
          
          final rosettaCmd = 'softwareupdate --install-rosetta --agree-to-license';
          final rosettaProcess = await Process.start('bash', ['-c', rosettaCmd]);
          final rosettaStdout = StringBuffer();
          final rosettaStderr = StringBuffer();
          
          rosettaProcess.stdout.transform(utf8.decoder).listen((data) {
            print('${_timestamp()} [ROSETTA STDOUT] $data');
            rosettaStdout.write(data);
          });
          rosettaProcess.stderr.transform(utf8.decoder).listen((data) {
            print('${_timestamp()} [ROSETTA STDERR] $data');
            rosettaStderr.write(data);
          });
          
          final rosettaExit = await rosettaProcess.exitCode.timeout(const Duration(minutes: 5));
          print('${_timestamp()} DEBUG: Rosetta 2 install exit code: $rosettaExit');
          
          if (rosettaExit == 0) {
            print('${_timestamp()} DEBUG: Rosetta 2 installed, retrying tool installation...');
            
            // Recreate askpass script and environment for retry if needed
            Map<String, String>? retryEnv;
            File? retryAskpass;
            
            if (adminPassword != null && adminPassword.isNotEmpty && packageManager == 'brew') {
              final tempDir = Directory.systemTemp;
              retryAskpass = File('${tempDir.path}/.askpass_retry_${DateTime.now().millisecondsSinceEpoch}.sh');
              await retryAskpass.writeAsString('#!/bin/bash\necho "$adminPassword"');
              await Process.run('chmod', ['700', retryAskpass.path]);
              
              retryEnv = Map<String, String>.from(Platform.environment);
              retryEnv['SUDO_ASKPASS'] = retryAskpass.path;
            }
            
            // Retry the original installation
            final retryProcess = retryEnv != null 
                ? await Process.start('bash', ['-c', installCmd], environment: retryEnv)
                : await Process.start('bash', ['-c', installCmd]);
            final retryStdout = StringBuffer();
            final retryStderr = StringBuffer();
            
            retryProcess.stdout.transform(utf8.decoder).listen((data) {
              print('${_timestamp()} [RETRY STDOUT] $data');
              retryStdout.write(data);
            });
            retryProcess.stderr.transform(utf8.decoder).listen((data) {
              print('${_timestamp()} [RETRY STDERR] $data');
              retryStderr.write(data);
            });
            
            final retryExit = await retryProcess.exitCode.timeout(const Duration(minutes: 3));
            
            // Clean up retry askpass script
            if (retryAskpass != null) {
              try {
                if (await retryAskpass.exists()) await retryAskpass.delete();
              } catch (_) {}
            }
            
            if (retryExit == 0) {
              final verified = await checkToolExists(primaryTool, settings, llmService);
              print('${_timestamp()} DEBUG: Post-retry verification: ${verified ? "SUCCESS" : "FAILED"}');
              return verified;
            }
          }
        }
      }

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
      case 'brew':
        return 'brew install $package';
      case 'choco':
        return 'choco install -y $package';
      case 'scoop':
        return 'scoop install $package';
      case 'winget':
        return 'winget install --id $package --silent';
      case 'apt-get':
        return 'sudo apt-get install -y $package';
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
      
      if (Platform.isWindows) {
        if (await isWslAvailable()) {
          result = await _executeInWsl(execCommand);
        } else {
          // Native Windows without WSL
          result = await _executeInPowerShell(execCommand);
        }
      } else if (Platform.isLinux || Platform.isMacOS) {
        result = await _executeInShell(execCommand);
      } else {
        return {
          'exitCode': -1,
          'output': 'Unsupported platform',
          'error': 'Platform not supported',
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

  static Future<CommandResult> _executeInPowerShell(String command) async {
    try {
      // For commands that need elevation, use Start-Process with -Verb RunAs
      // For now, execute as-is and let Windows UAC handle elevation prompts
      final process = await Process.start('powershell', ['-Command', command])
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
