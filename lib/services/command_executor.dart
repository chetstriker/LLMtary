import 'dart:io';
import 'dart:async';
import 'dart:convert';
import '../models/llm_settings.dart';
import '../database/database_helper.dart';
import '../utils/json_parser.dart';
import '../utils/output_sanitizer.dart';
import 'llm_service.dart';
import 'tool_manager.dart';

// Re-export tool_manager types so existing callers don't need to change imports
export 'tool_manager.dart' show ToolUsageInfo, ToolOption, ToolExample;

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

  // Track known-invalid nmap script names to avoid wasting iterations
  static final Set<String> _invalidNmapScripts = {'dcom', 'rdp-enum-encryption'};

  // Tool flag hint dictionary for commonly misused tools
  static const Map<String, String> _toolFlagHints = {
    'ffuf': 'ffuf -w WORDLIST -u URL/FUZZ [-e .php,.html,.txt] [-x http://proxy:8080 (proxy only, NOT extensions)] [-mc 200,301,302] [-fc 404]',
    'nmap': 'nmap [-sV] [-sC] [-p PORTS] [-oX outfile.xml] [--script SCRIPTNAME] (scripts: smb-enum-shares, http-title, ftp-anon, ssl-cert, msrpc-enum, etc. — NOT "dcom", use msrpc-enum for RPC)',
    'curl': 'curl [-sk] [-o /dev/null] [-w "%{http_code}"] [-H "Header: value"] [-d "body"] [-X POST] [-b "cookie=val"] [-L]',
    'hydra': 'hydra -L users.txt -P pass.txt [-s PORT] [-f] SERVICE://TARGET (services: ftp, ssh, http-post-form, smb)',
    'sqlmap': 'sqlmap -u "URL" [--data "body"] [--dbs] [--tables] [--dump] [-p PARAM] [--level=3] [--risk=2]',
    'wfuzz': 'wfuzz -w WORDLIST -u URL/FUZZ [--hc 404] [--hw N] [-H "Header: val"]',
    'gobuster': 'gobuster dir -u URL -w WORDLIST [-x .php,.html] [-b 404,403] [-t 40]',
    'nikto': 'nikto -h TARGET [-p PORT] [-ssl] [-C all]',
    'enum4linux': 'enum4linux [-a] [-U] [-S] [-G] TARGET',
    'smbclient': r"smbclient //TARGET/SHARE [-U 'user%pass'] [-N] [-c 'ls']",
    'rpcclient': "rpcclient -U '' -N TARGET -c 'enumdomusers'",
    'crackmapexec': 'crackmapexec smb TARGET [-u USER] [-p PASS] [--shares] [--users] [--pass-pol]',
    'ncat': 'ncat [-w TIMEOUT] [-z] TARGET PORT  (use -w3 for short timeout)',
    'ftp': 'ftp TARGET PORT  (then: open TARGET PORT, user anonymous, ls, get FILE)',
  };

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
    'mysql': 'mysql',
    'mysql-client': 'mysql',
    'mariadb-client': 'mysql',
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
      final data = JsonParser.tryParseJson(response);
      if (data == null) throw FormatException('No valid JSON in response');

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

  /// Add a known-invalid nmap script name so future commands using it are skipped.
  static void addInvalidNmapScript(String scriptName) {
    final name = scriptName.trim();
    if (name.isNotEmpty && _invalidNmapScripts.add(name)) {
      print('${_timestamp()} DEBUG: Added invalid nmap script to blocklist: $name');
    }
  }

  /// Return a formatted hint block for the given list of tool names.
  /// Only includes entries that appear in [tools].
  static String getToolHints(List<String> tools) {
    final matched = <String>[];
    for (final tool in tools) {
      final key = tool.trim().toLowerCase();
      if (_toolFlagHints.containsKey(key)) {
        matched.add('- $key: ${_toolFlagHints[key]}');
      }
    }
    if (matched.isEmpty) return '';
    return '## Tool Usage Reference (correct flags):\n${matched.join('\n')}';
  }

  /// Extract the tool name from a command string (first token, path prefix stripped).
  static List<String> extractToolsFromCommand(String command) {
    final trimmed = command.trim();
    if (trimmed.isEmpty) return [];
    // Take the first whitespace-delimited token and strip any leading path
    final firstToken = trimmed.split(RegExp(r'\s+')).first;
    final toolName = firstToken.split(RegExp(r'[/\\]')).last.toLowerCase();
    return toolName.isNotEmpty ? [toolName] : [];
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
  
  // Each entry is a RegExp pattern matched against the full command (case-insensitive).
  // Use word-boundary / anchored patterns to avoid false positives like 'rfi' matching 'rm -rf /'.
  static final _dangerousPatterns = [
    RegExp(r'rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/', caseSensitive: false),  // rm -rf /
    RegExp(r'\bformat\s+[a-z]:', caseSensitive: false),                 // format C:
    RegExp(r'del\s+/f\s+/[sq]\s+[a-z]:', caseSensitive: false),        // del /f /q c:
    RegExp(r'rmdir\s+/s\s+/q\s+[a-z]:', caseSensitive: false),         // rmdir /s /q c:
    RegExp(r'\bmkfs\b', caseSensitive: false),                          // mkfs
    RegExp(r'dd\s+if=/dev/zero\s+of=/dev/', caseSensitive: false),      // dd if=/dev/zero of=/dev/...
    RegExp(r':\(\)\{:\|:&\};:', caseSensitive: false),                  // fork bomb
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
  "check_command": "command to verify if setup is needed (e.g., 'msfconsole -q -x "db_status; exit"' for metasploit)",
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
    return JsonParser.tryParseJson(response) ?? {};
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
        process.stdout.transform(utf8.decoder).listen((_) {});
        process.stderr.transform(utf8.decoder).listen((_) {});
        final exitCode = await process.exitCode;
        print('${_timestamp()} DEBUG: Exit code: $exitCode');
        return exitCode == 0;
      } else if (Platform.isWindows) {
        // Native Windows – use 'where' (cmd equivalent of 'which')
        print('${_timestamp()} DEBUG: Native Windows check: where $binaryName');
        final result = await Process.run('where', [binaryName])
            .timeout(const Duration(seconds: 5));
        print('${_timestamp()} DEBUG: Exit code: ${result.exitCode}');
        return result.exitCode == 0;
      } else if (Platform.isLinux || Platform.isMacOS) {
        print('${_timestamp()} DEBUG: Running command: $checkCmd');
        final process = await Process.start('bash', ['-c', checkCmd]);
        process.stdout.transform(utf8.decoder).listen((_) {});
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

  static Future<String> detectPackageManager() async {
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
      final managers = ['choco', 'scoop', 'winget'];
      for (final manager in managers) {
        try {
          final result = await Process.run('where', [manager]);
          if (result.exitCode == 0) return manager;
        } catch (e) {}
      }
      return 'choco'; // Default for Windows (most common)
    }

    // For Linux (native or WSL): detect distro family from /etc/os-release
    // first, then pick the correct package manager. This prevents false
    // positives when multiple package managers are installed (e.g. CachyOS
    // ships apt as a compatibility layer but pacman is the real manager).
    final isWsl = Platform.isWindows && await isWslAvailable();
    final distroFamily = await _detectDistroFamily(isWsl);

    // Map distro family to the correct package manager order
    List<String> prioritizedManagers;
    switch (distroFamily) {
      case 'arch':
        // Check for AUR helpers first (paru, yay), then pacman
        prioritizedManagers = ['paru', 'yay', 'pacman'];
        break;
      case 'debian':
        prioritizedManagers = ['apt-get'];
        break;
      case 'fedora':
        prioritizedManagers = ['dnf', 'yum'];
        break;
      case 'rhel':
        prioritizedManagers = ['yum', 'dnf'];
        break;
      case 'suse':
        prioritizedManagers = ['zypper'];
        break;
      case 'alpine':
        prioritizedManagers = ['apk'];
        break;
      default:
        // Unknown distro — fall back to which-based scan in a sensible order
        prioritizedManagers = ['pacman', 'apt-get', 'dnf', 'yum', 'zypper', 'apk'];
    }

    for (final manager in prioritizedManagers) {
      try {
        final ProcessResult result;
        if (isWsl) {
          result = await Process.run('wsl', ['which', manager]);
        } else {
          result = await Process.run('which', [manager]);
        }
        if (result.exitCode == 0) return manager;
      } catch (e) {}
    }

    return 'apt-get'; // Default fallback
  }

  /// Detect the Linux distro family from /etc/os-release.
  /// Returns 'arch', 'debian', 'fedora', 'rhel', 'suse', 'alpine', or 'unknown'.
  static Future<String> _detectDistroFamily(bool isWsl) async {
    try {
      final cmd = 'cat /etc/os-release 2>/dev/null';
      final ProcessResult result;
      if (isWsl) {
        result = await Process.run('wsl', ['bash', '-c', cmd])
            .timeout(const Duration(seconds: 5));
      } else {
        result = await Process.run('bash', ['-c', cmd])
            .timeout(const Duration(seconds: 5));
      }
      final content = (result.stdout as String? ?? '').toLowerCase();
      if (content.isEmpty) return 'unknown';

      // Parse ID and ID_LIKE fields
      String id = '';
      String idLike = '';
      for (final line in content.split('\n')) {
        if (line.startsWith('id=')) {
          id = line.substring(3).replaceAll('"', '').trim();
        } else if (line.startsWith('id_like=')) {
          idLike = line.substring(8).replaceAll('"', '').trim();
        }
      }

      // Check ID_LIKE first (e.g. cachyos has id_like=arch)
      final combined = '$id $idLike';
      if (combined.contains('arch')) return 'arch';
      if (combined.contains('debian') || combined.contains('ubuntu')) return 'debian';
      if (combined.contains('fedora')) return 'fedora';
      if (combined.contains('rhel') || combined.contains('centos')) return 'rhel';
      if (combined.contains('suse') || combined.contains('opensuse')) return 'suse';
      if (id == 'alpine') return 'alpine';

      return 'unknown';
    } catch (_) {
      return 'unknown';
    }
  }

  static Future<bool> installTool(String tool, LLMSettings settings, LLMService llmService, {String? adminPassword, Future<String?> Function(String)? onPasswordNeeded}) async {
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
      final packageManager = await detectPackageManager();
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
      } else if (packageManager == 'paru' || packageManager == 'yay') {
        packageManagerInfo = 'Arch Linux using $packageManager (AUR helper)';
        exampleCommand = '$packageManager -S --noconfirm PACKAGE_NAME';
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

Arch Linux (pacman):
- nmap: {"command": "sudo pacman -S --noconfirm nmap", "package": "nmap"}
- impacket: {"command": "sudo pacman -S --noconfirm impacket", "package": "impacket"}
- Note: Many pentesting tools are in the AUR, not the official repos

Arch Linux (paru/yay AUR helper):
- nmap: {"command": "paru -S --noconfirm nmap", "package": "nmap"}
- metasploit: {"command": "paru -S --noconfirm metasploit", "package": "metasploit"}
- Note: paru/yay do NOT use sudo — they handle elevation internally

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

      // Validate that the LLM's command uses the correct package manager.
      // If the LLM suggests apt-get but we detected pacman (or vice versa),
      // regenerate the command using the correct package manager.
      const knownManagers = ['apt-get', 'apt', 'yum', 'dnf', 'pacman', 'paru', 'yay', 'zypper', 'apk', 'brew', 'choco', 'scoop', 'winget'];
      final wrongManager = knownManagers.where((m) => m != packageManager && installCmd.contains(m)).firstOrNull;
      if (wrongManager != null) {
        print('${_timestamp()} DEBUG: LLM suggested $wrongManager but detected $packageManager — regenerating command');
        final pkg = decision['package'] ?? primaryTool;
        installCmd = _getInstallCommand(packageManager, pkg);
        print('${_timestamp()} DEBUG: Corrected install command: $installCmd');
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

      // For AUR helpers (paru/yay), no sudo needed — they handle elevation internally
      if ((packageManager == 'paru' || packageManager == 'yay') && installCmd.contains('sudo')) {
        installCmd = installCmd.replaceAll('sudo ', '');
      }

      // For Windows package managers, handle elevation differently
      final isWindowsNative = Platform.isWindows && !isWsl;
      if (isWindowsNative && (packageManager == 'choco' || packageManager == 'scoop' || packageManager == 'winget')) {
        // Windows package managers need to run elevated - will be handled by executeCommand
        // Remove any sudo that LLM might have added
        installCmd = installCmd.replaceAll('sudo ', '');
      }

      // Sudo handling: two paths depending on whether an admin password is available.
      final hasSudo = installCmd.contains('sudo ');
      if (hasSudo && !isWindowsNative && packageManager != 'brew' && packageManager != 'paru' && packageManager != 'yay') {
        if (adminPassword != null && adminPassword.isNotEmpty) {
          // Password provided — verify it works with sudo -S, then let the install
          // command run via "echo PASSWORD | sudo -S ..." below. No -n transformation needed.
          print('${_timestamp()} DEBUG: Admin password provided — verifying sudo -S access...');
          try {
            final sudoCheck = await Process.run('bash',
                ['-c', 'echo "$adminPassword" | sudo -S true 2>/dev/null'])
                .timeout(const Duration(seconds: 5));
            if (sudoCheck.exitCode != 0) {
              print('${_timestamp()} DEBUG: Admin password incorrect or sudo not available');
              return false;
            }
            print('${_timestamp()} DEBUG: sudo -S access confirmed');
          } catch (e) {
            print('${_timestamp()} DEBUG: sudo -S check failed: $e');
            return false;
          }
        } else {
          // No password — check if sudo is already cached (non-interactive)
          print('${_timestamp()} DEBUG: No admin password — checking cached sudo access...');
          try {
            ProcessResult sudoCheck;
            if (Platform.isWindows && await isWslAvailable()) {
              sudoCheck = await Process.run('wsl', ['sudo', '-n', 'true']).timeout(const Duration(seconds: 5));
            } else {
              sudoCheck = await Process.run('sudo', ['-n', 'true']).timeout(const Duration(seconds: 5));
            }
            if (sudoCheck.exitCode != 0) {
              print('${_timestamp()} DEBUG: sudo requires password and none was provided — prompting user...');
              if (onPasswordNeeded != null) {
                final prompted = await onPasswordNeeded(
                    'Enter sudo password to install $primaryTool:');
                if (prompted != null && prompted.isNotEmpty) {
                  // Verify the prompted password works
                  final verify = await Process.run('bash',
                      ['-c', 'echo "$prompted" | sudo -S true 2>/dev/null'])
                      .timeout(const Duration(seconds: 5));
                  if (verify.exitCode != 0) {
                    print('${_timestamp()} DEBUG: Prompted password incorrect');
                    return false;
                  }
                  adminPassword = prompted;
                  print('${_timestamp()} DEBUG: Prompted password accepted');
                } else {
                  print('${_timestamp()} DEBUG: User declined to provide password — cannot install');
                  return false;
                }
              } else {
                print('${_timestamp()} DEBUG: sudo requires password and none was provided — cannot install');
                print('${_timestamp()} DEBUG: User should run: $installCmd');
                return false;
              }
            }
            // Cached — use sudo -n to prevent any interactive prompt
            installCmd = installCmd.replaceAll('sudo ', 'sudo -n ');
            print('${_timestamp()} DEBUG: sudo cache confirmed (no password needed)');
          } catch (e) {
            print('${_timestamp()} DEBUG: sudo check failed: $e - proceeding anyway');
          }
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
          // Strip any sudo variant (sudo, sudo -n, sudo -S) — we'll supply our own sudo -S
          final cmdWithoutSudo = installCmd.replaceFirst(RegExp(r'sudo\s+(-\w+\s+)*'), '').trim();
          final sudoCmd = 'echo "$adminPassword" | sudo -S bash -c "$cmdWithoutSudo"';
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
      case 'paru':
        return 'paru -S --noconfirm $package';
      case 'yay':
        return 'yay -S --noconfirm $package';
      case 'zypper':
        return 'sudo zypper install -y $package';
      case 'apk':
        return 'sudo apk add $package';
      default:
        return 'sudo apt-get install -y $package';
    }
  }

  /// Extract all script names from an nmap --script argument.
  /// Handles both `--script name1,name2` and repeated `--script name` patterns.
  static List<String> _extractNmapScriptNames(String command) {
    final scripts = <String>[];
    // Match all --script <value> occurrences (value may be comma-separated)
    final pattern = RegExp(r'--script\s+([^\s\-][^\s]*)', caseSensitive: false);
    for (final match in pattern.allMatches(command)) {
      final value = match.group(1) ?? '';
      for (final name in value.split(',')) {
        final trimmed = name.trim();
        if (trimmed.isNotEmpty) scripts.add(trimmed);
      }
    }
    return scripts;
  }

  /// Parse nmap output for invalid-script error messages and register any found names.
  static void _checkNmapOutputForInvalidScripts(String output) {
    // Pattern: "NSE: failed to open: /usr/share/nmap/scripts/dcom.nse"
    // Pattern: "dcom did not match a category, filename, or directory"
    // Pattern: "No such script: dcom"
    final patterns = [
      RegExp(r"Failed to open[^/]*/usr/share/nmap/scripts/([^\s\.]+)", caseSensitive: false),
      RegExp(r"(\S+)\s+did not match a category", caseSensitive: false),
      RegExp(r"No such script[:\s]+(\S+)", caseSensitive: false),
    ];
    for (final re in patterns) {
      for (final match in re.allMatches(output)) {
        final name = (match.group(1) ?? '').trim();
        if (name.isNotEmpty) {
          addInvalidNmapScript(name);
        }
      }
    }
  }

  /// Phase 5.1: Returns true if the command was an nmap UDP/SNMP scan that failed
  /// because root privileges are required.
  static bool _isSnmpRootFailure(String command, String output) {
    final cmdLower = command.toLowerCase();
    final outLower = output.toLowerCase();
    return (cmdLower.contains('nmap') && cmdLower.contains('-su')) &&
        (outLower.contains('requires root privileges') ||
         outLower.contains('quitting!') ||
         outLower.contains('must be root'));
  }

  /// Phase 5.1: Retry SNMP enumeration using non-root tools when nmap UDP scan
  /// fails due to privilege requirements.
  static Future<Map<String, dynamic>?> _retrySnmpWithoutRoot(String originalCmd, bool elevated) async {
    // Extract target IP from original nmap command
    final ipMatch = RegExp(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b').firstMatch(originalCmd);
    if (ipMatch == null) return null;
    final target = ipMatch.group(1)!;

    final fallbacks = [
      'snmpwalk -v2c -c public $target 2>/dev/null',
      'onesixtyone $target public 2>/dev/null',
      'snmpwalk -v2c -c private $target 2>/dev/null',
      'snmpwalk -v1 -c public $target 2>/dev/null',
    ];

    for (final cmd in fallbacks) {
      try {
        final result = await executeCommand(cmd, elevated)
            .timeout(const Duration(seconds: 20));
        final out = (result['output'] ?? '').toString();
        // Return first result that has actual SNMP data (not just empty or error)
        if ((result['exitCode'] as int? ?? -1) == 0 && out.length > 30) {
          return result;
        }
      } catch (_) {
        continue;
      }
    }
    return null;
  }

  static Future<Map<String, dynamic>> executeCommand(String command, bool requireApproval, {String? adminPassword, Future<String?> Function(String)? onApprovalNeeded}) async {
    for (final pattern in _dangerousPatterns) {
      if (pattern.hasMatch(command)) {
        return {
          'exitCode': -1,
          'output': 'BLOCKED: Dangerous command detected',
          'error': 'Command matches dangerous pattern: ${pattern.pattern}',
        };
      }
    }

    // Phase 4.2 — Nmap script name validation
    // Before executing, check whether any --script names are known-invalid.
    if (command.contains('--script')) {
      final scriptNames = _extractNmapScriptNames(command);
      for (final name in scriptNames) {
        if (_invalidNmapScripts.contains(name.toLowerCase()) ||
            _invalidNmapScripts.contains(name)) {
          print('${_timestamp()} DEBUG: Skipping nmap command — script "$name" is known invalid');
          return {
            'exitCode': 1,
            'output': "SKIPPED: nmap script '$name' is known invalid. Use a different approach.",
            'error': "Invalid nmap script: $name",
          };
        }
      }
    }

    // Check approval via callback (callback decides live whether approval is needed)
    if (onApprovalNeeded != null) {
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
      // Inject sudo password only when the command itself starts with 'sudo'.
      // Wrapping arbitrary commands in 'bash -c "..."' breaks single-quoted
      // strings inside the command (e.g. curl -d '{"key":"val"}').
      String execCommand = command;
      if (adminPassword != null && adminPassword.isNotEmpty) {
        if (command.trim().startsWith('sudo') && !command.contains('sudo -S')) {
          execCommand = command.replaceFirst('sudo', 'echo "$adminPassword" | sudo -S');
        }
        // For commands that don't start with sudo, run as-is.
        // The LLM is responsible for including sudo where needed.
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

      // Phase 4.2 — parse nmap output for invalid script names and register them
      if (command.contains('nmap')) {
        final combinedOutput = '${result.output}\n${result.error}';
        _checkNmapOutputForInvalidScripts(combinedOutput);

        // Phase 5.1: SNMP privilege fallback — if nmap UDP scan failed due to root requirement,
        // automatically retry with non-root SNMP tools
        if (_isSnmpRootFailure(command, combinedOutput)) {
          final fallbackResult = await _retrySnmpWithoutRoot(command, requireApproval);
          if (fallbackResult != null) return fallbackResult;
        }
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

  /// Max combined stdout+stderr size before we kill the process (25 MB).
  static const int _maxOutputBytes = 25 * 1024 * 1024;

  /// Detect repetitive/useless output: if the last N lines are identical,
  /// the command is stuck in a loop producing no new information.
  static const int _repetitionThreshold = 50;

  /// Global command timeout. Generous to accommodate any tool the LLM chooses.
  static const Duration _commandTimeout = Duration(minutes: 30);

  /// Kill a process and all its children to prevent orphaned subprocesses.
  static Future<void> _killProcessTree(Process process) async {
    try {
      process.kill(ProcessSignal.sigkill);
      if (!Platform.isWindows) {
        await Process.run('pkill', ['-9', '-P', '${process.pid}'])
            .timeout(const Duration(seconds: 3))
            .catchError((_) => ProcessResult(0, 0, '', ''));
      }
    } catch (_) {}
  }

  /// Check if recent output lines are all identical (stuck in a loop).
  static bool _isRepetitiveOutput(List<String> recentLines) {
    if (recentLines.length < _repetitionThreshold) return false;
    final last = recentLines.last.trim();
    if (last.isEmpty) return false;
    int count = 0;
    for (int i = recentLines.length - 1; i >= 0 && count < _repetitionThreshold; i--) {
      if (recentLines[i].trim() == last) {
        count++;
      } else {
        break;
      }
    }
    return count >= _repetitionThreshold;
  }

  static Future<CommandResult> _executeInWsl(String command) async {
    Process? process;
    try {
      process = await Process.start('wsl', ['bash', '-c', command],
          workingDirectory: Directory.systemTemp.path)
          .timeout(_commandTimeout);

      final stdoutBuffer = StringBuffer();
      final stderrBuffer = StringBuffer();
      int totalBytes = 0;
      bool killed = false;
      String? killReason;
      final recentLines = <String>[];

      final decoder = Utf8Decoder(allowMalformed: true);

      process.stdout.transform(decoder).listen((data) {
        if (killed) return;
        final sanitized = OutputSanitizer.sanitize(data);
        totalBytes += sanitized.length;
        // Track recent lines for repetition detection
        final lines = sanitized.split('\n');
        for (final line in lines) {
          if (line.trim().isNotEmpty) {
            recentLines.add(line);
            if (recentLines.length > _repetitionThreshold + 10) {
              recentLines.removeAt(0);
            }
          }
        }
        if (totalBytes > _maxOutputBytes) {
          killed = true;
          killReason = 'Output exceeded ${_maxOutputBytes ~/ 1024}KB limit';
          _killProcessTree(process!);
          return;
        }
        if (_isRepetitiveOutput(recentLines)) {
          killed = true;
          killReason = 'Repetitive output detected (${_repetitionThreshold}+ identical lines)';
          _killProcessTree(process!);
          return;
        }
        print('${_timestamp()} [STDOUT] $sanitized');
        stdoutBuffer.write(sanitized);
      });

      process.stderr.transform(decoder).listen((data) {
        if (killed) return;
        final sanitized = OutputSanitizer.sanitize(data);
        totalBytes += sanitized.length;
        if (totalBytes > _maxOutputBytes) {
          killed = true;
          killReason = 'Output exceeded ${_maxOutputBytes ~/ 1024}KB limit';
          _killProcessTree(process!);
          return;
        }
        print('${_timestamp()} [STDERR] $sanitized');
        stderrBuffer.write(sanitized);
      });

      final exitCode = await process.exitCode.timeout(_commandTimeout);
      if (killed) {
        return CommandResult(-1, stdoutBuffer.toString(),
            'KILLED: $killReason. The command was producing excessive or repetitive output and was terminated.');
      }
      return CommandResult(exitCode, stdoutBuffer.toString(), stderrBuffer.toString());
    } on TimeoutException {
      if (process != null) await _killProcessTree(process);
      return CommandResult(-1, "", "Command timed out.");
    } catch (e) {
      if (process != null) await _killProcessTree(process);
      return CommandResult(-1, "", "Error: $e");
    }
  }

  static Future<CommandResult> _executeInPowerShell(String command) async {
    Process? process;
    try {
      process = await Process.start('powershell', ['-Command', command]);

      final stdoutBuffer = StringBuffer();
      final stderrBuffer = StringBuffer();
      int totalBytes = 0;
      bool killed = false;
      String? killReason;
      final recentLines = <String>[];

      final decoder = Utf8Decoder(allowMalformed: true);

      process.stdout.transform(decoder).listen((data) {
        if (killed) return;
        final sanitized = OutputSanitizer.sanitize(data);
        totalBytes += sanitized.length;
        final lines = sanitized.split('\n');
        for (final line in lines) {
          if (line.trim().isNotEmpty) {
            recentLines.add(line);
            if (recentLines.length > _repetitionThreshold + 10) {
              recentLines.removeAt(0);
            }
          }
        }
        if (totalBytes > _maxOutputBytes) {
          killed = true;
          killReason = 'Output exceeded ${_maxOutputBytes ~/ 1024}KB limit';
          _killProcessTree(process!);
          return;
        }
        if (_isRepetitiveOutput(recentLines)) {
          killed = true;
          killReason = 'Repetitive output detected (${_repetitionThreshold}+ identical lines)';
          _killProcessTree(process!);
          return;
        }
        print('${_timestamp()} [STDOUT] $sanitized');
        stdoutBuffer.write(sanitized);
      });

      process.stderr.transform(decoder).listen((data) {
        if (killed) return;
        final sanitized = OutputSanitizer.sanitize(data);
        totalBytes += sanitized.length;
        if (totalBytes > _maxOutputBytes) {
          killed = true;
          killReason = 'Output exceeded ${_maxOutputBytes ~/ 1024}KB limit';
          _killProcessTree(process!);
          return;
        }
        print('${_timestamp()} [STDERR] $sanitized');
        stderrBuffer.write(sanitized);
      });

      final exitCode = await process.exitCode.timeout(_commandTimeout);
      if (killed) {
        return CommandResult(-1, stdoutBuffer.toString(),
            'KILLED: $killReason. The command was producing excessive or repetitive output and was terminated.');
      }
      return CommandResult(exitCode, stdoutBuffer.toString(), stderrBuffer.toString());
    } on TimeoutException {
      if (process != null) await _killProcessTree(process);
      return CommandResult(-1, "", "Command timed out.");
    } catch (e) {
      if (process != null) await _killProcessTree(process);
      return CommandResult(-1, "", "Error: $e");
    }
  }

  // Output sanitization moved to OutputSanitizer class

  static Future<CommandResult> _executeInShell(String command) async {
    Process? process;
    try {
      process = await Process.start('/bin/bash', ['-c', command],
          workingDirectory: Directory.systemTemp.path);

      final stdoutBuffer = StringBuffer();
      final stderrBuffer = StringBuffer();
      int totalBytes = 0;
      bool killed = false;
      String? killReason;
      final recentLines = <String>[];

      final decoder = Utf8Decoder(allowMalformed: true);

      process.stdout.transform(decoder).listen((data) {
        if (killed) return;
        final sanitized = OutputSanitizer.sanitize(data);
        totalBytes += sanitized.length;
        final lines = sanitized.split('\n');
        for (final line in lines) {
          if (line.trim().isNotEmpty) {
            recentLines.add(line);
            if (recentLines.length > _repetitionThreshold + 10) {
              recentLines.removeAt(0);
            }
          }
        }
        if (totalBytes > _maxOutputBytes) {
          killed = true;
          killReason = 'Output exceeded ${_maxOutputBytes ~/ 1024}KB limit';
          _killProcessTree(process!);
          return;
        }
        if (_isRepetitiveOutput(recentLines)) {
          killed = true;
          killReason = 'Repetitive output detected (${_repetitionThreshold}+ identical lines)';
          _killProcessTree(process!);
          return;
        }
        print('${_timestamp()} [STDOUT] $sanitized');
        stdoutBuffer.write(sanitized);
      });

      process.stderr.transform(decoder).listen((data) {
        if (killed) return;
        final sanitized = OutputSanitizer.sanitize(data);
        totalBytes += sanitized.length;
        if (totalBytes > _maxOutputBytes) {
          killed = true;
          killReason = 'Output exceeded ${_maxOutputBytes ~/ 1024}KB limit';
          _killProcessTree(process!);
          return;
        }
        print('${_timestamp()} [STDERR] $sanitized');
        stderrBuffer.write(sanitized);
      });

      final exitCode = await process.exitCode.timeout(_commandTimeout);
      if (killed) {
        return CommandResult(-1, stdoutBuffer.toString(),
            'KILLED: $killReason. The command was producing excessive or repetitive output and was terminated.');
      }
      return CommandResult(exitCode, stdoutBuffer.toString(), stderrBuffer.toString());
    } on TimeoutException {
      if (process != null) await _killProcessTree(process);
      return CommandResult(-1, "", "Command timed out.");
    } catch (e) {
      if (process != null) await _killProcessTree(process);
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

// Data classes ToolUsageInfo, ToolOption, ToolExample moved to tool_manager.dart
// and re-exported via this file's export statement.
