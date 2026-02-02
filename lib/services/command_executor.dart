import 'dart:io';
import 'dart:async';
import 'dart:convert';
import '../models/llm_settings.dart';
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
      final os = await getOsInfo();
      print('${_timestamp()} DEBUG: Detected OS: $os');
      
      final prompt = '''What command should I run to check if "$tool" is installed on $os?

Respond with JSON:
{
  "command": "the exact command to check if tool exists",
  "explanation": "brief explanation"
}

Examples:
- For metasploit on Linux: {"command": "which msfconsole", "explanation": "msfconsole is the main binary"}
- For nmap on Linux: {"command": "which nmap", "explanation": "nmap is the binary name"}

Respond ONLY with valid JSON.''';
      
      final response = await llmService.sendMessage(settings, prompt).timeout(Duration(seconds: 30));
      final decision = _parseJson(response);
      final checkCmd = decision['command'] ?? 'which $tool';
      
      print('${_timestamp()} DEBUG: LLM suggested check command: $checkCmd');
      
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
      // Check if already installed
      if (await checkToolExists(tool, settings, llmService)) {
        print('${_timestamp()} DEBUG: Tool $tool already installed');
        return true;
      }
      
      final os = await getOsInfo();
      print('${_timestamp()} DEBUG: Installing on OS: $os');
      
      final prompt = '''What command should I run to install "$tool" on $os?

Respond with JSON:
{
  "command": "the exact command to install the tool",
  "package": "the package name"
}

Examples:
- For metasploit on Kali Linux: {"command": "sudo apt-get update && sudo apt-get install -y metasploit-framework", "package": "metasploit-framework"}
- For nmap on Ubuntu: {"command": "sudo apt-get install -y nmap", "package": "nmap"}

Respond ONLY with valid JSON.''';
      
      final response = await llmService.sendMessage(settings, prompt).timeout(Duration(seconds: 30));
      final decision = _parseJson(response);
      final installCmd = decision['command'];
      
      if (installCmd == null || installCmd.isEmpty) {
        print('${_timestamp()} DEBUG: LLM did not provide install command');
        return false;
      }
      
      print('${_timestamp()} DEBUG: LLM suggested install command: $installCmd');
      
      if (Platform.isWindows && await isWslAvailable()) {
        print('${_timestamp()} DEBUG: Running install command in WSL');
        final process = await Process.start('wsl', ['bash', '-c', installCmd]);
        
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
        
        final exitCode = await process.exitCode.timeout(const Duration(minutes: 5));
        print('${_timestamp()} DEBUG: Install exit code: $exitCode');
        return exitCode == 0;
      } else if (Platform.isLinux || Platform.isMacOS) {
        print('${_timestamp()} DEBUG: Running install command');
        final process = await Process.start('bash', ['-c', installCmd]);
        
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
        
        final exitCode = await process.exitCode.timeout(const Duration(minutes: 5));
        print('${_timestamp()} DEBUG: Install exit code: $exitCode');
        return exitCode == 0;
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

  static Future<Map<String, dynamic>> executeCommand(String command, bool requireApproval) async {
    for (final dangerous in _dangerousCommands) {
      if (command.toLowerCase().contains(dangerous.toLowerCase())) {
        return {
          'exitCode': -1,
          'output': 'BLOCKED: Dangerous command detected',
          'error': 'Command contains dangerous pattern: $dangerous',
        };
      }
    }

    try {
      CommandResult result;
      
      if (Platform.isWindows && await isWslAvailable()) {
        result = await _executeInWsl(command);
      } else if (Platform.isLinux || Platform.isMacOS) {
        result = await _executeInShell(command);
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
      
      process.stdout.transform(utf8.decoder).listen((data) {
        print('[STDOUT] $data');
        stdoutBuffer.write(data);
      });
      
      process.stderr.transform(utf8.decoder).listen((data) {
        print('[STDERR] $data');
        stderrBuffer.write(data);
      });
      
      final exitCode = await process.exitCode;
      return CommandResult(exitCode, stdoutBuffer.toString(), stderrBuffer.toString());
    } on TimeoutException {
      return CommandResult(-1, "", "Command timed out.");
    } catch (e) {
      return CommandResult(-1, "", "Error: $e");
    }
  }

  static Future<CommandResult> _executeInShell(String command) async {
    try {
      final process = await Process.start('/bin/bash', ['-c', command])
          .timeout(const Duration(minutes: 5));
      
      final stdoutBuffer = StringBuffer();
      final stderrBuffer = StringBuffer();
      
      process.stdout.transform(utf8.decoder).listen((data) {
        print('[STDOUT] $data');
        stdoutBuffer.write(data);
      });
      
      process.stderr.transform(utf8.decoder).listen((data) {
        print('[STDERR] $data');
        stderrBuffer.write(data);
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
