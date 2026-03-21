import 'dart:io';
import '../models/environment_info.dart';
import 'command_executor.dart';

/// Discovers the local execution environment once per app session.
/// All checks are deterministic shell commands — no LLM calls.
class EnvironmentDiscovery {
  static EnvironmentInfo? _cached;

  /// Returns the cached environment info, or discovers it on first call.
  static Future<EnvironmentInfo> discover() async {
    if (_cached != null) return _cached!;
    _cached = await _run();
    return _cached!;
  }

  /// Force re-discovery (e.g. after tool installation).
  static void invalidateCache() => _cached = null;

  static Future<EnvironmentInfo> _run() async {
    final osInfo = await CommandExecutor.getOsInfo();
    final isWindows = Platform.isWindows;
    final isWsl = isWindows && await CommandExecutor.isWslAvailable();
    final isNativeWindows = isWindows && !isWsl;

    // 1. Package manager
    final packageManager = await CommandExecutor.detectPackageManager();

    // 2. Wordlist discovery
    final wordlists = isNativeWindows ? <String>[] : await _discoverWordlists();

    // 3. Netcat variant
    final netcatBinary = isNativeWindows ? null : await _discoverNetcat(isWsl);

    // 4. Root/sudo check
    final hasRoot = isNativeWindows ? false : await _checkRoot(isWsl);

    // 5. Tool availability
    final tools = isNativeWindows
        ? <String, String>{}
        : await _discoverTools(isWsl);

    final env = EnvironmentInfo(
      packageManager: packageManager,
      availableWordlists: wordlists,
      availableTools: tools,
      netcatBinary: netcatBinary,
      hasRoot: hasRoot,
      osInfo: osInfo,
    );

    print('DEBUG: [EnvironmentDiscovery] Package manager: $packageManager');
    print('DEBUG: [EnvironmentDiscovery] Wordlists found: ${wordlists.length}');
    print('DEBUG: [EnvironmentDiscovery] Netcat binary: $netcatBinary');
    print('DEBUG: [EnvironmentDiscovery] Has root: $hasRoot');
    print('DEBUG: [EnvironmentDiscovery] Available tools: ${tools.keys.join(', ')}');

    return env;
  }

  static Future<List<String>> _discoverWordlists() async {
    try {
      final cmd = r"find /usr/share -maxdepth 4 \( -path '*/wordlist*' -o -path '*/seclists*' -o -path '*/dirb*' -o -path '*/dirbuster*' -o -path '*/wfuzz*' \) -name '*.txt' -type f 2>/dev/null | head -100";
      final result = await _shell(cmd);
      final lines = result
          .split('\n')
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty && l.startsWith('/'))
          .toList();

      // Also check macOS homebrew path
      if (Platform.isMacOS) {
        final brewCmd = r"find /opt/homebrew/share -maxdepth 4 \( -path '*/wordlist*' -o -path '*/seclists*' \) -name '*.txt' -type f 2>/dev/null | head -50";
        final brewResult = await _shell(brewCmd);
        lines.addAll(brewResult
            .split('\n')
            .map((l) => l.trim())
            .where((l) => l.isNotEmpty && l.startsWith('/')));
      }

      return lines;
    } catch (_) {
      return [];
    }
  }

  static Future<String?> _discoverNetcat(bool isWsl) async {
    for (final binary in ['ncat', 'nc', 'netcat']) {
      try {
        final result = await _shell('which $binary 2>/dev/null');
        if (result.trim().isNotEmpty) {
          // If ncat, note it supports --ssl
          if (binary == 'ncat') return 'ncat (nmap variant, supports --ssl)';
          return binary;
        }
      } catch (_) {}
    }
    return null;
  }

  static Future<bool> _checkRoot(bool isWsl) async {
    try {
      // Check if running as root
      final idResult = await _shell('id -u 2>/dev/null');
      if (idResult.trim() == '0') return true;

      // Check if sudo is cached (no password needed)
      final sudoResult = await _shell('sudo -n true 2>/dev/null; echo \$?');
      return sudoResult.trim() == '0';
    } catch (_) {
      return false;
    }
  }

  static Future<Map<String, String>> _discoverTools(bool isWsl) async {
    const tools = [
      'nmap', 'curl', 'dig', 'smbclient', 'gobuster', 'ffuf', 'nikto',
      'nuclei', 'searchsploit', 'whatweb', 'testssl.sh', 'sqlmap', 'hydra',
      'openssl', 'wpscan', 'feroxbuster', 'masscan', 'crackmapexec',
      'netexec', 'responder', 'john', 'hashcat', 'enum4linux', 'dirb',
      'wfuzz', 'snmpwalk', 'onesixtyone', 'nbtscan', 'dnsrecon',
      'wafw00f', 'commix', 'smbmap', 'tcpdump', 'tshark',
    ];

    final result = <String, String>{};
    try {
      // Batch check all tools in one shell command for speed
      final checkCmd = tools.map((t) => 'which $t 2>/dev/null && echo "FOUND:$t"').join('; ');
      final output = await _shell(checkCmd);
      for (final line in output.split('\n')) {
        if (line.startsWith('FOUND:')) {
          final tool = line.substring(6).trim();
          if (tool.isNotEmpty) {
            // Find the path from the preceding line
            result[tool] = tool;
          }
        } else if (line.trim().startsWith('/') && line.trim().isNotEmpty) {
          // This is a path line from 'which' — the next FOUND: line will tell us the tool name
          // We'll just store the path when we see FOUND
          final toolName = line.trim().split('/').last;
          if (toolName.isNotEmpty) {
            result[toolName] = line.trim();
          }
        }
      }
    } catch (_) {}
    return result;
  }

  /// Run a shell command and return stdout.
  static Future<String> _shell(String cmd) async {
    try {
      final isWsl = Platform.isWindows && await CommandExecutor.isWslAvailable();
      ProcessResult result;
      if (isWsl) {
        result = await Process.run('wsl', ['bash', '-c', cmd])
            .timeout(const Duration(seconds: 15));
      } else {
        result = await Process.run('bash', ['-c', cmd])
            .timeout(const Duration(seconds: 15));
      }
      return (result.stdout as String? ?? '').trim();
    } catch (_) {
      return '';
    }
  }
}
