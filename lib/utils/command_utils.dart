/// Command normalization, similarity detection, validation, and fixing utilities.
///
/// Extracted from exploit_executor.dart to keep the orchestration loop clean.
class CommandUtils {
  /// Classify a command into a high-level approach category.
  /// Used for semantic repetition detection (e.g. "tried 3 curl requests to same endpoint").
  static String classifyApproach(String command) {
    final cmd = command.toLowerCase();
    // Extract target endpoint if present
    final urlMatch = RegExp(r'https?://[^\s"]+').firstMatch(cmd);
    final url = urlMatch?.group(0) ?? '';
    final host = RegExp(r'https?://([^:/\s]+)').firstMatch(url)?.group(1) ?? '';
    final port = RegExp(r':([0-9]+)').firstMatch(url)?.group(1) ?? '';

    if (cmd.contains('hydra')) return 'hydra:$host:$port';
    if (cmd.contains('sqlmap')) return 'sqlmap:$host:$port';
    if (cmd.contains('searchsploit') && cmd.contains('-m')) return 'searchsploit-download';
    if (cmd.contains('searchsploit')) return 'searchsploit-search';
    if (cmd.contains('msfconsole') && cmd.contains('search')) return 'msf-search';
    if (cmd.contains('msfconsole')) return 'msf-exploit';
    if (cmd.contains('nmap') && cmd.contains('vulners')) return 'nmap-vulners:$port';
    if (cmd.contains('nmap') && cmd.contains('--script')) {
      final script = RegExp(r'--script[=\s]+([^\s]+)').firstMatch(cmd)?.group(1) ?? '';
      return 'nmap-script:$script:$port';
    }
    if (cmd.contains('nmap')) return 'nmap:$port';
    if (cmd.contains('curl') && url.isNotEmpty) {
      // Group curls to same host:port as one approach
      return 'curl:$host:$port';
    }
    if (cmd.contains('nikto')) return 'nikto:$host:$port';
    if (cmd.contains('dirb') || cmd.contains('gobuster') || cmd.contains('ffuf')) return 'dirbust:$host:$port';
    return 'other:${cmd.split(' ').first}';
  }

  /// Check if the LLM response contains degenerate repetition.
  /// Returns true if the response has excessive repeated phrases.
  static bool hasRepetitionLoop(String response, {int threshold = 5}) {
    if (response.length < 200) return false;
    // Check for repeated sentences (30+ char phrases appearing 5+ times)
    final sentences = response.split(RegExp(r'[.\n]')).where((s) => s.trim().length > 30).toList();
    final counts = <String, int>{};
    for (final s in sentences) {
      final key = s.trim().toLowerCase();
      counts[key] = (counts[key] ?? 0) + 1;
      if (counts[key]! >= threshold) return true;
    }
    return false;
  }

  /// Check if a Hydra command targets an HTTP form (likely needs verification).
  static bool isHydraHttpForm(String command) {
    final cmd = command.toLowerCase();
    return cmd.contains('hydra') && (cmd.contains('http-post-form') || cmd.contains('http-get-form'));
  }
  /// Normalize a command string for duplicate detection.
  ///
  /// Lowercases, collapses whitespace, strips curl flags, and masks timestamps.
  static String normalizeCommand(String cmd) {
    return cmd
        .trim()
        .toLowerCase()
        .replaceAll(RegExp(r'\s+'), ' ')
        .replaceAll(RegExp(r'curl\s+(-[a-zA-Z]+\s+)*'), 'curl ')
        .replaceAll(RegExp(r'\d{4}-\d{2}-\d{2}'), 'DATE')
        .replaceAll(RegExp(r'\d{2}:\d{2}:\d{2}'), 'TIME');
  }

  /// Check if a command is functionally similar to already executed commands.
  ///
  /// Catches exact duplicates and same-tool-same-endpoint patterns.
  static bool isSimilarCommand(String newCmd, Set<String> executed) {
    final normalized = normalizeCommand(newCmd);

    // Check for exact normalized match
    if (executed.any((c) => normalizeCommand(c) == normalized)) {
      return true;
    }

    final newCmdLower = newCmd.toLowerCase();
    for (final exec in executed) {
      final execLower = exec.toLowerCase();

      // Same curl to same path
      if (newCmdLower.contains('curl') && execLower.contains('curl')) {
        final newPath =
            RegExp(r'https?://[^\s]+').firstMatch(newCmdLower)?.group(0);
        final execPath =
            RegExp(r'https?://[^\s]+').firstMatch(execLower)?.group(0);
        if (newPath != null && execPath != null && newPath == execPath) {
          return true;
        }
      }

      // Same nmap scan (same port + same script)
      if (newCmdLower.contains('nmap') && execLower.contains('nmap')) {
        final newPort =
            RegExp(r'-p\s*(\d+)').firstMatch(newCmdLower)?.group(1);
        final execPort =
            RegExp(r'-p\s*(\d+)').firstMatch(execLower)?.group(1);
        final newScript =
            RegExp(r'--script[=\s]+([^\s]+)').firstMatch(newCmdLower)?.group(1);
        final execScript =
            RegExp(r'--script[=\s]+([^\s]+)').firstMatch(execLower)?.group(1);

        if (newPort == execPort && newScript == execScript) {
          return true;
        }
      }

      // Same hydra target (same host:port, even with different failure strings)
      if (newCmdLower.contains('hydra') && execLower.contains('hydra')) {
        // If both target same IP and same port, it's similar
        final newTarget = RegExp(r'(\d+\.\d+\.\d+\.\d+)').firstMatch(newCmdLower)?.group(1);
        final execTarget = RegExp(r'(\d+\.\d+\.\d+\.\d+)').firstMatch(execLower)?.group(1);
        final newPort = RegExp(r'-s\s*(\d+)').firstMatch(newCmdLower)?.group(1);
        final execPort = RegExp(r'-s\s*(\d+)').firstMatch(execLower)?.group(1);
        if (newTarget == execTarget && newPort == execPort) {
          return true;
        }
      }
    }

    return false;
  }

  /// Validate a command before execution.
  ///
  /// Returns an error message string if the command is invalid, or null if OK.
  static String? validateCommand(String command) {
    // Reject heredoc syntax — it never works inside wsl bash -c "..."
    // The LLM should use printf/tee or write files with echo -e instead.
    if (command.contains("<< 'EOF'") || command.contains('<< "EOF"') || RegExp(r'<<\s*[A-Z_]+\b').hasMatch(command)) {
      return 'ERROR: Heredoc syntax (<< EOF) does NOT work inside wsl bash -c. '
          'To write a multi-line file use: '
          r"printf 'line1\nline2\n' > temp/file.py && python3 temp/file.py  OR  "
          r"echo -e 'line1\nline2' | tee temp/file.py && python3 temp/file.py";
    }

    // Reject excessively long commands (likely contain inline hex/binary payloads)
    if (command.length > 2000) {
      return 'ERROR: Command is too long (${command.length} chars, max 2000). Do NOT embed hex/binary payloads inline. '
          "Instead: 1) Write the exploit script to a file first (e.g., cat > temp/exploit.py << 'PYEOF' ... PYEOF), "
          '2) Then execute the file (python3 temp/exploit.py).';
    }

    // Check for .rb files being run directly with any interpreter
    if (command.contains('.rb') && !command.contains('msfconsole')) {
      if (RegExp(r'\b(ruby|python[23]?|bash|perl|sh)\s+\S*\.rb\b')
          .hasMatch(command)) {
        return 'ERROR: .rb files are Metasploit modules. They cannot be run directly with any interpreter. Use msfconsole: msfconsole -q -x "use exploit/path/to/module; ..."';
      }
      if (command.contains('metasploit-framework') &&
          command.contains('.rb') &&
          (command.contains('python') || command.contains('ruby'))) {
        return 'ERROR: Metasploit modules (.rb) from GitHub cannot be run directly. They must be loaded inside msfconsole with "use exploit/path".';
      }
    }

    // Check for msfconsole search without proper keyword:value format
    if (command.contains('msfconsole') && command.contains('search')) {
      final searchMatch =
          RegExp(r'search\s*;|search\s+[^:]+;').firstMatch(command);
      if (searchMatch != null && !command.contains('search ') ||
          (command.contains('search ') &&
              !RegExp(r'search\s+\w+:').hasMatch(command))) {
        if (!command.contains(':') ||
            !RegExp(r'search\s+\w+:').hasMatch(command)) {
          return 'ERROR: Metasploit search requires keyword:value format. Use: search cve:XXXX or search name:product or search type:exploit name:xxx';
        }
      }
    }

    return null; // Command is OK
  }

  /// Check if an approach category has been tried too many times.
  /// Returns true if the same approach type has been used >= maxAttempts times.
  /// curl to the same host:port is capped at 2 to prevent login-loop exhaustion.
  static bool isApproachExhausted(String command, Map<String, int> approachCounts, {int maxAttempts = 3}) {
    final approach = classifyApproach(command);
    final limit = approach.startsWith('curl:') ? 2 : maxAttempts;
    return (approachCounts[approach] ?? 0) >= limit;
  }

  /// Record an approach and return the updated count.
  static int recordApproach(String command, Map<String, int> approachCounts) {
    final approach = classifyApproach(command);
    approachCounts[approach] = (approachCounts[approach] ?? 0) + 1;
    return approachCounts[approach]!;
  }

  /// Fix/improve commands before execution (add timeouts, fix paths, etc).
  static String fixCommand(String command) {
    var fixed = command;

    // Remove any shell timeout wrapper from nmap — nmap -p- needs 5-10 minutes.
    // The WSL executor already has a 5-minute process timeout.
    fixed = fixed.replaceAllMapped(
      RegExp(r'^timeout\s+\d+\s+(nmap\b)', caseSensitive: false),
      (m) => m.group(1)!,
    );

    // Add timeout to curl commands
    if (fixed.contains('curl ') &&
        !fixed.contains('--connect-timeout') &&
        !fixed.contains('-m ')) {
      fixed = fixed.replaceFirst('curl ', 'curl --connect-timeout 15 ');
    }

    // Add timeout to wget commands
    if (fixed.contains('wget ') &&
        !fixed.contains('--timeout') &&
        !fixed.contains('-T ')) {
      fixed = fixed.replaceFirst('wget ', 'wget --timeout=15 ');
    }

    // Ensure searchsploit -m outputs to temp directory
    if (fixed.contains('searchsploit -m') &&
        !fixed.contains('cd temp') &&
        !fixed.contains('cd ./temp')) {
      final edbMatch =
          RegExp(r'searchsploit\s+-m\s+(\d+)').firstMatch(fixed);
      if (edbMatch != null) {
        final edbId = edbMatch.group(1);
        fixed = 'cd temp && rm -f $edbId.* 2>/dev/null; $fixed';
      } else {
        fixed = 'cd temp && $fixed';
      }
    }

    // Fix nmap --script=CVE-XXXX patterns (nmap scripts are never named by CVE)
    final nmapCveScript = RegExp(r'--script[=\s]+CVE-\d{4}-\d+');
    if (nmapCveScript.hasMatch(fixed)) {
      fixed = fixed.replaceAll(nmapCveScript, '--script=vulners');
    }

    // Fix Hydra http-post-form:
    // 1. Ensure the port is passed via -s PORT (Hydra defaults to port 80 for http-post-form)
    // 2. Replace double-quoted form spec with single-quoted to avoid bash parsing issues
    if (fixed.contains('hydra') && fixed.contains('http-post-form')) {
      // Extract port from the form path if present (e.g. http://host:8080/login)
      // or from a -s flag already in the command
      final hasPortFlag = RegExp(r'\s-s\s+\d+').hasMatch(fixed);
      if (!hasPortFlag) {
        // Extract port from a URL in the form spec (e.g. http://host:8080/login)
        final portInForm = RegExp(r'http[s]?://[^:]+:(\d+)').firstMatch(fixed)?.group(1);
        final port = portInForm;
        if (port != null && port != '80' && port != '443') {
          // Insert -s PORT before the target IP
          fixed = fixed.replaceAllMapped(
            RegExp(r'(hydra\s+(?:-[a-zA-Z]\s+\S+\s+)*)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'),
            (m) => '${m.group(1)}-s $port ${m.group(2)}',
          );
        }
      }
      // Replace http-post-form "..." with http-post-form '...' to avoid bash quote issues
      fixed = fixed.replaceAllMapped(
        RegExp(r'''http-post-form\s+"([^"]+)"'''),
        (m) => "http-post-form '${m.group(1)}'",
      );
    }

    return fixed;
  }

  /// Truncate long output for history to prevent context overflow.
  static String truncateOutput(String output, int maxLength) {
    if (output.length <= maxLength) return output;
    final keep = maxLength ~/ 2;
    return '${output.substring(0, keep)}\n...[truncated ${output.length - maxLength} chars]...\n${output.substring(output.length - keep)}';
  }

  /// Compact history to prevent context size overflow.
  ///
  /// Keeps the header (initial analysis) and the most recent iterations.
  static String compactHistory(String history, {int maxChars = 10000}) {
    if (history.length <= maxChars) return history;

    final iterPattern = RegExp(r'Iteration \d+:');
    final firstIter = iterPattern.firstMatch(history);

    if (firstIter == null) {
      return history.substring(history.length - maxChars);
    }

    // Keep the header capped at 1500 chars
    final headerEnd = firstIter.start;
    final header = history.substring(0, headerEnd.clamp(0, 1500));

    final remaining = maxChars - header.length - 100;
    if (remaining <= 0) return header;

    final iterations = history.substring(headerEnd);
    if (iterations.length <= remaining) {
      return '$header$iterations';
    }

    return '$header\n[...earlier iterations omitted for context limits...]\n\n${iterations.substring(iterations.length - remaining)}';
  }
}
