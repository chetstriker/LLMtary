/// Command normalization, similarity detection, validation, and fixing utilities.
///
/// Extracted from exploit_executor.dart to keep the orchestration loop clean.
class CommandUtils {
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
    }

    return false;
  }

  /// Validate a command before execution.
  ///
  /// Returns an error message string if the command is invalid, or null if OK.
  static String? validateCommand(String command) {
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

  /// Fix/improve commands before execution (add timeouts, fix paths, etc).
  static String fixCommand(String command) {
    var fixed = command;

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
  static String compactHistory(String history, {int maxChars = 6000}) {
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
