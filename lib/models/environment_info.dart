/// Pre-discovered environment information cached once per app session.
/// Injected into all LLM prompts so the model never wastes iterations
/// guessing tool paths, package managers, or wordlist locations.
class EnvironmentInfo {
  final String packageManager;
  final List<String> availableWordlists;
  final Map<String, String> availableTools;
  final String? netcatBinary;
  final bool hasRoot;
  final String osInfo;

  const EnvironmentInfo({
    required this.packageManager,
    required this.availableWordlists,
    required this.availableTools,
    this.netcatBinary,
    required this.hasRoot,
    required this.osInfo,
  });

  /// Format as a prompt block for injection into LLM prompts.
  String toPromptBlock() {
    final buf = StringBuffer();
    buf.writeln('## ENVIRONMENT (pre-discovered — do NOT re-discover these):');
    buf.writeln('- Package manager: $packageManager');
    if (netcatBinary != null) {
      buf.writeln('- Netcat binary: $netcatBinary (use this instead of \'nc\')');
    } else {
      buf.writeln('- Netcat: NOT available — do not use nc/ncat/netcat');
    }
    buf.writeln('- Sudo/root: ${hasRoot ? 'available' : 'NOT available — do not use sudo or commands requiring root'}');
    if (!hasRoot) {
      buf.writeln('- UDP scans: NOT possible (requires root) — skip all UDP scanning');
    }

    if (availableWordlists.isNotEmpty) {
      buf.writeln('- Available wordlists:');
      for (final wl in availableWordlists) {
        buf.writeln('    $wl');
      }
    } else {
      buf.writeln('- Wordlists: NONE found — do NOT attempt to use wordlist-based tools (gobuster, ffuf, dirb, wfuzz). Skip directory enumeration rather than searching for wordlists.');
    }

    if (availableTools.isNotEmpty) {
      buf.writeln('- Confirmed available tools: ${availableTools.keys.join(', ')}');
    }

    final unavailable = <String>[];
    for (final tool in ['nmap', 'curl', 'dig', 'smbclient', 'gobuster', 'ffuf',
        'nikto', 'nuclei', 'searchsploit', 'whatweb', 'testssl.sh', 'sqlmap',
        'hydra', 'openssl', 'nc', 'ncat', 'dirb', 'dirsearch', 'cewl', 'enum4linux']) {
      if (!availableTools.containsKey(tool) && netcatBinary != tool) {
        unavailable.add(tool);
      }
    }
    if (unavailable.isNotEmpty) {
      buf.writeln('- Tools NOT installed (do NOT attempt to use): ${unavailable.join(', ')}');
    }

    return buf.toString();
  }
}
