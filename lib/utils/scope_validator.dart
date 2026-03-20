enum ScopeResult {
  /// Target is explicitly in scope.
  inScope,
  /// Target is not in any scope entry (scope is defined but target not listed).
  outOfScope,
  /// Target is in scope but also in the exclusions list — exclusions win.
  excluded,
  /// No scope has been defined — all targets are implicitly allowed.
  noScopeDefined,
}

class ScopeValidator {
  /// Check [target] against the project scope/exclusion lists.
  ///
  /// [scopeList] — entries from [Project.scopeList] (CIDRs, IPs, FQDNs, wildcards, "*")
  /// [exclusionList] — entries from [Project.exclusionList]
  static ScopeResult validate(
    String target,
    List<String> scopeList,
    List<String> exclusionList,
  ) {
    final t = target.trim().toLowerCase();
    if (t.isEmpty) return ScopeResult.noScopeDefined;

    // If no scope defined, everything is implicitly allowed
    if (scopeList.isEmpty) return ScopeResult.noScopeDefined;

    // Check exclusions first — exclusions always win over scope
    if (exclusionList.isNotEmpty && _matchesAny(t, exclusionList)) {
      return ScopeResult.excluded;
    }

    // Wildcard "*" means all targets are in scope
    if (scopeList.contains('*')) return ScopeResult.inScope;

    return _matchesAny(t, scopeList) ? ScopeResult.inScope : ScopeResult.outOfScope;
  }

  static bool _matchesAny(String target, List<String> entries) {
    for (final entry in entries) {
      if (_matches(target, entry.trim().toLowerCase())) return true;
    }
    return false;
  }

  static bool _matches(String target, String entry) {
    if (entry.isEmpty) return false;

    // Exact match
    if (target == entry) return true;

    // CIDR notation (IPv4 only)
    if (entry.contains('/')) {
      return _matchesCidr(target, entry);
    }

    // Wildcard domain: *.example.com matches sub.example.com
    if (entry.startsWith('*.')) {
      final suffix = entry.substring(1); // .example.com
      return target.endsWith(suffix) || target == suffix.substring(1);
    }

    // Plain domain: example.com also matches www.example.com subdomains
    // (intentionally NOT doing this — require explicit wildcard for subdomain matching)

    return false;
  }

  /// Returns true if [ip] falls within the [cidr] range (IPv4 only).
  static bool _matchesCidr(String ip, String cidr) {
    try {
      final parts = cidr.split('/');
      if (parts.length != 2) return false;
      final networkIp = parts[0];
      final prefixLen = int.parse(parts[1]);
      if (prefixLen < 0 || prefixLen > 32) return false;

      final networkInt = _ipToInt(networkIp);
      final targetInt = _ipToInt(ip);
      if (networkInt == null || targetInt == null) return false;

      final mask = prefixLen == 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) & 0xFFFFFFFF;
      return (networkInt & mask) == (targetInt & mask);
    } catch (_) {
      return false;
    }
  }

  static int? _ipToInt(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return null;
    var result = 0;
    for (final part in parts) {
      final byte = int.tryParse(part);
      if (byte == null || byte < 0 || byte > 255) return null;
      result = (result << 8) | byte;
    }
    return result;
  }

  /// Human-readable description of a [ScopeResult] for UI display.
  static String describeResult(ScopeResult result, String target) {
    switch (result) {
      case ScopeResult.inScope:
        return '$target is within the defined engagement scope.';
      case ScopeResult.outOfScope:
        return '$target is NOT in scope for this engagement. Testing blocked.';
      case ScopeResult.excluded:
        return '$target is explicitly excluded from scope. Testing blocked.';
      case ScopeResult.noScopeDefined:
        return 'No scope defined — proceeding (consider defining scope in project settings).';
    }
  }
}
