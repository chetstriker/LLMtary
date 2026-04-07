// Device classification engine for LLMtary.
//
// Classifies a target device based on open ports and service banners extracted
// from recon JSON, then returns a targeted analysis prompt set and an
// execution-loop context block appropriate for that device type.

// ---------------------------------------------------------------------------
// DeviceType enum
// ---------------------------------------------------------------------------

enum DeviceType {
  router,
  printer,
  windowsWorkstation,
  windowsServer,
  linuxServer,
  mediaDevice,
  apiServer,
  databaseServer,
  networkAppliance,
  iotDevice,
  unknown,
}

// ---------------------------------------------------------------------------
// DeviceClassifier
// ---------------------------------------------------------------------------

class DeviceClassifier {
  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /// Classifies [deviceJson] into the best-matching [DeviceType].
  ///
  /// Each candidate type receives a numeric score based on port presence and
  /// banner/OS string matches. The type with the highest score wins. Ties are
  /// broken by the priority order defined in [DeviceType] (lower index wins).
  static DeviceType classify(Map<String, dynamic> deviceJson) {
    final ports = _extractPorts(deviceJson);
    final allText = _allTextValues(deviceJson);

    final scores = <DeviceType, int>{
      for (final t in DeviceType.values) t: 0,
    };

    // --- Router ---
    {
      int s = 0;
      if (ports.contains(80) && ports.contains(443)) s += 3;
      if (ports.contains(53)) s += 2;
      if (ports.contains(49152)) s += 2; // UPnP
      final ip = _extractIpAddress(deviceJson);
      if (ip != null && (ip.endsWith('.1') || ip.endsWith('.254'))) s += 3;
      if (_containsAny(allText,
          ['router', 'gateway', 'linksys', 'asus', 'netgear', 'cisco',
           'ubiquiti', 'mikrotik', 'openwrt'])) { s += 4; }
      scores[DeviceType.router] = s;
    }

    // --- Printer ---
    {
      int s = 0;
      if (ports.contains(515)) s += 4; // LPR
      if (ports.contains(631)) s += 4; // IPP
      if (ports.contains(9100)) s += 4; // JetDirect
      if (_containsAny(allText,
          ['brother', 'hp', 'canon', 'zebra', 'lexmark', 'debut httpd',
           'ipp', 'jetdirect', 'printer'])) { s += 4; }
      scores[DeviceType.printer] = s;
    }

    // --- Windows Workstation / Windows Server ---
    {
      int base = 0;
      if (ports.contains(445)) base += 4;
      final smbFindings = deviceJson['smb_findings'];
      if (smbFindings is List && smbFindings.isNotEmpty) base += 3;
      if (_containsAny(allText, ['windows'])) base += 3;
      final os = _extractOs(deviceJson);
      if (_containsAny(os, ['windows'])) base += 2;

      final isServer = ports.contains(3389) ||
          _containsAny(allText, ['windows server', 'server 2016',
              'server 2019', 'server 2022', 'server 2012', 'server 2008']);
      if (isServer) {
        scores[DeviceType.windowsServer] = base + 2;
        scores[DeviceType.windowsWorkstation] = base;
      } else {
        scores[DeviceType.windowsWorkstation] = base + 1;
        scores[DeviceType.windowsServer] = base;
      }
    }

    // --- Linux Server ---
    {
      int s = 0;
      if (ports.contains(22)) s += 3;
      if (!ports.contains(445)) s += 1;
      if (!_containsAny(allText, ['windows'])) s += 1;
      final ttlStr = _findValue(deviceJson, 'ttl');
      if (ttlStr != null && ttlStr.contains('64')) s += 2;
      final os = _extractOs(deviceJson);
      if (_containsAny(os, ['linux', 'ubuntu', 'debian', 'centos',
          'fedora', 'rhel', 'alpine'])) { s += 3; }
      scores[DeviceType.linuxServer] = s;
    }

    // --- Media Device ---
    {
      int s = 0;
      if (ports.contains(8008)) s += 3;
      if (ports.contains(8009)) s += 2;
      if (ports.contains(10001)) s += 2;
      if (_containsAny(allText,
          ['google', 'chromecast', 'roku', 'apple tv', 'plex', 'cast'])) {
        s += 4;
      }
      scores[DeviceType.mediaDevice] = s;
    }

    // --- API Server ---
    {
      int s = 0;
      final apiPorts = {3000, 8000, 8080, 8888};
      final openApiPorts = ports.intersection(apiPorts);
      if (openApiPorts.isNotEmpty) { s += 2 * openApiPorts.length; }
      if (_containsAny(allText,
          ['swagger', 'openapi', 'uvicorn', 'fastapi', 'express', 'flask',
           'api'])) { s += 4; }
      scores[DeviceType.apiServer] = s;
    }

    // --- Database Server ---
    {
      int s = 0;
      final dbPorts = {3306, 5432, 27017, 6379, 1433, 1521};
      final openDbPorts = ports.intersection(dbPorts);
      s += 5 * openDbPorts.length;
      scores[DeviceType.databaseServer] = s;
    }

    // --- Network Appliance ---
    {
      int s = 0;
      if (ports.contains(161)) s += 4; // SNMP
      if (_containsAny(allText,
          ['cisco', 'juniper', 'fortinet', 'palo alto', 'aruba',
           'extreme networks'])) { s += 4; }
      scores[DeviceType.networkAppliance] = s;
    }

    // --- IoT Device ---
    {
      int s = 0;
      if (ports.contains(23)) s += 3; // Telnet
      if (!ports.contains(445)) s += 1;
      if (!ports.contains(22)) s += 1;
      if (_containsAny(allText,
          ['embedded', 'iot', 'arduino', 'esp8266', 'esp32'])) { s += 4; }
      scores[DeviceType.iotDevice] = s;
    }

    // unknown always stays 0 — picked only as a fallback.

    // Find the winner. DeviceType.values is ordered by priority so the first
    // type in enum declaration wins ties.
    DeviceType best = DeviceType.unknown;
    int bestScore = 0;
    for (final type in DeviceType.values) {
      if (type == DeviceType.unknown) continue;
      final score = scores[type]!;
      if (score > bestScore) {
        bestScore = score;
        best = type;
      }
    }
    return best;
  }

  // -------------------------------------------------------------------------

  /// Returns the ordered list of analysis prompt type names for [type].
  static List<String> getAnalysisPromptSet(DeviceType type) {
    switch (type) {
      case DeviceType.router:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'webApp',
          'sslTls',
          'snmpManagement',
          'privilegeEscalation',
        ];
      case DeviceType.printer:
        return [
          'cveVersionAnalysis',
          'defaultCredentials',
          'networkServices',
          'sslTls',
          'webApp',
        ];
      case DeviceType.windowsWorkstation:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'activeDirectory',
          'privilegeEscalation',
          'webApp',
          'sslTls',
        ];
      case DeviceType.windowsServer:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'activeDirectory',
          'privilegeEscalation',
          'webApp',
          'sslTls',
          'snmpManagement',
        ];
      case DeviceType.linuxServer:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'privilegeEscalation',
          'webApp',
          'sslTls',
        ];
      case DeviceType.mediaDevice:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'sslTls',
          'webApp',
        ];
      case DeviceType.apiServer:
        return [
          'cveVersionAnalysis',
          'webApp',
          'webAppApi',
          'webAppHeaders',
          'sslTls',
          'networkServices',
        ];
      case DeviceType.databaseServer:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'privilegeEscalation',
          'databaseSpecific',
        ];
      case DeviceType.networkAppliance:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'snmpManagement',
          'sslTls',
          'webApp',
        ];
      case DeviceType.iotDevice:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'defaultCredentials',
          'sslTls',
        ];
      case DeviceType.unknown:
        return [
          'cveVersionAnalysis',
          'networkServices',
          'webApp',
          'sslTls',
        ];
    }
  }

  // -------------------------------------------------------------------------

  /// Returns a human-readable context block for injection into execution loop
  /// prompts.  Format:
  ///
  /// ```
  /// ## Device Type: {TypeName}
  /// Focus areas: ...
  /// Likely useful tools: ...
  /// Avoid: ...
  /// ```
  static String getDeviceContext(
      DeviceType type, Map<String, dynamic> deviceJson) {
    final name = _typeName(type);
    final focus = _focusAreas(type);
    final tools = _likelyTools(type);
    final avoid = _avoidList(type);
    return '## Device Type: $name\n'
        'Focus areas: $focus\n'
        'Likely useful tools: $tools\n'
        'Avoid: $avoid';
  }

  // -------------------------------------------------------------------------

  /// Returns true if [deviceJson] contains Active Directory indicators.
  static bool hasActiveDirectoryIndicators(Map<String, dynamic> deviceJson) {
    final ports = _extractPorts(deviceJson);

    // Kerberos / LDAP / Global Catalog ports
    const adPorts = {88, 389, 636, 3268, 3269};
    if (ports.intersection(adPorts).isNotEmpty) return true;

    // SMB findings with non-WORKGROUP domain
    final smbFindings = deviceJson['smb_findings'];
    if (smbFindings is List) {
      for (final entry in smbFindings) {
        if (entry is Map) {
          final domain = (entry['domain'] ?? entry['workgroup'] ?? '')
              .toString()
              .trim()
              .toUpperCase();
          if (domain.isNotEmpty && domain != 'WORKGROUP') return true;
        }
      }
    }

    // Windows OS + non-empty smb_findings
    final os = _extractOs(deviceJson);
    if (_containsAny(os, ['windows']) &&
        smbFindings is List &&
        smbFindings.isNotEmpty) {
      return true;
    }

    // Hostname ends with domain suffix patterns
    final hostname = (deviceJson['device']?['hostname'] ??
            deviceJson['hostname'] ??
            '')
        .toString()
        .toLowerCase();
    const domainSuffixes = ['.local', '.corp', '.internal', '.ad', '.lan'];
    for (final suffix in domainSuffixes) {
      if (hostname.endsWith(suffix)) return true;
    }

    return false;
  }

  // -------------------------------------------------------------------------

  /// Returns true if any value in [deviceJson] (recursively) contains IPv6
  /// address evidence.
  static bool hasIPv6Evidence(Map<String, dynamic> deviceJson) {
    return _searchForIPv6(_jsonValue(deviceJson));
  }

  // -------------------------------------------------------------------------

  /// Returns true if SNMP port 161/162 is open, or any banner mentions "snmp".
  static bool hasSnmpEvidence(Map<String, dynamic> deviceJson) {
    final ports = _extractPorts(deviceJson);
    if (ports.contains(161) || ports.contains(162)) return true;
    final allText = _allTextValues(deviceJson);
    return _containsAny(allText, ['snmp']);
  }

  // -------------------------------------------------------------------------

  /// Returns true if port 8009 is open or any service/banner contains "ajp".
  static bool hasAjpEvidence(Map<String, dynamic> deviceJson) {
    final ports = _extractPorts(deviceJson);
    if (ports.contains(8009)) return true;
    final allText = _allTextValues(deviceJson);
    return _containsAny(allText, ['ajp']);
  }

  // -------------------------------------------------------------------------
  // Helper methods
  // -------------------------------------------------------------------------

  /// Extracts all open port numbers from the [deviceJson] open_ports array.
  static Set<int> _extractPorts(Map<String, dynamic> deviceJson) {
    final result = <int>{};
    final openPorts = deviceJson['open_ports'];
    if (openPorts is List) {
      for (final entry in openPorts) {
        if (entry is Map) {
          final portVal = entry['port'];
          if (portVal is int) {
            result.add(portVal);
          } else if (portVal is String) {
            final parsed = int.tryParse(portVal);
            if (parsed != null) result.add(parsed);
          }
        } else if (entry is int) {
          result.add(entry);
        }
      }
    }
    return result;
  }

  // -------------------------------------------------------------------------

  /// Returns true if [haystack] (lowercased) contains any of [needles]
  /// (each lowercased).
  static bool _containsAny(String haystack, List<String> needles) {
    final lower = haystack.toLowerCase();
    for (final needle in needles) {
      if (lower.contains(needle.toLowerCase())) return true;
    }
    return false;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /// Collects all string values in [deviceJson] into a single space-separated
  /// string for bulk substring matching.
  static String _allTextValues(Map<String, dynamic> deviceJson) {
    final buffer = StringBuffer();
    _collectStrings(_jsonValue(deviceJson), buffer);
    return buffer.toString();
  }

  static void _collectStrings(Object? node, StringBuffer buf) {
    if (node is String) {
      buf.write(' ');
      buf.write(node);
    } else if (node is Map) {
      for (final v in node.values) {
        _collectStrings(v, buf);
      }
    } else if (node is List) {
      for (final item in node) {
        _collectStrings(item, buf);
      }
    }
  }

  /// Wraps [deviceJson] as [Object?] for uniform recursive traversal.
  static Object? _jsonValue(Map<String, dynamic> deviceJson) => deviceJson;

  /// Recursively searches [node] for IPv6 address evidence.
  static bool _searchForIPv6(Object? node) {
    if (node is String) {
      final s = node.toLowerCase();
      return s.contains('::') ||
          s.startsWith('fe80:') ||
          s.startsWith('2001:') ||
          s.startsWith('2600:');
    } else if (node is Map) {
      for (final v in node.values) {
        if (_searchForIPv6(v)) return true;
      }
    } else if (node is List) {
      for (final item in node) {
        if (_searchForIPv6(item)) return true;
      }
    }
    return false;
  }

  /// Extracts the primary IP address from [deviceJson] if available.
  static String? _extractIpAddress(Map<String, dynamic> deviceJson) {
    final device = deviceJson['device'];
    if (device is Map) {
      final ip = device['ip'] ?? device['ip_address'] ?? device['address'];
      if (ip is String && ip.isNotEmpty) return ip;
    }
    final ip = deviceJson['ip'] ?? deviceJson['ip_address'] ?? deviceJson['address'];
    if (ip is String && ip.isNotEmpty) return ip;
    return null;
  }

  /// Extracts the OS string from [deviceJson].
  static String _extractOs(Map<String, dynamic> deviceJson) {
    final device = deviceJson['device'];
    if (device is Map) {
      final os = device['os'];
      if (os is String) return os;
    }
    final os = deviceJson['os'];
    if (os is String) return os;
    return '';
  }

  /// Searches [deviceJson] for a top-level or nested key matching [key] and
  /// returns its string representation, or null if not found.
  static String? _findValue(Map<String, dynamic> deviceJson, String key) {
    if (deviceJson.containsKey(key)) {
      return deviceJson[key]?.toString();
    }
    final device = deviceJson['device'];
    if (device is Map && device.containsKey(key)) {
      return device[key]?.toString();
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // Device context content helpers
  // -------------------------------------------------------------------------

  static String _typeName(DeviceType type) {
    switch (type) {
      case DeviceType.router:
        return 'Router';
      case DeviceType.printer:
        return 'Printer';
      case DeviceType.windowsWorkstation:
        return 'Windows Workstation';
      case DeviceType.windowsServer:
        return 'Windows Server';
      case DeviceType.linuxServer:
        return 'Linux Server';
      case DeviceType.mediaDevice:
        return 'Media Device';
      case DeviceType.apiServer:
        return 'API Server';
      case DeviceType.databaseServer:
        return 'Database Server';
      case DeviceType.networkAppliance:
        return 'Network Appliance';
      case DeviceType.iotDevice:
        return 'IoT Device';
      case DeviceType.unknown:
        return 'Unknown';
    }
  }

  static String _focusAreas(DeviceType type) {
    switch (type) {
      case DeviceType.router:
        return 'default admin credentials, exposed management interface, '
            'SNMP community string enumeration, UPnP exposure, '
            'DNS rebinding, firmware version CVEs, OSPF/BGP abuse.';
      case DeviceType.printer:
        return 'default web credentials, FTP anonymous access, '
            'Telnet cleartext, JetDirect PJL commands (port 9100), '
            'IPP vulnerabilities, SNMP community strings, firmware version CVEs.';
      case DeviceType.windowsWorkstation:
        return 'SMB relay and credential capture, '
            'local privilege escalation, weak service permissions, '
            'unpatched OS CVEs, cleartext credential exposure, '
            'Active Directory enumeration if domain-joined.';
      case DeviceType.windowsServer:
        return 'SMB relay, NTLM/Kerberos abuse, ADCS misconfigurations, '
            'BloodHound-style lateral movement paths, '
            'unpatched RCE CVEs, exposed RDP weak credentials, '
            'service account privilege escalation.';
      case DeviceType.linuxServer:
        return 'SSH weak credentials or key reuse, sudo misconfigurations, '
            'SUID/SGID binaries, cron job injection, '
            'world-writable sensitive files, unpatched kernel/service CVEs, '
            'exposed internal service APIs.';
      case DeviceType.mediaDevice:
        return 'unauthenticated REST/HTTP control API, '
            'Cast protocol command injection, '
            'exposed debug/developer endpoints, '
            'firmware version CVEs, cleartext traffic interception.';
      case DeviceType.apiServer:
        return 'authentication bypass, IDOR/BOLA, '
            'JWT algorithm confusion, mass assignment, '
            'exposed Swagger/OpenAPI documentation with sensitive endpoints, '
            'rate limiting absence, SSRF via URL parameters, '
            'sensitive data in error responses.';
      case DeviceType.databaseServer:
        return 'unauthenticated or default credential access, '
            'privilege escalation via UDF/stored procedures, '
            'data exfiltration via SQL or NoSQL injection, '
            'replication channel interception, '
            'exposed admin interface without authentication.';
      case DeviceType.networkAppliance:
        return 'SNMP community string enumeration, '
            'default admin credentials on web/SSH/Telnet, '
            'routing protocol injection (BGP/OSPF), '
            'firmware version CVEs, '
            'ACL bypass via crafted packets.';
      case DeviceType.iotDevice:
        return 'Telnet/SSH default credentials, '
            'hardcoded credentials in firmware, '
            'unauthenticated HTTP management interface, '
            'MQTT/CoAP protocol exposure, '
            'firmware extraction and analysis, embedded OS CVEs.';
      case DeviceType.unknown:
        return 'open service enumeration, default credentials, '
            'version CVE matching, SSL/TLS weaknesses.';
    }
  }

  static String _likelyTools(DeviceType type) {
    switch (type) {
      case DeviceType.router:
        return 'curl, hydra (web form), snmpwalk, snmpget, nmap (--script http-auth,snmp-info,upnp-info), '
            'routersploit.';
      case DeviceType.printer:
        return 'ftp, telnet, curl, ncat (port 9100 for PJL), ipp-tool, hydra (web form), snmpwalk.';
      case DeviceType.windowsWorkstation:
        return 'crackmapexec, impacket suite (secretsdump, psexec, wmiexec), '
            'enum4linux-ng, nmap (--script smb*), bloodhound-python.';
      case DeviceType.windowsServer:
        return 'crackmapexec, impacket suite, bloodhound-python, certipy, '
            'nmap (--script smb*,ldap*,krb5*), evil-winrm, hydra (rdp/smb).';
      case DeviceType.linuxServer:
        return 'ssh, nmap (--script ssh*,vuln), linpeas, sudo -l, find (SUID), '
            'hydra (ssh), curl.';
      case DeviceType.mediaDevice:
        return 'curl, nmap (--script http*), catt (Chromecast control), '
            'mitmproxy (cleartext traffic analysis).';
      case DeviceType.apiServer:
        return 'curl, ffuf, burpsuite, jwt-tool, sqlmap (parameter-targeted), '
            'nmap (--script http-methods,http-auth-finder), nuclei.';
      case DeviceType.databaseServer:
        return 'mysql (CLI), psql, mongosh, redis-cli, sqlmap, '
            'nmap (--script mysql-info,pgsql-brute,mongodb-info), hydra.';
      case DeviceType.networkAppliance:
        return 'snmpwalk, snmpget, onesixtyone, hydra (ssh/http/telnet), '
            'nmap (--script snmp*,cisco*,http-auth), curl.';
      case DeviceType.iotDevice:
        return 'telnet, ftp, curl, nmap (--script telnet-ntlm-info,mqtt-subscribe,coap-resources), '
            'hydra (telnet/http), binwalk (firmware).';
      case DeviceType.unknown:
        return 'nmap, curl, hydra, nikto, nuclei.';
    }
  }

  static String _avoidList(DeviceType type) {
    switch (type) {
      case DeviceType.router:
        return 'SQL injection, Active Directory/Kerberos tests, '
            'database-specific enumeration, web application fuzzing beyond admin panel.';
      case DeviceType.printer:
        return 'SQL injection, Active Directory/Kerberos tests, '
            'web application fuzzing beyond admin panel, ADCS/NTLM relay.';
      case DeviceType.windowsWorkstation:
        return 'Database-specific enumeration (unless DB port is open), '
            'IoT/embedded firmware analysis, SNMP bulk walks unless port 161 is open.';
      case DeviceType.windowsServer:
        return 'IoT/embedded firmware analysis, '
            'database-specific tools unless DB port is open.';
      case DeviceType.linuxServer:
        return 'Active Directory/Kerberos/ADCS tests (unless domain indicators present), '
            'Windows-specific tools, database enumeration unless DB port is open.';
      case DeviceType.mediaDevice:
        return 'SQL injection, Active Directory/Kerberos, '
            'deep web application fuzzing, SMB relay.';
      case DeviceType.apiServer:
        return 'Active Directory/Kerberos tests (unless domain indicators present), '
            'SMB relay, database direct-connect unless DB port open, '
            'low-level network protocol abuse.';
      case DeviceType.databaseServer:
        return 'Active Directory/Kerberos tests (unless domain indicators present), '
            'web application fuzzing (unless HTTP port open), '
            'wireless/RF attacks.';
      case DeviceType.networkAppliance:
        return 'SQL injection, web application fuzzing beyond admin panel, '
            'Active Directory/Kerberos, database enumeration.';
      case DeviceType.iotDevice:
        return 'Active Directory/Kerberos/ADCS tests, '
            'SQL injection against the device itself, '
            'SMB relay, complex web application fuzzing.';
      case DeviceType.unknown:
        return 'None — apply broad enumeration first to narrow attack surface.';
    }
  }
}
