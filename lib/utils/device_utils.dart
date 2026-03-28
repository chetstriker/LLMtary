import 'dart:convert';

enum TargetScope { internal, external }

/// Detected cloud provider / platform.
enum CloudProvider { aws, azure, gcp, digitalOcean, linode, vultr, oracle, ibm, none }

/// Detects cloud-platform signals in device JSON data.
///
/// Used by [VulnerabilityAnalyzer] to decide whether to fire cloud-specific
/// analysis prompts, and by [ExploitExecutor] to inject cloud context.
class CloudIndicators {
  /// The detected provider (may be [CloudProvider.none]).
  final CloudProvider provider;

  /// True if an instance metadata endpoint was found or referenced.
  final bool hasMetadataEndpoint;

  /// True if IAM role / service-account credentials were referenced.
  final bool hasIamCredentials;

  /// True if object storage (S3, GCS, Azure Blob) is referenced.
  final bool hasObjectStorage;

  /// True if the target is a managed container / serverless platform.
  final bool isServerless;

  /// True when cloud indicators come from DNS/CNAME/public IP ranges rather
  /// than from internal metadata endpoint references.
  final bool isExternallyExposed;

  /// True when SSRF-capable parameters are identified on a cloud-hosted target
  /// (IMDS reachable only via SSRF from the target's perspective).
  final bool hasInternalCloudAccess;

  const CloudIndicators({
    this.provider = CloudProvider.none,
    this.hasMetadataEndpoint = false,
    this.hasIamCredentials = false,
    this.hasObjectStorage = false,
    this.isServerless = false,
    this.isExternallyExposed = false,
    this.hasInternalCloudAccess = false,
  });

  /// Returns true if any cloud signal was found.
  bool get isCloud => provider != CloudProvider.none ||
      hasMetadataEndpoint || hasIamCredentials || hasObjectStorage || isServerless;

  /// Friendly label for use in prompts.
  String get providerName {
    switch (provider) {
      case CloudProvider.aws:          return 'AWS';
      case CloudProvider.azure:        return 'Azure';
      case CloudProvider.gcp:          return 'GCP';
      case CloudProvider.digitalOcean: return 'DigitalOcean';
      case CloudProvider.linode:       return 'Linode/Akamai Cloud';
      case CloudProvider.vultr:        return 'Vultr';
      case CloudProvider.oracle:       return 'Oracle Cloud';
      case CloudProvider.ibm:          return 'IBM Cloud';
      case CloudProvider.none:         return 'Unknown Cloud';
    }
  }

  /// Detect cloud signals from raw device JSON text.
  static CloudIndicators detect(String deviceData) {
    final text = deviceData.toLowerCase();

    // --- Provider detection ---
    CloudProvider provider = CloudProvider.none;
    if (text.contains('amazonaws.com') || text.contains('aws') ||
        text.contains('ec2') || text.contains('elasticbeanstalk') ||
        text.contains('169.254.169.254')) {
      provider = CloudProvider.aws;
    } else if (text.contains('azure') || text.contains('microsoft.com') ||
        text.contains('azurewebsites') || text.contains('cloudapp.azure')) {
      provider = CloudProvider.azure;
    } else if (text.contains('googleapis.com') || text.contains('gcp') ||
        text.contains('google cloud') || text.contains('appspot.com') ||
        text.contains('metadata.google.internal')) {
      provider = CloudProvider.gcp;
    } else if (text.contains('digitalocean') || text.contains('droplet')) {
      provider = CloudProvider.digitalOcean;
    } else if (text.contains('linode') || text.contains('akamai cloud')) {
      provider = CloudProvider.linode;
    } else if (text.contains('vultr')) {
      provider = CloudProvider.vultr;
    } else if (text.contains('oracle cloud') || text.contains('oraclecloud')) {
      provider = CloudProvider.oracle;
    } else if (text.contains('ibm cloud') || text.contains('ibmcloud')) {
      provider = CloudProvider.ibm;
    }

    final hasMetadata = text.contains('169.254.169.254') ||
        text.contains('metadata.google.internal') ||
        text.contains('metadata endpoint') ||
        text.contains('imds');

    final hasIam = text.contains('iam') || text.contains('service account') ||
        text.contains('access_key') || text.contains('aws_secret') ||
        text.contains('managed identity');

    final hasStorage = text.contains('s3') || text.contains('blob.core') ||
        text.contains('storage.googleapis') || text.contains('object storage');

    final isServerless = text.contains('lambda') || text.contains('cloud function') ||
        text.contains('azure function') || text.contains('app engine') ||
        text.contains('fargate') || text.contains('cloud run') ||
        text.contains('container registry') || text.contains('ecr') ||
        text.contains('gcr.io') || text.contains('acr.io');

    // Cloud indicators from DNS/CNAME/public signals → externally exposed
    final isExternallyExposed = text.contains('cname') ||
        text.contains('amazonaws.com') || text.contains('azurewebsites') ||
        text.contains('cloudapp.azure') || text.contains('appspot.com') ||
        text.contains('cloudfront') || text.contains('pages.dev') ||
        text.contains('netlify') || text.contains('herokuapp');

    // SSRF-capable parameters on a cloud-hosted target → internal cloud access
    final hasInternalCloudAccess = (provider != CloudProvider.none || hasMetadata) &&
        (text.contains('url=') || text.contains('redirect=') ||
         text.contains('fetch=') || text.contains('proxy=') ||
         text.contains('ssrf') || text.contains('webhook') ||
         text.contains('import=') || text.contains('src='));

    return CloudIndicators(
      provider: provider,
      hasMetadataEndpoint: hasMetadata,
      hasIamCredentials: hasIam,
      hasObjectStorage: hasStorage,
      isServerless: isServerless,
      isExternallyExposed: isExternallyExposed,
      hasInternalCloudAccess: hasInternalCloudAccess,
    );
  }
}

/// Utilities for extracting information from device JSON data.
class DeviceUtils {
  /// Extract the target IP address or hostname from device data JSON.
  ///
  /// Tries structured JSON fields first, falls back to regex IP extraction.
  /// Returns a FQDN or IP string; returns 'unknown' only if nothing can be found.
  static String extractTargetIp(String deviceData) {
    try {
      final deviceJson = json.decode(deviceData);
      final ip = deviceJson['device']?['ip_address']?.toString() ??
          deviceJson['ip_address']?.toString();
      if (ip != null && ip.isNotEmpty) return ip;

      // Fall back to device name — may be a FQDN like www.example.org
      final name = deviceJson['device']?['name']?.toString() ??
          deviceJson['name']?.toString();
      if (name != null && name.isNotEmpty && name != 'unknown') {
        print('DEBUG: [DeviceUtils] ip_address empty/missing — using name: $name');
        return name;
      }
    } catch (e) {
      // JSON parse failure — try regex fallback
    }

    // Last resort: extract first IPv4 from raw string
    final ipMatch =
        RegExp(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})').firstMatch(deviceData);
    if (ipMatch != null) return ipMatch.group(1)!;

    print('DEBUG: [DeviceUtils] extractTargetIp: could not determine target — returning "unknown"');
    return 'unknown';
  }

  /// Extract only the target identifier (hostname or IP) suitable for use in
  /// commands. Prefers FQDN hostnames for external targets, numeric IPs for
  /// internal ones. Never returns 'unknown'.
  static String extractTargetIdentifier(String deviceData) {
    return extractTargetIp(deviceData);
  }

  /// Returns true if an IPv4 address (given as four parsed octets) falls in
  /// any private, reserved, or special-use range that should receive the
  /// internal analysis prompt set.
  ///
  /// Covers:
  ///   10.0.0.0/8        — RFC 1918 private
  ///   172.16.0.0/12     — RFC 1918 private
  ///   192.168.0.0/16    — RFC 1918 private
  ///   100.64.0.0/10     — RFC 6598 CGNAT / shared address space
  ///   169.254.0.0/16    — RFC 3927 link-local (also caught by string prefix above)
  ///   127.0.0.0/8       — loopback (also caught by string prefix above)
  static bool _isPrivateIpv4(int o1, int o2) {
    if (o1 == 10) return true;                           // 10.0.0.0/8
    if (o1 == 172 && o2 >= 16 && o2 <= 31) return true; // 172.16.0.0/12
    if (o1 == 192 && o2 == 168) return true;             // 192.168.0.0/16
    if (o1 == 100 && o2 >= 64 && o2 <= 127) return true; // 100.64.0.0/10 CGNAT
    if (o1 == 169 && o2 == 254) return true;             // 169.254.0.0/16 link-local
    if (o1 == 127) return true;                          // 127.0.0.0/8 loopback
    return false;
  }

  /// Classify a target address as internal or external.
  ///
  /// Internal: RFC-1918 ranges, CGNAT (100.64.0.0/10), loopback, link-local,
  /// IPv6 ULA (fc00::/7), or plain hostnames with no dots (e.g. "myserver").
  /// Everything else is external.
  static TargetScope classifyTarget(String address) {
    final a = address.trim().toLowerCase();

    // Loopback
    if (a == 'localhost' || a.startsWith('127.')) return TargetScope.internal;

    // Link-local (IPv4)
    if (a.startsWith('169.254.')) return TargetScope.internal;

    // IPv6 loopback / link-local
    if (a == '::1' || a.startsWith('fe80:')) return TargetScope.internal;

    // IPv6 ULA (fc00::/7) — private IPv6 addresses, equivalent to RFC-1918.
    // Covers both fc00::/8 and fd00::/8 prefixes.
    if (a.startsWith('fc') || a.startsWith('fd')) return TargetScope.internal;

    // Plain hostname with no dots → assume internal
    if (!a.contains('.') && !a.contains(':')) return TargetScope.internal;

    // Try to parse as IPv4
    final parts = a.split('.');
    if (parts.length == 4) {
      final octets = parts.map((p) => int.tryParse(p)).toList();
      if (octets.every((o) => o != null)) {
        final o1 = octets[0]!;
        final o2 = octets[1]!;
        if (_isPrivateIpv4(o1, o2)) return TargetScope.internal;
        // Everything else is a routable IP → external
        return TargetScope.external;
      }
    }

    // Hostname with dots (e.g. www.cdpho.org) → external
    return TargetScope.external;
  }

  /// Returns true if the device data indicates the target is behind a CDN.
  /// Used by ExploitExecutor to apply CDN-aware iteration strategy.
  static bool hasCdnIndicators(String deviceData) {
    const cdnProviders = [
      'cloudflare', 'fastly', 'akamai', 'cloudfront', 'sucuri',
      'incapsula', 'imperva', 'azureedge', 'azurefd', 'pages.dev',
    ];
    final text = deviceData.toLowerCase();
    return cdnProviders.any((p) => text.contains(p));
  }

  /// Extract the list of open ports from device data JSON.
  static List<Map<String, dynamic>> extractPorts(String deviceData) {
    try {
      final deviceJson = json.decode(deviceData);
      final ports = deviceJson['open_ports'] as List?;
      if (ports != null) {
        return ports.cast<Map<String, dynamic>>();
      }
    } catch (e) {
      // Silently return empty list on parse failure
    }
    return [];
  }
}

/// Filters device JSON to include only sections relevant to a specific prompt
/// category, reducing token usage by 30-70% per prompt call.
///
/// Each filter method returns a re-encoded JSON string containing only the
/// device metadata, relevant ports, and relevant findings sections.
class DeviceDataFilter {
  // Port sets for filtering
  static const _webPorts = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 4443, 9443, 7001, 7002, 4848, 9990, 8161, 9000, 9200, 5601, 3001};
  // Keep ambiguous ports in the filter set — the gating logic in
  // VulnerabilityAnalyzer decides whether to fire web prompts at all.
  // If it does fire, the filter should include data for those ports.
  static const _webServices = {'http', 'https', 'http-alt', 'http-proxy'};
  static const _adPorts = {88, 389, 636, 445, 53, 3268, 3269, 135, 139, 5985, 5986};
  static const _adServices = {'kerberos', 'ldap', 'ldaps', 'microsoft-ds', 'smb', 'msrpc', 'globalcatalog', 'winrm'};
  static const _networkPorts = {21, 22, 23, 25, 53, 110, 111, 135, 139, 161, 389, 445, 512, 513, 514, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 27017, 5985, 5986, 2375, 2376, 6443, 1883, 5672, 9092};
  static const _snmpPorts = {161, 162, 623, 514, 2055, 1812, 1813, 8291};

  /// Returns deviceJson filtered to web-related ports and findings only.
  static String forWeb(String deviceJson) =>
      _filter(deviceJson, portFilter: _isWebPort, keepSections: const ['web_findings', 'waf_findings']);

  /// Returns deviceJson filtered to AD-related ports and findings only.
  static String forAd(String deviceJson) =>
      _filter(deviceJson, portFilter: _isAdPort, keepSections: const ['smb_findings']);

  /// Returns deviceJson filtered to network service ports.
  static String forNetwork(String deviceJson) =>
      _filter(deviceJson, portFilter: _isNetworkPort, keepSections: const ['smb_findings', 'ftp_findings', 'ssh_findings', 'db_findings']);

  /// Returns deviceJson filtered to DNS/OSINT findings only (no port filtering).
  static String forDns(String deviceJson) =>
      _filter(deviceJson, keepSections: const ['dns_findings', 'other_findings'], keepAllPorts: false, portFilter: (_, __) => false);

  /// Returns deviceJson filtered to SNMP/management ports.
  static String forSnmp(String deviceJson) =>
      _filter(deviceJson, portFilter: _isSnmpPort, keepSections: const ['other_findings']);

  /// Returns deviceJson filtered to SSL/TLS-relevant ports (web ports).
  static String forSsl(String deviceJson) => forWeb(deviceJson);

  /// Returns deviceJson filtered to database ports.
  static String forDatabase(String deviceJson) =>
      _filter(deviceJson, portFilter: _isDatabasePort, keepSections: const ['db_findings']);

  /// Returns full deviceJson unchanged (for prompts that need everything).
  static String full(String deviceJson) => deviceJson;

  // --- Port matchers ---

  static bool _isWebPort(int port, String service) =>
      _webPorts.contains(port) || _webServices.any((s) => service.contains(s));

  static bool _isAdPort(int port, String service) =>
      _adPorts.contains(port) || _adServices.any((s) => service.contains(s));

  static bool _isNetworkPort(int port, String service) =>
      _networkPorts.contains(port);

  static bool _isSnmpPort(int port, String service) =>
      _snmpPorts.contains(port);

  static bool _isDatabasePort(int port, String service) =>
      const {1433, 1521, 3306, 5432, 6379, 27017, 9200, 5984, 8086, 11211}.contains(port) ||
      const {'mysql', 'postgresql', 'mssql', 'oracle', 'redis', 'mongodb', 'elasticsearch'}.any((s) => service.contains(s));

  /// Core filtering logic. Keeps device metadata always, filters ports by
  /// [portFilter], and retains only the [keepSections] finding categories.
  static String _filter(String deviceJson, {
    bool Function(int port, String service)? portFilter,
    List<String> keepSections = const [],
    bool keepAllPorts = false,
  }) {
    try {
      final d = json.decode(deviceJson) as Map<String, dynamic>;
      final result = <String, dynamic>{};

      // Always keep device metadata
      if (d.containsKey('device')) result['device'] = d['device'];
      if (d.containsKey('ip') || d.containsKey('ip_address')) {
        result['ip'] = d['ip'] ?? d['ip_address'];
      }
      for (final key in ['hostname', 'name', 'os', 'operating_system', 'os_version', 'mac', 'target', 'address', 'domain_information', 'technologies']) {
        if (d.containsKey(key) && d[key] != null) result[key] = d[key];
      }

      // Filter ports
      final ports = (d['open_ports'] as List?) ?? [];
      if (keepAllPorts || portFilter == null) {
        if (ports.isNotEmpty) result['open_ports'] = ports;
      } else {
        final filtered = ports.where((p) {
          final port = p['port'] is int ? p['port'] as int : int.tryParse(p['port']?.toString() ?? '') ?? 0;
          final service = (p['service'] ?? '').toString().toLowerCase();
          return portFilter(port, service);
        }).toList();
        if (filtered.isNotEmpty) result['open_ports'] = filtered;
      }

      // Keep only requested finding sections
      for (final section in keepSections) {
        if (d.containsKey(section) && d[section] != null) {
          final val = d[section];
          // Skip empty lists/maps
          if (val is List && val.isEmpty) continue;
          if (val is Map && val.isEmpty) continue;
          result[section] = val;
        }
      }

      // Always keep nmap_scripts if any matched ports reference them
      if (d.containsKey('nmap_scripts') && d['nmap_scripts'] is List) {
        final scripts = d['nmap_scripts'] as List;
        if (result.containsKey('open_ports') && scripts.isNotEmpty) {
          final keptPorts = (result['open_ports'] as List).map((p) =>
              p['port'] is int ? p['port'] as int : int.tryParse(p['port']?.toString() ?? '') ?? 0).toSet();
          final filteredScripts = scripts.where((s) {
            final port = s['port'] is int ? s['port'] as int : int.tryParse(s['port']?.toString() ?? '') ?? 0;
            return keptPorts.contains(port);
          }).toList();
          if (filteredScripts.isNotEmpty) result['nmap_scripts'] = filteredScripts;
        }
      }

      return json.encode(result);
    } catch (_) {
      // On parse failure, return original to avoid breaking analysis
      return deviceJson;
    }
  }
}
