import 'dart:convert';

enum TargetScope { internal, external }

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

  /// Classify a target address as internal or external.
  ///
  /// Internal: RFC-1918 ranges, loopback, link-local, or plain hostnames
  /// with no dots (e.g. "myserver"). Everything else is external.
  static TargetScope classifyTarget(String address) {
    final a = address.trim().toLowerCase();

    // Loopback
    if (a == 'localhost' || a.startsWith('127.')) return TargetScope.internal;

    // Link-local
    if (a.startsWith('169.254.')) return TargetScope.internal;

    // IPv6 loopback / link-local
    if (a == '::1' || a.startsWith('fe80:')) return TargetScope.internal;

    // Plain hostname with no dots → assume internal
    if (!a.contains('.') && !a.contains(':')) return TargetScope.internal;

    // Try to parse as IPv4
    final parts = a.split('.');
    if (parts.length == 4) {
      final octets = parts.map((p) => int.tryParse(p)).toList();
      if (octets.every((o) => o != null)) {
        final o1 = octets[0]!;
        final o2 = octets[1]!;
        // 10.0.0.0/8
        if (o1 == 10) return TargetScope.internal;
        // 172.16.0.0/12
        if (o1 == 172 && o2 >= 16 && o2 <= 31) return TargetScope.internal;
        // 192.168.0.0/16
        if (o1 == 192 && o2 == 168) return TargetScope.internal;
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
