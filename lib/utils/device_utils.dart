import 'dart:convert';

enum TargetScope { internal, external }

/// Utilities for extracting information from device JSON data.
class DeviceUtils {
  /// Extract the target IP address from device data JSON.
  ///
  /// Tries structured JSON fields first, falls back to regex IP extraction.
  static String extractTargetIp(String deviceData) {
    try {
      final deviceJson = json.decode(deviceData);
      return deviceJson['device']?['ip_address'] ??
          deviceJson['ip_address'] ??
          deviceJson['device']?['name'] ??
          'unknown';
    } catch (e) {
      final ipMatch =
          RegExp(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})').firstMatch(deviceData);
      if (ipMatch != null) return ipMatch.group(1)!;
      return 'unknown';
    }
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
