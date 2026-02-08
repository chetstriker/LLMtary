import 'dart:convert';

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
