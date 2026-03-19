import 'package:flutter_test/flutter_test.dart';
import 'package:penexecuter/utils/device_utils.dart';

void main() {
  group('DeviceUtils.classifyTarget', () {
    // RFC-1918 internal ranges
    test('10.x.x.x is internal', () {
      expect(DeviceUtils.classifyTarget('10.0.0.1'), TargetScope.internal);
      expect(DeviceUtils.classifyTarget('10.255.255.255'), TargetScope.internal);
    });

    test('172.16-31.x.x is internal', () {
      expect(DeviceUtils.classifyTarget('172.16.0.1'), TargetScope.internal);
      expect(DeviceUtils.classifyTarget('172.31.255.255'), TargetScope.internal);
    });

    test('172.15.x.x and 172.32.x.x are external (outside /12)', () {
      expect(DeviceUtils.classifyTarget('172.15.0.1'), TargetScope.external);
      expect(DeviceUtils.classifyTarget('172.32.0.1'), TargetScope.external);
    });

    test('192.168.x.x is internal', () {
      expect(DeviceUtils.classifyTarget('192.168.0.1'), TargetScope.internal);
      expect(DeviceUtils.classifyTarget('192.168.255.255'), TargetScope.internal);
    });

    // Loopback and link-local
    test('localhost is internal', () {
      expect(DeviceUtils.classifyTarget('localhost'), TargetScope.internal);
    });

    test('127.x.x.x is internal', () {
      expect(DeviceUtils.classifyTarget('127.0.0.1'), TargetScope.internal);
      expect(DeviceUtils.classifyTarget('127.0.0.2'), TargetScope.internal);
    });

    test('169.254.x.x link-local is internal', () {
      expect(DeviceUtils.classifyTarget('169.254.1.1'), TargetScope.internal);
    });

    // IPv6
    test('::1 IPv6 loopback is internal', () {
      expect(DeviceUtils.classifyTarget('::1'), TargetScope.internal);
    });

    test('fe80: link-local IPv6 is internal', () {
      expect(DeviceUtils.classifyTarget('fe80::1'), TargetScope.internal);
    });

    // Plain hostname (no dots) — internal by convention
    test('plain hostname with no dots is internal', () {
      expect(DeviceUtils.classifyTarget('fileserver'), TargetScope.internal);
      expect(DeviceUtils.classifyTarget('DC01'), TargetScope.internal);
    });

    // Public IPv4
    test('public IPv4 is external', () {
      expect(DeviceUtils.classifyTarget('8.8.8.8'), TargetScope.external);
      expect(DeviceUtils.classifyTarget('1.1.1.1'), TargetScope.external);
      expect(DeviceUtils.classifyTarget('203.0.113.1'), TargetScope.external);
    });

    // FQDNs (with dots) — external
    test('FQDN is external', () {
      expect(DeviceUtils.classifyTarget('example.com'), TargetScope.external);
      expect(DeviceUtils.classifyTarget('www.target.org'), TargetScope.external);
      expect(DeviceUtils.classifyTarget('api.internal.example.com'), TargetScope.external);
    });

    // Edge cases: leading/trailing whitespace, mixed case
    test('whitespace is trimmed', () {
      expect(DeviceUtils.classifyTarget('  10.0.0.1  '), TargetScope.internal);
      expect(DeviceUtils.classifyTarget('  8.8.8.8  '), TargetScope.external);
    });

    test('case insensitive for localhost', () {
      expect(DeviceUtils.classifyTarget('LOCALHOST'), TargetScope.internal);
    });

    // 192.169.x.x is NOT 192.168 — should be external
    test('192.169.x.x is external (not RFC-1918)', () {
      expect(DeviceUtils.classifyTarget('192.169.0.1'), TargetScope.external);
    });
  });
}
