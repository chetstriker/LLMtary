import 'package:flutter_test/flutter_test.dart';
import 'package:penexecuter/services/vulnerability_analyzer.dart';
import 'package:penexecuter/utils/subdomain_takeover_fingerprints.dart';

void main() {
  final analyzer = VulnerabilityAnalyzer();

  // ---------------------------------------------------------------------------
  // Helper to build minimal device JSON strings
  // ---------------------------------------------------------------------------
  String deviceWithPort(int port, {String service = 'unknown', String banner = ''}) =>
      '{"open_ports":[{"port":$port,"protocol":"tcp","service":"$service","banner":"$banner"}]}';

  String deviceWithKeyword(String keyword) =>
      '{"device":{"name":"$keyword"},"open_ports":[]}';

  String emptyDevice() => '{"open_ports":[]}';

  // ---------------------------------------------------------------------------
  // _hasBusinessLogicSurface
  // ---------------------------------------------------------------------------
  group('_hasBusinessLogicSurface', () {
    test('fires on login keyword', () {
      expect(analyzer.testHasBusinessLogicSurface('{"web_findings":[{"url":"http://x/login"}]}'), isTrue);
    });
    test('fires on checkout keyword', () {
      expect(analyzer.testHasBusinessLogicSurface('{"web_findings":[{"url":"http://x/checkout"}]}'), isTrue);
    });
    test('fires on password keyword', () {
      expect(analyzer.testHasBusinessLogicSurface('{"other":"password reset endpoint"}'), isTrue);
    });
    test('does not fire on plain port scan with no keywords', () {
      expect(analyzer.testHasBusinessLogicSurface(deviceWithPort(22, service: 'ssh')), isFalse);
    });
    test('does not fire on empty device', () {
      expect(analyzer.testHasBusinessLogicSurface(emptyDevice()), isFalse);
    });
  });

  // ---------------------------------------------------------------------------
  // _hasWirelessIndicators
  // ---------------------------------------------------------------------------
  group('_hasWirelessIndicators', () {
    test('fires on wpa keyword', () {
      expect(analyzer.testHasWirelessIndicators('{"device":{"os":"WPA2 AP"}}'), isTrue);
    });
    test('fires on ubiquiti keyword', () {
      expect(analyzer.testHasWirelessIndicators(deviceWithKeyword('ubiquiti')), isTrue);
    });
    test('fires on 802.11 keyword', () {
      expect(analyzer.testHasWirelessIndicators('{"notes":"802.11ac access point"}'), isTrue);
    });
    test('does not fire on plain web server', () {
      expect(analyzer.testHasWirelessIndicators(deviceWithPort(80, service: 'http')), isFalse);
    });
    test('does not fire on empty device', () {
      expect(analyzer.testHasWirelessIndicators(emptyDevice()), isFalse);
    });
  });

  // ---------------------------------------------------------------------------
  // _hasNetworkInfrastructure
  // ---------------------------------------------------------------------------
  group('_hasNetworkInfrastructure', () {
    test('fires on telnet port 23', () {
      expect(analyzer.testHasNetworkInfrastructure(deviceWithPort(23, service: 'telnet')), isTrue);
    });
    test('fires on BGP port 179', () {
      expect(analyzer.testHasNetworkInfrastructure(deviceWithPort(179, service: 'bgp')), isTrue);
    });
    test('fires on cisco keyword in hostname', () {
      expect(analyzer.testHasNetworkInfrastructure('{"device":{"name":"core-sw01-cisco"},"open_ports":[]}'), isTrue);
    });
    test('fires on vlan keyword', () {
      expect(analyzer.testHasNetworkInfrastructure('{"notes":"vlan 10 configured"}'), isTrue);
    });
    test('does not fire on plain web server', () {
      expect(analyzer.testHasNetworkInfrastructure(deviceWithPort(443, service: 'https')), isFalse);
    });
  });

  // ---------------------------------------------------------------------------
  // _hasPackageRegistryIndicators
  // ---------------------------------------------------------------------------
  group('_hasPackageRegistryIndicators', () {
    test('fires on port 8081 (Nexus/Artifactory)', () {
      expect(analyzer.testHasPackageRegistryIndicators(deviceWithPort(8081)), isTrue);
    });
    test('fires on port 4873 (Verdaccio)', () {
      expect(analyzer.testHasPackageRegistryIndicators(deviceWithPort(4873)), isTrue);
    });
    test('fires on artifactory keyword', () {
      expect(analyzer.testHasPackageRegistryIndicators('{"web_findings":[{"url":"http://x/artifactory/"}]}'), isTrue);
    });
    test('does not fire on port 80', () {
      expect(analyzer.testHasPackageRegistryIndicators(deviceWithPort(80, service: 'http')), isFalse);
    });
    test('does not fire on empty device', () {
      expect(analyzer.testHasPackageRegistryIndicators(emptyDevice()), isFalse);
    });
  });

  // ---------------------------------------------------------------------------
  // _hasThickClientIndicators
  // ---------------------------------------------------------------------------
  group('_hasThickClientIndicators', () {
    test('fires on RMI port 1099', () {
      expect(analyzer.testHasThickClientIndicators(deviceWithPort(1099, service: 'rmi')), isTrue);
    });
    test('fires on JMX port 9999', () {
      expect(analyzer.testHasThickClientIndicators(deviceWithPort(9999, service: 'jmx')), isTrue);
    });
    test('fires on IIOP port 1050', () {
      expect(analyzer.testHasThickClientIndicators(deviceWithPort(1050, service: 'iiop')), isTrue);
    });
    test('does not fire on SSH port 22', () {
      expect(analyzer.testHasThickClientIndicators(deviceWithPort(22, service: 'ssh')), isFalse);
    });
  });

  // ---------------------------------------------------------------------------
  // _hasJavaMiddlewareIndicators
  // ---------------------------------------------------------------------------
  group('_hasJavaMiddlewareIndicators', () {
    test('fires on WebLogic port 7001', () {
      expect(analyzer.testHasJavaMiddlewareIndicators(deviceWithPort(7001, service: 'weblogic')), isTrue);
    });
    test('fires on ActiveMQ port 61616', () {
      expect(analyzer.testHasJavaMiddlewareIndicators(deviceWithPort(61616, service: 'activemq')), isTrue);
    });
    test('fires on kafka keyword', () {
      expect(analyzer.testHasJavaMiddlewareIndicators('{"notes":"kafka broker running"}'), isTrue);
    });
    test('does not fire on plain HTTP', () {
      expect(analyzer.testHasJavaMiddlewareIndicators(deviceWithPort(80, service: 'http')), isFalse);
    });
  });

  // ---------------------------------------------------------------------------
  // _hasSourceCodeIndicators
  // ---------------------------------------------------------------------------
  group('_hasSourceCodeIndicators', () {
    test('fires on package.json reference', () {
      expect(analyzer.testHasSourceCodeIndicators('{"web_findings":[{"url":"http://x/package.json"}]}'), isTrue);
    });
    test('fires on gitea keyword', () {
      expect(analyzer.testHasSourceCodeIndicators('{"device":{"name":"gitea-server"}}'), isTrue);
    });
    test('fires on git port 9418', () {
      expect(analyzer.testHasSourceCodeIndicators('{"notes":"port :9418 open"}'), isTrue);
    });
    test('does not fire on empty device', () {
      expect(analyzer.testHasSourceCodeIndicators(emptyDevice()), isFalse);
    });
  });

  // ---------------------------------------------------------------------------
  // SubdomainTakeoverFingerprints
  // ---------------------------------------------------------------------------
  group('SubdomainTakeoverFingerprints', () {
    test('matchCname returns platform name for known CNAME', () {
      expect(SubdomainTakeoverFingerprints.matchCname('foo.azurewebsites.net'), equals('Azure App Service'));
      expect(SubdomainTakeoverFingerprints.matchCname('bar.github.io'), equals('GitHub Pages'));
      expect(SubdomainTakeoverFingerprints.matchCname('bucket.s3.amazonaws.com'), equals('AWS S3'));
    });

    test('matchCname returns null for unknown CNAME', () {
      expect(SubdomainTakeoverFingerprints.matchCname('example.com'), isNull);
    });

    test('isUnclaimed returns true when body matches signature', () {
      expect(
        SubdomainTakeoverFingerprints.isUnclaimed('foo.azurewebsites.net', '404 Web Site not found'),
        isTrue,
      );
      expect(
        SubdomainTakeoverFingerprints.isUnclaimed('bar.github.io', "There isn't a GitHub Pages site here"),
        isTrue,
      );
      expect(
        SubdomainTakeoverFingerprints.isUnclaimed('bucket.s3.amazonaws.com', 'NoSuchBucket'),
        isTrue,
      );
    });

    test('isUnclaimed returns false when body does not match', () {
      expect(
        SubdomainTakeoverFingerprints.isUnclaimed('foo.azurewebsites.net', '<html>Welcome to my site</html>'),
        isFalse,
      );
    });

    test('isUnclaimed returns false for unknown CNAME with non-matching body', () {
      expect(
        SubdomainTakeoverFingerprints.isUnclaimed('example.com', 'Hello World'),
        isFalse,
      );
    });

    test('isUnclaimed is case-insensitive', () {
      expect(
        SubdomainTakeoverFingerprints.isUnclaimed('foo.azurewebsites.net', '404 WEB SITE NOT FOUND'),
        isTrue,
      );
    });
  });
}
