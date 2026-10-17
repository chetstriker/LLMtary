import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/vulnerability_analyzer.dart';

void main() {
  group('VulnerabilityAnalyzer.isLikelyDuplicateProblem (authenticated re-analysis dedup)', () {
    bool dup(String t1, String p1, String t2, String p2) =>
        VulnerabilityAnalyzer.isLikelyDuplicateProblem(t1, p1, t2, p2);

    test('reworded same issue is a duplicate (the bug: exact-name let it through)', () {
      // Second pass rewords the same finding; exact problem-name match missed it.
      expect(
        dup('SQL Injection', 'SQL injection in the login form',
            'SQL Injection', 'SQL Injection on login form'),
        isTrue,
      );
    });

    test('normalized fingerprint match (stop words / order) is a duplicate', () {
      expect(
        dup('Info Disclosure', 'Exposure of the server version via HTTP header',
            'Info Disclosure', 'HTTP header server version exposure'),
        isTrue,
      );
    });

    test('same title different type: still deduped by fingerprint', () {
      expect(dup('TypeA', 'Weak TLS configuration', 'TypeB', 'Weak TLS configuration'), isTrue);
    });

    test('genuinely different findings are not duplicates', () {
      expect(
        dup('SQL Injection', 'SQL injection in login form',
            'XSS', 'Reflected XSS in search parameter'),
        isFalse,
      );
    });

    test('similar words but different vuln type and low overlap: not a duplicate', () {
      expect(
        dup('Open Port', 'Open Redis port 6379 exposed',
            'Weak Credentials', 'Default admin password accepted'),
        isFalse,
      );
    });
  });
}
