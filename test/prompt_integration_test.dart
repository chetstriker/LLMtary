import 'package:flutter_test/flutter_test.dart';
import 'package:penexecuter/services/prompt_templates.dart';
import 'package:penexecuter/models/vulnerability.dart';
import 'package:penexecuter/utils/json_parser.dart';

/// Integration tests verifying that analysis prompts produce structurally valid
/// output and that proofCommandExpectedOutput is parsed and stored correctly.
///
/// These tests use a mock LLM response (hardcoded JSON) to validate the parsing
/// pipeline without requiring a live LLM connection.
void main() {
  const sampleDeviceJson = '''
{
  "device": {"ip_address": "10.0.0.5", "name": "testhost", "os": "Linux", "os_version": "Ubuntu 22.04"},
  "open_ports": [
    {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "Apache httpd", "version": "2.4.49"},
    {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "Apache httpd", "version": "2.4.49"},
    {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.2p1"}
  ],
  "web_findings": [{"url": "http://10.0.0.5:80", "status": 200, "server": "Apache/2.4.49", "technologies": ["WordPress 6.2"]}]
}
''';

  /// Simulated LLM response for a prompt — a valid JSON array with all required fields.
  const mockLlmResponse = '''
[
  {
    "problem": "Apache 2.4.49 Path Traversal (CVE-2021-41773)",
    "cve": "CVE-2021-41773",
    "description": "Apache 2.4.49 path traversal via URL-encoded dot-dot sequences.",
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "evidence": "Apache httpd 2.4.49 on port 80",
    "evidence_quote": "Apache httpd 2.4.49",
    "recommendation": "Upgrade Apache to 2.4.51 or later.",
    "vulnerabilityType": "Path Traversal",
    "attackVector": "NETWORK",
    "attackComplexity": "LOW",
    "privilegesRequired": "NONE",
    "userInteraction": "NONE",
    "scope": "CHANGED",
    "confidentialityImpact": "HIGH",
    "integrityImpact": "HIGH",
    "availabilityImpact": "HIGH",
    "businessRisk": "Full server compromise via path traversal to RCE.",
    "exploitAvailable": "true",
    "exploitMaturity": "FUNCTIONAL",
    "suggestedTools": "curl",
    "proofCommand": "curl -s 'http://10.0.0.5/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd'",
    "proofCommandExpectedOutput": "root:x:0:0"
  }
]
''';

  group('Prompt structure validation', () {
    test('businessLogicDeepDivePrompt produces non-empty prompt string', () {
      final prompt = PromptTemplates.businessLogicDeepDivePrompt(sampleDeviceJson);
      expect(prompt, isNotEmpty);
      expect(prompt, contains('business logic'));
    });

    test('wirelessSecurityPrompt produces non-empty prompt string', () {
      final prompt = PromptTemplates.wirelessSecurityPrompt(sampleDeviceJson);
      expect(prompt, isNotEmpty);
      expect(prompt, contains('wireless'));
    });

    test('networkInfrastructureAttackPrompt produces non-empty prompt string', () {
      final prompt = PromptTemplates.networkInfrastructureAttackPrompt(sampleDeviceJson);
      expect(prompt, isNotEmpty);
      expect(prompt, contains('network infrastructure'));
    });

    test('thickClientBinaryProtocolPrompt produces non-empty prompt string', () {
      final prompt = PromptTemplates.thickClientBinaryProtocolPrompt(sampleDeviceJson);
      expect(prompt, isNotEmpty);
    });

    test('supplyChainAnalysisPrompt produces non-empty prompt string', () {
      final prompt = PromptTemplates.supplyChainAnalysisPrompt(sampleDeviceJson);
      expect(prompt, isNotEmpty);
      expect(prompt, contains('supply chain'));
    });

    test('all prompts include proofCommand in output format block', () {
      // The _outputFormatBlock is embedded in every prompt — verify via a sample
      final prompt = PromptTemplates.webAppCorePrompt(sampleDeviceJson);
      expect(prompt, contains('proofCommand'));
      expect(prompt, contains('proofCommandExpectedOutput'));
    });
  });

  group('Mock LLM response parsing', () {
    test('proofCommandExpectedOutput is parsed from mock response', () {
      final items = JsonParser.tryParseJsonArray(mockLlmResponse);
      expect(items, isNotNull);
      expect(items!.length, 1);

      final v = items.first as Map<String, dynamic>;
      expect(v['proofCommand'], isNotEmpty);
      expect(v['proofCommandExpectedOutput'], equals('root:x:0:0'));
    });

    test('Vulnerability model stores proofCommandExpectedOutput', () {
      final items = JsonParser.tryParseJsonArray(mockLlmResponse)!;
      final v = items.first as Map<String, dynamic>;

      final vuln = Vulnerability(
        problem: v['problem'] ?? '',
        description: v['description'] ?? '',
        severity: v['severity'] ?? 'MEDIUM',
        confidence: v['confidence'] ?? 'LOW',
        evidence: v['evidence'] ?? '',
        recommendation: v['recommendation'] ?? '',
        vulnerabilityType: v['vulnerabilityType'] ?? '',
        businessRisk: v['businessRisk'] ?? '',
        proofCommand: v['proofCommand']?.toString(),
        proofCommandExpectedOutput: v['proofCommandExpectedOutput']?.toString(),
      );

      expect(vuln.proofCommand, contains('curl'));
      expect(vuln.proofCommandExpectedOutput, equals('root:x:0:0'));
    });

    test('Vulnerability toMap/fromMap round-trips proofCommandExpectedOutput', () {
      final vuln = Vulnerability(
        problem: 'Test',
        description: 'Test desc',
        severity: 'HIGH',
        confidence: 'MEDIUM',
        evidence: 'test evidence',
        recommendation: 'fix it',
        vulnerabilityType: 'RCE',
        businessRisk: 'high risk',
        proofCommand: 'curl http://target/test',
        proofCommandExpectedOutput: 'uid=0(root)',
      );

      final map = vuln.toMap();
      expect(map['proofCommandExpectedOutput'], equals('uid=0(root)'));

      final restored = Vulnerability.fromMap(map);
      expect(restored.proofCommandExpectedOutput, equals('uid=0(root)'));
    });
  });
}
