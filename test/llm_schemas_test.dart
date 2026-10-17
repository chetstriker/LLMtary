import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/llm_schemas.dart';

void main() {
  group('LlmSchemas (exact JSON schemas for structured LLM calls)', () {
    test('findingsArray is an array of finding objects with pinned enums', () {
      final a = LlmSchemas.findingsArray;
      expect(a['type'], 'array');
      final item = a['items'] as Map<String, dynamic>;
      expect(item['type'], 'object');
      final props = item['properties'] as Map<String, dynamic>;
      expect((props['severity'] as Map)['enum'], containsAll(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']));
      expect((props['confidence'] as Map)['enum'], containsAll(['HIGH', 'MEDIUM', 'LOW']));
      // the pipeline depends on these being present
      expect(item['required'], containsAll(['problem', 'evidence_quote']));
      // optional descriptive fields must still be allowed through
      expect(item['additionalProperties'], isTrue);
    });

    test('exploitDecision exposes the fields the loop reads', () {
      final props = LlmSchemas.exploitDecision['properties'] as Map<String, dynamic>;
      expect(props.keys, containsAll(['confirmed', 'needs_exploitation', 'reason', 'evidence_quote']));
      expect((props['confirmed'] as Map)['type'], 'boolean');
    });

    test('commandValidation requires valid and lists issues', () {
      final s = LlmSchemas.commandValidation;
      expect(s['required'], contains('valid'));
      final props = s['properties'] as Map<String, dynamic>;
      expect((props['valid'] as Map)['type'], 'boolean');
      expect((props['issues'] as Map)['type'], 'array');
    });
  });
}
