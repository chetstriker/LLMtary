/// Exact JSON schemas for the structured LLM calls.
///
/// Part 1 of the LLMtary structured-output work: instead of asking the model for
/// a generic `format: 'json'` (Ollama) or `response_format: json_object` (OpenAI),
/// we hand it the EXACT schema of the object/array we parse. A generic "give me
/// json" lets a small local model (e.g. a 14B over Ollama) drift on field names,
/// enum values and nesting; a precise schema constrains the decode so the parse
/// on our side stops failing silently.
///
/// Schemas are intentionally lenient where the shape is wide: the enum-bearing
/// and required fields are pinned (these are what a weak model gets wrong), while
/// `additionalProperties` stays open so optional descriptive fields are not
/// rejected. Keep these in sync with the output-format blocks in
/// `prompt_templates.dart` and the parsers that consume them.
class LlmSchemas {
  LlmSchemas._();

  static const _severity = {
    'type': 'string',
    'enum': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
  };
  static const _confidence = {
    'type': 'string',
    'enum': ['HIGH', 'MEDIUM', 'LOW'],
  };

  /// A single vulnerability finding (the object the analyzer prompts emit in an
  /// array). Pins the enum fields and the two fields the pipeline depends on
  /// (`problem`, `evidence_quote`); leaves the rest open.
  static const Map<String, dynamic> finding = {
    'type': 'object',
    'properties': {
      'problem': {'type': 'string'},
      'cve': {'type': 'string'},
      'description': {'type': 'string'},
      'severity': _severity,
      'confidence': _confidence,
      'evidence': {'type': 'string'},
      'evidence_quote': {'type': 'string'},
      'recommendation': {'type': 'string'},
      'vulnerabilityType': {'type': 'string'},
      'attackVector': {
        'type': 'string',
        'enum': ['NETWORK', 'ADJACENT', 'LOCAL', 'PHYSICAL'],
      },
      'proofCommand': {'type': 'string'},
    },
    'required': ['problem', 'severity', 'confidence', 'evidence_quote'],
    'additionalProperties': true,
  };

  /// The analyzer prompts return a BARE ARRAY of findings.
  static const Map<String, dynamic> findingsArray = {
    'type': 'array',
    'items': finding,
  };

  /// Exploit-step decision (exploit_executor): the loop reads these fields.
  static const Map<String, dynamic> exploitDecision = {
    'type': 'object',
    'properties': {
      'thought': {'type': 'string'},
      'command': {'type': 'string'},
      'confirmed': {'type': 'boolean'},
      'needs_exploitation': {'type': 'boolean'},
      'reason': {'type': 'string'},
      'evidence_quote': {'type': 'string'},
    },
    'additionalProperties': true,
  };

  /// Command validation (command_executor Tier-2): valid/issues/corrected.
  static const Map<String, dynamic> commandValidation = {
    'type': 'object',
    'properties': {
      'valid': {'type': 'boolean'},
      'issues': {
        'type': 'array',
        'items': {'type': 'string'},
      },
      'corrected_command': {'type': 'string'},
    },
    'required': ['valid'],
    'additionalProperties': true,
  };
}
