/// Thrown when LLM settings are incomplete or invalid.
class ConfigurationException implements Exception {
  final String message;
  const ConfigurationException(this.message);
  @override
  String toString() => message;
}

/// Thrown when an LLM provider API returns an error.
class LLMApiException implements Exception {
  final String provider;
  final int statusCode;
  final String body;
  const LLMApiException(this.provider, this.statusCode, this.body);
  @override
  String toString() => '$provider error: $statusCode - $body';
}

/// Thrown when an LLM response cannot be parsed as expected JSON.
class LLMParseException implements Exception {
  final String message;
  final String? rawResponse;
  const LLMParseException(this.message, {this.rawResponse});
  @override
  String toString() => message;
}

/// Thrown when a target is outside the defined engagement scope.
class ScopeViolationException implements Exception {
  final String message;
  const ScopeViolationException(this.message);
  @override
  String toString() => message;
}
