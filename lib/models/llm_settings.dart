import 'llm_provider.dart';

class LLMSettings {
  final LLMProvider provider;
  final String? baseUrl;
  final String? apiKey;
  final String modelName;
  final double temperature;
  final int maxTokens;
  final int timeoutSeconds;
  /// Max exploit-loop iterations when the finding has a known CVE. Default 30.
  final int maxIterationsWithCve;
  /// Max exploit-loop iterations for generic/no-CVE findings. Default 15.
  final int maxIterationsNoCve;

  LLMSettings({
    required this.provider,
    this.baseUrl,
    this.apiKey,
    required this.modelName,
    this.temperature = 0.22,
    this.maxTokens = 32000,
    this.timeoutSeconds = 180,
    this.maxIterationsWithCve = 30,
    this.maxIterationsNoCve = 15,
  });

  Map<String, dynamic> toJson() => {
    'provider': provider.name,
    'baseUrl': baseUrl,
    'apiKey': apiKey,
    'modelName': modelName,
    'temperature': temperature,
    'maxTokens': maxTokens,
    'timeoutSeconds': timeoutSeconds,
    'maxIterationsWithCve': maxIterationsWithCve,
    'maxIterationsNoCve': maxIterationsNoCve,
  };

  factory LLMSettings.fromJson(Map<String, dynamic> json) => LLMSettings(
    provider: LLMProvider.values.firstWhere((e) => e.name == json['provider'], orElse: () => LLMProvider.none),
    baseUrl: json['baseUrl'] as String?,
    apiKey: json['apiKey'] as String?,
    modelName: json['modelName'] as String? ?? '',
    temperature: (json['temperature'] as num?)?.toDouble() ?? 0.22,
    maxTokens: json['maxTokens'] as int? ?? 32000,
    timeoutSeconds: json['timeoutSeconds'] as int? ?? 180,
    maxIterationsWithCve: json['maxIterationsWithCve'] as int? ?? 30,
    maxIterationsNoCve: json['maxIterationsNoCve'] as int? ?? 15,
  );

  factory LLMSettings.defaultSettings() => LLMSettings(provider: LLMProvider.none, modelName: '');
}
