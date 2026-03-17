import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/llm_settings.dart';
import '../models/llm_provider.dart';
import '../utils/app_exceptions.dart';

class LLMService {
  final Function(String, String)? onPromptResponse;
  bool enableDebugLogging;

  LLMService({this.onPromptResponse, this.enableDebugLogging = false});
  // System prompt establishing expertise and enabling web search behavior
  static const String _securityExpertSystemPrompt = '''You are an elite penetration tester and cybersecurity expert with deep expertise in:
- Vulnerability assessment and exploitation techniques
- CVE analysis and exploit development
- Network security, web application security, and infrastructure security
- Tools: Metasploit, Nmap, Burp Suite, sqlmap, nuclei, searchsploit, and custom exploits
- OWASP Top 10, MITRE ATT&CK framework, and CVSS scoring

## CORE PRINCIPLES:
1. ACCURACY: Never guess - verify everything with evidence
2. THOROUGHNESS: Consider all attack vectors and exploitation paths
3. PRECISION: Provide exact commands, exact versions, exact CVE IDs
4. SAFETY: Focus on proof-of-concept, avoid destructive actions

## RESPONSE REQUIREMENTS:
- Always respond with valid JSON when requested
- Cite specific evidence for all claims
- Include exact version numbers and CVE IDs
- Provide working, non-interactive commands
- Do NOT suggest curling Google, MITRE, or NVD websites — they return CAPTCHAs or block automated requests
- Use your training knowledge for CVE details and exploit techniques''';

  Future<String> sendMessage(LLMSettings settings, String message, {bool useSystemPrompt = true}) async {
    final timeout = Duration(seconds: settings.timeoutSeconds);
    final systemPrompt = useSystemPrompt ? _securityExpertSystemPrompt : null;

    print('\n=== LLM REQUEST ===');
    print('Provider: ${settings.provider.displayName}');
    print('Model: ${settings.modelName}');
    print('Prompt: ${message.substring(0, message.length > 200 ? 200 : message.length)}...');

    String response;
    switch (settings.provider) {
      case LLMProvider.ollama:
        response = await _sendOllama(settings, message, timeout, systemPrompt);
        break;
      case LLMProvider.lmStudio:
        response = await _sendLMStudio(settings, message, timeout, systemPrompt);
        break;
      case LLMProvider.claude:
        response = await _sendClaude(settings, message, timeout, systemPrompt);
        break;
      case LLMProvider.chatGPT:
        response = await _sendChatGPT(settings, message, timeout, systemPrompt);
        break;
      case LLMProvider.gemini:
        response = await _sendGemini(settings, message, timeout, systemPrompt);
        break;
      case LLMProvider.openRouter:
        response = await _sendOpenRouter(settings, message, timeout, systemPrompt);
        break;
      default:
        throw const ConfigurationException('No AI provider selected');
    }

    print('\n=== LLM RESPONSE ===');
    print('Response: ${response.substring(0, response.length > 500 ? 500 : response.length)}...');
    print('==================\n');

    onPromptResponse?.call(message, response);
    return response;
  }

  // --- Shared HTTP helpers ---

  /// Send an HTTP POST with debug logging and error checking.
  Future<http.Response> _sendHttpPost(
    String url,
    Map<String, String> headers,
    Map<String, dynamic> body,
    Duration timeout,
    String providerName,
  ) async {
    if (enableDebugLogging) {
      print('DEBUG [$providerName]: POST $url');
      print('DEBUG [$providerName]: Model: ${body['model'] ?? 'N/A'}');
      if (headers.length > 1) {
        print('DEBUG [$providerName]: Headers: ${headers.keys.join(", ")}');
      }
    }

    final response = await http.post(
      Uri.parse(url),
      headers: headers,
      body: json.encode(body),
    ).timeout(timeout);

    if (enableDebugLogging) {
      print('DEBUG [$providerName]: Response status: ${response.statusCode}');
      if (response.statusCode != 200) {
        print('DEBUG [$providerName]: Response body: ${response.body}');
      }
    }

    return response;
  }

  /// Build the standard OpenAI-compatible messages array.
  List<Map<String, String>> _buildChatMessages(String message, String? systemPrompt) {
    final messages = <Map<String, String>>[];
    if (systemPrompt != null) {
      messages.add({'role': 'system', 'content': systemPrompt});
    }
    messages.add({'role': 'user', 'content': message});
    return messages;
  }

  /// Extract text from an OpenAI-compatible chat completion response.
  String _extractChatResponse(http.Response response, String providerName) {
    if (response.statusCode == 200) {
      final choices = json.decode(response.body)['choices'] as List?;
      return choices?[0]['message']['content'] as String? ?? 'No response';
    }
    throw LLMApiException(providerName, response.statusCode, response.body);
  }

  // --- Provider implementations ---

  Future<String> _sendOllama(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'prompt': message,
      'stream': false,
      'format': 'json',
      'options': {
        'temperature': settings.temperature,
        'num_predict': settings.maxTokens,
      },
    };

    if (systemPrompt != null) {
      body['system'] = systemPrompt;
    }

    final url = '${settings.baseUrl}/api/generate';
    final response = await _sendHttpPost(
      url, {'Content-Type': 'application/json'}, body, timeout, 'Ollama',
    );

    if (response.statusCode == 200) {
      return json.decode(response.body)['response'] as String? ?? 'No response';
    }
    throw LLMApiException('Ollama', response.statusCode, response.body);
  }

  Future<String> _sendLMStudio(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': _buildChatMessages(message, systemPrompt),
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
    };

    final headers = <String, String>{'Content-Type': 'application/json'};
    if (settings.apiKey != null && settings.apiKey!.trim().isNotEmpty) {
      headers['Authorization'] = 'Bearer ${settings.apiKey}';
    }

    final baseUrl = settings.baseUrl?.replaceAll(RegExp(r'/v1/?$'), '') ?? '';
    final url = '$baseUrl/v1/chat/completions';
    final response = await _sendHttpPost(url, headers, body, timeout, 'LM Studio');
    return _extractChatResponse(response, 'LM Studio');
  }

  Future<String> _sendClaude(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'max_tokens': settings.maxTokens,
      'messages': [{'role': 'user', 'content': message}],
    };

    if (systemPrompt != null) {
      body['system'] = systemPrompt;
    }

    // Enable extended thinking for supported models (requires temperature=1)
    if (settings.modelName.contains('sonnet') || settings.modelName.contains('opus')) {
      body['thinking'] = {'type': 'enabled', 'budget_tokens': 10000};
      body['temperature'] = 1;
    } else {
      body['temperature'] = settings.temperature;
    }

    final response = await _sendHttpPost(
      'https://api.anthropic.com/v1/messages',
      {
        'Content-Type': 'application/json',
        'x-api-key': settings.apiKey ?? '',
        'anthropic-version': '2023-06-01',
      },
      body,
      timeout,
      'Claude',
    );

    if (response.statusCode == 200) {
      final content = json.decode(response.body)['content'] as List?;
      // Find the text block (skip thinking blocks)
      for (var block in content ?? []) {
        if (block['type'] == 'text') {
          return block['text'] as String? ?? 'No response';
        }
      }
      return content?[0]['text'] as String? ?? 'No response';
    }
    throw LLMApiException('Claude', response.statusCode, response.body);
  }

  Future<String> _sendChatGPT(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': _buildChatMessages(message, systemPrompt),
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
      'store': false,
    };

    // Enable structured outputs for supported models
    if (settings.modelName.contains('gpt-4o') || settings.modelName.contains('gpt-4-turbo')) {
      body['response_format'] = {'type': 'json_object'};
    }

    final response = await _sendHttpPost(
      'https://api.openai.com/v1/chat/completions',
      {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ${settings.apiKey ?? ''}',
      },
      body,
      timeout,
      'ChatGPT',
    );
    return _extractChatResponse(response, 'ChatGPT');
  }

  Future<String> _sendGemini(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final body = <String, dynamic>{
      'contents': [
        {
          'role': 'user',
          'parts': [{'text': message}]
        }
      ],
      'generationConfig': {
        'temperature': settings.temperature,
        'maxOutputTokens': settings.maxTokens,
        'responseMimeType': 'application/json',
      },
    };

    if (systemPrompt != null) {
      body['systemInstruction'] = {
        'parts': [{'text': systemPrompt}]
      };
    }

    // Enable Google Search grounding (essential for real-time CVE data)
    body['tools'] = [
      {
        'googleSearchRetrieval': {
          'dynamicRetrievalConfig': {
            'mode': 'MODE_DYNAMIC',
            'dynamicThreshold': 0.1,
          }
        }
      }
    ];

    final url = 'https://generativelanguage.googleapis.com/v1beta/models/${settings.modelName}:generateContent?key=${settings.apiKey}';
    final response = await _sendHttpPost(
      url, {'Content-Type': 'application/json'}, body, timeout, 'Gemini',
    );

    if (response.statusCode == 200) {
      final responseBody = json.decode(response.body);
      final candidates = responseBody['candidates'] as List?;
      final parts = candidates?[0]['content']['parts'] as List?;
      return parts?[0]['text'] as String? ?? 'No response';
    }
    throw LLMApiException('Gemini', response.statusCode, response.body);
  }

  Future<String> _sendOpenRouter(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': _buildChatMessages(message, systemPrompt),
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
      'provider': {'data_collection': 'deny'},
    };

    final baseUrl = settings.baseUrl?.isNotEmpty == true ? settings.baseUrl : 'https://openrouter.ai/api/v1';
    final url = '$baseUrl/chat/completions';
    final response = await _sendHttpPost(
      url,
      {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ${settings.apiKey ?? ''}',
        'HTTP-Referer': 'https://penexecute.app',
        'X-Title': 'PenExecute Security Scanner',
      },
      body,
      timeout,
      'OpenRouter',
    );

    if (response.statusCode == 200) {
      final choices = json.decode(response.body)['choices'] as List?;
      final content = choices?[0]['message']['content'] as String? ?? '';
      if (content.isEmpty || content == 'No response') {
        throw const LLMApiException('OpenRouter', 200, 'Model returned empty response');
      }
      return content;
    }
    throw LLMApiException('OpenRouter', response.statusCode, response.body);
  }

  /// Fetch and parse a model list from an API endpoint.
  Future<List<String>> _fetchModelList(
    String url,
    Map<String, String> headers,
    String providerName,
    List<String> Function(Map<String, dynamic> data) extractModels,
  ) async {
    if (enableDebugLogging) {
      print('DEBUG [$providerName Models]: GET $url');
    }

    final response = await http.get(Uri.parse(url), headers: headers);

    if (enableDebugLogging) {
      print('DEBUG [$providerName Models]: Response status: ${response.statusCode}');
    }

    if (response.statusCode == 200) {
      final data = json.decode(response.body);
      final models = extractModels(data);
      print('DEBUG: $providerName returned ${models.length} models');
      return models;
    }

    print('DEBUG: $providerName API failed');
    return [];
  }

  Future<List<String>> fetchAvailableModels(LLMSettings settings) async {
    try {
      print('DEBUG: fetchAvailableModels called for ${settings.provider}');
      switch (settings.provider) {
        case LLMProvider.ollama:
          return _fetchModelList(
            '${settings.baseUrl}/api/tags', {}, 'Ollama',
            (data) => (data['models'] as List?)?.map((m) => m['name'] as String).toList() ?? [],
          );
        case LLMProvider.lmStudio:
          final headers = <String, String>{};
          if (settings.apiKey != null && settings.apiKey!.trim().isNotEmpty) {
            headers['Authorization'] = 'Bearer ${settings.apiKey}';
          }
          final baseUrl = settings.baseUrl?.replaceAll(RegExp(r'/v1/?$'), '') ?? '';
          return _fetchModelList(
            '$baseUrl/v1/models', headers, 'LM Studio',
            (data) => (data['data'] as List?)?.map((m) => m['id'] as String).toList() ?? [],
          );
        case LLMProvider.claude:
          return _fetchModelList(
            'https://api.anthropic.com/v1/models',
            {'x-api-key': settings.apiKey ?? '', 'anthropic-version': '2023-06-01'},
            'Claude',
            (data) => (data['data'] as List?)?.map((m) => m['id'] as String).toList() ?? [],
          );
        case LLMProvider.chatGPT:
          return _fetchModelList(
            'https://api.openai.com/v1/models',
            {'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
            'ChatGPT',
            (data) => (data['data'] as List?)
                ?.map((m) => m['id'] as String)
                .where((id) => id.startsWith('gpt'))
                .toList() ?? [],
          );
        case LLMProvider.gemini:
          return _fetchModelList(
            'https://generativelanguage.googleapis.com/v1beta/models?key=${settings.apiKey}',
            {}, 'Gemini',
            (data) => (data['models'] as List?)
                ?.where((m) => (m['supportedGenerationMethods'] as List?)?.contains('generateContent') ?? false)
                .map((m) => (m['name'] as String).replaceFirst('models/', ''))
                .toList() ?? [],
          );
        case LLMProvider.openRouter:
          return _fetchModelList(
            'https://openrouter.ai/api/v1/models',
            {'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
            'OpenRouter',
            (data) => (data['data'] as List?)?.map((m) => m['id'] as String).toList() ?? [],
          );
        default:
          return [];
      }
    } catch (e) {
      print('DEBUG: fetchAvailableModels error: $e');
      return [];
    }
  }
}
