import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/llm_settings.dart';
import '../models/llm_provider.dart';

class LLMService {
  final Function(String, String)? onPromptResponse;

  LLMService({this.onPromptResponse});
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

## WEB SEARCH BEHAVIOR:
When analyzing vulnerabilities, you SHOULD search for:
- CVE details: "CVE-XXXX-XXXXX details affected versions"
- Exploits: "[CVE] exploit poc github"
- Metasploit modules: "[CVE] metasploit"
- Tool usage: "[product] [version] exploitation"
- Patches: "[product] [version] security patch"

## RESPONSE REQUIREMENTS:
- Always respond with valid JSON when requested
- Cite specific evidence for all claims
- Include exact version numbers and CVE IDs
- Provide working, non-interactive commands''';

  Future<String> sendMessage(LLMSettings settings, String message, {bool useSystemPrompt = true}) async {
    final timeout = Duration(seconds: settings.timeoutSeconds);
    final systemPrompt = useSystemPrompt ? _securityExpertSystemPrompt : null;

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
        throw Exception('No AI provider selected');
    }

    onPromptResponse?.call(message, response);
    return response;
  }

  Future<String> _sendOllama(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    // Ollama supports system prompt via the 'system' field
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

    final response = await http.post(
      Uri.parse('${settings.baseUrl}/api/generate'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      return json.decode(response.body)['response'] as String? ?? 'No response';
    }
    throw Exception('Ollama error: ${response.statusCode}');
  }

  Future<String> _sendLMStudio(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final messages = <Map<String, String>>[];

    if (systemPrompt != null) {
      messages.add({'role': 'system', 'content': systemPrompt});
    }
    messages.add({'role': 'user', 'content': message});

    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': messages,
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
    };

    final baseUrl = settings.baseUrl?.replaceAll(RegExp(r'/v1/?$'), '') ?? '';
    final response = await http.post(
      Uri.parse('$baseUrl/v1/chat/completions'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final data = json.decode(response.body);
      final choices = data['choices'] as List?;
      return choices?[0]['message']['content'] as String? ?? 'No response';
    }
    throw Exception('LM Studio error: ${response.statusCode} - ${response.body}');
  }

  Future<String> _sendClaude(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'max_tokens': settings.maxTokens,
      'messages': [{'role': 'user', 'content': message}],
    };

    // Add system prompt if provided
    if (systemPrompt != null) {
      body['system'] = systemPrompt;
    }

    // Enable extended thinking for supported models (requires temperature=1)
    if (settings.modelName.contains('sonnet') || settings.modelName.contains('opus')) {
      body['thinking'] = {'type': 'enabled', 'budget_tokens': 10000};
      body['temperature'] = 1; // Required for extended thinking
    } else {
      body['temperature'] = settings.temperature;
    }

    final response = await http.post(
      Uri.parse('https://api.anthropic.com/v1/messages'),
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': settings.apiKey ?? '',
        'anthropic-version': '2023-06-01',
      },
      body: json.encode(body),
    ).timeout(timeout);

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
    throw Exception('Claude error: ${response.statusCode} - ${response.body}');
  }

  Future<String> _sendChatGPT(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final messages = <Map<String, String>>[];

    if (systemPrompt != null) {
      messages.add({'role': 'system', 'content': systemPrompt});
    }
    messages.add({'role': 'user', 'content': message});

    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': messages,
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
      'store': false,
    };

    // Enable structured outputs for supported models
    if (settings.modelName.contains('gpt-4o') || settings.modelName.contains('gpt-4-turbo')) {
      body['response_format'] = {'type': 'json_object'};
    }

    final response = await http.post(
      Uri.parse('https://api.openai.com/v1/chat/completions'),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ${settings.apiKey ?? ''}'
      },
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final choices = json.decode(response.body)['choices'] as List?;
      return choices?[0]['message']['content'] as String? ?? 'No response';
    }
    throw Exception('ChatGPT error: ${response.statusCode}');
  }

  Future<String> _sendGemini(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final contents = <Map<String, dynamic>>[];

    // Gemini uses systemInstruction for system prompts
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

    // Add system instruction if provided
    if (systemPrompt != null) {
      body['systemInstruction'] = {
        'parts': [{'text': systemPrompt}]
      };
    }

    // Enable Google Search grounding for all models (essential for real-time CVE data)
    // Lower threshold = more likely to search
    body['tools'] = [
      {
        'googleSearchRetrieval': {
          'dynamicRetrievalConfig': {
            'mode': 'MODE_DYNAMIC',
            'dynamicThreshold': 0.1  // Lower threshold for more aggressive searching
          }
        }
      }
    ];

    final response = await http.post(
      Uri.parse('https://generativelanguage.googleapis.com/v1beta/models/${settings.modelName}:generateContent?key=${settings.apiKey}'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final responseBody = json.decode(response.body);
      final candidates = responseBody['candidates'] as List?;
      final parts = candidates?[0]['content']['parts'] as List?;
      return parts?[0]['text'] as String? ?? 'No response';
    }
    throw Exception('Gemini error: ${response.statusCode} - ${response.body}');
  }

  Future<String> _sendOpenRouter(LLMSettings settings, String message, Duration timeout, String? systemPrompt) async {
    final messages = <Map<String, String>>[];

    if (systemPrompt != null) {
      messages.add({'role': 'system', 'content': systemPrompt});
    }
    messages.add({'role': 'user', 'content': message});

    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': messages,
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
      'response_format': {'type': 'json_object'},
      'provider': {
        'data_collection': 'deny',
      },
    };

    final response = await http.post(
      Uri.parse('${settings.baseUrl}/chat/completions'),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ${settings.apiKey ?? ''}',
        'HTTP-Referer': 'https://penexecute.app',
        'X-Title': 'PenExecute Security Scanner',
      },
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final choices = json.decode(response.body)['choices'] as List?;
      final content = choices?[0]['message']['content'] as String? ?? '';
      if (content.isEmpty || content == 'No response') {
        throw Exception('Model returned empty response');
      }
      return content;
    }
    throw Exception('OpenRouter error: ${response.statusCode} - ${response.body}');
  }

  Future<List<String>> fetchAvailableModels(LLMSettings settings) async {
    try {
      print('DEBUG: fetchAvailableModels called for ${settings.provider}');
      switch (settings.provider) {
        case LLMProvider.ollama:
          final response = await http.get(Uri.parse('${settings.baseUrl}/api/tags'));
          if (response.statusCode == 200) {
            final data = json.decode(response.body);
            return (data['models'] as List?)?.map((m) => m['name'] as String).toList() ?? [];
          }
          return ['llama2', 'mistral', 'codellama'];
        case LLMProvider.lmStudio:
          final response = await http.get(Uri.parse('${settings.baseUrl}/models'));
          if (response.statusCode == 200) {
            final data = json.decode(response.body);
            return (data['data'] as List?)?.map((m) => m['id'] as String).toList() ?? [];
          }
          return [];
        case LLMProvider.claude:
          return [
            'claude-opus-4-5-20251101',
            'claude-sonnet-4-5-20250929',
            'claude-haiku-4-5-20251001',
            'claude-3-5-sonnet-20241022',
            'claude-3-5-haiku-20241022',
          ];
        case LLMProvider.chatGPT:
          final response = await http.get(
            Uri.parse('https://api.openai.com/v1/models'),
            headers: {'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
          );
          if (response.statusCode == 200) {
            final data = json.decode(response.body);
            return (data['data'] as List?)?.map((m) => m['id'] as String).where((id) => id.startsWith('gpt')).toList() ?? [];
          }
          return ['gpt-4o', 'gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo'];
        case LLMProvider.gemini:
          return [
            'gemini-2.0-flash-exp',    // Latest with enhanced capabilities
            'gemini-1.5-pro-latest',   // Best for complex analysis
            'gemini-1.5-pro',
            'gemini-1.5-flash-latest', // Fast with web search
            'gemini-1.5-flash',
          ];
        case LLMProvider.openRouter:
          print('DEBUG: Fetching OpenRouter models with API key: ${settings.apiKey?.substring(0, 10)}...');
          final response = await http.get(
            Uri.parse('https://openrouter.ai/api/v1/models'),
            headers: {'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
          );
          print('DEBUG: OpenRouter response status: ${response.statusCode}');
          if (response.statusCode == 200) {
            final data = json.decode(response.body);
            final models = (data['data'] as List?)?.map((m) => m['id'] as String).toList() ?? [];
            print('DEBUG: OpenRouter returned ${models.length} models');
            return models;
          }
          print('DEBUG: OpenRouter API failed, returning fallback models');
          return [
            'perplexity/llama-3.1-sonar-huge-128k-online',  // Best for web search
            'perplexity/llama-3.1-sonar-large-128k-online', // Fast web search
            'anthropic/claude-3.5-sonnet',
            'openai/gpt-4o',
            'google/gemini-pro-1.5-exp',
          ];
        default:
          return [];
      }
    } catch (e) {
      print('DEBUG: fetchAvailableModels error: $e');
      return [];
    }
  }
}
