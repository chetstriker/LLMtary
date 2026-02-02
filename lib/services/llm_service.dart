import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/llm_settings.dart';
import '../models/llm_provider.dart';

class LLMService {
  Future<String> sendMessage(LLMSettings settings, String message) async {
    final timeout = Duration(seconds: settings.timeoutSeconds);
    switch (settings.provider) {
      case LLMProvider.ollama:
        return await _sendOllama(settings, message, timeout);
      case LLMProvider.lmStudio:
        return await _sendLMStudio(settings, message, timeout);
      case LLMProvider.claude:
        return await _sendClaude(settings, message, timeout);
      case LLMProvider.chatGPT:
        return await _sendChatGPT(settings, message, timeout);
      case LLMProvider.gemini:
        return await _sendGemini(settings, message, timeout);
      case LLMProvider.openRouter:
        return await _sendOpenRouter(settings, message, timeout);
      default:
        throw Exception('No AI provider selected');
    }
  }

  Future<String> _sendOllama(LLMSettings settings, String message, Duration timeout) async {
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

  Future<String> _sendLMStudio(LLMSettings settings, String message, Duration timeout) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': [{'role': 'user', 'content': message}],
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
      'response_format': {'type': 'json_object'},
    };

    final response = await http.post(
      Uri.parse('${settings.baseUrl}/chat/completions'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final data = json.decode(response.body);
      final choices = data['choices'] as List?;
      return choices?[0]['message']['content'] as String? ?? 'No response';
    }
    throw Exception('LM Studio error: ${response.statusCode}');
  }

  Future<String> _sendClaude(LLMSettings settings, String message, Duration timeout) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'max_tokens': settings.maxTokens,
      'messages': [{'role': 'user', 'content': message}],
      'temperature': settings.temperature,
    };

    // Enable extended thinking for supported models
    if (settings.modelName.contains('sonnet') || settings.modelName.contains('opus')) {
      body['thinking'] = {'type': 'enabled', 'budget_tokens': 10000};
    }

    final response = await http.post(
      Uri.parse('https://api.anthropic.com/v1/messages'),
      headers: {'Content-Type': 'application/json', 'x-api-key': settings.apiKey ?? '', 'anthropic-version': '2023-06-01'},
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final content = json.decode(response.body)['content'] as List?;
      return content?[0]['text'] as String? ?? 'No response';
    }
    throw Exception('Claude error: ${response.statusCode}');
  }

  Future<String> _sendChatGPT(LLMSettings settings, String message, Duration timeout) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': [{'role': 'user', 'content': message}],
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
    };

    // Enable structured outputs for supported models
    if (settings.modelName.contains('gpt-4o') || settings.modelName.contains('gpt-4-turbo')) {
      body['response_format'] = {'type': 'json_object'};
    }

    final response = await http.post(
      Uri.parse('https://api.openai.com/v1/chat/completions'),
      headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final choices = json.decode(response.body)['choices'] as List?;
      return choices?[0]['message']['content'] as String? ?? 'No response';
    }
    throw Exception('ChatGPT error: ${response.statusCode}');
  }

  Future<String> _sendGemini(LLMSettings settings, String message, Duration timeout) async {
    final body = <String, dynamic>{
      'contents': [{'parts': [{'text': message}]}],
      'generationConfig': {
        'temperature': settings.temperature,
        'maxOutputTokens': settings.maxTokens,
        'responseMimeType': 'application/json',
      },
    };

    // Enable Google Search grounding for Pro models
    if (settings.modelName.contains('pro')) {
      body['tools'] = [{'googleSearchRetrieval': {'dynamicRetrievalConfig': {'mode': 'MODE_DYNAMIC', 'dynamicThreshold': 0.3}}}];
    }

    final response = await http.post(
      Uri.parse('https://generativelanguage.googleapis.com/v1beta/models/${settings.modelName}:generateContent?key=${settings.apiKey}'),
      headers: {'Content-Type': 'application/json'},
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final candidates = json.decode(response.body)['candidates'] as List?;
      final parts = candidates?[0]['content']['parts'] as List?;
      return parts?[0]['text'] as String? ?? 'No response';
    }
    throw Exception('Gemini error: ${response.statusCode}');
  }

  Future<String> _sendOpenRouter(LLMSettings settings, String message, Duration timeout) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': [{'role': 'user', 'content': message}],
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
    };

    // Enable web search via Perplexity for all models
    body['transforms'] = ['middle-out'];
    body['provider'] = {
      'allow_fallbacks': true,
      'order': ['Perplexity'],
      'require_parameters': false,
    };

    // Enable structured outputs if model supports it
    if (settings.modelName.contains('gpt-4') || settings.modelName.contains('claude') || settings.modelName.contains('gemini')) {
      body['response_format'] = {'type': 'json_object'};
    }

    final response = await http.post(
      Uri.parse('${settings.baseUrl}/chat/completions'),
      headers: {'Content-Type': 'application/json', 'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
      body: json.encode(body),
    ).timeout(timeout);
    if (response.statusCode == 200) {
      final choices = json.decode(response.body)['choices'] as List?;
      return choices?[0]['message']['content'] as String? ?? 'No response';
    }
    throw Exception('OpenRouter error: ${response.statusCode}');
  }

  Future<List<String>> fetchAvailableModels(LLMSettings settings) async {
    try {
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
          return ['claude-opus-4-5-20251101', 'claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001'];
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
          return ['gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-pro'];
        case LLMProvider.openRouter:
          final response = await http.get(
            Uri.parse('https://openrouter.ai/api/v1/models'),
            headers: {'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
          );
          if (response.statusCode == 200) {
            final data = json.decode(response.body);
            return (data['data'] as List?)?.map((m) => m['id'] as String).toList() ?? [];
          }
          return ['anthropic/claude-3.5-sonnet', 'openai/gpt-4o', 'google/gemini-pro-1.5'];
        default:
          return [];
      }
    } catch (e) {
      return [];
    }
  }
}
