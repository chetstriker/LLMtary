import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/llm_settings.dart';
import '../models/llm_provider.dart';
import '../utils/app_exceptions.dart';

/// Phase A.3: Simple counting semaphore for limiting concurrent LLM calls.
///
/// Used by [LLMService] to prevent cloud providers from being overwhelmed when
/// multiple targets are analyzed in parallel. Local providers (Ollama, LM Studio)
/// are exempt — call [LLMSemaphore.isCloudProvider] to check.
class LLMSemaphore {
  final int maxConcurrent;
  int _current = 0;
  final _queue = Queue<Completer<void>>();

  LLMSemaphore(this.maxConcurrent);

  /// Returns true for cloud LLM providers that need rate-limit protection.
  static bool isCloudProvider(LLMProvider provider) {
    switch (provider) {
      case LLMProvider.claude:
      case LLMProvider.chatGPT:
      case LLMProvider.gemini:
      case LLMProvider.openRouter:
        return true;
      default:
        return false;
    }
  }

  Future<void> acquire() async {
    if (_current < maxConcurrent) {
      _current++;
      return;
    }
    final completer = Completer<void>();
    _queue.add(completer);
    await completer.future;
  }

  void release() {
    if (_queue.isNotEmpty) {
      final next = _queue.removeFirst();
      next.complete();
    } else {
      _current--;
    }
  }

  /// Convenience wrapper: acquires the semaphore, runs [fn], then releases.
  Future<T> run<T>(Future<T> Function() fn) async {
    await acquire();
    try {
      return await fn();
    } finally {
      release();
    }
  }
}

class LLMService {
  final Function(String, String)? onPromptResponse;
  bool enableDebugLogging;

  /// Phase E.4: Session-level retry counter — incremented on every retry across
  /// all LLM calls. When it exceeds [_retryWarningThreshold], a suggestion is
  /// logged to encourage the user to check their provider.
  int _sessionRetryCount = 0;
  static const int _retryWarningThreshold = 10;

  /// Phase E.1: Maximum retry attempts (first attempt + 2 retries = 3 total).
  static const int _maxRetries = 2;

  /// Phase A.3: Global semaphore shared across all LLMService instances.
  /// Limits concurrent in-flight calls to cloud providers (Claude, ChatGPT,
  /// Gemini, OpenRouter) to avoid overwhelming rate limits when many targets
  /// are analyzed in parallel. Default: 10 concurrent cloud calls.
  static final LLMSemaphore globalCloudSemaphore = LLMSemaphore(10);

  LLMService({this.onPromptResponse, this.enableDebugLogging = false});

  /// Returns a `[HH:MM:SS.mmm]` timestamp string for console output.
  static String _ts() => '[${DateTime.now().toIso8601String().substring(11, 23)}]';

  /// Prints [text] in chunks so Flutter's debug console doesn't truncate it.
  static void _printLong(String label, String text) {
    const chunkSize = 800;
    final ts = _ts();
    if (text.length <= chunkSize) {
      print('$ts $label: $text');
      return;
    }
    print('$ts $label (${text.length} chars):');
    for (var i = 0; i < text.length; i += chunkSize) {
      print(text.substring(i, i + chunkSize > text.length ? text.length : i + chunkSize));
    }
  }
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

  Future<String> sendMessage(LLMSettings settings, String message, {
    bool useSystemPrompt = true,
    String? systemPromptOverride,
    void Function(int sent, int received)? onTokensUsed,
  }) async {
    final timeout = Duration(seconds: settings.timeoutSeconds);
    final systemPrompt = systemPromptOverride ?? (useSystemPrompt ? _securityExpertSystemPrompt : null);

    print('${_ts()}\n=== LLM REQUEST ===');
    print('${_ts()} Provider: ${settings.provider.displayName}');
    print('${_ts()} Model: ${settings.modelName}');
    _printLong('Prompt', message);

    // Phase E.1: Retry loop — up to _maxRetries retries on timeout and transient errors.
    // E.3: Timeout is unchanged on retries so the model has a full budget per attempt.
    // Max wall-clock time: (1 + _maxRetries) * timeoutSeconds + backoff delays.
    String response = '';
    Exception? lastException;
    for (int attempt = 0; attempt <= _maxRetries; attempt++) {
      if (attempt > 0) {
        _sessionRetryCount++;
        print('${_ts()} LLM call failed, retrying (attempt ${attempt + 1}/${_maxRetries + 1})...');
        // E.4: warn when session accumulates many retries
        if (_sessionRetryCount == _retryWarningThreshold) {
          print('${_ts()} WARNING: Multiple LLM timeouts detected ($_sessionRetryCount retries). '
              'Consider increasing timeout in AI Settings or checking provider status.');
        }
      }

      try {
        // Phase A.3: Acquire the global semaphore for cloud providers to prevent
        // overwhelming rate limits when multiple targets run analysis in parallel.
        // Local providers (Ollama, LM Studio) skip the semaphore entirely.
        Future<String> doProviderCall() async {
          switch (settings.provider) {
            case LLMProvider.ollama:
              return await _sendOllama(settings, message, timeout, systemPrompt, onTokensUsed: onTokensUsed);
            case LLMProvider.lmStudio:
              return await _sendLMStudio(settings, message, timeout, systemPrompt, onTokensUsed: onTokensUsed);
            case LLMProvider.claude:
              return await _sendClaude(settings, message, timeout, systemPrompt, onTokensUsed: onTokensUsed);
            case LLMProvider.chatGPT:
              return await _sendChatGPT(settings, message, timeout, systemPrompt, onTokensUsed: onTokensUsed);
            case LLMProvider.gemini:
              return await _sendGemini(settings, message, timeout, systemPrompt, onTokensUsed: onTokensUsed);
            case LLMProvider.openRouter:
              return await _sendOpenRouter(settings, message, timeout, systemPrompt, onTokensUsed: onTokensUsed);
            default:
              throw const ConfigurationException('No AI provider selected');
          }
        }

        if (LLMSemaphore.isCloudProvider(settings.provider)) {
          response = await globalCloudSemaphore.run(doProviderCall);
        } else {
          response = await doProviderCall();
        }
        // Success — exit retry loop
        lastException = null;
        break;
      } on LLMApiException catch (e) {
        // Retry on transient HTTP errors (429, 5xx); rethrow on client errors (4xx)
        if (e.statusCode == 429 || e.statusCode >= 500) {
          lastException = e;
          if (attempt < _maxRetries) {
            // Phase E.1: 429 uses Retry-After if available, else exponential backoff
            final backoffSeconds = attempt == 0 ? 5 : 15;
            print('${_ts()} HTTP ${e.statusCode} from ${settings.provider.displayName} — '
                'waiting ${backoffSeconds}s before retry ${attempt + 2}/${_maxRetries + 1}...');
            await Future.delayed(Duration(seconds: backoffSeconds));
          }
        } else {
          rethrow; // 400/401/403 — don't retry
        }
      } on TimeoutException catch (e) {
        lastException = e;
        if (attempt < _maxRetries) {
          final backoffSeconds = attempt == 0 ? 3 : 10;
          print('${_ts()} LLM call timed out — waiting ${backoffSeconds}s before retry '
              '${attempt + 2}/${_maxRetries + 1}...');
          await Future.delayed(Duration(seconds: backoffSeconds));
        }
      } catch (e) {
        // Non-retryable errors (config errors, network hard failures, etc.)
        rethrow;
      }
    }

    // If all attempts failed, rethrow the last exception
    if (lastException != null) throw lastException;

    print('${_ts()}\n=== LLM RESPONSE ===');
    _printLong('Response', response);
    print('${_ts()} ==================\n');

    onPromptResponse?.call(message, response);
    return response;
  }

  // --- Shared HTTP helpers ---

  /// Send an HTTP POST with debug logging and error checking.
  ///
  /// Uses a dedicated [http.Client] per request so that on timeout the client
  /// is forcibly closed, tearing down the underlying TCP socket. Without this,
  /// `Future.timeout()` on `http.post()` can hang indefinitely when the server
  /// accepts the connection but stops responding mid-stream.
  Future<http.Response> _sendHttpPost(
    String url,
    Map<String, String> headers,
    Map<String, dynamic> body,
    Duration timeout,
    String providerName,
  ) async {
    if (enableDebugLogging) {
      print('${_ts()} DEBUG [$providerName]: POST $url');
      print('${_ts()} DEBUG [$providerName]: Model: ${body['model'] ?? 'N/A'}');
      if (headers.length > 1) {
        print('${_ts()} DEBUG [$providerName]: Headers: ${headers.keys.join(", ")}');
      }
    }

    final client = http.Client();
    try {
      final response = await client.post(
        Uri.parse(url),
        headers: headers,
        body: json.encode(body),
      ).timeout(timeout, onTimeout: () {
        // Forcibly close the client to tear down the TCP socket.
        client.close();
        throw TimeoutException('$providerName request timed out after ${timeout.inSeconds}s', timeout);
      });

      if (enableDebugLogging) {
        print('${_ts()} DEBUG [$providerName]: Response status: ${response.statusCode}');
        if (response.statusCode != 200) {
          print('${_ts()} DEBUG [$providerName]: Response body: ${response.body}');
        }
      }

      return response;
    } catch (e) {
      // Ensure the client is always closed, even on non-timeout errors.
      client.close();
      rethrow;
    }
  }

  /// Build the standard OpenAI-compatible messages array.
  /// Send a multi-turn conversation as a pre-built message list.
  /// For providers that support multi-turn (OpenAI-compatible: LM Studio,
  /// ChatGPT, OpenRouter), this sends the full conversation. For others,
  /// it falls back to extracting the last user message and system prompt.
  /// Phase E.2: sendMessages() uses the same retry logic as sendMessage().
  /// The retry wraps the outer provider call so all providers benefit from it.
  Future<String> sendMessages(LLMSettings settings, List<Map<String, String>> messages, {
    void Function(int sent, int received)? onTokensUsed,
  }) async {
    // Extract system prompt and last user message for providers that need them
    String? systemPrompt;
    String lastUserMessage = '';
    for (final msg in messages) {
      if (msg['role'] == 'system') systemPrompt = msg['content'];
      if (msg['role'] == 'user') lastUserMessage = msg['content'] ?? '';
    }

    final timeout = Duration(seconds: settings.timeoutSeconds);

    print('${_ts()}\n=== LLM CONVERSATION ===');
    print('${_ts()} Provider: ${settings.provider.displayName}');
    print('${_ts()} Messages: ${messages.length}');

    // Non-OpenAI providers fall back to sendMessage() which already has retry logic
    switch (settings.provider) {
      case LLMProvider.lmStudio:
      case LLMProvider.chatGPT:
      case LLMProvider.openRouter:
        break; // handled below with retry loop
      default:
        return await sendMessage(settings, lastUserMessage,
            systemPromptOverride: systemPrompt, onTokensUsed: onTokensUsed);
    }

    // Phase E.2: Retry loop for OpenAI-compatible multi-turn providers
    String response = '';
    Exception? lastException;
    for (int attempt = 0; attempt <= _maxRetries; attempt++) {
      if (attempt > 0) {
        _sessionRetryCount++;
        print('${_ts()} LLM conversation failed, retrying (attempt ${attempt + 1}/${_maxRetries + 1})...');
        if (_sessionRetryCount == _retryWarningThreshold) {
          print('${_ts()} WARNING: Multiple LLM timeouts detected ($_sessionRetryCount retries). '
              'Consider increasing timeout in AI Settings or checking provider status.');
        }
      }

      try {
        Future<String> doConversationCall() async {
          switch (settings.provider) {
            case LLMProvider.lmStudio:
              return await _sendLMStudioMessages(settings, messages, timeout, onTokensUsed: onTokensUsed);
            case LLMProvider.chatGPT:
              return await _sendChatGPTMessages(settings, messages, timeout, onTokensUsed: onTokensUsed);
            case LLMProvider.openRouter:
              return await _sendOpenRouterMessages(settings, messages, timeout, onTokensUsed: onTokensUsed);
            default:
              return '';
          }
        }
        // Phase A.3: All conversation providers here are cloud providers
        response = await globalCloudSemaphore.run(doConversationCall);
        lastException = null;
        break;
      } on LLMApiException catch (e) {
        if (e.statusCode == 429 || e.statusCode >= 500) {
          lastException = e;
          if (attempt < _maxRetries) {
            final backoffSeconds = attempt == 0 ? 5 : 15;
            print('${_ts()} HTTP ${e.statusCode} — waiting ${backoffSeconds}s before retry '
                '${attempt + 2}/${_maxRetries + 1}...');
            await Future.delayed(Duration(seconds: backoffSeconds));
          }
        } else {
          rethrow;
        }
      } on TimeoutException catch (e) {
        lastException = e;
        if (attempt < _maxRetries) {
          final backoffSeconds = attempt == 0 ? 3 : 10;
          print('${_ts()} LLM conversation timed out — waiting ${backoffSeconds}s before retry '
              '${attempt + 2}/${_maxRetries + 1}...');
          await Future.delayed(Duration(seconds: backoffSeconds));
        }
      } catch (e) {
        rethrow;
      }
    }

    if (lastException != null) throw lastException;

    print('${_ts()}\n=== LLM RESPONSE ===');
    _printLong('Response', response);
    print('${_ts()} ==================\n');

    onPromptResponse?.call(lastUserMessage, response);
    return response;
  }

  /// LM Studio: send full conversation message list.
  Future<String> _sendLMStudioMessages(LLMSettings settings, List<Map<String, String>> messages, Duration timeout, {void Function(int, int)? onTokensUsed}) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': messages,
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
    };
    final url = '${settings.baseUrl}/v1/chat/completions';
    final response = await _sendHttpPost(
      url, {'Content-Type': 'application/json'}, body, timeout, 'LM Studio',
    );
    if (response.statusCode == 200) {
      final decoded = json.decode(response.body);
      final usage = decoded['usage'] as Map<String, dynamic>?;
      if (onTokensUsed != null && usage != null) {
        onTokensUsed(usage['prompt_tokens'] as int? ?? 0, usage['completion_tokens'] as int? ?? 0);
      }
    }
    return _extractChatResponse(response, 'LM Studio');
  }

  /// ChatGPT: send full conversation message list.
  Future<String> _sendChatGPTMessages(LLMSettings settings, List<Map<String, String>> messages, Duration timeout, {void Function(int, int)? onTokensUsed}) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': messages,
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
      'store': false,
    };
    if (settings.modelName.contains('gpt-4o') || settings.modelName.contains('gpt-4-turbo')) {
      body['response_format'] = {'type': 'json_object'};
    }
    final response = await _sendHttpPost(
      'https://api.openai.com/v1/chat/completions',
      {'Content-Type': 'application/json', 'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
      body, timeout, 'ChatGPT',
    );
    if (response.statusCode == 200) {
      final decoded = json.decode(response.body);
      final usage = decoded['usage'] as Map<String, dynamic>?;
      if (onTokensUsed != null && usage != null) {
        onTokensUsed(usage['prompt_tokens'] as int? ?? 0, usage['completion_tokens'] as int? ?? 0);
      }
    }
    return _extractChatResponse(response, 'ChatGPT');
  }

  /// OpenRouter: send full conversation message list.
  Future<String> _sendOpenRouterMessages(LLMSettings settings, List<Map<String, String>> messages, Duration timeout, {void Function(int, int)? onTokensUsed}) async {
    final body = <String, dynamic>{
      'model': settings.modelName,
      'messages': messages,
      'temperature': settings.temperature,
      'max_tokens': settings.maxTokens,
    };
    final response = await _sendHttpPost(
      'https://openrouter.ai/api/v1/chat/completions',
      {'Content-Type': 'application/json', 'Authorization': 'Bearer ${settings.apiKey ?? ''}'},
      body, timeout, 'OpenRouter',
    );
    if (response.statusCode == 200) {
      final decoded = json.decode(response.body);
      final usage = decoded['usage'] as Map<String, dynamic>?;
      if (onTokensUsed != null && usage != null) {
        onTokensUsed(usage['prompt_tokens'] as int? ?? 0, usage['completion_tokens'] as int? ?? 0);
      }
    }
    return _extractChatResponse(response, 'OpenRouter');
  }

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

  Future<String> _sendOllama(LLMSettings settings, String message, Duration timeout, String? systemPrompt, {void Function(int, int)? onTokensUsed}) async {
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
      final body = json.decode(response.body);
      final text = body['response'] as String? ?? 'No response';
      if (onTokensUsed != null) {
        final sent = body['prompt_eval_count'] as int? ?? message.length ~/ 4;
        final received = body['eval_count'] as int? ?? text.length ~/ 4;
        onTokensUsed(sent, received);
      }
      return text;
    }
    throw LLMApiException('Ollama', response.statusCode, response.body);
  }

  Future<String> _sendLMStudio(LLMSettings settings, String message, Duration timeout, String? systemPrompt, {void Function(int, int)? onTokensUsed}) async {
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
    if (response.statusCode == 200) {
      final decoded = json.decode(response.body);
      final usage = decoded['usage'] as Map<String, dynamic>?;
      if (onTokensUsed != null && usage != null) {
        onTokensUsed(
          usage['prompt_tokens'] as int? ?? message.length ~/ 4,
          usage['completion_tokens'] as int? ?? 0,
        );
      }
    }
    return _extractChatResponse(response, 'LM Studio');
  }

  Future<String> _sendClaude(LLMSettings settings, String message, Duration timeout, String? systemPrompt, {void Function(int, int)? onTokensUsed}) async {
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
      final decoded = json.decode(response.body);
      final usage = decoded['usage'] as Map<String, dynamic>?;
      if (onTokensUsed != null && usage != null) {
        onTokensUsed(
          usage['input_tokens'] as int? ?? message.length ~/ 4,
          usage['output_tokens'] as int? ?? 0,
        );
      }
      final content = decoded['content'] as List?;
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

  Future<String> _sendChatGPT(LLMSettings settings, String message, Duration timeout, String? systemPrompt, {void Function(int, int)? onTokensUsed}) async {
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
    if (response.statusCode == 200) {
      final decoded = json.decode(response.body);
      final usage = decoded['usage'] as Map<String, dynamic>?;
      if (onTokensUsed != null && usage != null) {
        onTokensUsed(
          usage['prompt_tokens'] as int? ?? message.length ~/ 4,
          usage['completion_tokens'] as int? ?? 0,
        );
      }
    }
    return _extractChatResponse(response, 'ChatGPT');
  }

  Future<String> _sendGemini(LLMSettings settings, String message, Duration timeout, String? systemPrompt, {void Function(int, int)? onTokensUsed}) async {
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
      final meta = responseBody['usageMetadata'] as Map<String, dynamic>?;
      if (onTokensUsed != null && meta != null) {
        onTokensUsed(
          meta['promptTokenCount'] as int? ?? message.length ~/ 4,
          meta['candidatesTokenCount'] as int? ?? 0,
        );
      }
      final candidates = responseBody['candidates'] as List?;
      final parts = candidates?[0]['content']['parts'] as List?;
      return parts?[0]['text'] as String? ?? 'No response';
    }
    throw LLMApiException('Gemini', response.statusCode, response.body);
  }

  Future<String> _sendOpenRouter(LLMSettings settings, String message, Duration timeout, String? systemPrompt, {void Function(int, int)? onTokensUsed}) async {
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
        'HTTP-Referer': 'https://llmtary.app',
        'X-Title': 'LLMtary Security Scanner',
      },
      body,
      timeout,
      'OpenRouter',
    );

    if (response.statusCode == 200) {
      final decoded = json.decode(response.body);
      final usage = decoded['usage'] as Map<String, dynamic>?;
      if (onTokensUsed != null && usage != null) {
        onTokensUsed(
          usage['prompt_tokens'] as int? ?? message.length ~/ 4,
          usage['completion_tokens'] as int? ?? 0,
        );
      }
      final choices = decoded['choices'] as List?;
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
      print('${_ts()} DEBUG [$providerName Models]: GET $url');
    }

    final response = await http.get(Uri.parse(url), headers: headers);

    if (enableDebugLogging) {
      print('${_ts()} DEBUG [$providerName Models]: Response status: ${response.statusCode}');
    }

    if (response.statusCode == 200) {
      final data = json.decode(response.body);
      final models = extractModels(data);
      print('${_ts()} DEBUG: $providerName returned ${models.length} models');
      return models;
    }

    print('${_ts()} DEBUG: $providerName API failed');
    return [];
  }

  Future<List<String>> fetchAvailableModels(LLMSettings settings) async {
    try {
      print('${_ts()} DEBUG: fetchAvailableModels called for ${settings.provider}');
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
      print('${_ts()} DEBUG: fetchAvailableModels error: $e');
      return [];
    }
  }
}
