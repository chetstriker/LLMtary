enum LLMProvider {
  none,
  ollama,
  lmStudio,
  claude,
  chatGPT,
  gemini,
  openRouter,
  custom;

  String get displayName {
    switch (this) {
      case LLMProvider.none:
        return 'None';
      case LLMProvider.ollama:
        return 'Ollama';
      case LLMProvider.lmStudio:
        return 'LM Studio';
      case LLMProvider.claude:
        return 'Claude (Anthropic)';
      case LLMProvider.chatGPT:
        return 'ChatGPT (OpenAI)';
      case LLMProvider.gemini:
        return 'Gemini (Google)';
      case LLMProvider.openRouter:
        return 'OpenRouter';
      case LLMProvider.custom:
        return 'Custom';
    }
  }

  bool get requiresApiKey => this == LLMProvider.claude || this == LLMProvider.chatGPT || this == LLMProvider.gemini || this == LLMProvider.openRouter;
  bool get supportsOptionalApiKey => this == LLMProvider.lmStudio;
  bool get requiresBaseUrl => this == LLMProvider.ollama || this == LLMProvider.lmStudio || this == LLMProvider.custom;

  String get defaultBaseUrl {
    switch (this) {
      case LLMProvider.ollama:
        return 'http://localhost:11434';
      case LLMProvider.lmStudio:
        return 'http://localhost:1234/v1';
      case LLMProvider.openRouter:
        return 'https://openrouter.ai/api/v1';
      default:
        return '';
    }
  }
}
