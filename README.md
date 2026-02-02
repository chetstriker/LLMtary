# PenExecute

A Flutter desktop application for automated penetration testing and vulnerability validation using AI-powered analysis.

## Features

- **AI-Powered Vulnerability Analysis**: Analyzes device information to identify security vulnerabilities
- **Automated Exploit Testing**: Uses LLM to generate and execute validation commands
- **Cross-Platform**: Runs on Windows, macOS, and Linux
- **Command Approval Mode**: Optional manual approval before executing commands
- **Real-Time Command Logging**: View all executed commands and their outputs
- **Multiple AI Providers**: Supports Ollama, LM Studio, Claude, ChatGPT, Gemini, and OpenRouter

## Architecture

```
lib/
├── models/           # Data models (Vulnerability, CommandLog, LLMSettings)
├── services/         # Business logic (LLMService, CommandExecutor, VulnerabilityAnalyzer)
├── database/         # SQLite database operations
├── screens/          # UI screens (MainScreen, SettingsScreen)
└── widgets/          # Reusable widgets and state management
```

## Setup

1. Install Flutter SDK
2. Clone repository
3. Run `flutter pub get`
4. Run `flutter run -d windows` (or macos/linux)

## Usage

1. **Configure AI Settings**: Click settings icon, select AI provider, enter credentials
2. **Input Device Data**: Paste device JSON data (ports, services, versions)
3. **Analyze**: Click "Analyze" to identify vulnerabilities
4. **Select & Execute**: Check vulnerabilities to test, click "Execute Selected"
5. **Review Results**: Check status icons (✓ confirmed, ✗ not vulnerable, ? undetermined)
6. **Export Logs**: Download command history for reporting

## Device Data Format

```json
{
  "device": {
    "ip_address": "192.168.1.1",
    "name": "router"
  },
  "open_ports": [
    {
      "port": 80,
      "service": "http",
      "product": "httpd/2.4",
      "version": "2.4.41"
    }
  ]
}
```

## Safety Features

- Dangerous command blocking (rm -rf, format, etc.)
- Command approval mode
- Tool installation validation
- OS-specific command generation
- Timeout protection

## Dependencies

- `sqflite_common_ffi`: SQLite database
- `http`: HTTP requests for AI APIs
- `provider`: State management
- `process_run`: Cross-platform shell execution

## License

Private project - not for public distribution
