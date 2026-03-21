# PenExecute — Technology Stack

## Languages
- **Dart** (primary, SDK ^3.10.4) — all application logic
- **Swift** — macOS runner (MainFlutterWindow, AppDelegate)
- **C++** — Windows runner (win32_window, flutter_window)
- **C** — Linux runner (my_application, GTK)

## Framework
- **Flutter** (stable channel) — desktop-only; no mobile targets
- Material Design with dark theme (`Brightness.dark`, primary `Color(0xFF00F5FF)`)
- Desktop support must be explicitly enabled: `flutter config --enable-<platform>-desktop`

## Key Dependencies (pubspec.yaml)

| Package | Version | Purpose |
|---------|---------|---------|
| `sqflite_common_ffi` | ^2.3.0 | SQLite on desktop (FFI-based; initialized in main()) |
| `provider` | ^6.1.1 | State management (ChangeNotifier/ChangeNotifierProvider) |
| `http` | ^1.2.0 | LLM API HTTP calls |
| `process_run` | ^1.1.0 | Cross-platform shell command execution |
| `path` | ^1.9.0 | Cross-platform file path construction |
| `path_provider` | ^2.1.0 | Platform-specific directory resolution |
| `archive` | ^3.4.0 | ZIP archive creation for .penex export |
| `pointycastle` | ^3.7.0 | AES encryption for .penex bundles |
| `file_picker` | ^8.1.6 | Native file/directory picker dialogs |
| `dropdown_button2` | ^2.3.9 | Enhanced dropdown widget |
| `dbus` | ^0.7.10 | D-Bus integration (Linux) |
| `cupertino_icons` | ^1.0.8 | iOS-style icons |

## Dev Dependencies
- `flutter_lints` ^6.0.0 — lint rules via `analysis_options.yaml`
- `flutter_test` — unit and widget testing

## Database
- **SQLite** via `sqflite_common_ffi` — initialized with `sqfliteFfiInit()` + `databaseFactory = databaseFactoryFfi` in `main()`
- Tables: projects, targets, vulnerabilities, command_logs, prompt_logs, debug_logs, credentials, settings, provider_settings
- DB file: `.dart_tool/sqflite_common_ffi/databases/penexecute.db`

## Build Commands
```bash
flutter pub get              # Install dependencies
flutter analyze              # Run linter (flutter_lints)
flutter test                 # Run all tests
flutter test test/<file>     # Run single test file
flutter run -d linux         # Run on Linux
flutter run -d macos         # Run on macOS
flutter run -d windows       # Run on Windows
flutter build linux --release
flutter build macos --release
flutter build windows --release
```

## Platform Build Systems
- **Linux**: CMake (`linux/CMakeLists.txt`)
- **macOS**: Xcode workspace (`macos/Runner.xcworkspace`), CocoaPods (`Podfile`)
- **Windows**: CMake (`windows/CMakeLists.txt`)

## LLM Provider Integration (llm_service.dart)
All providers share a unified interface. HTTP calls via `package:http`.

| Provider | Base URL | Auth |
|----------|----------|------|
| Ollama | `http://localhost:11434` | None |
| LM Studio | `http://localhost:1234/v1` | None |
| Claude | `https://api.anthropic.com` | `x-api-key` header |
| ChatGPT | `https://api.openai.com/v1` | Bearer token |
| Gemini | `https://generativelanguage.googleapis.com` | API key param |
| OpenRouter | `https://openrouter.ai/api/v1` | Bearer token |
| Custom | Configurable | Configurable |

## Shell Execution (command_executor.dart)
- **Linux/macOS**: `sh -c` or `bash -c`
- **Windows**: PowerShell or cmd; WSL bash when detected
- Exposes: `Platform.isWindows`, `Platform.isMacOS`, `Platform.isLinux`, WSL detection flag
- Dangerous command blocklist enforced before execution

## Encryption (.penex files)
- AES via `pointycastle`
- ZIP archive via `archive`
- Password-protected; lost passwords unrecoverable

## Linting
- `analysis_options.yaml` includes `package:flutter_lints/flutter.yaml`
- No custom rules enabled by default (commented out examples only)
