# PenExecute — Project Structure

## Directory Layout

```
penexecuter/
├── lib/
│   ├── main.dart                    # App entry point; sqflite FFI init; ChangeNotifierProvider setup
│   ├── constants/
│   │   └── app_constants.dart       # Color palette, SettingsKeys, config defaults (temp 0.22, tokens 4096, timeout 240s)
│   ├── database/
│   │   └── database_helper.dart     # SQLite persistence — projects, targets, vulns, logs, credentials, settings
│   ├── models/
│   │   ├── vulnerability.dart       # Vulnerability model with CVSS v3.1 fields, status enum, RemediationClass, PostExploitAccessType
│   │   ├── command_log.dart         # Shell command execution record
│   │   ├── credential.dart          # DiscoveredCredential with fingerprint, isVerified, toPromptLine()
│   │   ├── target.dart              # Scan target with address, status, jsonFilePath
│   │   ├── project.dart             # Project container with scanComplete/analysisComplete/hasResults flags
│   │   ├── llm_settings.dart        # AI provider configuration (provider, baseUrl, apiKey, modelName, temperature, maxTokens, timeoutSeconds)
│   │   ├── llm_provider.dart        # LLMProvider enum with metadata
│   │   ├── environment_info.dart    # Detected OS/environment information
│   │   └── web_session.dart         # Web session state model
│   ├── screens/
│   │   ├── home_screen.dart         # Project selection and management screen
│   │   ├── main_screen.dart         # Primary workspace (analysis, execution, results)
│   │   └── settings_screen.dart     # AI provider and execution settings
│   ├── services/
│   │   ├── vulnerability_analyzer.dart  # Multi-prompt parallel analysis pipeline (Phase 1 + Phase 2)
│   │   ├── exploit_executor.dart        # Autonomous exploit testing loop (~91KB, largest file)
│   │   ├── recon_service.dart           # LLM-guided autonomous recon engine
│   │   ├── prompt_templates.dart        # All LLM prompt text (~70KB)
│   │   ├── llm_service.dart             # Unified LLM API client (6 providers)
│   │   ├── command_executor.dart        # Cross-platform shell execution (~48KB)
│   │   ├── report_generator.dart        # HTML/Markdown/CSV report generation
│   │   ├── report_content_service.dart  # Report content assembly
│   │   ├── project_porter.dart          # Encrypted .penex export/import
│   │   ├── storage_service.dart         # File system path management
│   │   ├── tool_manager.dart            # Tool availability detection and caching
│   │   ├── background_process_manager.dart  # Manages long-running listener processes (Responder, ntlmrelayx)
│   │   ├── environment_discovery.dart   # OS/environment detection
│   │   └── subnet_scanner.dart          # Network subnet scanning
│   ├── utils/
│   │   ├── device_utils.dart            # Target IP extraction, scope classification (internal/external), CloudIndicators
│   │   ├── command_utils.dart           # Command history, deduplication, approach exhaustion tracking
│   │   ├── cvss_calculator.dart         # CVSS score computation helpers
│   │   ├── json_parser.dart             # Robust JSON extraction from LLM responses
│   │   ├── output_sanitizer.dart        # Sensitive data redaction before storage/display
│   │   ├── app_exceptions.dart          # Typed exception hierarchy
│   │   ├── file_dialog.dart             # File picker helpers
│   │   ├── scope_validator.dart         # Validates findings against target scope
│   │   └── subdomain_takeover_fingerprints.dart  # Known subdomain takeover fingerprints
│   └── widgets/
│       ├── app_state.dart               # Global ChangeNotifier (single source of truth for all UI state)
│       ├── vulnerability_table.dart     # Sortable findings table with status indicators
│       ├── command_log_panel.dart       # Real-time command output viewer
│       ├── prompt_log_panel.dart        # LLM prompt/response inspector
│       ├── debug_log_panel.dart         # Internal debug event stream
│       ├── command_approval_widget.dart # Approval mode command review UI
│       ├── device_input_panel.dart      # Scan data JSON input
│       ├── target_input_panel.dart      # Target management panel
│       ├── results_modal.dart           # Post-execution findings summary
│       ├── admin_password_dialog.dart   # sudo credential entry dialog
│       ├── report_config_dialog.dart    # Report generation options dialog
│       ├── scope_config_dialog.dart     # Scope configuration dialog
│       └── resize_border.dart           # Custom window resize border widget
├── test/
│   ├── detection_helpers_test.dart
│   ├── device_utils_test.dart
│   ├── migration_test.dart
│   ├── prompt_integration_test.dart
│   ├── recon_service_test.dart
│   └── widget_test.dart
├── linux/runner/                    # Linux GTK runner (C/CMake)
├── macos/Runner/                    # macOS runner (Swift/Xcode)
├── windows/runner/                  # Windows runner (C++/CMake)
├── pubspec.yaml                     # Flutter dependencies
├── analysis_options.yaml            # Dart linter config (flutter_lints)
├── CLAUDE.md                        # AI assistant guidance for this repo
└── PLAN.md                          # Development planning notes
```

## Core Data Flow

1. **Input**: User pastes device JSON or runs autonomous recon via `ReconService`
2. **Analysis**: `VulnerabilityAnalyzer` runs Phase 1 (fast context), then Phase 2 (full analysis enriched with Phase 1 context)
3. **Execution**: `ExploitExecutor` runs agentic loop per finding — generates commands, executes via `CommandExecutor`, evaluates output, updates status
4. **Chain reasoning**: Post-execution pass identifies multi-step attack paths from confirmed findings
5. **Persistence**: `DatabaseHelper` (SQLite); global state via `AppState` (Provider/ChangeNotifier)

## Key Architectural Patterns

### State Management
`AppState` is the single `ChangeNotifier` for the entire app. All UI widgets consume it via `Provider.of<AppState>`. It holds: vulnerabilities, command logs, LLM settings, current project/target, credentials, confirmed artifacts, debug/prompt logs.

### Scope Classification
`DeviceUtils.classifyTarget()` determines internal (RFC-1918, loopback, link-local, plain hostname) vs external (public IP, FQDN). This distinction drives which prompt sets fire in `VulnerabilityAnalyzer` and `PromptTemplates`.

### Vulnerability Status Flow
`pending` → `confirmed` | `not_vulnerable` | `undetermined`

### Credential Bank
`AppState` maintains `_credentials` (List) + `_credentialFingerprints` (Set for dedup). Verified credentials are persisted to SQLite; inferred credentials are memory-only. Both are injected into LLM prompts via `credentialBankPromptBlock()`.

### Cross-Platform Shell Execution
`CommandExecutor` handles all OS differences: Windows uses PowerShell/cmd or WSL bash; POSIX uses sh/bash. All file paths use the `path` package — never hardcoded separators.

### Prompt Design
All prompts in `PromptTemplates` are objective-first (what to achieve, not which tool to use). No specific tool names or CVE IDs in analysis prompts. Output format is always a JSON schema for consistent parsing.
