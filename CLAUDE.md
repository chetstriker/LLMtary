# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
flutter pub get              # Install dependencies
flutter analyze              # Run linter
flutter run -d linux         # Run on Linux (or macos/windows)
flutter build linux --release
flutter test                 # Run tests
flutter test test/widget_test.dart  # Run single test file
```

## Architecture

PenExecute is a Flutter desktop app for AI-assisted penetration testing. It accepts JSON reconnaissance data for a target, uses an LLM to identify vulnerabilities, then executes test commands to validate each finding.

### Core Data Flow

1. **Input**: User pastes device JSON (ports/services/versions) into the UI
2. **Analysis**: `VulnerabilityAnalyzer` fires multiple LLM prompts → parses JSON output → deduplicates findings
3. **Execution**: `ExploitExecutor` runs an agentic loop (max 10 iterations per vuln) generating and running OS commands, then determining vuln status (confirmed/not_vulnerable/undetermined)
4. **Persistence**: SQLite via `DatabaseHelper`; global UI state via `AppState` (Provider/ChangeNotifier)

### Key Services

- **`exploit_executor.dart`** (largest file, ~91KB) — Orchestrates the active testing loop. Builds compact context from device JSON (only ports relevant to the vulnerability), calls LLM for commands, executes them, detects stuck loops (repeated failures / unreachable target), validates whether tests actually reached the target.
- **`vulnerability_analyzer.dart`** — Fires batched analysis prompts based on target scope (internal RFC-1918 vs external/FQDN). Prompt sets: CVE matching, web app core/API-auth/logic-headers/secrets (4 passes), network services, SNMP/management, SSL/TLS, Active Directory (3 passes: credential/escalation/lateral), privilege escalation (when OS indicators present), DNS/OSINT/subdomain recon and email security (external only).
- **`prompt_templates.dart`** (~70KB) — All LLM prompts. Prompts are objective-based (not tool-centric). Output format is always a JSON schema for consistent parsing.
- **`llm_service.dart`** — Unified interface to 6 providers: Ollama, LM Studio, Claude, ChatGPT, Gemini, OpenRouter.
- **`command_executor.dart`** (~48KB) — Cross-platform shell execution with dangerous-command blocking, sudo credential caching, tool validation, and timeout protection.
- **`device_utils.dart`** — Target classification (internal vs external) and device JSON field extraction.

### Target Scope Classification

Internal targets (RFC-1918, loopback, link-local, plain hostnames) get a different analysis prompt set than external targets (public IPs, FQDNs). This distinction runs throughout `VulnerabilityAnalyzer` and `PromptTemplates`. Always check `DeviceUtils.classifyTarget()` when modifying analysis logic.

### Prompt Design Convention

Prompts in `PromptTemplates` use objective descriptions rather than specific tool examples. This is intentional — the LLM selects the appropriate tool based on what's available. Do not revert to tool-specific examples.

### State Management

`AppState` (`widgets/app_state.dart`) is the single ChangeNotifier for the entire app. It holds vulnerabilities, command logs, LLM settings, the current project/target, and debug/prompt logs. UI widgets consume it via `Provider.of<AppState>`.

### Vulnerability Status Flow

Vulnerabilities start as `pending`. After execution they become:
- `confirmed` — evidence of the vulnerability was found
- `not_vulnerable` — test conclusively proved no vulnerability
- `undetermined` — target unreachable or inconclusive (early exit from stuck-loop detection)

### Cross-Platform Notes

Command generation must work on Windows, macOS, and Linux. `CommandExecutor` handles OS-specific adaptations. When modifying exploitation prompts, ensure commands are platform-agnostic or the platform is checked explicitly.

### Default Config (app_constants.dart)

- Temperature: 0.22
- Max tokens: 4096
- Timeout: 240s per command
