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

1. **Input**: User pastes device JSON (ports/services/versions) into the UI, or uses the built-in `ReconService` to autonomously collect scan data via an LLM-guided recon loop. Recon output is stored per-target and merged with any user-supplied JSON.
2. **Analysis** (2-phase): `VulnerabilityAnalyzer` runs a phased pipeline:
   - **Phase 1** — fast context discovery: CVE/version matching, DNS/OSINT, network services, SNMP. Results build a context block.
   - **Phase 2** — full vulnerability analysis: all web, AD, tech-specific, and specialized prompts, each enriched with Phase 1 context. Phase 2 findings are more targeted because they know what Phase 1 found.
   - Post-analysis: deduplication, evidence-quote validation, businessRisk-aware sort, and (if ≥2 HIGH/CRITICAL AD findings) a BloodHound-style attack chain reasoning pass.
3. **Execution**: `ExploitExecutor` runs an agentic loop (max 10 iterations per vuln) generating and running OS commands, then determining vuln status (confirmed/not_vulnerable/undetermined). Includes OPSEC guidance injection and rate-limit detection.
4. **Chain reasoning**: After all vulns are tested, if ≥2 are confirmed, a post-execution chain reasoning pass identifies multi-step attack paths and adds them as `AttackChain` findings.
5. **Persistence**: SQLite via `DatabaseHelper`; global UI state via `AppState` (Provider/ChangeNotifier)

### Key Services

- **`recon_service.dart`** — Autonomous LLM-guided reconnaissance engine. Runs discovery commands (nmap, DNS, web fingerprinting) and builds/enriches device JSON before analysis. Defines `ReconPhase` enum (`portScan`, `serviceBanner`, `webFingerprint`, `dnsEnum`, `osDetect`), `ReconResult` model (structured recon output that merges into device JSON), nmap XML parser, banner grabber, WAF detector, and DNS/certificate hostname extractors. The `enrichWithRecon()` static method is the integration point — call it before `VulnerabilityAnalyzer.analyzeDevice()` to enrich user-supplied JSON with automated recon data.
- **`exploit_executor.dart`** (largest file, ~91KB) — Orchestrates the active testing loop. Builds compact context from device JSON (only ports relevant to the vulnerability), calls LLM for commands, executes them, detects stuck loops (repeated failures / unreachable target), validates whether tests actually reached the target. Includes lockout-aware spray counter (hard interception when safety threshold exceeded), subdomain takeover fast-path verification, and post-exploitation pillaging with lateral movement/persistence/domain dominance/pivoting prompts.
- **`vulnerability_analyzer.dart`** — Fires batched analysis prompts based on target scope (internal RFC-1918 vs external/FQDN). Prompt sets: CVE matching, web app core/API-auth/logic-headers/secrets (4 passes), network services, SNMP/management, SSL/TLS, Active Directory (3 passes: credential/escalation/lateral), privilege escalation (when OS indicators present), DNS/OSINT/subdomain recon and email security (external only). Additional conditional prompts: business logic deep-dive, wireless security, network infrastructure attacks, thick client/binary protocols, supply chain analysis, cloud exposed resources, cloud infrastructure misconfig.
- **`prompt_templates.dart`** (~70KB) — All LLM prompts. Prompts are objective-based (not tool-centric). Output format is always a JSON schema for consistent parsing. Includes post-exploitation prompts: `lateralMovementPrompt`, `persistencePrompt`, `domainDominancePrompt` — scoped by `PostExploitAccessType` and fired after vulnerability confirmation.
- **`llm_service.dart`** — Unified interface to 6 providers: Ollama, LM Studio, Claude, ChatGPT, Gemini, OpenRouter.
- **`command_executor.dart`** (~48KB) — Cross-platform shell execution with dangerous-command blocking, sudo credential caching, tool validation, and timeout protection.
- **`device_utils.dart`** — Target classification (internal vs external), device JSON field extraction, and `CloudIndicators` detection (provider, metadata endpoint, IAM credentials, object storage, serverless, `isExternallyExposed`, `hasInternalCloudAccess`).

### Target Scope Classification

Internal targets (RFC-1918, loopback, link-local, plain hostnames) get a different analysis prompt set than external targets (public IPs, FQDNs). This distinction runs throughout `VulnerabilityAnalyzer` and `PromptTemplates`. Always check `DeviceUtils.classifyTarget()` when modifying analysis logic.

### Prompt Design Convention

Prompts in `PromptTemplates` describe **what to check or achieve**, not **which tool to use** or **which CVE to look for**. This is intentional and must be preserved.

- **No specific tool names in analysis prompts.** Say "enumerate SMB shares" not "run enum4linux". The LLM picks the best tool available on the tester's machine. Do not add `nmap`, `sqlmap`, `metasploit`, or any other tool name as a required instruction.
- **No specific CVE IDs in analysis prompts.** Say "check for known RCE vulnerabilities in this version range" not "check for CVE-2021-44228". CVE matching is handled by `cveVersionAnalysisPrompt()`, which instructs the LLM to match observed versions against known vulnerability ranges — it does not enumerate specific CVEs.
- **Objective-first framing.** Each prompt section should start from the attacker's objective ("gain OS command execution", "extract authentication material") and describe what evidence or conditions would indicate that objective is achievable. The LLM then determines which commands and tools to use.
- **Platform-neutral language.** Avoid Linux-only or Windows-only command references in analysis prompts. The execution loop already injects OS context; analysis prompts should remain OS-agnostic.

Do not revert to tool-specific or CVE-specific examples when editing prompts.

### State Management

`AppState` (`widgets/app_state.dart`) is the single ChangeNotifier for the entire app. It holds vulnerabilities, command logs, LLM settings, the current project/target, and debug/prompt logs. UI widgets consume it via `Provider.of<AppState>`.

### Vulnerability Status Flow

Vulnerabilities start as `pending`. After execution they become:
- `confirmed` — evidence of the vulnerability was found
- `not_vulnerable` — test conclusively proved no vulnerability
- `undetermined` — target unreachable or inconclusive (early exit from stuck-loop detection)

### Cross-Platform Requirement

**PenExecute must run correctly on Windows, macOS, and Linux.** This is a hard requirement — every code change must work on all three platforms.

- Shell command generation must work on the host OS. `CommandExecutor` handles OS-specific adaptations and exposes `Platform.isWindows`, `Platform.isMacOS`, `Platform.isLinux`, and a WSL detection flag. When modifying any command generation or execution logic, verify it handles all three OS code paths.
- File path construction must use `path` package helpers (`join`, `dirname`, etc.) — never hardcode `/` separators.
- Temp file locations, process spawning, and tool invocation all differ between Windows (PowerShell/cmd/WSL) and POSIX systems. Check `CommandExecutor` before adding any OS-level operation.
- Flutter desktop builds require `flutter config --enable-<platform>-desktop` and platform-specific build commands (`flutter build linux/macos/windows`). Test the analyze step (`flutter analyze`) before committing changes that touch platform-sensitive paths.

### Default Config (app_constants.dart)

- Temperature: 0.22
- Max tokens: 4096
- Timeout: 240s per command
