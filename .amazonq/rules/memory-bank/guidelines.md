# PenExecute — Development Guidelines

## Code Quality Standards

### Dart Style
- Follow `flutter_lints` rules (`analysis_options.yaml` includes `package:flutter_lints/flutter.yaml`)
- Use `const` constructors wherever possible (seen throughout widget and model code)
- Prefer named parameters with defaults over positional parameters for models with many fields
- Use `required` keyword for mandatory named parameters
- Private fields prefixed with `_`; expose via getters only

### Naming Conventions
- Classes: `UpperCamelCase` — `VulnerabilityAnalyzer`, `ExploitExecutor`, `CloudIndicators`
- Files: `snake_case.dart` — `device_utils.dart`, `exploit_executor.dart`
- Enums: `UpperCamelCase` type, `lowerCamelCase` values — `VulnerabilityStatus.notVulnerable`, `TargetScope.internal`
- Constants/settings keys: collected in `AppConstants` / `SettingsKeys` classes
- Boolean getters: `is*` or `has*` prefix — `isCloud`, `hasMetadataEndpoint`, `sessionPasswordEntered`

### Documentation
- Public classes and methods get doc comments (`///`)
- Doc comments describe *what* the method does and any non-obvious behavior
- Inline comments explain *why*, not *what* — used for non-obvious logic (e.g. CVSS weight tables, RFC range checks)
- Platform-specific runner files (Swift, C, C++) use minimal comments; generated files marked `// Generated file. Do not edit.`

---

## Architectural Patterns

### State Management
- Single `ChangeNotifier` (`AppState`) for all UI state — never create additional top-level providers
- Mutate state only through `AppState` methods; call `notifyListeners()` after every mutation
- Async state mutations: `await` the async work, then `notifyListeners()`
- Consume state in widgets via `Provider.of<AppState>(context)` or `context.watch<AppState>()`

```dart
// Pattern: mutate + notify
void setExecutionStatus(String status) {
  _executionStatus = status;
  notifyListeners();
}

// Pattern: async mutate + notify
Future<void> addTarget(Target target) async {
  final id = await DatabaseHelper.insertTarget(_projectId, target);
  target.id = id;
  _targets.add(target);
  notifyListeners();
}
```

### Model Design
- Models are plain Dart classes (no `@JsonSerializable`) with manual `toMap()` / `fromMap()` for SQLite
- `fromMap` uses null-coalescing defaults: `map['field'] as String? ?? ''`
- Enums serialized by `.name` / `values.firstWhere((e) => e.name == ..., orElse: () => defaultValue)`
- Computed properties (e.g. `cvssScore`, `cvssVector`, `classifyRemediation`) live on the model class

```dart
// Pattern: enum round-trip
status: VulnerabilityStatus.values.firstWhere(
  (e) => e.name == map['status'],
  orElse: () => VulnerabilityStatus.pending,
),
```

### Service Layer
- Services are stateless classes with static or instance methods — no `ChangeNotifier`
- Services receive `AppState` or specific data as parameters; they do not hold references to `AppState`
- Long-running services (e.g. `ExploitExecutor`) accept callback parameters for status updates rather than directly mutating state

### Utility Classes
- Pure static methods only — no instance state
- Graceful failure: catch exceptions, return null/empty/default rather than throwing
- Regex and string matching: always `.toLowerCase()` the input before matching

```dart
// Pattern: graceful JSON extraction
static List<Map<String, dynamic>> extractPorts(String deviceData) {
  try {
    final deviceJson = json.decode(deviceData);
    final ports = deviceJson['open_ports'] as List?;
    if (ports != null) return ports.cast<Map<String, dynamic>>();
  } catch (e) {
    // Silently return empty list on parse failure
  }
  return [];
}
```

---

## Prompt Design Rules (CRITICAL — do not violate)

These rules are enforced throughout `prompt_templates.dart` and must be preserved in all edits:

1. **Objective-first framing** — describe what to achieve, not which tool to use
   - ✅ "enumerate SMB shares and test for read/write access"
   - ❌ "run enum4linux -a"

2. **No specific tool names in analysis prompts** — the LLM picks tools based on what's available
   - ❌ Do not add `nmap`, `sqlmap`, `metasploit`, `nikto`, etc. as required instructions

3. **No specific CVE IDs in analysis prompts** — CVE matching is handled by `cveVersionAnalysisPrompt()` only
   - ❌ "check for CVE-2021-44228"
   - ✅ "check for known RCE vulnerabilities in this version range"

4. **Platform-neutral language** — avoid Linux-only or Windows-only command references in analysis prompts; the execution loop injects OS context

5. **JSON output schema** — every prompt must specify a JSON output schema for consistent parsing by `JsonParser`

---

## Cross-Platform Requirements (HARD REQUIREMENT)

Every code change must work on Windows, macOS, and Linux.

- **File paths**: always use `path` package (`join`, `dirname`, `basename`) — never hardcode `/` or `\`
- **Shell execution**: check `CommandExecutor` before adding any OS-level operation
  - Windows: PowerShell/cmd or WSL bash (detected at runtime)
  - POSIX: sh/bash
- **Platform checks**: use `Platform.isWindows`, `Platform.isMacOS`, `Platform.isLinux`
- **Temp files**: use `path_provider` for platform-appropriate directories
- **Window sizing**: minimum 1375×700 (set in macOS `MainFlutterWindow.swift` and equivalent platform runners)

---

## Database Patterns

- All DB operations go through `DatabaseHelper` static methods
- Never access the raw `Database` object outside `DatabaseHelper` except for bulk deletes in `AppState.deleteTarget()`
- Settings stored as key-value strings via `DatabaseHelper.saveSetting()` / `getSetting()`
- Provider settings stored separately via `saveProviderSettings()` / `getProviderSettings()`
- Always check `_projectId > 0` and `_currentProject?.id != null` before persisting

```dart
// Pattern: guard before DB write
if (cred.isVerified && _currentProject?.id != null) {
  DatabaseHelper.insertCredential(cred, _currentProject!.id!);
}
```

---

## LLM Response Handling

- Always parse LLM responses through `JsonParser.tryParseJson()` or `tryParseJsonArray()` — never `json.decode()` directly on raw LLM output
- Check for truncated responses with `JsonParser.isTruncatedResponse()`
- Strip markdown code fences before parsing with `JsonParser.stripMarkdownCodeFences()`
- Cap extracted JSON at 50,000 characters to guard against degenerate responses

---

## Credential Bank Patterns

- Add credentials via `AppState.addCredential()` — never directly to `_credentials`
- Deduplication is by `DiscoveredCredential.fingerprint` (service/host/username composite)
- Verified credentials (seen in command output) → persisted to SQLite
- Inferred credentials (LLM-suggested) → memory-only, labeled in prompts as unverified
- Inject into prompts via `AppState.credentialBankPromptBlock(host)`

---

## Scope Classification

- Always use `DeviceUtils.classifyTarget(address)` to determine internal vs external
- Internal: RFC-1918 (10/8, 172.16/12, 192.168/16), CGNAT (100.64/10), loopback, link-local, IPv6 ULA (fc/fd), plain hostnames (no dots)
- External: everything else (public IPs, FQDNs with dots)
- This classification drives which prompt sets fire — never bypass it

---

## Safety Controls

- Dangerous command blocklist is enforced in `CommandExecutor` — do not add bypass logic
- Approval mode (`requireApproval`) must be checked before every command execution
- Sensitive output must pass through `OutputSanitizer` before storage or display
- Never log raw credentials, API keys, or tokens

---

## Platform Runner Conventions (Swift/C/C++)

- macOS Swift runners: minimal — only override what Flutter requires (`awakeFromNib`, plugin registration)
- Window minimum size set in platform runner, not in Flutter Dart code
- Generated plugin registrant files (`GeneratedPluginRegistrant.swift`, `.cc`) are auto-generated — do not edit manually
- C header guards: `#ifndef FLUTTER_<NAME>_H_` / `#define FLUTTER_<NAME>_H_` / `#endif // FLUTTER_<NAME>_H_`
- GTK application uses GLib type system macros (`G_DECLARE_FINAL_TYPE`)

---

## Command Pre-Flight Validation

All commands in the exploit executor loop pass through `CommandValidator.validate()` before execution. The validator lives in `lib/utils/command_validator.dart`.

### Two-tier architecture

**Tier 1 — Static checks (zero token cost, always runs):**
- Non-script file execution detection: hard-blocks `bash /path/to/wordlist.txt` and similar — the exact failure mode of the wordlist-as-script hang
- Dangerous shell patterns: hard-blocks `cat file | bash` and `curl url | bash`
- WSL path translation: auto-corrects `C:\Users\...` → `/mnt/c/Users/...` when Windows paths appear in commands
- Bare-word flag detection: soft warning only, never blocks

**Tier 2 — LLM-assisted validation (selective, cached):**
- Only fires for tools in the high-risk set (nmap, sqlmap, gobuster, ffuf, hydra, nuclei, msfconsole, testssl.sh, enum4linux, crackmapexec, netexec, wpscan, feroxbuster, nikto, wfuzz, john, hashcat, responder, smbclient, rpcclient, ldapsearch, kerbrute)
- Uses cached `ToolUsageInfo` from `CommandExecutor.getToolUsageInfo()` — first call per tool costs one LLM round-trip, every subsequent call is free
- 20-second timeout — validation failure always passes through, never stalls the loop

### Invariants

- **Hard blocks are reserved for unambiguous failures** — only non-script file execution and pipe-to-shell patterns warrant a hard block
- **Corrections are silent substitutions** — the corrected command appears in the debug log but the loop continues without pausing
- **Validation is best-effort** — a timeout or LLM error in Tier 2 must never stall the execution loop; always pass through
- **High-risk tool set is a single constant** — `CommandValidator._highRiskTools` — update it in one place when new complex tools are added
- **`CommandValidator` never re-detects the OS** — it calls `CommandExecutor.getOsInfo()` which uses the cached value from `EnvironmentDiscovery`
