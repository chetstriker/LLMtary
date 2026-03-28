# PenExecute

A Flutter desktop application that uses large language models to automate penetration testing workflows — from recon and vulnerability analysis through active exploit validation and professional report generation.

---

## How It Works

PenExecute feeds structured scan data (ports, services, banners, DNS records, WAF findings, SSL certificates) into a phased LLM analysis pipeline that mirrors a real engagement workflow: **passive recon → active recon → vulnerability discovery → targeted exploitation → post-exploitation**. Each phase's findings enrich the next, producing more targeted and accurate results than a flat parallel approach.

The resulting findings are then individually validated through an autonomous exploit testing loop that executes real commands on your machine, evaluates the output, and iterates until the vulnerability is confirmed, ruled out, or all reasonable approaches are exhausted. After testing completes, a final chain reasoning pass identifies how confirmed findings can be combined into multi-step attack paths.

Everything runs locally — the LLM sends commands to your shell, not to a cloud execution environment.

---

## Features

### Multi-Scope Analysis
- Automatically classifies targets as **internal** (RFC-1918, LAN) or **external** (internet-facing)
- Fires different prompt sets depending on scope — external targets get SSL/TLS analysis, DNS/OSINT analysis, and CDN/WAF-aware findings; internal targets get network service and Active Directory-focused analysis
- Prevents cross-scope noise (no SMB findings on external targets, no subdomain takeover findings on internal hosts)

### Phased Engagement Architecture
Analysis runs in two sequential phases, mirroring the structure of a professional engagement:

**Phase 1 — Passive recon and service fingerprinting** (fast, always runs):
- **CVE/Version Analysis** — strict product+version matching against known vulnerability ranges
- **Network Service Analysis** — SMB, SSH, FTP, databases, SNMP/management protocols, WinRM/WMI, IPv6 attack surface
- **DNS/OSINT and Email Security** — zone transfer, subdomain recon, SPF/DMARC gaps (external targets)
- Phase 1 results are compiled into a context block that is injected into every Phase 2 prompt

**Phase 2 — Full vulnerability analysis** (runs after Phase 1, enriched with Phase 1 context):
- **Web Application Analysis** — four focused passes: core injection/CMS/auth weaknesses, API/CORS/JWT/GraphQL/OAuth authentication, business logic/SSTI/request smuggling/security headers, and secrets/configuration exposure
- **Active Directory Analysis** — three focused passes: credential attacks (password spraying, Kerberoasting, LDAP null bind), privilege escalation (ADCS, ACL abuse, delegation), and lateral movement (relay attacks, Pass-the-Hash/Ticket, WinRM)
- **SSL/TLS Analysis** — cipher strength, protocol versions, certificate validity, known TLS vulnerability classes
- **Privilege Escalation Analysis** — OS-level escalation paths (sudo, SUID, service permissions, scheduled tasks, registry, token impersonation)
- **Technology deep-dives** — WordPress, Jenkins, Atlassian, Tomcat, Exchange, Elasticsearch, VMware, GitLab, Citrix, Drupal, MSSQL, ADCS, WAF bypass (each fires only when indicators for that technology are present)

**Post-analysis:**
- Findings are deduplicated, evidence-quote validated, and sorted by severity, confidence, and business risk
- If ≥2 HIGH/CRITICAL Active Directory findings are found, a BloodHound-style attack chain reasoning pass fires to identify multi-step paths to Domain Administrator

### Active Exploit Testing Loop
- Each selected finding goes through a validation loop that runs real commands against the target
- The LLM plans its approach, executes commands, evaluates output, and adapts — progressing through RECON → VERIFICATION → EXPLOITATION → CONFIRMATION phases
- Loop terminates when: vulnerability is confirmed with proof, ruled out conclusively, or all reasonable approaches are exhausted
- Configurable iteration caps per finding type (CVE-backed vs. speculative), settable in AI Configuration
- Duplicate command detection and semantic approach exhaustion tracking prevent spinning
- **OPSEC-aware prompting** — each iteration includes guidance on request pacing, scan noise reduction, tool signature minimization, and test impact limits
- **Rate-limit detection** — if command output contains rate-limiting or blocking signals (429, "too many requests", "you have been blocked", etc.), the executor detects it, notifies the LLM, and adjusts its approach for the next iteration
- Metasploit pre-flight check runs once before testing begins; Metasploit is skipped for the session if unavailable
- **Two-tier command validation** runs before every command execution:
  - *Tier 1 (static, zero cost)*: blocks non-script file execution (e.g. passing a wordlist to bash), pipe-to-shell patterns (`curl url | bash`), and auto-corrects Windows paths in WSL contexts
  - *Tier 2 (LLM-assisted, cached)*: validates correct flag usage for high-risk tools (nmap, sqlmap, gobuster, hydra, nuclei, metasploit, etc.); first call per tool costs one LLM round-trip, all subsequent calls are free; 20-second timeout — never stalls the loop

### Attack Chain Reasoning
- When a vulnerability is confirmed, the executor identifies whether it enables or simplifies testing another vulnerability type ("chain opportunity") and notes it in the finding's proof
- Confirmed artifacts (RCE, SQLi, auth bypass, LFI, SSRF, etc.) are fed forward as context — subsequent vulnerabilities on the same target know what access has already been achieved
- After all per-vulnerability loops complete, if ≥2 findings are confirmed, a post-execution chain reasoning pass fires — identifying how the confirmed findings can be combined into higher-impact multi-step attack paths. These are added as `AttackChain` findings in the vulnerability table

### Post-Exploitation Enumeration
- When a confirmed finding grants high-value access (RCE, command injection, authentication bypass, default credentials), a **Post-Exploitation Enumeration** pseudo-vulnerability is automatically queued
- The enumeration loop enumerates users, groups, network interfaces, running services, readable credential files, and privilege escalation paths — documenting the full impact of the access achieved

### Credential Bank
- Discovered credentials are collected into a session-wide credential bank
- Credentials are automatically included as context when testing subsequent vulnerabilities on the same target — enabling credential reuse and chained attack paths
- Deduplicates by service/host/username fingerprint
- Verified credentials (seen in command output) are persisted to SQLite; inferred credentials (LLM-suggested) are memory-only and labeled as unverified in prompts
- When verified credentials are discovered during execution, an **authenticated re-analysis** pass automatically runs for the affected target to surface additional findings that require credentials

### Command Approval Mode
- Optional mode that pauses before executing each command and shows it to the user for approval or denial
- Approved commands run; denied commands are skipped with the LLM notified to try a different approach
- The toggle takes effect immediately — enabling or disabling approval mid-execution applies to the very next command

### Autonomous Recon
- Built-in recon service that drives initial scan data collection through an LLM-guided loop
- Supports both internal and external recon workflows with appropriate tool selection
- Saves all output to organized per-target directories

### Project Management
- Multiple named projects, each with multiple targets
- All findings, command logs, and credentials are persisted in SQLite and associated with the correct project/target
- Export and import projects as encrypted `.penex` bundles (AES encryption, password-protected)

### Report Generation
- **HTML report** — professional formatted report with cover page, executive summary, severity breakdown by target, full findings with CVSS-style metadata, and discovered credentials table
- **Markdown report** — same content as HTML in portable Markdown format
- **CSV export** — flat findings list for import into spreadsheets or other tools
- Assessment start and end dates are saved per-project; end date defaults to today if not explicitly set
- AI-assisted generation for executive summary, methodology, risk rating model, and conclusion sections

### Cross-Platform
- Runs natively on **Linux**, **macOS**, and **Windows**
- On Windows, detects WSL availability and uses bash via WSL when present; falls back to PowerShell/cmd with Windows-compatible commands when not
- OS detection informs the LLM's command choices throughout the testing loop

### Safety Controls
- **Dangerous command blocklist** — hard-blocks destructive commands: `rm -rf /`, `format`, `mkfs`, `dd if=`, `shutdown`, `reboot`, fork bombs (`:(){ :|:& };:`), and similar patterns. These are never executed regardless of LLM output.
- **Non-script file execution detection** — hard-blocks attempts to execute non-script files as shell scripts (e.g. passing a wordlist as a bash argument), which would cause the process to hang indefinitely
- **Pipe-to-shell blocking** — hard-blocks `cat file | bash`, `curl url | bash`, and similar patterns
- **Command approval mode** — when enabled, every command is shown to the user before execution; the user can allow once, always allow (adds to whitelist), or deny
- **Configurable command whitelist** — commands added to the whitelist always execute without prompting, even in approval mode
- **Per-tool setup validation** — tools that require initialization (e.g. Metasploit database via `msfdb init`) are checked before use; the tool is skipped for the session if the check fails
- **Connection timeout protection** — when a port connection times out, the executor is instructed not to retry that port
- **Sensitive output sanitization** — command output is scrubbed of credentials, API keys, and tokens before storage and display
- **Scope enforcement** — findings are validated against the configured scope and exclusion lists; out-of-scope findings are discarded

---

## Supported AI Providers

| Provider | Type | Notes |
|----------|------|-------|
| Ollama | Local | Default base URL: `http://localhost:11434` |
| LM Studio | Local | Default base URL: `http://localhost:1234/v1` |
| Claude (Anthropic) | Cloud | API key required |
| ChatGPT (OpenAI) | Cloud | API key required |
| Gemini (Google) | Cloud | API key required |
| OpenRouter | Cloud | API key required; access to many models via one API |
| Custom | Any | Configurable base URL and API key |

Provider settings are saved per-provider — switching providers restores that provider's previously saved API key, model, and base URL.

### LLM Requirements

PenExecute's prompts are large and require strong reasoning capabilities. Not all models will produce usable results. The exploit system prompt alone exceeds 6,000 tokens, and the recon system prompt exceeds 5,600 tokens — a 4K context window is physically too small.

#### Local Model Tiers (Ollama / LM Studio)

| Tier | Model Size | JSON Reliability | Quality | VRAM (Q4) | Recommendation |
|------|-----------|-----------------|---------|-----------|----------------|
| **Not usable** | 7-8B | ~50-60% | Poor — hallucinates flags, repeats failed approaches, can't chain reasoning | ~6 GB | Not supported |
| **Bare minimum** | 14B | ~70-80% | Fair — handles single-step vulns, struggles with complex chains | ~12 GB | Usable for simple targets; expect some retries |
| **Recommended minimum** | 32B | ~85-90% | Good — reliable multi-step reasoning, solid exploit chains | ~24 GB | Recommended for serious penetration testing |
| **Professional** | 70B+ | ~95%+ | Very good — best local results, handles all prompt complexity | ~48 GB | Best local experience; dual GPU setups work well |

#### Minimum Local Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Parameters** | 14B (e.g., Qwen 2.5 14B, Llama 3 14B) | 32B+ (e.g., Qwen 2.5 32B, Llama 3 70B) |
| **Context window** | 8K tokens (absolute floor) | 32K+ tokens (64K+ preferred) |
| **Quantization** | Q4_K_M or higher | Q5_K_M or higher |
| **VRAM** | ~12 GB (14B Q4) | ~24 GB (32B Q4) or ~48 GB (70B Q4) |
| **RAM (CPU inference)** | 16 GB+ (14B, very slow) | 64 GB+ (32B-70B) |
| **Inference speed** | Functional at any speed | 15+ tokens/second for interactive use |

> **Note:** Models below 14B parameters are not supported. They produce unreliable JSON output, hallucinate tool flags and command syntax, and fail at the multi-step reasoning required for exploit chains.

#### Cloud Providers (no hardware requirements)

Cloud providers (Claude, ChatGPT, Gemini, OpenRouter) handle all compute remotely. Any machine that can run the Flutter desktop app is sufficient. Recommended models:

| Provider | Recommended Models |
|----------|-------------------|
| **Anthropic** | Claude Opus, Claude Sonnet |
| **OpenAI** | GPT-4o, GPT-4 Turbo |
| **Google** | Gemini 1.5 Pro, Gemini 2.5 Pro |
| **OpenRouter** | Any of the above via unified API |

Cloud providers offer the best results due to large context windows (128K-200K tokens) and frontier-class reasoning. They are recommended when local hardware is limited.

---

## Setup

### Prerequisites

- [Flutter SDK](https://docs.flutter.dev/get-started/install) (stable channel)
- Desktop support enabled: `flutter config --enable-linux-desktop` (or `macos`/`windows`)

### Build & Run

```bash
git clone <repo>
cd penexecute
flutter pub get
flutter run -d linux     # or: macos, windows
```

For a release build:
```bash
flutter build linux      # or: macos, windows
```

### Recommended Pentest Tools

PenExecute shells out to whatever tools are available on your system. The more tools installed, the more testing approaches the LLM can take. Commonly used tools include:

- **nmap** — port scanning and service version detection
- **nuclei** — template-based vulnerability scanning
- **curl / wget** — HTTP request crafting and testing
- **dig / host** — DNS enumeration
- **smbclient / enum4linux** — SMB enumeration (internal)
- **searchsploit** — local exploit database search
- **sqlmap** — SQL injection testing
- **gobuster / ffuf / dirb** — directory and path enumeration
- **hydra / medusa** — credential brute-forcing
- **testssl.sh / sslscan** — TLS configuration analysis
- **nikto** — web server vulnerability scanning
- **metasploit** — exploit framework (requires `msfdb init`)

The LLM selects tools based on the objective — if a useful tool is missing, it will attempt to install it automatically. If installation fails, it adapts and tries alternative approaches.

---

## Usage

### 1. Configure AI Settings
Click the settings icon (top right). Select your AI provider, enter your API key and model name. A "Test" button validates the configuration. Settings are saved per-provider.

**Recommended models:** Models with strong reasoning and large context windows perform best. Claude Opus/Sonnet, GPT-4o, Gemini 1.5 Pro, and large Ollama models (70B+) all work well. Smaller models (< 13B) tend to produce lower-quality findings and make more command errors.

### 2. Create or Select a Project
Projects organize your work. Create a named project, then add targets to it. Each target can be a hostname, FQDN, or IP address.

### 3. Input Scan Data
Use the **SCOPE / RECON** tab to run autonomous recon against your targets, or paste existing scan data JSON directly. The JSON schema is documented below.

### 4. Analyze
Navigate to the **VULN / HUNT** tab and click **Analyze**. Multiple LLM passes run in parallel. Findings appear in the vulnerability table as they arrive, sorted by severity.

### 5. Select and Execute
Navigate to the **PROOF / EXPLOIT** tab. Check the vulnerabilities you want to actively test and click **Execute Selected**. The exploit testing loop runs each finding through active validation. Status icons update in real time:
- `[PENDING]` — not yet tested
- `[CONFIRMED]` — exploitation succeeded with proof
- `[NOT VULNERABLE]` — definitively ruled out
- `[UNDETERMINED]` — tested but inconclusive (all approaches exhausted or target unreachable)

### 6. Review and Export
Navigate to the **RESULT / REPORT** tab to view the full findings summary and generate your report as HTML, Markdown, or CSV.

---

## Scan Data JSON Format

The minimum required format. All fields beyond `device` and `open_ports` are optional but improve analysis quality significantly.

```json
{
  "device": {
    "ip_address": "192.168.1.100",
    "name": "webserver01",
    "os": "Linux",
    "os_version": "Ubuntu 22.04"
  },
  "open_ports": [
    {
      "port": 80,
      "protocol": "tcp",
      "state": "open",
      "service": "http",
      "product": "Apache httpd",
      "version": "2.4.49",
      "extra_info": "(Ubuntu)",
      "cpe": "cpe:/a:apache:http_server:2.4.49"
    },
    {
      "port": 443,
      "protocol": "tcp",
      "state": "open",
      "service": "ssl/https",
      "product": "Apache httpd",
      "version": "2.4.49"
    }
  ],
  "nmap_scripts": [
    {
      "port": 445,
      "script": "smb-vuln-ms17-010",
      "output": "VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1"
    }
  ],
  "web_findings": [
    {
      "url": "http://192.168.1.100:80",
      "status": 200,
      "server": "Apache/2.4.49",
      "content_type": "text/html",
      "technologies": ["WordPress 6.2", "PHP 8.1"],
      "headers": {
        "X-Powered-By": "PHP/8.1.0"
      }
    }
  ],
  "smb_findings": [
    {
      "share": "ADMIN$",
      "access": "READ",
      "comment": "Remote Admin"
    }
  ],
  "dns_findings": [
    {
      "record_type": "CNAME",
      "name": "www.example.com",
      "value": "wp.wpenginepowered.com"
    },
    {
      "record_type": "MX",
      "name": "example.com",
      "value": "10 mail.example.com"
    },
    {
      "record_type": "TXT",
      "name": "example.com",
      "value": "v=spf1 include:spf.protection.outlook.com ~all"
    }
  ],
  "waf_findings": [
    {
      "waf": "Cloudflare",
      "detected_by": "cf-ray header",
      "notes": "Rate limiting likely"
    }
  ],
  "other_findings": [
    {
      "type": "spf",
      "data": "v=spf1 include:spf.protection.outlook.com ~all"
    }
  ],
  "domain_information": {
    "domain_name": "example.com",
    "registrar": "Network Solutions, LLC",
    "creation_date": "2001-03-15T00:00:00Z",
    "registry_expiry_date": "2030-03-15T00:00:00Z",
    "dnssec": "unsigned"
  }
}
```

---

## Findings Schema

Each vulnerability finding includes:

| Field | Description |
|-------|-------------|
| `problem` | Short descriptive name |
| `cve` | CVE ID if applicable |
| `description` | Attack technique, affected path/parameter, example payload, and what an attacker gains |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` |
| `evidence` | Exact data from scan output supporting the finding |
| `recommendation` | Remediation guidance |
| `vulnerabilityType` | Attack class (RCE, SQLi, XSS, LFI, Auth Bypass, etc.) |
| `attackVector` | CVSS attack vector |
| `attackComplexity` | CVSS attack complexity |
| `privilegesRequired` | CVSS privileges required |
| `userInteraction` | CVSS user interaction |
| `confidentialityImpact` | CVSS confidentiality impact |
| `integrityImpact` | CVSS integrity impact |
| `availabilityImpact` | CVSS availability impact |
| `businessRisk` | Real-world business impact if exploited — data breach, ransomware pivot, regulatory exposure, operational disruption |

---

## Project File Format

Projects are exported as `.penex` files — AES-encrypted ZIP archives. The archive contains:
- Project metadata
- All target data
- All vulnerability findings
- Associated scan output files from the storage directory

Import requires the same password used during export. Lost passwords cannot be recovered.

---

## Architecture

```
lib/
├── constants/
│   └── app_constants.dart        # Color palette, settings keys, config defaults
├── database/
│   └── database_helper.dart      # SQLite persistence (projects, targets, vulns, logs)
├── models/
│   ├── vulnerability.dart        # Finding model with CVSS fields and status
│   ├── command_log.dart          # Shell command execution record
│   ├── credential.dart           # Discovered credential
│   ├── target.dart               # Scan target
│   ├── project.dart              # Project container
│   ├── llm_settings.dart         # AI provider configuration
│   └── llm_provider.dart         # Provider enum with metadata
├── screens/
│   ├── home_screen.dart          # Project selection and management
│   ├── main_screen.dart          # Primary workspace with tab navigation
│   ├── settings_screen.dart      # AI provider and execution settings
│   └── tabs/
│       ├── scope_recon_tab.dart  # Autonomous recon and target management
│       ├── vuln_hunt_tab.dart    # Vulnerability analysis pipeline
│       ├── proof_exploit_tab.dart # Exploit execution and results
│       └── result_report_tab.dart # Report generation
├── services/
│   ├── vulnerability_analyzer.dart  # Multi-prompt parallel analysis pipeline
│   ├── exploit_executor.dart        # Autonomous exploit testing loop
│   ├── recon_service.dart           # LLM-guided recon data collection
│   ├── prompt_templates.dart        # All analysis and execution prompt text
│   ├── command_executor.dart        # Shell command execution with safety controls
│   ├── llm_service.dart             # LLM API client (all providers)
│   ├── report_generator.dart        # HTML/Markdown/CSV report generation
│   ├── report_content_service.dart  # AI-assisted report section generation
│   ├── project_porter.dart          # Encrypted project export/import
│   ├── storage_service.dart         # File system path management
│   ├── tool_manager.dart            # Tool availability detection and caching
│   ├── background_process_manager.dart  # Long-running listener processes (Responder, ntlmrelayx)
│   └── environment_discovery.dart   # OS/environment detection
├── utils/
│   ├── device_utils.dart         # Target IP extraction and scope classification
│   ├── command_utils.dart        # Command history, deduplication, approach tracking
│   ├── command_validator.dart    # Two-tier pre-execution command validation
│   ├── cvss_calculator.dart      # CVSS score computation
│   ├── json_parser.dart          # Robust JSON extraction from LLM responses
│   ├── output_sanitizer.dart     # Sensitive data redaction
│   └── app_exceptions.dart       # Typed exception hierarchy
└── widgets/
    ├── app_state.dart            # Global ChangeNotifier state
    ├── vulnerability_table.dart  # Sortable findings table with status indicators
    ├── command_log_panel.dart    # Real-time command output viewer
    ├── prompt_log_panel.dart     # LLM prompt/response inspector
    ├── debug_log_panel.dart      # Internal debug event stream
    ├── command_approval_widget.dart  # Approval mode command review UI
    ├── device_input_panel.dart   # Scan data JSON input
    ├── target_input_panel.dart   # Target management panel
    └── results_modal.dart        # Post-execution findings summary
```

---

## Settings Reference

| Setting | Description |
|---------|-------------|
| AI Provider | Which LLM backend to use |
| Base URL | API endpoint (local providers and Custom) |
| API Key | Authentication for cloud providers |
| Model | Model identifier string |
| Temperature | LLM sampling temperature (lower = more deterministic; default 0.22) |
| Max Tokens | Maximum tokens per LLM response (default 4096) |
| Timeout | Seconds before an LLM request times out (default 240s) |
| Max Iterations (with CVE) | Exploitation loop cap for findings with a known CVE ID |
| Max Iterations (no CVE) | Exploitation loop cap for generic findings without a CVE ID |
| Require Approval | Pause and prompt before executing each shell command; toggle takes effect immediately |
| Command Whitelist | Commands that bypass the approval prompt |
| Storage Path | Base directory for scan output file storage |

---

## Safety and Responsibility

PenExecute executes real shell commands on your local machine against real targets. It is intended for use by security professionals in authorized penetration testing engagements, security research, and CTF competitions.

**You are responsible for ensuring you have authorization to test any target.** Unauthorized scanning or exploitation is illegal in most jurisdictions regardless of the tools used.

The built-in safety controls (dangerous command blocklist, non-script execution detection, pipe-to-shell blocking, approval mode, timeout protection, scope enforcement) are designed to prevent accidents, not to substitute for professional judgment and proper engagement scoping.

---

## License

Private project — not for public distribution.
