# PenExecute

A Flutter desktop application that uses large language models to automate penetration testing workflows — from recon and vulnerability analysis through active exploit validation and professional report generation.

---

## How It Works

PenExecute feeds structured scan data (ports, services, banners, DNS records, WAF findings, SSL certificates) into a multi-prompt LLM analysis pipeline. Each analysis prompt is scoped to a specific attack domain — CVE/version matching, web application vulnerabilities, SSL/TLS configuration, DNS/OSINT intelligence, and more. The resulting findings are then individually validated through an autonomous exploit testing loop that executes real commands on your machine, evaluates the output, and iterates until the vulnerability is confirmed, ruled out, or all reasonable approaches are exhausted.

Everything runs locally — the LLM sends commands to your shell, not to a cloud execution environment.

---

## Features

### Multi-Scope Analysis
- Automatically classifies targets as **internal** (RFC-1918, LAN) or **external** (internet-facing)
- Fires different prompt sets depending on scope — external targets get SSL/TLS analysis, DNS/OSINT analysis, and CDN/WAF-aware findings; internal targets get network service and Active Directory-focused analysis
- Prevents cross-scope noise (no SMB findings on external targets, no subdomain takeover findings on internal hosts)

### Parallel Vulnerability Analysis
- Runs multiple specialized LLM analysis passes simultaneously against the same target data
- **CVE/Version Analysis** — strict product+version matching against known vulnerability ranges
- **Web Application Analysis** — four focused passes: core injection/CMS/auth weaknesses, API/CORS/JWT/GraphQL authentication, business logic/SSTI/request smuggling/security headers, and secrets/configuration exposure
- **Active Directory Analysis** — three focused passes: credential attacks (password spraying, Kerberoasting, LDAP null bind), privilege escalation (ADCS, ACL abuse, delegation), and lateral movement (relay attacks, Pass-the-Hash/Ticket, WinRM)
- **Network Service Analysis** — SMB, SSH, FTP, databases, SNMP/management protocols, WinRM/WMI, IPv6 attack surface, and other non-web services (internal targets)
- **SSL/TLS Analysis** — cipher strength, protocol versions, certificate validity, known TLS vulnerability classes
- **DNS/OSINT and Email Security Analysis** — zone transfer, subdomain attack surface inference, SPF/DMARC gaps, email security posture (external targets)
- **Privilege Escalation Analysis** — OS-level escalation paths (sudo, SUID, service permissions, scheduled tasks, registry, token impersonation) when OS indicators are present
- Deduplicates findings across all passes before presenting results

### Active Exploit Testing Loop
- Each selected finding goes through a validation loop that runs real commands against the target
- The LLM plans its approach, executes commands, evaluates output, and adapts — progressing through RECON → VERIFICATION → EXPLOITATION → CONFIRMATION phases
- Loop terminates when: vulnerability is confirmed with proof, ruled out conclusively, or all reasonable approaches are exhausted
- Hard cap of **100 iterations** for CVE-backed findings, **20 iterations** for speculative findings
- Duplicate command detection and semantic approach exhaustion tracking prevent spinning
- Metasploit pre-flight check runs once before testing begins; Metasploit is skipped for the session if unavailable

### Credential Bank
- Discovered credentials are collected into a session-wide credential bank
- Credentials are automatically included as context when testing subsequent vulnerabilities on the same target — enabling credential reuse and chained attack paths
- Deduplicates by service/host/username fingerprint

### Command Approval Mode
- Optional mode that pauses before executing each command and shows it to the user for approval or denial
- Approved commands run; denied commands are skipped with the LLM notified to try a different approach

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

### Cross-Platform
- Runs natively on **Linux**, **macOS**, and **Windows**
- On Windows, detects WSL availability and uses bash via WSL when present; falls back to PowerShell/cmd with Windows-compatible commands when not
- OS detection informs the LLM's command choices throughout the testing loop

### Safety Controls
- Dangerous command blocklist (`rm -rf`, `format`, `mkfs`, `dd`, `shutdown`, `:(){ :|:& };:`, etc.)
- Configurable command whitelist for commands that should always be allowed without prompting
- Per-tool setup validation — tools that require initialization (e.g. Metasploit database) are checked before use
- Connection timeout warnings — when a port connection times out, the executor is instructed not to retry that port
- Sensitive output sanitization before storage and display

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
Click the settings icon (top right). Select your AI provider, enter your API key and model name. A "Test Connection" button validates the configuration. Settings are saved per-provider.

**Recommended models:** Models with strong reasoning and large context windows perform best. Claude Opus/Sonnet, GPT-4o, Gemini 1.5 Pro, and large Ollama models (70B+) all work well. Smaller models (< 13B) tend to produce lower-quality findings and make more command errors.

### 2. Create or Select a Project
Projects organize your work. Create a named project, then add targets to it. Each target can be a hostname, FQDN, or IP address.

### 3. Input Scan Data
Paste your existing scan data JSON into the device input panel, or use the built-in recon feature to collect scan data autonomously. The JSON schema is documented below.

### 4. Analyze
Click **Analyze** to run the vulnerability analysis pipeline. Multiple LLM passes run in parallel. Findings appear in the vulnerability table as they arrive, sorted by severity.

### 5. Select and Execute
Check the vulnerabilities you want to actively test. Click **Execute Selected**. The exploit testing loop runs each finding through active validation. Status icons update in real time:
- `[PENDING]` — not yet tested
- `[CONFIRMED]` — exploitation succeeded with proof
- `[NOT VULNERABLE]` — definitively ruled out
- `[UNDETERMINED]` — tested but inconclusive (all approaches exhausted or target unreachable)

### 6. Review and Export
Click **Results** to view the full findings summary. Export as HTML, Markdown, or CSV from the toolbar.

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
│   ├── main_screen.dart          # Primary workspace (analysis, execution, results)
│   └── settings_screen.dart      # AI provider and execution settings
├── services/
│   ├── vulnerability_analyzer.dart  # Multi-prompt parallel analysis pipeline
│   ├── exploit_executor.dart        # Autonomous exploit testing loop
│   ├── recon_service.dart           # LLM-guided recon data collection
│   ├── prompt_templates.dart        # All analysis and execution prompt text
│   ├── command_executor.dart        # Shell command execution with safety controls
│   ├── llm_service.dart             # LLM API client (all providers)
│   ├── report_generator.dart        # HTML/Markdown/CSV report generation
│   ├── project_porter.dart          # Encrypted project export/import
│   ├── storage_service.dart         # File system path management
│   └── tool_manager.dart            # Tool availability detection and caching
├── utils/
│   ├── device_utils.dart         # Target IP extraction and scope classification
│   ├── command_utils.dart        # Command history, deduplication, approach tracking
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
| Require Approval | Pause and prompt before executing each shell command |
| Command Whitelist | Commands that bypass the approval prompt |
| Storage Path | Base directory for scan output file storage |

---

## Safety and Responsibility

PenExecute executes real shell commands on your local machine against real targets. It is intended for use by security professionals in authorized penetration testing engagements, security research, and CTF competitions.

**You are responsible for ensuring you have authorization to test any target.** Unauthorized scanning or exploitation is illegal in most jurisdictions regardless of the tools used.

The built-in safety controls (dangerous command blocklist, approval mode, timeout protection) are designed to prevent accidents, not to substitute for professional judgment and proper engagement scoping.

---

## License

Private project — not for public distribution.
