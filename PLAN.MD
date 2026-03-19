# PenExecute Master Improvement Plan

**Goal:** Make PenExecute the most thorough and capable autonomous penetration testing tool available — professional-grade, fully dynamic, and LLM-driven at every layer with zero hardcoded tool or CVE constraints.

---

## Guiding Principles (apply to ALL work)

1. **Objective-based prompts only.** Prompts describe *what to look for* and *what the attacker is trying to achieve* — never *which tool to use* or *which specific CVE to check*. Tools change and new CVEs are published daily; attacker objectives do not.

2. **The replacement test.** Before finishing any prompt, ask: *"If every tool named or implied in this prompt were replaced by a completely different tool tomorrow, would this prompt still work?"* If yes, it is correctly objective-based. If no, rewrite it.

3. **Evidence-first.** Every finding must be rooted in data present in the recon input. Speculative findings are rated LOW confidence and filtered. A missed finding is better than a false positive that erodes trust.

4. **Parallel and independent.** Analysis prompts fire independently and in parallel. Results merge post-analysis. No prompt should depend on output from another prompt.

5. **Prompt size discipline.** Each prompt must stay focused enough that any LLM — including small local models — can produce quality output. When a prompt covers more than 8–10 distinct attack classes, it must be split.

---

## Status Legend

- `[ ]` Not started
- `[~]` In progress
- `[x]` Complete

---

## Phase 1 — Critical Bug Fixes *(Complete)*

### 1.1 — Remove hardcoded tool list from exploit executor response schema `[x]`
### 1.2 — XSS knowledge base incorrectly mapped to SQL Injection section `[x]`
### 1.3 — External network service ports silently dropped (no prompt existed) `[x]`
### 1.4 — SSL/TLS analysis only fired on external targets `[x]`
### 1.5 — `_hasMxRecords()` fragile string matching (false matches on "proxy", "vmx") `[x]`

---

## Phase 2 — Exploit Executor Loop Improvements *(Complete)*

### 2.1 — Make iteration prompt fully objective-based (remove tool names from scope strategy) `[x]`
### 2.2 — Reduce max iterations with smart phase tracking and early exit `[x]`
### 2.3 — Credential bank: cross-vulnerability intelligence sharing `[x]`
### 2.4 — Exploitation chains: confirmed findings context injected into subsequent tests `[x]`
### 2.5 — WAF/CDN-aware iteration strategy (origin discovery before app-layer testing) `[x]`
### 2.6 — Surface phase and iteration count in UI during active testing `[x]`
### 2.7 — Post-exploitation enumeration pseudo-vulnerability auto-queued after confirmed RCE `[x]`
### 2.8 — Distinguish undetermined outcome reasons (unreachable / waf_blocked / phases_exhausted / etc.) `[x]`

---

## Phase 3 — Analysis Prompt Categories v1 *(Complete)*

### 3.1 — Active Directory analysis prompt `[x]`
### 3.2 — CORS misconfiguration analysis `[x]`
### 3.3 — API security analysis (GraphQL, JWT, REST) `[x]`
### 3.4 — HTTP security headers analysis `[x]`
### 3.5 — Business logic and race condition analysis `[x]`

---

## Phase 4 — Report Generation *(Complete)*

### 4.1 — Report generation service `[x]`
### 4.2 — CVSS score calculation `[x]`
### 4.3 — Per-finding copy to clipboard `[x]`
### 4.4 — Informational finding category (separate from exploitable findings) `[x]`

---

## Phase 5 — Analysis Quality Improvements *(Complete)*

### 5.1 — Deduplicate SPF/DMARC findings between DNS and email prompts `[x]`
### 5.2 — Evidence enforcement: mandatory `evidence_quote` field validated against raw device data `[x]`
### 5.3 — DoS and third-party infrastructure filter `[x]`
### 5.4 — Confidence and relevance filtering (remove low-confidence findings with no evidence) `[x]`
### 5.5 — Confidence floor rule added to every analysis prompt's RULES section `[x]`

---

## Phase 6 — Observability *(Complete)*

### 6.1 — Exploit loop phase tracking `[x]`
### 6.2 — Distinguish test-failed vs test-negative outcomes `[x]`
### 6.3 — Discovered credentials UI panel `[x]`

---

## Phase 7 — Code Quality *(Ongoing)*

### 7.1 — Prompt file organization (split into analysis / execution / knowledge sub-files) `[~]`
**When:** Once `prompt_templates.dart` exceeds ~1500 lines, split into:
- `prompts/analysis_prompts.dart` — all analysis-phase prompts
- `prompts/execution_prompts.dart` — iteration and evaluation prompts
- `prompts/knowledge_base.dart` — `knowledgeForType()` and knowledge sections
- `prompt_templates.dart` — thin facade re-exporting the above

### 7.2 — Target classification unit tests `[x]`

---

## Phase 8 — Web Application Coverage Gaps *(Complete)*

All items added to `webAppCorePrompt()` or `webAppModernPrompt()` and `knowledgeForType()`.

### 8.1 — Server-Side Template Injection (SSTI) `[x]`
### 8.2 — Host Header Injection `[x]`
### 8.3 — OAuth 2.0 Misconfigurations `[x]`
### 8.4 — HTTP Request Smuggling (evidence-gated: only when proxy chain is detected) `[x]`
### 8.5 — Open Redirects `[x]`
### 8.6 — WebSocket Security `[x]`
### 8.7 — CRLF Injection `[x]`
### 8.8 — Prototype Pollution (Node.js/JavaScript targets only) `[x]`

---

## Phase 9 — Active Directory Coverage Gaps *(Complete)*

All items added to `adAnalysisPrompt()`.

### 9.1 — Netlogon authentication bypass class `[x]`
### 9.2 — Windows Print Spooler privilege escalation class `[x]`
### 9.3 — Kerberos delegation attacks (unconstrained, constrained, RBCD) `[x]`
### 9.4 — ACL / DACL privilege escalation paths `[x]`
### 9.5 — Group Policy Preferences credential exposure `[x]`
### 9.6 — ADCS additional misconfiguration patterns (ESC2–ESC8, CA-level flags, web enrollment relay) `[x]`
### 9.7 — Shadow Credentials (Key Credential Link abuse) `[x]`
### 9.8 — LAPS credential exposure `[x]`

---

## Phase 10 — New Infrastructure Analysis Categories *(Complete)*

### 10.1 — Container / Kubernetes / DevOps infrastructure prompt `[x]`
### 10.2 — IoT / Embedded device analysis prompt `[x]`
### 10.3 — OT / SCADA / ICS protocol detection prompt (exposure identification, not active exploitation) `[x]`

---

## Phase 11 — Prompt Architecture Improvements *(Complete)*

### 11.1 — Web app prompt split: `webAppCorePrompt()` + `webAppModernPrompt()` (parallel calls) `[x]`
### 11.2 — `knowledgeForType()` missing type mappings added (command injection, SSTI, open redirect, OAuth, host header, CRLF, WebSocket, privilege escalation, config weakness) `[x]`
### 11.3 — Tool usage patterns rewritten as capability-first descriptions (not tool-first) `[x]`

---

## Phase 12 — Port and Service Coverage Gaps *(Complete)*

### 12.1 — Expanded port classification sets (container, DevOps, message brokers, enterprise middleware, OT, IoT) `[x]`
### 12.2 — Prompt firing matrix documentation updated to reflect all prompts and fire conditions `[x]`

---

---

## Phase 13 — Prompt Size and Density Reduction *(New — not yet implemented)*

**Problem:** From a professional assessment of the current prompts, two prompts are too large to produce consistent quality output from smaller LLMs, and the AD prompt in particular will cause weaker models to hallucinate or skip sections. Splitting these prompts does not reduce coverage — it forces each prompt to be more focused and actionable.

**Rule for all splits:** Each half must be independently executable. No half should require context from the other half to produce findings. Both halves fire under the same condition and merge through the deduplication pipeline.

---

### 13.1 — Split `webAppModernPrompt()` into two focused prompts `[x]`

**File:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`

**Why:** `webAppModernPrompt()` currently covers 15+ attack classes. This exceeds what smaller models can process reliably in a single context. The classes naturally split into two coherent groups.

**Split A — `webAppApiAuthPrompt()`** — API surface and authentication protocol attacks:
- CORS misconfiguration: attacker objective is to make cross-origin requests with the victim's credentials by exploiting a server that reflects arbitrary Origin headers. Look for: reflected Origin in Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials: true; null origin with credentials; subdomain wildcard origins.
- GraphQL security: attacker objective is to enumerate the full data schema and exploit query abuse. Look for: introspection enabled in production (reveals all types, queries, mutations); nested query depth with no limit (resource exhaustion); batch query abuse that bypasses rate limiting.
- JWT security: attacker objective is to forge authentication tokens without the signing key. Look for: algorithm confusion (asymmetric to HMAC — using the public key as HMAC secret); algorithm "none" acceptance; weak HMAC secrets; `kid` parameter injection (path traversal, SQL injection to control key selection); `jku`/`x5u` header injection pointing to attacker-controlled key sources.
- REST API authorization: attacker objective is to access or modify resources belonging to other users or with higher privilege. Look for: object-level authorization bypass (changing numeric IDs in request paths or parameters); function-level authorization bypass (accessing admin endpoints without admin role); mass assignment (adding unexpected fields like `role` or `isAdmin` to POST/PUT bodies); API version downgrade (older versions lacking authentication added to newer ones).
- OAuth 2.0 misconfigurations: attacker objective is account takeover or authorization code theft. Look for: open `redirect_uri` not strictly validated against a registered allowlist; missing or predictable `state` parameter (CSRF-based account takeover); authorization codes or tokens visible in URL parameters or browser history; implicit flow token leakage.
- WebSocket security: attacker objective is to hijack authenticated WebSocket sessions or inject through message channels. Look for: missing Origin header validation on WebSocket handshake (cross-site WebSocket hijacking); injection vulnerabilities in message content (SQLi, XSS, command injection via WebSocket channel); authentication bypass on WebSocket endpoints.
- Prototype pollution: attacker objective is to modify the shared JavaScript object prototype to bypass authorization or achieve code execution. Look for: Node.js or Express indicators; JSON endpoints accepting nested objects with `__proto__`, `constructor`, or `prototype` keys; any object merge or deep-assign operation on user-supplied data.

**Split B — `webAppLogicHeadersPrompt()`** — Business logic, state, and HTTP-level attacks:
- Business logic and race conditions: attacker objective is to exploit the application's intended flow for unintended gain. Look for: race conditions in any state-modifying operation (coupon redemption, balance modification, inventory reservation); price or value manipulation (negative quantities, zero-price items, integer overflow in monetary fields); workflow bypass (accessing later steps directly without completing required prior steps); privilege parameter manipulation (role or permission sent in request body, modifiable by attacker).
- SSTI: covered in existing Core prompt — if not already in Core, include here.
- Host header injection: attacker objective is to poison the Host header used by the application to construct URLs in emails or responses. Look for: password reset or email confirmation flows (password reset poisoning — CRITICAL); caching infrastructure with unkeyed Host header; internal routing based on Host value (SSRF escalation path).
- HTTP request smuggling: attacker objective is to inject a request prefix that poisons the next victim's request by exploiting parsing differences between a front-end proxy and back-end server. Fire only when proxy chain evidence is present (Via header, X-Forwarded-For, CDN/load balancer headers, HTTP/1.1 in use through a proxy layer). Do not generate speculatively.
- Open redirects: attacker objective is to redirect users to attacker-controlled destinations using the target's trusted domain. Look for: URL parameters named `return`, `redirect`, `next`, `url`, `goto`, `destination`, `target`, `location`, `to`, `forward`, `continue`; 302 responses with a URL parameter in the Location header. Severity: LOW alone; MEDIUM when OAuth is present (authorization code theft chain); MEDIUM when combined with authentication flows.
- CRLF injection: attacker objective is to inject arbitrary HTTP headers by inserting carriage-return and line-feed characters into parameters reflected in response headers. Look for: any URL parameter or form field reflected verbatim in a response header value (Location, Set-Cookie, Content-Disposition). Severity: MEDIUM for header injection; HIGH if Set-Cookie injection enabling session fixation is evidenced.
- HTTP security headers: attacker objective is to exploit missing defensive headers. Generate findings only when response headers are captured in recon data — not speculatively. Cover: Content-Security-Policy (missing or weak — enables XSS escalation); X-Frame-Options / frame-ancestors CSP (clickjacking); X-Content-Type-Options (MIME confusion); Referrer-Policy (credential leakage); Permissions-Policy.

**Fire condition:** Both new prompts fire under the same conditions as `webAppModernPrompt()` currently does (HTTP/HTTPS ports present). Run in parallel. Retire `webAppModernPrompt()` once both replacements are confirmed to be firing and merging correctly.

**Implementation steps:**
1. Write `webAppApiAuthPrompt()` in `prompt_templates.dart`
2. Write `webAppLogicHeadersPrompt()` in `prompt_templates.dart`
3. Add both to the `futures` list in `analyzeDevice()` under the same `hasWeb` condition
4. Remove `webAppModernPrompt()` from the futures list
5. Delete or archive `webAppModernPrompt()` method
6. Run a test scan against a known web target and verify both prompts return findings
7. Update the prompt firing matrix comment in `analyzeDevice()`

---

### 13.2 — Split `adAnalysisPrompt()` into three focused prompts `[x]`

**File:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`

**Why:** The current AD prompt covers 16 attack paths in a single ~150-line prompt. Smaller LLMs cannot hold all of this in effective working context and will miss or hallucinate sections. These 16 paths fall cleanly into three conceptual groups that a professional AD pentester works through sequentially.

**Split A — `adReconCredentialPrompt()`** — Initial access and credential material collection:
- LDAP null bind and unauthenticated enumeration: attacker objective is to enumerate domain objects without any credentials. Look for: LDAP or LDAPS port accessible, any indication of null bind success or BaseDN disclosure. Impact: usernames, groups, password policy, organizational structure — all feed subsequent attacks.
- Password spraying viability: attacker objective is to obtain a valid credential pair without triggering account lockout. Look for: password policy data (lockout threshold, observation window); enumerated usernames from any source (LDAP, Kerberos, SMB); any indication of weak account naming conventions. Generate a finding describing what spraying conditions exist and what makes this environment viable or resistant.
- AS-REP Roasting: attacker objective is to obtain an offline-crackable hash for accounts that do not require Kerberos pre-authentication — without any credentials. Look for: any indication of accounts with pre-auth disabled (userAccountControl flag data, LDAP enumeration output, recon tool output referencing pre-auth status); LDAP accessible (null bind may reveal account attributes).
- Kerberoasting: attacker objective is to obtain offline-crackable service ticket hashes using any valid domain account. Look for: any Service Principal Names visible in recon data; LDAP accessible (SPNs are readable by any authenticated user). Impact: service account password hash extractable and crackable offline.
- GPP credential exposure: attacker objective is to recover plaintext passwords from Group Policy Preference XML files in SYSVOL — readable by every domain user. Look for: domain environment confirmed; any SYSVOL access or reference to Group Policy files; `cpassword` attributes. Generate as a HIGH confidence finding in any confirmed domain environment — it always warrants testing.

**Split B — `adPrivilegeEscalationPrompt()`** — Privilege escalation once initial access exists:
- ADCS certificate template misconfigurations: attacker objective is to obtain a certificate usable for domain admin authentication by exploiting misconfigured certificate templates or CA-level settings. Look for: Certificate Authority present (web enrollment path, IIS with certificate services, certsrv indicators); any certificate template that allows low-privilege enrollment with high-privilege certificate use; CA-level flags that allow SAN specification on any template; web enrollment accepting NTLM authentication (relay attack surface). Severity: CRITICAL — ADCS misconfigurations provide a direct path to Domain Admin via PKINIT.
- ACL / DACL privilege escalation paths: attacker objective is to exploit excessive permissions on AD objects to reset passwords, add SPNs, configure delegation, or take ownership of high-value accounts. Look for: any LDAP ACL data; BloodHound-style output; references to GenericAll, GenericWrite, WriteDACL, ForceChangePassword, WriteOwner on user or computer objects; service accounts with membership in privileged groups (Backup Operators, Account Operators, Server Operators). Severity: MEDIUM to CRITICAL depending on the target object.
- Kerberos delegation attacks: attacker objective is to impersonate any domain user (including Domain Admins) to any service by exploiting delegation configuration. Three variants: unconstrained delegation (any host with TrustedForDelegation stores TGTs for all authenticating users — compromise yields impersonation of domain admins); constrained delegation with protocol transition (impersonate any user to specified services without their interaction); resource-based constrained delegation (write access to a computer object's msDS-AllowedToActOnBehalfOfOtherIdentity allows configuring impersonation — achievable with only GenericWrite on the computer object).
- Shadow Credentials (Key Credential Link abuse): attacker objective is to authenticate as any user or computer by adding an attacker-controlled RSA public key to their `msDS-KeyCredentialLink` attribute, then using PKINIT Kerberos to obtain their TGT — without knowing their password. Look for: Windows Server 2016+ environment; Azure AD Connect synchronization; any account with write access to user or computer objects (see ACL abuse).
- LAPS credential exposure: attacker objective is to read unique local administrator passwords stored in AD computer object attributes. Look for: `ms-Mcs-AdmPwd` or `ms-Mcs-AdmPwdExpirationTime` attributes visible in any LDAP output; LAPS deployment indicators. Severity: CRITICAL if passwords are readable; Informational if deployed and protected (note that LAPS limits Pass-the-Hash lateral movement scope).
- DCSync attack path: attacker objective is to simulate a Domain Controller replication request and extract all domain password hashes — including the krbtgt hash (enabling Golden Ticket attacks). Look for: any account other than Domain Controllers with Replicating Directory Changes permissions; recon output mentioning replication rights; any privilege path that could yield these permissions.

**Split C — `adLateralMovementPrompt()`** — Network-level attacks and lateral movement:
- SMB relay and LLMNR/NBNS poisoning: attacker objective is to capture NTLM authentication attempts by poisoning name resolution and relay them to SMB hosts without authentication — yielding code execution without any prior credentials. Look for: SMB signing disabled or not required (critical condition); Windows hosts present on the network; LLMNR/NBNS likely active (Windows default). Severity: CRITICAL if SMB signing is disabled on domain-joined hosts.
- Pass-the-Hash and Pass-the-Ticket: attacker objective is to use captured NTLM hashes or Kerberos tickets directly for authentication without cracking. Look for: any NTLM hash obtained or obtainable; Windows hosts where the same account is likely valid across multiple systems (common local admin passwords); Responder capture output; evidence of NTLM authentication in use.
- Netlogon authentication bypass class: attacker objective is to bypass domain controller authentication entirely via a cryptographic flaw in the Netlogon handshake — yielding unauthenticated domain-level access. Look for: Domain Controller identified (Kerberos port accessible, hostname or OS indicating DC role); Netlogon service reachable via SMB or RPC; absence of patch indicators for the authentication bypass class. Severity: CRITICAL — unauthenticated domain takeover.
- Windows Print Spooler privilege escalation class: attacker objective is to exploit the Print Spooler service to install drivers with SYSTEM privileges — yielding local privilege escalation on any Windows host or domain takeover when run against a Domain Controller. Look for: Windows hosts present; domain environment confirmed; Print Spooler service not explicitly disabled. Severity: HIGH on workstations, CRITICAL on Domain Controllers.

**Fire condition:** All three prompts fire under the same condition as `adAnalysisPrompt()` currently does. Run in parallel. Retire `adAnalysisPrompt()` once all three replacements are confirmed firing.

**Implementation steps:**
1. Write `adReconCredentialPrompt()` in `prompt_templates.dart`
2. Write `adPrivilegeEscalationPrompt()` in `prompt_templates.dart`
3. Write `adLateralMovementPrompt()` in `prompt_templates.dart`
4. Replace `adAnalysisPrompt()` in the `futures` list in `analyzeDevice()` with three new calls under the same `hasAd` condition
5. Delete or archive `adAnalysisPrompt()`
6. Run a test scan against an AD-indicator target and verify all three prompts return findings
7. Update the prompt firing matrix comment

---

## Phase 14 — Missing Coverage Gaps *(New — not yet implemented)*

These are attack surfaces that professional pentesters consistently hit but that have no coverage in any current prompt. Each requires a new prompt and/or additions to existing prompts. All descriptions must be objective-based — no specific tool names or CVE IDs.

---

### 14.1 — Dedicated Privilege Escalation Analysis Prompt `[x]`

**File:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`

**Why:** There is currently no analysis-phase prompt that identifies privilege escalation surface from recon data. The execution loop handles post-access PE (Phase 3b), but there is no analysis prompt that generates PE findings from the initial device scan. A server with a known OS and version string should immediately generate PE findings so they can be queued for testing.

**New prompt: `privilegeEscalationPrompt()`**

Attacker objective: move from any level of initial access (low-privilege shell, service account, web application process) to SYSTEM, root, or domain-level control on the target host.

**Linux privilege escalation surface to identify from recon data:**
- Sudo misconfiguration: any indication that the application or service account can run commands as root without a password — evidenced by application purpose (web server processes, cron-executed scripts, service accounts) or OS/version indicators suggesting default configurations
- SUID/SGID binary abuse: non-standard binaries with elevated permissions that can be exploited to execute arbitrary code with elevated privileges — look for any custom application paths or development tool indicators in the service banners
- Writable cron job paths: cron jobs that execute scripts in world-writable directories allow privilege escalation by replacing the script
- World-writable service files: systemd unit files, init scripts, or service wrapper scripts in writable locations
- Kernel version and local privilege escalation surface: the OS version string identifies the kernel version, which can be matched against local privilege escalation vulnerability classes. Look for: OS version string in recon data; any application version that pins to a specific OS release; kernel version indicators in banner data
- Credential material in accessible locations: configuration files for services often contain database passwords, API keys, or service account credentials — web application configuration, application server configuration, and database connection strings are high-value targets
- PATH hijacking: if the application executes commands from paths that include writable directories before system directories, an attacker with write access can place a replacement binary

**Windows privilege escalation surface to identify from recon data:**
- Unquoted service paths: Windows services configured with paths containing spaces and no quotes — any binary placed at the unquoted path prefix executes as the service account
- Weak service binary permissions: services whose executable paths are writable by non-privileged users
- AlwaysInstallElevated policy: Windows Installer policy that allows any user to install MSI packages with SYSTEM privileges
- Token impersonation surface: service accounts running as NetworkService, LocalService, or IIS AppPool accounts have impersonation privileges enabling escalation to SYSTEM in most Windows configurations
- Stored credential exposure: Windows Credential Manager, configuration files in application directories, and web application config files frequently contain recoverable credentials
- Scheduled task misconfigurations: tasks executing scripts in writable paths

**Fire condition:** Any host with an identified OS in the recon data — both internal and external. Also fire when service banners contain OS-level information (Apache on Ubuntu, IIS on Windows Server, etc.).

**Detection to add in `vulnerability_analyzer.dart`:**
- `_hasOsIndicators()`: returns true if device JSON contains OS field, operating_system field, or OS-revealing version strings in any port banner. This should be true for the vast majority of scanned hosts.
- Add `if (hasOs) _runPrompt(...)` to the `analyzeDevice()` futures list

---

### 14.2 — SNMP and Network Management Protocol Deep-Dive Prompt `[x]`

**File:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`

**Why:** SNMP is currently one bullet point in `networkServiceAnalysisPrompt()`. In real internal pentests, SNMP with default community strings yields far more than a version disclosure — it provides a complete map of the target's network environment: ARP tables, routing tables, running processes, installed software, interface configurations, and sometimes device credentials. This intelligence directly enables lateral movement target identification. SNMP deserves a dedicated prompt.

**New prompt: `snmpManagementPrompt()`**

**Attacker objective:** Enumerate the target's full network intelligence and configuration state through management protocol access, and identify any credential material or pivoting opportunities.

**SNMP analysis areas:**
- Default and weak community string access: SNMP v1 and v2c use cleartext community strings for authentication, with "public" (read) and "private" (read-write) as nearly universal defaults. Read access reveals all OIDs; write access allows modifying device configuration. Look for: SNMP port present; any indication of v1 or v2c in use; absence of SNMPv3 indicators.
- Information disclosure scope from read access: a successfully authenticated SNMP read yields: the full ARP cache (every IP-to-MAC mapping the device has seen — maps the entire reachable network); the full routing table (identifies network segments and gateways); all running processes and their command lines; all installed software and versions; all network interface configurations including IP addresses and MACs; system description, contact, and location strings; connected device information. Each of these is a separate finding category because each has a distinct attacker use.
- SNMP write access impact: write access to SNMP allows modifying device configuration: changing routing tables, modifying VLAN assignments, disabling interfaces, redirecting traffic, or in some devices executing configuration commands. This is a CRITICAL finding because it enables network-level manipulation.
- SNMPv3 weaknesses: even SNMPv3 can be misconfigured — weak authentication passwords, no encryption (authNoPriv mode), or default SNMPv3 credentials. Look for: SNMPv3 indicated but authentication bypass possible; cleartext SNMPv3 traffic (AuthNoPriv mode).
- SNMP trap receiver exposure: SNMP trap receivers that accept traps from any source without authentication can be used to inject false monitoring data or to identify the monitoring infrastructure.

**Other management protocols to cover in the same prompt:**
- NetFlow / IPFIX collector exposure: if a flow collection port is accessible, it may accept injected flow records, corrupting traffic analysis
- Syslog receiver: unauthenticated syslog receivers accept log injection from any source — useful for injecting false audit trails
- IPMI (Intelligent Platform Management Interface): if an IPMI or BMC port is accessible, authentication bypass in older IPMI versions allows reading password hashes for all configured users from the baseboard management controller — completely out-of-band from the OS, so OS-level controls do not apply. Severity: CRITICAL — IPMI access yields full hardware-level control independent of the operating system

**Fire condition:** SNMP port (161 UDP, 162 UDP) present in open ports, OR any management protocol port (IPMI: 623 UDP, syslog: 514 UDP/TCP) present.

**Detection to add in `vulnerability_analyzer.dart`:**
- `_hasSnmpOrManagementPorts()`: checks for SNMP (161/162), IPMI (623), syslog (514), and checks service names for "snmp", "ipmi", "syslog"
- Add `if (hasSnmp) _runPrompt(...)` to `analyzeDevice()` futures list

---

### 14.3 — WinRM, WMI, and Windows Remote Management Coverage `[x]`

**File:** `lib/services/prompt_templates.dart` — add to `networkServiceAnalysisPrompt()` and/or `adAnalysisPrompt()` (split C when implemented)

**Why:** WinRM (Windows Remote Management / PowerShell Remoting) on ports 5985 and 5986 is a primary Windows lateral movement vector in modern environments. It is not mentioned in any current prompt. WMI over DCOM (port 135 + dynamic high ports) is equally critical. Together these are the primary mechanisms for agentless Windows management — and primary mechanisms for lateral movement once credentials are obtained.

**Coverage to add:**

**WinRM (PowerShell Remoting):**
- Attacker objective: authenticate to the WinRM service with obtained credentials and execute PowerShell commands on the remote host — effectively yielding an interactive management session
- Look for: WinRM ports (5985 HTTP, 5986 HTTPS) in open port data; Windows host indicators; service name "winrm" or "microsoft-httpapi"
- When accessible with any credential (domain account, local admin): attacker gains PowerShell remoting session equivalent to interactive administrator access
- Severity: HIGH when accessible with non-admin credentials; CRITICAL when accessible from external network

**WMI over DCOM:**
- Attacker objective: execute commands on remote Windows systems using the Windows Management Instrumentation framework — a native Windows capability that most security products do not flag
- Look for: port 135 (RPC endpoint mapper) and high dynamic ports on Windows hosts; domain environment confirmed; any credential obtained
- WMI command execution requires only a valid credential for a local or domain account — no special configuration required
- Severity: HIGH — WMI-based lateral movement is difficult to detect and is natively trusted by Windows

**WinRM authentication testing:**
- When credentials are discovered (from credential bank), WinRM should be immediately tested as a lateral movement target on all Windows hosts in scope
- This is currently not explicitly called out — add to the AD lateral movement prompt (13.2, Split C) as a priority credential-reuse target

**Additions required:**
- Add WinRM ports (5985, 5986) to `_networkPorts` set in `vulnerability_analyzer.dart`
- Add "winrm", "powershell remoting" to `_networkServices` set
- Add WinRM/WMI attack surface description to `networkServiceAnalysisPrompt()` for internal targets
- Add WinRM as explicit lateral movement target in `adLateralMovementPrompt()` (13.2 Split C)
- Add WinRM to `knowledgeForType()` mapping for "winrm" and "lateral movement" types

---

### 14.4 — Secrets and Credential Exposure Analysis Prompt `[x]`

**File:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`

**Why:** Web applications frequently expose credential material through paths that are not injection vulnerabilities — exposed source control repositories, configuration files, backup files, and secret management misconfigurations. This is a distinct attack surface from the web app injection prompts and deserves its own analysis pass.

**New prompt: `secretsExposurePrompt()`**

**Attacker objective:** Discover credential material, API keys, or sensitive configuration data exposed through the web application without authentication.

**Attack surfaces to analyze:**

**Source control exposure:**
- Exposed version control metadata directories: development artifacts left in web-accessible paths reveal the application's complete source code history. Look for: indicators of web application technology suggesting in-place deployment; paths that suggest a repository root in the web root; any reference to source control in recon data. The impact is total — full source code disclosure reveals all credentials hardcoded in configuration files, API keys, database connection strings, and application logic.
- Common backup and archive files: developers frequently create backup copies of configuration files, database dumps, and compressed archives in web-accessible paths. Look for: any file management functionality; evidence of backup or deployment processes in recon data; paths referencing dates or "backup" in discovered URLs.

**Configuration file exposure:**
- Application configuration files accessible without authentication: environment configuration files (.env, application.properties, appsettings.json, config.php, database.yml, settings.py) routinely contain database credentials, API keys, cloud provider credentials, and service account passwords when accessible at their default paths. Look for: web application technology fingerprint (identifies which config file paths are likely); any directory enumeration results in recon showing configuration-related paths; error messages that reveal configuration file paths.
- Cloud provider credential files: cloud provider credential files (AWS credentials, GCP service account JSON, Azure credentials) stored in web-accessible paths or accessible via path traversal. Look for: SSRF findings that could be used to reach internal metadata; any cloud provider indicators in recon data.

**Secret management exposure:**
- Vault and secret management UI: secret management systems (HashiCorp Vault, AWS Secrets Manager web console, Azure Key Vault management interface) with unauthenticated or weakly authenticated management interfaces. Look for: management tool ports or paths in recon data; any secret management system indicators.
- Kubernetes secrets accessible via exposed API: if a Kubernetes API server is accessible (covered in container prompt), secrets stored in the cluster are readable — highlight when both Kubernetes API access and secret storage indicators are present.

**Cleartext credential transmission:**
- HTTP Basic Authentication over unencrypted connections: credentials submitted via Basic Auth over HTTP are transmitted in cleartext (Base64-encoded, not encrypted) — any passive network observer captures them. Look for: HTTP (not HTTPS) ports with authentication prompts; Basic Auth challenge in response headers; any indication of authentication over port 80 or other non-TLS ports.
- FTP credential exposure: FTP transmits credentials in cleartext by default. If FTP is in use for file transfer in conjunction with a web application, credentials used for FTP access may be reused for other services.

**Fire condition:** Any web port present (internal or external). This prompt fires alongside the web app prompts.

**Detection:** No new detection function needed — fires under the same `hasWeb` condition.

---

### 14.5 — IPv6 Attack Surface Coverage `[x]`

**File:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`

**Why:** IPv6 is enabled by default on all modern operating systems and network equipment. Many internal networks have IPv6 traffic active even when administrators believe they are running IPv4-only networks. IPv6 attack surfaces are frequently unmonitored, un-firewalled, and unpatched compared to their IPv4 equivalents.

**Coverage to add to `networkServiceAnalysisPrompt()` (internal targets):**

**IPv6 network-level attacks:**
- Rogue Router Advertisement (RA): on any network where IPv6 is active, an attacker on the local segment can broadcast Router Advertisement messages claiming to be the default IPv6 gateway. Hosts that accept these advertisements will route IPv6 traffic through the attacker, enabling man-in-the-middle attacks on all IPv6 traffic — without any authentication or prior access. Look for: any IPv6 address or interface data in recon; Windows or Linux hosts with default IPv6 stack active.
- DHCPv6 rogue server: similarly, a rogue DHCPv6 server can provide IPv6 addresses and DNS server configuration to all hosts on the local segment, redirecting DNS resolution to an attacker-controlled resolver — enabling phishing via DNS manipulation.
- IPv6 firewall bypass: IPv4 firewall rules frequently do not have IPv6 equivalents. Services blocked on IPv4 may be accessible on the same host via IPv6. Look for: any host with both IPv4 and IPv6 addresses; services that show as filtered on IPv4 but may be accessible on IPv6.
- IPv6 SLAAC attack: Stateless Address Autoconfiguration allows hosts to automatically configure IPv6 addresses from Router Advertisement prefixes — rogue RA advertisements can poison this process.

**IPv6 service exposure:**
- Services listening on IPv6 that are not listed in IPv4 port scans — network services may be bound to IPv6 interfaces without administrators realizing they are accessible
- IPv6 tunneling protocols (6to4, Teredo, ISATAP) that may bypass network segmentation controls

**Evidence to look for:** Any IPv6 address in recon data; Windows hosts (IPv6 enabled by default since Vista); Linux hosts with modern kernels (IPv6 enabled by default); any mention of dual-stack configuration.

**Additions required:**
- Add IPv6-related checks to `networkServiceAnalysisPrompt()` — a new subsection covering Rogue RA, DHCPv6 spoofing, and service exposure via IPv6
- Add IPv6 attack surface description to `knowledgeForType()` for "ipv6" and "network" types
- Note: IPv6 scanning is not currently possible from recon input alone — these findings should be generated at LOW-MEDIUM confidence as "IPv6 attack surface should be tested" recommendations when IPv6 indicators are present

---

### 14.6 — SSRF Cloud Metadata Chain Analysis `[x]`

**File:** `lib/services/prompt_templates.dart` — add to `webAppCorePrompt()`

**Why:** SSRF is covered in `webAppCorePrompt()` but only briefly. The cloud metadata endpoint chain is a critical escalation path for external targets hosted on cloud infrastructure — SSRF → cloud instance metadata → IAM role credentials → cloud provider API access → lateral movement into the entire cloud environment. This chain should be explicitly called out.

**Addition to `webAppCorePrompt()` SSRF section:**

**Cloud-hosted targets — SSRF escalation path:**
When the target appears to be hosted on a cloud provider (evidenced by CNAME records, IP ranges, or cloud provider HTTP headers in recon data), SSRF vulnerabilities have a uniquely high escalation path:
- Cloud instance metadata services expose a privileged HTTP endpoint accessible only from the instance itself — it returns the IAM role name and temporary credentials assigned to the instance
- Any SSRF vulnerability that allows reaching internal IP addresses can be used to query this metadata endpoint
- Successful retrieval of cloud credentials allows the attacker to authenticate to the cloud provider's API with whatever permissions the instance role has — potentially yielding full cloud account access, access to storage buckets, database credentials, other service credentials, and the ability to create new resources or backdoor accounts
- Look for: any SSRF-capable parameter (URL input, webhook URL, document import, image fetch from URL) combined with cloud hosting indicators; any error messages revealing internal IP ranges consistent with cloud metadata access

**Evidence to look for:** Cloud provider CNAME records (cloudfront, azureedge, amazonaws, etc.); server response headers identifying cloud infrastructure; SPF records with cloud provider IP ranges; any URL parameter that fetches remote content.

**Generate this finding when:** Any SSRF-capable attack surface is identified AND the target shows any cloud hosting indicator. Severity: CRITICAL — cloud credential exposure from a single SSRF finding can yield account-wide access.

---

### 14.7 — External Subdomain Enumeration Analysis Prompt `[x]`

**File:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`

**Why:** Subdomain enumeration is a first-class external pentesting activity. Shadow IT, abandoned applications, staging environments with weaker authentication, admin panels on alternative subdomains, and API endpoints on dedicated subdomains are consistently among the most impactful findings in external assessments. Currently, subdomain takeover is mentioned reactively (when CNAME records show dangling pointers), but there is no prompt that systematically approaches subdomain attack surface discovery.

**New prompt: `subdomainReconPrompt()`**

**Attacker objective:** Identify the full subdomain attack surface of the target organization — including shadow IT, staging environments, abandoned applications, and administrative interfaces hosted on non-primary subdomains.

**Analysis areas:**

**Attack surface inference from known data:**
- From MX records: mail server subdomains often reveal internal hostnames, geographic locations, and hosted service providers — and are frequently accessible directly for SMTP-level testing
- From SPF records: `ip4:` and `include:` directives reveal the organization's full email-sending IP range and hosted services
- From CNAME records: third-party service CNAMEs reveal which SaaS platforms are in use for which functions (marketing, support, authentication, payment) — each is a phishing and account compromise surface
- From certificate transparency logs: TLS certificates issued for `*.domain.com` and specific subdomains are publicly logged — inferring the subdomain attack surface from certificate data reveals infrastructure the organization may consider private

**High-value subdomain patterns for any organization:**
- Authentication and SSO endpoints (sso., auth., login., id., identity.) — these are the highest value targets: successful compromise yields access to every application using that SSO
- Administrative interfaces (admin., portal., manage., control., console.) — often have weaker authentication than production, may expose internal tools
- Staging and development environments (staging., dev., test., uat., qa., sandbox.) — frequently run with debug settings, relaxed authentication, and older software versions
- API subdomains (api., api-v1., api-v2., graphql.) — often have different authentication models than the main application, may have older endpoints without authentication added to newer versions
- VPN and remote access (vpn., remote., citrix., rdweb.) — credential exposure here yields direct network access
- Document and collaboration tools (docs., wiki., intranet., confluence., jira.) — often contain sensitive internal information accessible with any valid account

**Subdomain takeover surface:**
- Any CNAME record pointing to a third-party service endpoint should be evaluated for whether the subdomain name is claimed on that service — unclaimed subdomains allow an attacker to register the name and serve content under the organization's domain

**Fire condition:** External targets only, AND either: DNS findings are present in the device data, OR the target is an FQDN (not a raw IP). This fires in parallel with other external prompts.

**Detection to add in `vulnerability_analyzer.dart`:**
- `_isExternalFqdn()`: returns true if the target is external AND is an FQDN (contains at least one dot and is not an IP address)
- Fire `subdomainReconPrompt()` when `isExternal && (_hasDnsFindings(deviceJson) || _isExternalFqdn(deviceJson))`

---

## Phase 15 — Execution Loop Post-Exploitation Improvements *(New — not yet implemented)*

The execution loop already handles post-exploitation to some degree (Phase 2.7 added a post-exploitation pseudo-vulnerability). These tasks improve the structure and effectiveness of what happens after initial access is confirmed.

---

### 15.1 — Structured Post-Exploitation Prompt for Confirmed RCE `[x]`

**File:** `lib/services/exploit_executor.dart`, `lib/services/prompt_templates.dart`

**Why:** When an RCE or authentication bypass is confirmed, the current behavior queues a pseudo-vulnerability for further testing. The prompt given to that pseudo-vulnerability test uses the generic iteration prompt. A dedicated post-exploitation iteration prompt would be more effective — it knows the context (confirmed access type, OS, privilege level) and can direct the LLM toward a structured kill-chain rather than continuing to probe for the initial access.

**New prompt: `PromptTemplates.postExploitationPrompt()`**

The post-exploitation prompt should cover these objectives in order:

**1. Situational awareness (do this first — understand what access you have):**
- Identify current user and privilege level
- Identify the operating system, version, and patch level
- Identify the network interfaces and reachable network segments
- Identify what other services, applications, and data stores are accessible from this host
- Identify whether this host is domain-joined (if Windows) or part of a managed environment

**2. Credential collection (highest priority after situational awareness):**
- Look for credential material in all accessible locations: configuration files for every application running on the host, environment variables, shell history files, SSH private keys, browser saved passwords, application keystore files
- On Windows: check for saved credentials in Windows Credential Manager, unattend.xml files, SAM database (if local admin), application-specific credential storage
- On Linux: check /etc/shadow (if root), SSH authorized keys and private keys in all home directories, application configuration directories, database connection strings in web application configurations
- If domain-joined Windows: check for NTLM hashes (if local admin or SYSTEM), Kerberos ticket cache, any Active Directory credential material
- Every discovered credential must be fed to the credential bank for cross-service testing

**3. Lateral movement opportunities:**
- Identify all other hosts reachable from this system (ARP cache, routing table, DNS resolver cache, known hosts file, application connection strings pointing to other servers)
- Test discovered credentials against all reachable services immediately — credential reuse is extremely common
- Identify trust relationships: SSH keys that authorize access to other hosts, application service accounts with access to other systems, network shares accessible with current credentials

**4. Privilege escalation (if not already at highest privilege):**
- Follow the privilege escalation checklist appropriate for the OS (see privilege escalation analysis prompt, Phase 14.1)
- Priority: escalate to root/SYSTEM before collecting credentials that require elevated access

**5. Persistence indicators (document but do not necessarily implement):**
- Identify where a persistent backdoor could be placed — document as a finding showing the attacker's persistence capability, do not actually install persistence unless explicitly in scope
- Common persistence paths: cron jobs (Linux), scheduled tasks (Windows), startup directories, service installation (if SYSTEM/root), web shell in web root (if web server access)

**Implementation notes:**
- This prompt fires as the iteration prompt for any vulnerability where `vuln.vulnerabilityType == 'Post-Exploitation'` (the pseudo-vulnerability type from Phase 2.7)
- The initial context should include the confirmed access type, confirmed proof command output, and device context
- Credential bank and confirmed findings context are especially important for this prompt — they provide the foundation for lateral movement

---

### 15.2 — Exploitation Chain Awareness in Analysis Phase `[x]`

**File:** `lib/services/vulnerability_analyzer.dart`

**Why:** When multiple confirmed findings exist from prior vulnerability tests on the same target, the analysis phase for new targets should be aware of them. Currently, confirmed findings context is injected into the exploitation loop but not into the analysis phase. Analysis-phase prompts could generate better findings if they knew what the attacker already has.

**Change:** After existing confirmed findings are available for a target, inject a brief confirmed-findings summary into each analysis prompt. This allows the LLM to generate higher-quality findings such as:
- "Given that SQLi is confirmed on the login form, the attacker already has database access — prioritize checking for stored credentials or file write capabilities"
- "Given that LDAP null bind is confirmed, the following attack paths now have higher confidence because usernames and password policy are known"

**Implementation:**
- Pass `confirmedFindingsContext` to `VulnerabilityAnalyzer.analyzeDevice()`
- Append a brief "## CONFIRMED PRIOR FINDINGS:" section to each prompt that already has findings
- Keep this section brief — just enough context for the LLM to adjust confidence and generate chained findings

---

## Phase 16 — Knowledge Base Decontamination *(New — not yet implemented)*

The execution-phase knowledge base (`exploitKnowledgeBase` in `prompt_templates.dart`) still contains tool-specific syntax and hardcoded command examples that should be expressed as capability descriptions. This phase removes those dependencies while retaining the underlying operational guidance.

---

### 16.1 — Audit and rewrite all TOOL USAGE PATTERNS entries `[x]`

**File:** `lib/services/prompt_templates.dart` — `exploitKnowledgeBase` TOOL USAGE PATTERNS section

**Current problem:** Each tool entry begins with the tool name and specific flag syntax. When tool syntax changes, or when a better tool exists that the LLM would prefer, the hardcoded syntax anchors the LLM to a specific tool and may produce silent failures (wrong flags often produce empty output rather than an error message).

**Rewrite approach for each tool category:**

For each tool currently listed (credential testing tools, directory enumeration tools, template-based vulnerability scanners, HTTP testing tools, network scanners, exploitation frameworks, exploit databases):

1. Lead with the **capability it provides** — what the attacker is trying to accomplish and what output would confirm it
2. Name the tool as **one example** of a tool that provides this capability, not the only option
3. Note any **critical gotchas** for that specific tool (quoting requirements, CSRF handling, flag syntax ambiguity) as warnings rather than as the primary instruction
4. Explicitly state: "If this tool is not available or a better alternative exists for the objective, use the alternative — the goal is the capability, not the specific tool"

**Priority entries to rewrite first (highest risk of silent failure):**
- Template-based vulnerability scanners (flag syntax changes between versions — empty results are indistinguishable from "no vulnerabilities found")
- Directory enumeration tools (extension flag syntax confusion causes empty results)
- Credential testing tools for HTTP forms (CSRF handling failures cause false positives)

**Entries that can remain more prescriptive:**
- Exploitation framework patterns (the framework has a stable, consistent interface)
- Exploit database search patterns (stable search syntax)
- These should still note that alternatives exist, but the specific syntax guidance is valuable here

---

### 16.2 — Remove CVE-specific guidance from knowledge base sections `[x]`

**File:** `lib/services/prompt_templates.dart` — `exploitKnowledgeBase` technique sections

**Current problem:** Several knowledge base sections reference specific CVE IDs by number (e.g., dnsmasq CVE IDs in the DNS section, specific SMB CVE names). This creates the same hardcoding problem — new CVEs are published constantly, and the LLM should reason about vulnerability classes and match them to what it finds rather than checking a fixed list.

**Rewrite approach:**
- Replace specific CVE references with vulnerability class descriptions: "heap overflow in versions prior to X" instead of "CVE-XXXX-XXXX"
- Keep version threshold information when it is stable and useful: "dnsmasq versions prior to 2.78 contain heap overflow vulnerabilities in DNS parsing"
- Remove specific exploit IDs and database references — the LLM should search for what applies, not check a fixed list
- Exception: when a vulnerability class is so significant that the class name itself has become the identifier (e.g., "Heartbleed", "POODLE", "EternalBlue"), the class name can remain because it is the search term, not a hardcoded solution

---

### 16.3 — Audit execution iteration prompt for tool-specific language `[x]`

**File:** `lib/services/exploit_executor.dart` — the main iteration prompt in `testVulnerability()`

**Current problem:** The iteration prompt's TESTING STRATEGY section contains specific command syntax examples in Phase 2 and Phase 3 that name specific tools and flags. While examples are helpful, they should be framed as illustrations of the objective rather than as the required approach.

**Audit checklist:**
- Phase 1 (Reconnaissance): check that version detection guidance describes the objective (get exact product and version) without naming specific tool flags
- Phase 2 (Vulnerability Verification): ensure the guidance to "search for exploit modules" and "use vulnerability scanners" is objective-based rather than naming specific commands
- Phase 3 (Post-authentication testing): the CSRF token handling guidance is necessarily somewhat specific because it describes HTTP protocol mechanics — this is acceptable. Ensure it describes what to look for in the HTML rather than specific grep patterns.
- Phase 3b (Privilege escalation): the checklists in this section are necessarily specific (they describe what to check for). Ensure they describe conditions and indicators rather than specific tool commands.
- COMMAND CONSTRUCTION RULES: these are execution mechanics, not tool selection — keep them specific where they prevent command failures

---

## Implementation Order

Work through these phases in the sequence below. Each item is a discrete, completable step.

### Immediate Priority (biggest impact, independent of each other)

1. **14.1** — Privilege Escalation analysis prompt (fires on nearly every host, currently zero coverage)
2. **13.1** — Split `webAppModernPrompt()` into `webAppApiAuthPrompt()` + `webAppLogicHeadersPrompt()`
3. **14.4** — Secrets and Credential Exposure prompt (fires with web ports, high finding frequency)
4. **14.2** — SNMP / Management Protocol deep-dive prompt
5. **14.3** — WinRM/WMI coverage additions (add to existing prompts)

### Second Priority (significant AD and architecture improvements)

6. **13.2** — Split `adAnalysisPrompt()` into three focused prompts
7. **14.7** — External subdomain enumeration prompt
8. **14.6** — SSRF cloud metadata chain (add to existing web core prompt)
9. **14.5** — IPv6 attack surface (add to existing network service prompt)

### Third Priority (execution quality improvements)

10. **15.1** — Structured post-exploitation prompt for confirmed RCE
11. **15.2** — Exploitation chain awareness in analysis phase
12. **16.1** — Audit and rewrite TOOL USAGE PATTERNS entries (capability-first)
13. **16.2** — Remove CVE-specific guidance from knowledge base sections
14. **16.3** — Audit iteration prompt for tool-specific language

### Ongoing / When Triggered

15. **7.1** — Prompt file split (trigger: `prompt_templates.dart` exceeds ~1500 lines)

---

*Last updated: 2026-03-18*
*Phases 1–12: Complete.*
*Phase 13: Prompt size reduction — not started.*
*Phase 14: Missing coverage gaps — not started.*
*Phase 15: Execution loop post-exploitation — not started.*
*Phase 16: Knowledge base decontamination — not started.*
