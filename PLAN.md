# PenExecute — Gap Remediation Plan

**Created:** 2026-03-19
**Scope:** Nine identified gaps from professional pentester assessment
**Goal:** Elevate PenExecute from "impressive and above-average" to the best autonomous pentester available

---

## Implementation Phases

### Phase 1 — Quick Wins (Low Risk, High Value)
- [x] 1.1 IP Classification Completeness
- [x] 1.2 Cookie Security Attribute Checks
- [x] 1.3 Cross-Forest AD Trust Attacks

### Phase 2 — New Prompt Content
- [x] 2.1 Web Cache Poisoning Prompt
- [x] 2.2 postMessage Vulnerability Class
- [x] 2.3 Blind / OOB SSRF Methodology
- [x] 2.4 DOM / JavaScript Attack Surface Prompt

### Phase 3 — Structured Recon Baseline
- [x] 3.1 Deterministic Pre-LLM Baseline Runner
- [x] 3.2 Passive OSINT Integration

### Phase 4 — Prompt Architecture Optimization
- [x] 4.1 SSRF Bypass Section Conditional Extraction

---

## Phase 1 — Quick Wins

### 1.1 — IP Classification Completeness

**File:** `lib/utils/device_utils.dart`
**Method:** `classifyTarget()` (line ~182)
**Problem:** CGNAT (100.64.0.0/10) and IPv6 ULA (fc00::/7) are classified as external, causing the wrong prompt set to fire. AWS/Azure private VPC addresses beyond RFC-1918 also sometimes appear in device JSON.

**Steps:**

1. In `classifyTarget()`, after the existing link-local check (`169.254.`), add:
   - CGNAT range: `100.64.0.0/10` — check if `o1 == 100 && o2 >= 64 && o2 <= 127`
   - Shared address space is defined in RFC 6598 and used by carrier-grade NAT and large enterprise environments; targets in this range should receive the internal prompt set

2. In the IPv6 handling section, add ULA classification:
   - IPv6 ULA prefix: `fc00::/7` — addresses starting with `fc` or `fd` are internal
   - Check with `a.startsWith('fc') || a.startsWith('fd')` before the "hostname with dots → external" fallback
   - These are the IPv6 equivalent of RFC-1918 private addresses

3. Add a `_isPrivateIpv4(int o1, int o2, int o3, int o4)` helper that encapsulates all private/special ranges to keep the classifyTarget method readable:
   - 10.0.0.0/8
   - 172.16.0.0/12
   - 192.168.0.0/16
   - 100.64.0.0/10 (CGNAT / RFC 6598)
   - 169.254.0.0/16 (link-local)
   - 127.0.0.0/8 (loopback)

4. Add a unit test in `test/` covering:
   - `100.64.0.1` → internal
   - `100.127.255.254` → internal
   - `100.128.0.1` → external (just outside CGNAT range)
   - `fd00::1` → internal
   - `fc80::1` → internal
   - `2001:db8::1` → external

**Risk:** Low. Pure classification logic change, no prompt content altered.

---

### 1.2 — Cookie Security Attribute Checks

**File:** `lib/services/prompt_templates.dart`
**Method:** `webAppLogicHeadersPrompt()`
**Problem:** The HTTP Security Headers section covers CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy — but cookie security attributes are absent. These are a standard pentest checklist item and are captured in virtually every real engagement report.

**Steps:**

1. In `webAppLogicHeadersPrompt()`, locate the `### HTTP Security Headers` section.

2. Add a new subsection **immediately after** the existing headers list (before the `## RULES:` block):

```
### Cookie Security Attributes
Attacker objective: exploit insecure cookie configuration to steal session tokens, perform session fixation, or enable cross-site request forgery.
Generate when Set-Cookie headers were captured in recon data:
- Missing `HttpOnly` flag on session cookies: allows JavaScript to read the cookie — enables XSS-to-session-hijack escalation. Severity: MEDIUM. Generate for every session cookie missing this flag.
- Missing `Secure` flag on session cookies over HTTPS: cookie transmitted on any HTTP request including HTTP downgrade or mixed-content requests. Severity: MEDIUM on HTTPS-only sites; HIGH if HTTP is also accessible.
- Missing or insufficient `SameSite` attribute: `SameSite=None` without `Secure` allows cross-site transmission; absence of SameSite defaults to Lax in modern browsers but None in older ones — CSRF via cross-site form submission may be possible. Severity: MEDIUM when used with authentication cookies.
- Overly broad `Domain` attribute: `Domain=.example.com` makes the cookie available to all subdomains — if any subdomain is compromised, session cookies are accessible there. Severity: MEDIUM when subdomain takeover surface exists.
- Overly broad `Path` attribute: `Path=/` on a sensitive cookie exposes it to all paths including those serving untrusted content. Severity: LOW.
- Session cookie without `__Host-` or `__Secure-` prefix on HTTPS applications: these prefixes enforce Secure flag and restrict Domain/Path, preventing cookie injection via subdomain compromise. Absence is a LOW finding but worth noting for defence-in-depth.
Evidence to require: Set-Cookie response headers captured in recon data. Do NOT generate speculatively.
```

3. Update the `## RULES:` block to add:
   - `- Cookie attributes: only if Set-Cookie headers were captured in recon data`

4. The `_outputFormatBlock()` already handles severity/confidence, so no format changes needed.

**Risk:** Minimal. Additive prompt content within an existing prompt.

---

### 1.3 — Cross-Forest AD Trust Attacks

**File:** `lib/services/prompt_templates.dart`
**Method:** `adLateralMovementPrompt()` (or whichever AD prompt covers lateral/persistence)
**Problem:** Cross-forest trust abuse (SID history injection, trust ticket forging, msDS-AllowedToDelegateTo across trusts, foreign principal group membership) is absent. This is relevant in any multi-forest enterprise engagement — common in large organizations.

**Steps:**

1. Read the full content of `adLateralMovementPrompt()` to find the correct insertion point.

2. Add a **Cross-Forest Trust Abuse** section covering:

   - **SID History Injection:** When a user migrates between domains/forests, their old SID can be added to the sIDHistory attribute. If a trust is not filtered for SID history (SID filtering disabled), forging a ticket with a privileged SID from the trusted forest in the sIDHistory field grants privileges in the trusting forest. Evidence: inter-forest trust present; SID filtering status determinable from trust attributes (`netdom trust` output or trust object in AD). Severity: CRITICAL — trust-wide domain compromise.

   - **Trust Ticket Forging (inter-realm TGT):** When cross-forest trust keys are known (obtainable after compromising either forest's Domain Controller), a golden ticket-equivalent can be forged for the inter-forest TGT, granting full access to the trusted forest's resources without knowing any account's credentials. Evidence: Domain Controller compromise in either forest; trust key material extracted from NTDS.dit or DCSync. Severity: CRITICAL.

   - **msDS-AllowedToDelegateTo Across Trusts:** Service accounts with unconstrained or constrained Kerberos delegation configured to targets in a trusted forest receive TGTs from users authenticating to them — if those TGTs are for users in the trusted forest, they can be used to impersonate those users against forest resources. Evidence: delegation-enabled service accounts present; cross-forest trust confirmed. Severity: HIGH.

   - **Foreign Security Principals (FSPs):** AD stores references to security principals from trusted forests as Foreign Security Principals. If an FSP is a member of a privileged group in the current forest (e.g., Domain Admins), compromising the account in the source forest yields privileges in the target forest. Evidence: Foreign Security Principals objects in the AD forest (CN=ForeignSecurityPrincipals container populated); cross-forest trust attributes. Severity: HIGH.

   - **Selective Authentication Bypass:** Some forest trusts are configured with "Selective Authentication" which should restrict which users from the trusted forest can authenticate. Misconfigurations in the "Allowed to Authenticate" permission on computer objects can bypass this restriction. Evidence: selective authentication flag on trust object. Severity: HIGH.

3. Add a fire condition in `vulnerability_analyzer.dart`: only generate cross-forest content when both `_hasAdIndicators()` is true AND the device data contains trust-related keywords (`trust`, `forest`, `enterprise admins`, `schema admins`, `forestdns`). Add a `_hasCrossForestIndicators()` helper that checks for these keywords.

4. Pass this as an additional context block into `adLateralMovementPrompt()` when the condition is met, rather than always including it (keeps the default prompt shorter).

**Risk:** Low-medium. New section in existing AD prompt, gated behind a new detection helper.

---

## Phase 2 — New Prompt Content

### 2.1 — Web Cache Poisoning Prompt

**Files:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`
**Problem:** Web Cache Poisoning is a distinct attack class from Host Header Injection. Unkeyed headers, fat GET parameter cloaking, Vary misconfigurations, and cache-key normalization differences are not covered. Impact is uniquely high because a single successful poison affects all users served the cached response.

**Steps:**

1. **Add `_hasCacheIndicators()` detection helper in `vulnerability_analyzer.dart`:**
   - Returns true when any of the following appear in device JSON:
     - Cache-related response headers captured: `X-Cache`, `CF-Cache-Status`, `Age`, `X-Varnish`, `X-Cache-Hits`, `Via`
     - CDN/proxy indicators already detected (`DeviceUtils.hasCdnIndicators()` returns true)
     - Caching platform keywords: `varnish`, `squid`, `nginx cache`, `fastly`, `akamai`, `cloudflare`
   - Cache poisoning requires a caching layer — without it, no caching of poisoned responses occurs

2. **Add `webCachePoisoningPrompt(String deviceJson)` to `PromptTemplates`:**

   The prompt must cover these distinct attack techniques:

   **Unkeyed Headers:**
   The cache key is what the cache uses to decide whether two requests are equivalent and can share a response. If the origin server's behavior is influenced by a header that is NOT part of the cache key, an attacker can inject a malicious value in that header — the poisoned response is then cached and served to all users who make the same "keyed" request.
   - `X-Forwarded-Host`: Many applications use this to construct absolute URLs in responses (redirects, canonical links, email links). If cached with an attacker-controlled host, all users receive responses with attacker-controlled URLs. Severity: HIGH.
   - `X-Original-URL` / `X-Rewrite-URL`: Some frameworks (Symfony, Django) use these to override the request path. Injecting a different path causes the wrong content to be cached at the original URL. Severity: HIGH.
   - `X-Override-URL` / `X-HTTP-Method-Override`: Framework-specific headers that may alter the response without being keyed.
   - `Forwarded` (RFC 7239): Structured equivalent of X-Forwarded-* headers; often processed but not keyed.
   - Testing approach: add each unkeyed header with a unique value, observe if the response differs, then verify the modified response was cached by making a second request without the header.

   **Fat GET / Parameter Cloaking:**
   Some caches include only the URL path and specific query parameters in the cache key, ignoring query parameters that appear after a delimiter or parameters that the framework processes differently. An attacker includes a malicious parameter that the origin processes but the cache ignores, poisoning the cache entry for the "clean" URL.
   - Fat GET: a GET request with a body containing parameters — the cache keys on the URL only, but the origin processes body parameters, resulting in a poisoned response cached for the URL. Evidence: origin server processes GET body parameters (detectable when GET with body returns different content from GET without body). Severity: HIGH.
   - Parameter cloaking via `?utm_content=x%26other_param=poison`: URL-encoded ampersands that some parsers split and some don't — the cache may key on the literal string while the origin splits it.
   - Cache parameter exclusion: some CDN configs explicitly exclude tracking parameters (utm_*, fbclid, gclid) from the cache key. If the origin reflects these parameters, injecting XSS in an excluded parameter poisons the cache. Severity: CRITICAL when XSS is reflected.

   **Vary Header Misconfigurations:**
   The `Vary` response header tells caches which request headers to include in the cache key. Misconfigurations allow cache key collisions:
   - `Vary: User-Agent` with predictable user agents: responses vary by UA but a common UA's response can be poisoned for all users with that UA. Evidence: Vary header present in captured response headers. Severity: MEDIUM.
   - `Vary: Accept-Encoding` with encoding-based XSS: if reflected content differs based on encoding header and that response is cached, encoding manipulation may cache XSS for users who receive the gzip variant.
   - Vary: * (poison any shared cache): rarely used but means nothing is ever cached — informational.

   **Web Cache Deception (distinct from poisoning):**
   The attacker tricks a victim into requesting a URL that looks like a static asset but actually serves the victim's authenticated dynamic content — which then gets cached and is readable by the attacker.
   - Attack path: victim visits `https://target.com/account/profile.css` — if the application serves the `/account/profile` response for this URL (strips the unrecognized extension) and the cache stores it based on the `.css` extension thinking it's static, the attacker can then fetch the same URL and receive the victim's profile data.
   - Evidence: application serves authenticated content at URLs with static-file-like suffixes; CDN or cache configured to cache responses by file extension.
   - Severity: HIGH when sensitive authenticated data is exposed.

   **Cache-Key Normalization Differences:**
   The cache and origin may normalize URLs differently (path encoding, trailing slashes, case sensitivity). A URL that the cache considers different from a cached entry but the origin considers equivalent may serve the poisoned cached response to unexpectedly matched requests. Evidence: any discrepancy in how the cache and origin handle URL variations.

   **Rules for the prompt:**
   - Only fire when cache indicators are present (cache response headers or known CDN)
   - Confidence floor: MEDIUM requires captured cache headers; HIGH requires a cache hit confirmed on a test request
   - Each technique is a separate finding
   - Do NOT generate cache poisoning findings for targets with no cache indicators

3. **Register the new prompt in `vulnerability_analyzer.dart`:**
   - Add `final hasCache = _hasCacheIndicators(deviceJson);` in the detection block
   - Add to the Phase 2 `Future.wait` block: `if (hasCache) run2(PromptTemplates.webCachePoisoningPrompt(deviceJson))`
   - Update the prompt firing matrix comment table with the new row

4. **Add the detection method `_hasCacheIndicators` to `vulnerability_analyzer.dart` alongside the other detection helpers.**

**Risk:** Medium. New standalone prompt and detection helper. No existing prompt is modified.

---

### 2.2 — postMessage Vulnerability Class

**File:** `lib/services/prompt_templates.dart`
**Method:** `webAppApiAuthPrompt()`
**Problem:** The `postMessage` API is a distinct browser security boundary and cross-origin communication vulnerability class entirely absent from all prompts. Missing origin validation on `message` event listeners enables cross-origin data theft, CSRF, and XSS escalation.

**Steps:**

1. In `webAppApiAuthPrompt()`, locate the `### Prototype Pollution` section (near the end of the attack classes).

2. Add a new section **after Prototype Pollution** and **before the `## RULES:` block**:

```
### postMessage Security (Phase N)
Attacker objective: send a malicious message from an attacker-controlled origin to a vulnerable message event listener, enabling cross-origin data theft, unauthorized actions, or DOM manipulation.

Generate when Single Page Application or JavaScript-heavy application indicators are present:
- Required evidence: JavaScript framework indicators (React, Angular, Vue, Next.js, Nuxt, Ember), SPA routing indicators in recon (hash-based routing, history API paths), iframe usage indicators, or web messaging context observed

**Missing origin validation (Critical Class):**
The `window.addEventListener('message', handler)` API receives messages from any origin by default. If the handler does not check `event.origin` against an allowlist before acting on `event.data`, any page in any browser tab can send arbitrary messages and trigger the handler's actions.
- If the handler modifies the DOM with message data: DOM-based XSS via postMessage — attacker embeds the target in an iframe and sends a crafted message containing XSS payload
- If the handler triggers navigation or redirects: open redirect or URL redirection via postMessage
- If the handler sends sensitive data back with `event.source.postMessage()`: cross-origin data theft if the attacker origin receives the reply
- If the handler performs actions (form submission, API calls) based on message data: CSRF-equivalent via postMessage
Evidence: JavaScript framework present; any `postMessage`, `message`, or `addEventListener` references visible in JavaScript source during recon; SPA indicators.
Severity: CRITICAL for DOM XSS; HIGH for data theft or unauthorized action; MEDIUM for open redirect.

**Insecure postMessage target origin:**
`window.postMessage(data, '*')` sends messages to any receiving origin without restriction — if the recipient page processes the message, sensitive data in the message is exposed to any attacker-controlled page that can open a window to the target.
Evidence: JavaScript source containing `postMessage(` with `'*'` as the second argument.
Severity: MEDIUM — data in the message is exposed cross-origin.

**iframe-based postMessage exploitation:**
Applications that embed content in iframes and communicate via postMessage are particularly exposed:
- If the parent page passes authentication tokens, session data, or sensitive configuration via postMessage to an iframe, and the iframe content can be loaded from an attacker-controlled source via a misconfigured CSP or open redirect, the attacker iframe receives the sensitive data.
- Conversely, a malicious parent page can send crafted messages to legitimately embedded iframes.
Evidence: iframe usage; `postMessage` communication patterns; CSP that allows framing or does not restrict frame-ancestors.
Severity: HIGH when authentication material is transmitted.

**Rules:**
- Generate only when SPA/JavaScript-heavy application or iframe-based architecture indicators are present
- Confidence floor: LOW when only framework indicators are present (no observed messaging code); MEDIUM when SPA architecture is confirmed; HIGH when message handler patterns are visible in recon JavaScript
- Do NOT generate for traditional server-rendered pages with no JavaScript framework indicators
```

3. Update the rules block in `webAppApiAuthPrompt()` to add:
   - `- postMessage: only if SPA framework or iframe indicators are present`

**Risk:** Low. Additive content in an existing prompt section.

---

### 2.3 — Blind / OOB SSRF Methodology

**File:** `lib/services/prompt_templates.dart`
**Methods:** `webAppCorePrompt()`, `webAppApiAuthPrompt()`
**Problem:** The SSRF sections cover direct-response SSRF with filter bypass in depth, but Blind SSRF (where the server makes the request but returns no response to the attacker) with out-of-band DNS callbacks is a completely different testing methodology. Without OOB detection, blind SSRF is invisible to the tester.

**Steps:**

1. In `webAppCorePrompt()`, locate the `## SSRF INTERNAL SERVICE EXPLOITATION` section. Add a new section **after** it and **before** `## SSRF FILTER BYPASS TECHNIQUES`:

```
## BLIND SSRF — OUT-OF-BAND DETECTION (Phase N)
Attacker objective: detect SSRF vulnerabilities where the server makes an outbound request but the response is not returned to the attacker — requiring out-of-band detection via DNS callback or HTTP listener.

**Why blind SSRF requires different testing:**
Direct SSRF is confirmed when internal service responses appear in the HTTP reply. Blind SSRF occurs when the application makes the outbound request but either:
- Discards the response (fire-and-forget webhook, async processing)
- Returns a generic success/error without response body content
- Filters and sanitizes the returned content before including it in the response
In these cases, the attack surface is identical but cannot be confirmed without an out-of-band signal.

**Out-of-band interaction platforms:**
Blind SSRF is confirmed when the target server makes an outbound DNS lookup or HTTP request to an attacker-controlled domain in response to a crafted input. Platforms for this:
- Burp Collaborator (in Burp Suite Professional): generates unique subdomains that log all interactions
- interactsh (open-source, self-hosted or public): `oast.pro`, `oast.me` public instances; `interactsh-client` CLI
- canarytokens.org: generates unique URLs that notify on access
- requestbin.com / pipedream.com: HTTP request logging endpoints
- DNSlog.cn / dnslog.io: DNS-only OOB platforms

**Testing methodology for blind SSRF:**
1. Identify all parameters that may trigger server-side HTTP requests: url=, image=, webhook=, import=, fetch=, src=, proxy=, callback=, redirect=, host=, avatar=, icon=, feed=, endpoint=
2. Also test parameters that accept filenames or paths — some applications fetch these from configured or user-supplied base URLs
3. Set the parameter value to a unique OOB URL: `http://UNIQUE-ID.your-oast-domain.com/path`
4. Submit the request and check the OOB platform for an incoming DNS lookup or HTTP request
5. If a DNS lookup is received: blind SSRF is confirmed — the server resolved the attacker-controlled domain
6. If an HTTP request is received: full SSRF confirmed — follow up with cloud metadata escalation

**Severity for confirmed blind SSRF:**
- DNS-only callback confirmed: MEDIUM — confirms SSRF capability but cannot extract data via DNS alone
- HTTP callback confirmed: HIGH — full SSRF confirmed, escalate to cloud metadata / internal service access
- Blind SSRF on cloud-hosted target (cloud indicators present): CRITICAL — even without response body, follow-up payloads targeting 169.254.169.254 may yield IAM credentials via async processing paths

**Evidence to generate findings:**
Generate a blind SSRF finding when:
- Any URL-accepting parameter is observed in recon data AND the target is cloud-hosted (CRITICAL priority)
- File import, document conversion, PDF generation, webhook configuration, or similar functionality is observed (these are the highest-likelihood blind SSRF vectors)
- Image URL fetching or avatar URL features are present (consistently SSRF-capable, often blind)
Do NOT require OOB platform confirmation in the analysis output — that is a step for the execution phase. The analysis finding should describe the blind SSRF surface and instruct the tester to use an OOB platform.
```

2. In the exploit execution prompt (in `PromptTemplates`, find the execution/iteration prompt used by `ExploitExecutor`), add guidance for blind SSRF testing:
   - When the vulnerability type is SSRF and the description mentions "blind" or "out-of-band", the execution commands should use `interactsh-client` or a DNS logging endpoint
   - Check for `interactsh-client` availability before using it; fall back to a public OOB domain if not available
   - The execution loop should look for DNS callback confirmation in the `interactsh-client` output

3. Add a detection helper `_hasBlindSsrfSurface()` in `vulnerability_analyzer.dart` that checks for file import, webhook, image fetch, document conversion, and avatar URL indicators — this can be used to optionally boost the SSRF section priority in Phase 2 context.

**Risk:** Medium. Modifies an existing large prompt (webAppCorePrompt). Must be carefully placed to not disrupt the existing SSRF flow. The execution-phase changes are additive.

---

### 2.4 — DOM / JavaScript Attack Surface Prompt

**Files:** `lib/services/prompt_templates.dart`, `lib/services/vulnerability_analyzer.dart`
**Problem:** The XSS sections cover reflected and stored XSS but DOM-based XSS, JavaScript source analysis for secrets, client-side path traversal in SPAs, and postMessage (covered in 2.2) require a dedicated DOM/JS analysis pass that doesn't depend on server-side injection detection.

**Steps:**

1. **Add `_hasJavaScriptAppIndicators()` in `vulnerability_analyzer.dart`:**
   - Returns true when SPA framework or JavaScript-heavy application indicators exist:
     - Technologies array containing: `react`, `angular`, `vue`, `next.js`, `nuxt`, `svelte`, `ember`, `backbone`, `jquery`
     - HTTP response headers: `X-Powered-By: Express`, `X-Powered-By: Next.js`
     - Paths suggesting SPA: `/_next/`, `/static/js/`, `/assets/js/`, `bundle.js`, `app.js`, `main.js`, `chunk.js`
     - Hash routing indicators: `#/`, `/#/` in observed URLs
     - Webpack/bundler indicators in response content

2. **Add `domJavaScriptAnalysisPrompt(String deviceJson)` to `PromptTemplates`:**

   **Section 1 — DOM-based XSS Sources and Sinks:**
   DOM-based XSS occurs when JavaScript reads attacker-controlled data from a DOM source and writes it to a DOM sink without sanitization. Unlike reflected/stored XSS, the malicious payload never reaches the server — it exists entirely in the browser.

   Common DOM XSS sources (data origins):
   - `document.URL`, `document.documentURI`, `location.href`, `location.search`, `location.hash`, `location.pathname`
   - `document.referrer`, `window.name` (persists across navigations)
   - `postMessage` event data (covered below)
   - `localStorage`, `sessionStorage` (when populated from untrusted sources)

   Common DOM XSS sinks (execution points):
   - `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`
   - `eval()`, `setTimeout(string)`, `setInterval(string)`, `Function(string)`
   - jQuery: `$(input)`, `.html(input)`, `.append(input)`, `.after(input)`
   - `location.href = input` (open redirect + XSS via javascript: URI)
   - `src` attribute assignment, `href` attribute assignment

   Testing methodology: identify URL parameters or hash fragments reflected in the DOM, inject `#"><img src=x onerror=alert(1)>` into each DOM source and observe browser behavior. Evidence: SPA framework present; hash-based routing; URL parameters that control displayed content.
   Severity: HIGH — DOM XSS bypasses server-side filtering and WAF rules that inspect request bodies.

   **Section 2 — JavaScript Source File Analysis:**
   Client-side JavaScript bundles often contain secrets, internal endpoints, and architectural information:
   - Hardcoded API keys and tokens: look for patterns like `apiKey:`, `api_key:`, `token:`, `secret:`, `password:`, `credentials:`, AWS access key patterns (`AKIA`), JWT-format strings
   - Internal endpoint URLs: `/api/internal/`, `localhost:`, `10.`, `172.16-31.`, `192.168.` — these reveal backend architecture and internal services
   - Third-party service credentials: Stripe keys, Twilio keys, SendGrid keys, Google API keys embedded in frontend bundles
   - Commented-out debug endpoints and staging URLs
   - GraphQL schema fragments or introspection queries embedded in source
   Evidence to require: web application with JavaScript files accessible; any observable `.js` paths in recon data.
   Severity: CRITICAL for cloud provider keys or authentication secrets; HIGH for internal endpoint disclosure; MEDIUM for third-party service keys.

   **Section 3 — Client-Side Path Traversal in SPA Routing:**
   Single-page applications that construct file paths or resource identifiers from URL parameters may perform client-side path traversal — loading files or resources from unintended paths:
   - Angular/React/Vue router: if route parameters are used to load templates or resources (`/view?template=../../sensitive`), path traversal may load unintended content
   - Dynamic import: `import(userInput)` allows loading arbitrary modules
   - Fetch with relative paths constructed from URL segments
   Evidence: SPA routing visible; URL parameters that control displayed content or loaded resources.
   Severity: HIGH when sensitive files can be loaded; MEDIUM for information disclosure.

   **Section 4 — Prototype Pollution via Client-Side Sources (complement to server-side):**
   Client-side prototype pollution via URL fragment or query string parameters:
   - `?__proto__[foo]=bar` or `?constructor[prototype][foo]=bar` in applications that merge URL parameters into objects using vulnerable deep-merge operations
   - `location.search` parsed with vulnerable query string libraries
   - Direct gadgets: polluted properties used in innerHTML, eval, or function calls anywhere in the application
   Evidence: Node.js/JavaScript framework; deep-merge patterns visible in loaded JavaScript.
   Severity: HIGH for DOM XSS gadget chains; MEDIUM for application logic bypass.

   **Rules for the prompt:**
   - Only fire when JavaScript application indicators are present
   - JavaScript source analysis: MEDIUM confidence minimum when JS files are present; HIGH when specific patterns (API key patterns) are confirmed visible
   - DOM XSS: LOW when SPA indicators present but no specific source/sink patterns observed; MEDIUM when hash routing and reflected content confirmed; HIGH when specific sink patterns confirmed
   - Do NOT generate these findings for traditional server-rendered pages with no JavaScript framework

3. **Register in `vulnerability_analyzer.dart`:**
   - Add `final hasJsApp = hasWeb && _hasJavaScriptAppIndicators(deviceJson);`
   - Add to Phase 2 block: `if (hasJsApp) run2(PromptTemplates.domJavaScriptAnalysisPrompt(deviceJson))`
   - Update the prompt firing matrix comment table

**Risk:** Medium. New standalone prompt. The `_hasJavaScriptAppIndicators()` helper must be accurate to avoid firing on non-SPA targets.

---

## Phase 3 — Structured Recon Baseline

### 3.1 — Deterministic Pre-LLM Baseline Runner

**File:** `lib/services/recon_service.dart`
**Problem:** The current recon loop is entirely LLM-directed from iteration 1. The `_internalBaseline()` and `_externalBaseline()` methods inject priority objectives as text guidance, but there is no guarantee the LLM runs them in order or runs them at all before deciding to do something else. A professional pentest always starts with deterministic baseline steps.

**Design principle:** The pre-LLM baseline runs programmatically before the LLM loop starts. It is not an LLM decision. The baseline results populate the `findings` structure, so the LLM loop starts with richer context and doesn't need to rediscover what the baseline already found.

**Steps:**

1. **Create `_BaselineResult` class** (internal to recon_service.dart) to hold the structured output of the baseline run:
   ```dart
   class _BaselineResult {
     final bool hasWebPorts;
     final bool hasDnsData;
     final bool isAlive;
     final List<String> commandsRun;
   }
   ```

2. **Add `_runBaselineInternal(String address, _ExecEnv env, String outDir, Map<String, dynamic> findings)` method:**

   Execute these commands deterministically in order, merging results into `findings` after each:

   **Step B1 — Host liveness check (fast, before expensive scans):**
   - Linux/macOS: `ping -c 2 -W 2 {address}` — if all packets lost, set `_baselineHostDown = true` and skip remaining steps
   - Windows: `Test-NetConnection {address} -Port 443 -InformationLevel Quiet`
   - Purpose: avoid spending 30+ minutes on a port scan of a host that doesn't exist

   **Step B2 — Top-1000 fast port scan:**
   - `nmap -sV -sC --open -T4 --min-rate 1000 {address} -oX {outDir}/nmap_top1000.xml`
   - Parse the XML output with the existing nmap XML parser in ReconService
   - Merge port results into `findings['open_ports']`
   - This gives the LLM a populated port list to reason about from iteration 1

   **Step B3 — Full port scan (background, non-blocking):**
   - `nmap -sV --open -T4 -p- {address} -oX {outDir}/nmap_fullport.xml`
   - For internal targets: run synchronously (fast on LAN)
   - For external targets: start as background command, check output in a later LLM iteration via `_buildFocusHints`
   - Add a `fullPortScanPending` flag to historyHint so the LLM knows to defer full-port dependent decisions

   **Step B4 — Web fingerprinting (if HTTP/HTTPS ports found in B2):**
   - `curl -sk -I --max-time 10 http://{address}` and `curl -sk -I --max-time 10 https://{address}`
   - Parse response headers into `findings['web_findings']`
   - This ensures the LLM has actual HTTP headers (Server, X-Powered-By, etc.) before analyzing web stack

   **Step B5 — SSL/TLS scan (if port 443 found):**
   - Linux: `sslscan --no-colour {address}:443` (if available) or `openssl s_client -connect {address}:443 -showcerts </dev/null 2>&1 | head -50`
   - macOS: same as Linux
   - Windows: `Test-NetConnection {address} -Port 443` + `Invoke-WebRequest https://{address} -SkipCertificateCheck`
   - Merge TLS data into `findings['ssl_findings']` (add this key if not present)

   **Step B6 — DNS baseline (external targets or when address is a hostname):**
   - `dig {address} ANY +short` (or equivalent)
   - `dig {address} MX +short`
   - `dig {address} TXT +short`
   - Attempt zone transfer: `dig @{address} {domain} AXFR` (only against the target itself)
   - Merge into `findings['dns_findings']`

   **Step B7 — SMB baseline (internal targets only, if port 445 detected in B2):**
   - `nmap -p 445 --script smb-security-mode,smb2-security-mode,smb-os-discovery {address}`
   - Merge into `findings['smb_findings']`

3. **Add `_runBaselineExternal(String address, _ExecEnv env, String outDir, Map<String, dynamic> findings)` method:**

   External baseline is more conservative (no aggressive scans, no SMB):

   **Step B1 — Top-port scan (reduced rate for external):**
   - `nmap -sV -sC --open -T3 --top-ports 2000 {address} -oX {outDir}/nmap_top2000.xml`

   **Step B2 — Web fingerprinting (always run for external):**
   - Curl both HTTP and HTTPS, follow redirects, capture headers
   - Check for WAF/CDN headers in response

   **Step B3 — SSL/TLS (port 443):**
   - Same as internal B5

   **Step B4 — DNS enumeration:**
   - Full DNS record types
   - Check for zone transfer
   - Extract CNAMEs for subdomain takeover assessment

   **Step B5 — Technology detection:**
   - `whatweb -a 3 http://{address}` if available, or parse from curl headers

4. **Integrate baseline call into `reconTarget()`:**

   In `reconTarget()`, before the main `for` loop:
   ```dart
   onProgress?.call('[$address] Running baseline scan...');
   if (scope == TargetScope.internal) {
     await _runBaselineInternal(address, env, outDir, findings);
   } else {
     await _runBaselineExternal(address, env, outDir, findings);
   }
   onProgress?.call('[$address] Baseline complete. Starting LLM-guided deep scan...');
   ```

5. **Update `_buildFocusHints()` to account for baseline:**
   - Add a check: if baseline was run but full port scan is still pending (external targets), add a hint instructing the LLM not to re-run the top port scan but to wait for full port results
   - Add a `_baselineCompleted` flag to avoid the LLM re-running commands already in the baseline

6. **Handle tool unavailability gracefully:**
   - Each baseline step should catch `ProcessException` and `TimeoutException`
   - If `nmap` is not available, skip steps B2/B3 — the LLM loop will handle port discovery through whatever tools are available
   - Log which baseline steps completed/failed for the `historyHint` context

**Risk:** Medium-high. This is the most invasive change — it modifies the core recon loop flow. The key risk is double-running commands (baseline + LLM requesting the same commands). Mitigate by populating `executedCommands` with all baseline commands before the LLM loop starts.

---

### 3.2 — Passive OSINT Integration

**File:** `lib/services/recon_service.dart` (new method), `lib/services/prompt_templates.dart` (recon command prompt update)
**Problem:** Professional external engagements start with passive OSINT — Shodan, Censys, CT logs at recon time — before any active scanning. Currently no passive OSINT commands are run; the LLM might choose to run some but there's no guarantee.

**Design principle:** Passive OSINT runs only for external targets, requires no network connection to the target, and should complete before active scanning begins. It is implemented as an extension of the structured baseline (runs before step B1 of the external baseline).

**Steps:**

1. **Add `_runPassiveOsint(String address, _ExecEnv env, String outDir, Map<String, dynamic> findings)` method:**

   All commands are read-only and do not touch the target directly. Results populate `findings['osint_findings']`.

   **OSINT-O1 — Certificate Transparency Logs:**
   - `curl -s "https://crt.sh/?q={domain}&output=json"` — public API, no auth required
   - Parse JSON response: extract unique subdomains, SANs, certificate organization names, issuer
   - Merge unique subdomains into `findings['dns_findings']` as potential hostnames
   - Note: this requires the target to be a domain name, not a raw IP

   **OSINT-O2 — DNS-over-HTTPS passive resolution:**
   - For each subdomain discovered via CT logs, resolve A/AAAA records using `curl -s "https://dns.google/resolve?name={sub}&type=A"`
   - This is passive from the target's perspective (queries go to Google DNS, not the target)
   - Merge live subdomains with IP addresses into findings

   **OSINT-O3 — Shodan host lookup (if `shodan` CLI is installed):**
   - Check `which shodan` before attempting
   - If available and API key configured: `shodan host {address}` or `shodan search hostname:{domain}`
   - Parse output for open ports, banners, historical data, vulnerabilities
   - If Shodan is not available, add a note to findings that passive Shodan data was not collected

   **OSINT-O4 — GitHub secret scanning (if `gh` or `git` CLI is available):**
   - Search for the target organization/domain name in GitHub public repos:
     - `gh search code "{domain}" --limit 20 --json path,repository,url` (requires gh auth)
   - If `gh` is not authenticated, generate a manual guidance note in findings: "GitHub dorking for {domain} was not performed automatically — manually search GitHub for hardcoded credentials referencing this domain"
   - This is inherently a manual step in most cases; the automated version requires GH authentication

   **OSINT-O5 — Google dorking guidance (always generate for external):**
   - Cannot automate Google search without API key, but generate structured dork queries in findings:
     - `site:{domain} filetype:pdf`
     - `site:{domain} intitle:"index of"`
     - `site:{domain} inurl:admin`
     - `site:{domain} inurl:login`
     - `site:{domain} intext:"password"`
   - Store these in `findings['osint_dorks']` for the analyst to run manually or for a future automated integration

   **OSINT-O6 — WHOIS data:**
   - `whois {domain}` — extract registrar, registration date, expiry, registrant org/email, name servers
   - Parse into `findings['whois_data']`
   - Age and registrar data help identify phishing domains and expiry-based takeover opportunities

2. **Call passive OSINT from `reconTarget()` for external targets:**
   ```dart
   if (scope == TargetScope.external && _isDomainName(address)) {
     onProgress?.call('[$address] Running passive OSINT...');
     await _runPassiveOsint(address, env, outDir, findings);
   }
   ```

   Add `_isDomainName()` helper that returns true when the address contains a dot and is not a raw IP.

3. **Update the LLM recon prompt** to reference OSINT findings when present:
   - Add a `## OSINT DATA ALREADY COLLECTED:` section to `_buildCommandPrompt()` when `findings['osint_findings']` or `findings['osint_dorks']` is populated
   - This allows the LLM to build on the passive OSINT rather than re-running CT log queries

4. **Guard against network failures:**
   - `crt.sh` API calls should have a 15-second timeout
   - If any OSINT step fails (no internet, API down), log and continue — passive OSINT is enrichment, not blocking

**Risk:** Low-medium. All changes are additive and run before the existing loop. The main risk is adding significant latency to the external recon start. Mitigate by running OSINT-O1 (CT logs) and OSINT-O2 (DNS resolution) first as they are fastest and highest-value.

---

## Phase 4 — Prompt Architecture Optimization

### 4.1 — SSRF Bypass Section Conditional Extraction

**File:** `lib/services/prompt_templates.dart`
**Methods:** `webAppCorePrompt()`, `webAppApiAuthPrompt()`
**Problem:** The SSRF filter bypass techniques section (IP representation alternatives, redirect chain bypass, URL encoding, cloud IMDS variations, DNS rebinding) is ~80 lines of detailed text included unconditionally in every web scan. For targets with no SSRF-capable parameters, this content occupies LLM attention budget but generates no actionable findings. Long prompts cause LLM attention degradation on important early-prompt instructions.

**Steps:**

1. **Add `_hasSsrfCapableParameters()` detection helper in `vulnerability_analyzer.dart`:**
   - Returns true when any of these appear in device JSON:
     - URL-accepting parameter names: `url=`, `redirect=`, `fetch=`, `proxy=`, `callback=`, `import=`, `src=`, `image=`, `webhook=`, `endpoint=`, `host=`
     - File import or document conversion functionality keywords
     - Any `<a href`, `<iframe src`, `<img src` patterns with dynamic values in observed web content
     - Cloud hosting indicators (SSRF to metadata is critical surface regardless of observed parameters)

2. **Extract the bypass content into a standalone helper `_ssrfBypassBlock()`** in `PromptTemplates`:
   - Move the entire `## SSRF FILTER BYPASS TECHNIQUES (Phase 12)` section and the cloud-specific IMDS URL variations into this static getter
   - The block is unchanged — only its inclusion becomes conditional

3. **In `webAppCorePrompt()`**, change the bypass section from unconditional to:
   ```dart
   final bypassContext = hasSsrfParams
       ? PromptTemplates._ssrfBypassBlock()
       : '<!-- SSRF bypass techniques omitted: no SSRF-capable parameters observed in recon -->';
   ```
   Pass `hasSsrfParams` as a parameter to `webAppCorePrompt()`.

4. **Update the call site in `vulnerability_analyzer.dart`:**
   ```dart
   final hasSsrfParams = _hasSsrfCapableParameters(deviceJson);
   // ...
   if (hasWeb) run2(PromptTemplates.webAppCorePrompt(deviceJson, scope: scope, hasSsrfParams: hasSsrfParams)),
   ```

5. **Keep the cloud SSRF escalation chain section unconditional** — the cloud metadata escalation chain (169.254.169.254 path, IAM credential extraction) should remain in every web prompt because cloud-hosted targets need this regardless of whether SSRF-capable parameters were observed. Only the filter bypass techniques (IP encoding, redirect chains, DNS rebinding) should be conditional.

6. **Similarly apply to `webAppApiAuthPrompt()`** for the `### SSRF via API Endpoints — Filter Bypass Techniques` section:
   - Same parameter: `hasSsrfParams`
   - Same conditional logic

7. **Measure approximate token reduction:**
   - The SSRF bypass section is approximately 400-500 tokens
   - For targets with no SSRF-capable parameters, this reduces prompt size by ~8-10%
   - More importantly, it removes ~80 lines that appear between the cloud SSRF escalation rules and the output format rules, improving LLM attention on those sections

**Risk:** Low. This is purely a refactor of existing content — no functionality changes, only conditional inclusion. The detection helper `_hasSsrfCapableParameters()` must be conservative (false positives are fine — they include the bypass block; false negatives are bad — they omit it on real SSRF surfaces). Default to including the block when uncertain.

---

## Testing Requirements

For each phase, the following tests should pass before merging:

| Phase | Test |
|---|---|
| 1.1 | Unit tests for all new IP ranges in `test/` |
| 1.2 | Manual: confirm cookie findings appear for a target with captured Set-Cookie headers |
| 1.3 | Manual: confirm cross-forest section fires only with trust keyword present |
| 2.1 | Integration: confirm cache prompt fires for a target with X-Cache header in recon |
| 2.2 | Integration: confirm postMessage section fires for SPA target |
| 2.3 | Manual: confirm blind SSRF section appears in core prompt output |
| 2.4 | Integration: confirm DOM/JS prompt fires for React/Angular/Vue targets |
| 3.1 | Manual: confirm baseline commands appear in command log before LLM iterations |
| 3.1 | Regression: confirm LLM does not repeat baseline commands (executedCommands set) |
| 3.2 | Manual: confirm crt.sh output appears in findings for external domain target |
| 4.1 | Manual: confirm bypass block absent for targets with no SSRF parameters |
| 4.1 | Manual: confirm bypass block present for targets with url= or webhook= parameters |

---

## Implementation Order Recommendation

1. **Phase 1.1** — IP classification (smallest risk, immediate correctness improvement)
2. **Phase 1.2** — Cookie attributes (30-minute change, real finding value)
3. **Phase 2.1** — Web cache poisoning prompt (standalone, no existing code modified)
4. **Phase 2.4** — DOM/JS prompt (standalone, significant coverage gap closed)
5. **Phase 2.2** — postMessage additions (small addition to existing prompt)
6. **Phase 2.3** — Blind SSRF (modifies large existing prompt, more care needed)
7. **Phase 4.1** — SSRF bypass conditional (refactor, test carefully)
8. **Phase 3.1** — Structured baseline (largest change, highest risk, highest payoff)
9. **Phase 3.2** — Passive OSINT (additive to 3.1, lower risk)
10. **Phase 1.3** — Cross-forest AD (niche, implement last)
