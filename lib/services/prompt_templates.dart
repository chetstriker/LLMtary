/// Centralized prompt templates and knowledge bases for the exploit executor.
///
/// Separates the large prompt text from orchestration logic to keep
/// exploit_executor.dart focused on its core loop.
class PromptTemplates {
  // ---------------------------------------------------------------------------
  // Specialized analysis prompts
  // ---------------------------------------------------------------------------

  /// Web-application focused analysis prompt.
  /// Only fire when HTTP/HTTPS ports are present.
  static String webAppAnalysisPrompt(String deviceJson) => '''
You are an expert web-application penetration tester. Analyze the device data below and identify EXPLOITABLE web-application vulnerabilities only.

## DEVICE DATA:
$deviceJson

## SCOPE — only web attack classes:
- SQL Injection (login forms, search fields, URL params)
- XSS (reflected, stored, DOM)
- LFI / RFI / Path Traversal
- SSRF (internal IP access, cloud metadata)
- XXE (XML endpoints)
- Command Injection (any OS-interacting input)
- Authentication Bypass / Default Credentials on web forms
- IDOR / Broken Access Control
- Insecure File Upload / Webshell
- Deserialization (Java, PHP, .NET)
- CSRF-aware testing: GET page → extract token → POST with token
- Post-auth attack surface: after login, test every input for injection

## RULES:
- Only include findings for HTTP/HTTPS ports
- Every web port gets at minimum: default credentials, SQLi on login, directory enumeration
- Each attack class is a SEPARATE entry — never group SQLi + XSS together
- Description MUST include: URL path, HTTP method, parameter name, example payload
- Confidence for generic web attack classes on any web port = MEDIUM minimum

${_outputFormatBlock()}

Respond ONLY with a valid JSON array. No markdown, no explanations.''';

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
- DNS (zone transfer, recursion, dnsmasq CVEs)
- UPnP (SSDP info disclosure, SOAP command injection)
- Telnet (cleartext, default credentials)
- VNC (no auth, weak password)
- SNMP (default community strings, version 1/2c)
- Any other non-web service: banner grab → version → CVE match

## RULES:
- Only include findings for non-web ports
- EXACT product name from banner must match CVE affected product
- Router/IoT embedded Samba is NOT exploitable with server exploits
- Each CVE from vulners/vulscan output is a SEPARATE entry

${_outputFormatBlock()}

Respond ONLY with a valid JSON array. No markdown, no explanations.''';

  /// CVE / version-matching analysis prompt. Fires for all scans.
  static String cveVersionAnalysisPrompt(String deviceJson) => '''
You are an expert CVE researcher and penetration tester. Analyze the device data below and identify vulnerabilities through strict product+version matching and architectural reasoning.

## DEVICE DATA:
$deviceJson

## TASKS:

### 1. Strict CVE Matching
For every service with a product name AND version:
- Match EXACT product name to CVE affected product ("Apache/2.4.49" → Apache httpd CVE-2021-41773)
- Match version to vulnerable range
- If product cannot be positively identified, skip CVE entries (use LOW confidence generic entries instead)
- Include CVE ID, affected version range, and concrete exploitation method

### 2. Architectural / Novel CVE Reasoning
For services where the exact CVE is unknown or version is ambiguous:
- Reason about attack classes theoretically possible given the library/framework
  (e.g. "given this is an embedded HTTP server, what injection classes are plausible?")
- Assign LOW confidence and mark exploitAvailable=false for theoretical entries
- Still include concrete attack technique and example payload

## RULES:
- Never assume product from port number alone
- Unknown/generic banners: LOW confidence on CVEs, MEDIUM on generic attack classes
- Each CVE is a separate entry

${_outputFormatBlock()}

Respond ONLY with a valid JSON array. No markdown, no explanations.''';

  /// Returns only the relevant section of [exploitKnowledgeBase] for the given
  /// vulnerability type, keeping prompt size small.
  static String knowledgeForType(String vulnerabilityType) {
    final type = vulnerabilityType.toLowerCase();

    // Map type → section header keywords in the knowledge base
    final sectionMap = <String, List<String>>{
      'sqli': ['SQL INJECTION'],
      'sql injection': ['SQL INJECTION'],
      'xss': ['SQL INJECTION'], // XSS tips are embedded in web section; fall back to full web
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
      'ssl': ['SSL/TLS VULNERABILITIES'],
      'tls': ['SSL/TLS VULNERABILITIES'],
      'dns': ['DNS-BASED VULNERABILITIES'],
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
  // Private helpers
  // ---------------------------------------------------------------------------

  static String _outputFormatBlock() => r'''
## OUTPUT FORMAT:
Return a JSON array. Each entry is one specific exploitable issue.
[
  {
    "problem": "Short name, e.g. SQL Injection on login form port 666",
    "cve": "CVE-XXXX-XXXXX or empty string",
    "description": "What the vulnerability is, the specific attack technique, and what an attacker gains. Include HTTP method, path, parameter, example payload.",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "confidence": "HIGH|MEDIUM|LOW",
    "evidence": "Exact data from scan output that indicates this attack surface exists",
    "recommendation": "How to fix it",
    "vulnerabilityType": "RCE|SQLi|XSS|LFI|RFI|Command Injection|Auth Bypass|Default Credentials|Info Disclosure|DoS|Privilege Escalation|Path Traversal|SSRF|XXE|etc.",
    "attackVector": "NETWORK|ADJACENT|LOCAL|PHYSICAL",
    "attackComplexity": "LOW|HIGH",
    "privilegesRequired": "NONE|LOW|HIGH",
    "userInteraction": "NONE|REQUIRED",
    "scope": "UNCHANGED|CHANGED",
    "confidentialityImpact": "NONE|LOW|HIGH",
    "integrityImpact": "NONE|LOW|HIGH",
    "availabilityImpact": "NONE|LOW|HIGH",
    "exploitAvailable": "true/false",
    "exploitMaturity": "POC|FUNCTIONAL|HIGH",
    "suggestedTools": "curl,sqlmap,hydra,metasploit,etc."
  }
]''';

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
  /// Comprehensive knowledge base for exploitation techniques.
  /// Included in the main testing prompt to guide the LLM.
  static const String exploitKnowledgeBase = '''
## EXPLOITATION TECHNIQUES BY VULNERABILITY TYPE:

### REMOTE CODE EXECUTION (RCE)
- Metasploit modules: search for "use exploit/[os]/[service]" modules
- Manual exploitation: Look for PoC scripts on exploit-db, GitHub
- Common patterns: Command injection via special characters (;, |, \$(), `)
- Verification: Execute harmless command (id, whoami, hostname) and check output

### SQL INJECTION
- Tools: sqlmap -u "URL" --dbs --batch
- Manual: Test with ' OR '1'='1 and observe responses
- Blind SQLi: Time-based (SLEEP, BENCHMARK), Boolean-based
- Verification: Extract database version or table names
- CSRF-AWARE TESTING (CRITICAL for modern web apps):
  1. GET the login/form page first: curl -s -c /tmp/cookies.txt http://TARGET/login
  2. Extract CSRF token: grep -oP 'name="_?csrf[^"]*"\s+value="[^"]*"' or similar
  3. POST with token: curl -s -b /tmp/cookies.txt -d "csrf_token=TOKEN&username=admin'--&password=x" http://TARGET/login
  4. For sqlmap with CSRF: sqlmap -u URL --data="csrf=TOKEN&user=test&pass=test" --csrf-token="csrf" --batch
  5. WITHOUT the CSRF token, the server returns a different error page (not auth failure), causing FALSE POSITIVES

### BUFFER OVERFLOW
- Check: pattern_create.rb / pattern_offset.rb for offset
- Common exploits: searchsploit for exact version
- Verification: Crash the service or achieve code execution
- Metasploit: Often has reliable modules

### AUTHENTICATION BYPASS
- Default credentials: admin/admin, root/root, admin/password
- Tools: hydra, medusa, ncrack for brute force
- Verification: Successful login or session token
- HYDRA HTTP FORM VERIFICATION (CRITICAL):
  Hydra's http-post-form uses a failure string to detect failed logins.
  FALSE POSITIVES occur when:
  1. The app uses CSRF tokens — bare POST without token gets a different error page
  2. The failure string doesn't match the actual error (e.g., app returns JSON, not HTML)
  3. ALL tested passwords show as "valid" — this is a dead giveaway of misconfigured check
  AFTER Hydra reports success, ALWAYS verify:
  1. curl -s -c /tmp/cookies.txt http://TARGET/login (get CSRF token + session cookie)
  2. Extract CSRF token from response
  3. curl -s -b /tmp/cookies.txt -L -d "csrf=TOKEN&user=FOUND_USER&pass=FOUND_PASS" http://TARGET/login
  4. Check response for: redirect to dashboard, session cookie set, authenticated content
  5. If verification fails, the Hydra result is a FALSE POSITIVE

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
- Test: Request to internal IPs (127.0.0.1, 169.254.169.254)
- Cloud metadata: http://169.254.169.254/latest/meta-data/
- Verification: Response from internal service

### DESERIALIZATION
- Java: ysoserial gadget chains
- PHP: phpggc for gadget chains
- .NET: ysoserial.net
- Verification: Code execution or error indicating processing

### DNS-BASED VULNERABILITIES (dnsmasq, BIND, etc.)
- CVE-2017-14491: Heap overflow in dnsmasq < 2.78
- CVE-2017-14492: Heap overflow via DHCPv6
- Tools: Custom PoC scripts, Metasploit modules
- Verification: Service crash or memory corruption indicators

### SMB VULNERABILITIES
- EternalBlue (MS17-010): Metasploit ms17_010_eternalblue - ONLY for Windows servers
- SambaCry (CVE-2017-7494): ONLY for Linux servers with writable shares, NOT routers
- SMB signing: nmap --script smb2-security-mode
- Null sessions: smbclient -N -L //target
- Verification: Shell access or file access
- CRITICAL: Router/IoT embedded Samba is NOT exploitable with server exploits

### SSL/TLS VULNERABILITIES
- Heartbleed: nmap --script ssl-heartbleed
- POODLE: testssl.sh or nmap ssl-poodle
- Verification: Memory leak or downgrade success

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

### NUCLEI
- Scan: nuclei -u URL -t cves/
- Specific CVE: nuclei -u URL -t CVE-XXXX-XXXXX.yaml

### HYDRA (Credential Testing)
- Basic: hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET SERVICE
- HTTP form: hydra -l admin -P wordlist TARGET http-post-form '/login:user=^USER^&pass=^PASS^:F=Login failed'
- CRITICAL: Use single quotes around the http-post-form spec, NOT double quotes
  CORRECT: hydra ... http-post-form '/login:user=^USER^&pass=^PASS^:F=Login failed'
  WRONG:   hydra ... http-post-form "/login:user=^USER^&pass=^PASS^:F=Login failed"
  (Double quotes cause bash to interpret special characters inside the string)
- CSRF HANDLING: Hydra does NOT handle CSRF tokens. For apps with CSRF:
  1. Use curl to get CSRF token first
  2. Then use hydra with the token in the POST body
  3. Or use a custom script instead of hydra
- VERIFICATION: After Hydra reports "valid password found", ALWAYS verify with curl

### CURL/WGET (Web Testing)
- Basic: curl -v http://TARGET/path
- Headers: curl -H "Header: value" URL
- POST: curl -X POST -d "data" URL

### DIRB (Directory Brute Force)
- Basic: dirb http://TARGET /usr/share/dirb/wordlists/common.txt
- CORRECT extension syntax: dirb http://TARGET wordlist -X .php,.asp,.html (uppercase -X, comma-separated)
- WRONG: -x .asp,.html,.xml (lowercase -x expects a FILE path, not extensions)
- Silent mode: add -S flag
- Ignore codes: -N 404

### GOBUSTER (Directory Brute Force)
- Basic: gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt
- Extensions: -x php,asp,html (no dots, comma-separated)

### FFUF (Fast Fuzzer - preferred if available)
- Basic: ffuf -u http://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt
- Extensions: -e .php,.asp,.html
''';
}
