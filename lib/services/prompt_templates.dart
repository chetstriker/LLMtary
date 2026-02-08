/// Centralized prompt templates and knowledge bases for the exploit executor.
///
/// Separates the large prompt text from orchestration logic to keep
/// exploit_executor.dart focused on its core loop.
class PromptTemplates {
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

### BUFFER OVERFLOW
- Check: pattern_create.rb / pattern_offset.rb for offset
- Common exploits: searchsploit for exact version
- Verification: Crash the service or achieve code execution
- Metasploit: Often has reliable modules

### AUTHENTICATION BYPASS
- Default credentials: admin/admin, root/root, admin/password
- Tools: hydra, medusa, ncrack for brute force
- Verification: Successful login or session token

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
