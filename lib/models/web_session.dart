/// Maintains HTTP session state (cookie jar, CSRF token) across iterations
/// when the executor is testing web vulnerabilities.
class WebSession {
  /// Current cookie jar: name → value.
  final Map<String, String> cookies;

  /// Most recently extracted CSRF token name and value.
  String? csrfTokenName;
  String? csrfTokenValue;

  /// Base URL for the target web application (e.g. "https://example.com").
  final String baseUrl;

  WebSession({required this.baseUrl})
      : cookies = {};

  bool get hasCookies => cookies.isNotEmpty;
  bool get hasCsrfToken => csrfTokenName != null && csrfTokenValue != null;

  /// Merge cookies from a `Set-Cookie` style string into the jar.
  void addCookie(String name, String value) {
    cookies[name] = value;
  }

  /// Return curl-compatible -b "name=value; name2=value2" flag string.
  String get curlCookieFlag {
    if (cookies.isEmpty) return '';
    final pairs = cookies.entries.map((e) => '${e.key}=${e.value}').join('; ');
    return '-b "$pairs"';
  }

  /// Return curl-compatible -H "X-CSRF-Token: value" flag string if token present.
  String get curlCsrfFlag {
    if (!hasCsrfToken) return '';
    // Common CSRF header names — use the actual name if recognisable, else X-CSRF-Token
    final header = _csrfHeader(csrfTokenName!);
    return '-H "$header: $csrfTokenValue"';
  }

  static String _csrfHeader(String fieldName) {
    final lower = fieldName.toLowerCase();
    if (lower.contains('x-csrf') || lower.contains('x-xsrf')) return fieldName;
    if (lower == 'authenticity_token') return 'X-CSRF-Token';
    if (lower == '__requestverificationtoken') return 'RequestVerificationToken';
    return 'X-CSRF-Token';
  }

  /// Prompt block injected into every web-testing iteration.
  String toPromptBlock() {
    if (!hasCookies && !hasCsrfToken) return '';
    final buf = StringBuffer('## WEB SESSION STATE — carry this into every request:\n');
    if (hasCookies) {
      buf.writeln('### Active cookies (include with every authenticated request):');
      for (final e in cookies.entries) {
        buf.writeln('  - ${e.key} = ${e.value}');
      }
      buf.writeln('  curl flag: $curlCookieFlag');
    }
    if (hasCsrfToken) {
      buf.writeln('### CSRF token (include with every state-changing POST/PUT/DELETE):');
      buf.writeln('  ${csrfTokenName!} = ${csrfTokenValue!}');
      buf.writeln('  curl flag: $curlCsrfFlag');
    }
    buf.writeln('''
### Rules for session-aware testing:
- Include the cookie flag on EVERY request that requires authentication
- Re-fetch the CSRF token from a GET response if a POST returns 403/419
- If the session appears expired (redirect to /login), output SESSION_EXPIRED on its own line
- If you discover new cookies in a response, output: SET_COOKIE: <name>=<value>
- If you discover a CSRF token in a response, output: CSRF_TOKEN: <fieldName>=<value>
''');
    return buf.toString();
  }
}
