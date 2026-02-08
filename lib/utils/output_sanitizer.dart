/// Output sanitization utilities for cleaning command output.
///
/// Removes non-printable characters, control codes, and invalid UTF-8
/// from command output to prevent display issues.
class OutputSanitizer {
  /// Remove control characters except newline, carriage return, and tab.
  /// Replace non-ASCII characters with '?'.
  static String sanitize(String input) {
    final buffer = StringBuffer();
    for (int i = 0; i < input.length; i++) {
      final code = input.codeUnitAt(i);
      if (code == 0x0A || code == 0x0D || code == 0x09) {
        // Keep newline, carriage return, tab
        buffer.writeCharCode(code);
      } else if (code >= 0x20 && code <= 0x7E) {
        // Keep printable ASCII
        buffer.writeCharCode(code);
      } else if (code > 0x7E) {
        // Replace non-ASCII with ?
        buffer.write('?');
      }
      // Skip other control characters (0x00-0x1F except tab/newline/cr)
    }
    return buffer.toString();
  }
}
