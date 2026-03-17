import 'dart:convert';

/// Shared JSON parsing utilities for handling LLM responses.
///
/// LLM responses often contain markdown code fences, unbalanced braces,
/// or invalid escape sequences. These helpers handle all those cases.
class JsonParser {
  /// Remove markdown code fences (```json ... ```) from a string.
  static String stripMarkdownCodeFences(String raw) {
    var cleaned = raw.trim();
    if (cleaned.contains('```')) {
      cleaned = cleaned.replaceAll(RegExp(r'```json\s*', multiLine: true), '');
      cleaned = cleaned.replaceAll(RegExp(r'```\s*', multiLine: true), '');
    }
    return cleaned.trim();
  }

  /// Try to parse a JSON object from an LLM response string.
  ///
  /// Handles:
  /// - Markdown code fences
  /// - Extra text before/after JSON
  /// - Unbalanced braces
  /// - Invalid escape sequences (e.g. \')
  ///
  /// Returns null if parsing fails entirely.
  static Map<String, dynamic>? tryParseJson(String raw) {
    try {
      var cleaned = stripMarkdownCodeFences(raw);

      // Try direct parse first
      try {
        return json.decode(cleaned) as Map<String, dynamic>;
      } catch (_) {}

      // Find JSON object by bracket matching
      final extracted = _extractBalancedJson(cleaned, '{', '}');
      if (extracted != null) {
        if (extracted.length > 50000) return null; // Degenerate response — skip parse
        final fixed = _fixJsonString(extracted);
        return json.decode(fixed) as Map<String, dynamic>;
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// Try to parse a JSON array from an LLM response string.
  ///
  /// Returns null if parsing fails.
  static List<dynamic>? tryParseJsonArray(String raw) {
    try {
      var cleaned = stripMarkdownCodeFences(raw);

      // Try direct parse first
      try {
        return json.decode(cleaned) as List<dynamic>;
      } catch (_) {}

      // Find JSON array by bracket matching
      final extracted = _extractBalancedJson(cleaned, '[', ']');
      if (extracted != null) {
        if (extracted.length > 50000) return null; // Degenerate response — skip parse
        final fixed = _fixJsonString(extracted);
        return json.decode(fixed) as List<dynamic>;
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// Detect if a response was truncated (LLM hit token limit).
  static bool isTruncatedResponse(String errorMessage) {
    return errorMessage.contains('Unterminated string') ||
        errorMessage.contains('Unexpected end') ||
        errorMessage.contains('Unexpected character');
  }

  /// Extract a balanced JSON structure (object or array) from a string.
  static String? _extractBalancedJson(String text, String open, String close) {
    int count = 0;
    int start = -1;

    for (int i = 0; i < text.length; i++) {
      if (text[i] == open) {
        if (start == -1) start = i;
        count++;
      } else if (text[i] == close) {
        count--;
        if (count == 0 && start != -1) {
          return text.substring(start, i + 1);
        }
      }
    }

    // If we found an opening but no balanced close, return from start to last close
    if (start != -1) {
      final lastClose = text.lastIndexOf(close);
      if (lastClose > start) {
        return text.substring(start, lastClose + 1);
      }
    }

    return null;
  }

  /// Fix common JSON formatting issues from LLM responses.
  ///
  /// Handles invalid escape sequences like \' which LLMs sometimes produce.
  static String _fixJsonString(String jsonStr) {
    final buffer = StringBuffer();
    bool inString = false;
    bool escaped = false;

    for (int i = 0; i < jsonStr.length; i++) {
      final char = jsonStr[i];

      if (escaped) {
        if (char == "'" && inString) {
          // Convert \' to just ' (single quote doesn't need escaping in JSON)
          buffer.write("'");
        } else if (char == 'n' ||
            char == 'r' ||
            char == 't' ||
            char == '"' ||
            char == '\\' ||
            char == '/') {
          buffer.write('\\');
          buffer.write(char);
        } else {
          // Invalid escape sequence - just output the character
          buffer.write(char);
        }
        escaped = false;
        continue;
      }

      if (char == '\\') {
        escaped = true;
        continue;
      }

      if (char == '"' && !escaped) {
        inString = !inString;
      }

      buffer.write(char);
    }

    return buffer.toString();
  }
}
