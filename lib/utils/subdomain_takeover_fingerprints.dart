/// Fingerprint database for subdomain takeover detection.
/// Each entry maps a CNAME pattern to the HTTP response body signature
/// that indicates an unclaimed resource on that platform.
class SubdomainTakeoverFingerprints {
  /// Map of platform name → [cname_pattern, body_signature, severity]
  static const Map<String, _TakeoverFingerprint> fingerprints = {
    'Azure App Service': _TakeoverFingerprint(
      cnamePattern: 'azurewebsites.net',
      bodySignature: '404 Web Site not found',
      severity: 'HIGH',
    ),
    'GitHub Pages': _TakeoverFingerprint(
      cnamePattern: 'github.io',
      bodySignature: "There isn't a GitHub Pages site here",
      severity: 'HIGH',
    ),
    'AWS S3': _TakeoverFingerprint(
      cnamePattern: 's3.amazonaws.com',
      bodySignature: 'NoSuchBucket',
      severity: 'HIGH',
    ),
    'Netlify': _TakeoverFingerprint(
      cnamePattern: 'netlify.app',
      bodySignature: 'Not Found - Request ID',
      severity: 'HIGH',
    ),
    'Heroku': _TakeoverFingerprint(
      cnamePattern: 'herokuapp.com',
      bodySignature: 'No such app',
      severity: 'HIGH',
    ),
    'Fastly': _TakeoverFingerprint(
      cnamePattern: 'fastly.net',
      bodySignature: 'Fastly error: unknown domain',
      severity: 'HIGH',
    ),
    'Shopify': _TakeoverFingerprint(
      cnamePattern: 'myshopify.com',
      bodySignature: 'Sorry, this shop is currently unavailable',
      severity: 'HIGH',
    ),
    'Tumblr': _TakeoverFingerprint(
      cnamePattern: 'tumblr.com',
      bodySignature: 'Whatever you were looking for doesn\'t currently exist',
      severity: 'MEDIUM',
    ),
    'WP Engine': _TakeoverFingerprint(
      cnamePattern: 'wpenginepowered.com',
      bodySignature: 'The site you were looking for couldn\'t be found',
      severity: 'HIGH',
    ),
    'Surge.sh': _TakeoverFingerprint(
      cnamePattern: 'surge.sh',
      bodySignature: 'project not found',
      severity: 'HIGH',
    ),
    'ReadTheDocs': _TakeoverFingerprint(
      cnamePattern: 'readthedocs.io',
      bodySignature: 'unknown to Read the Docs',
      severity: 'MEDIUM',
    ),
    'Vercel': _TakeoverFingerprint(
      cnamePattern: 'vercel.app',
      bodySignature: 'The deployment could not be found',
      severity: 'HIGH',
    ),
  };

  /// Returns the platform name for a given CNAME target, or null if not recognized.
  static String? matchCname(String cnameTarget) {
    final lower = cnameTarget.toLowerCase();
    for (final entry in fingerprints.entries) {
      if (lower.contains(entry.value.cnamePattern)) return entry.key;
    }
    return null;
  }

  /// Returns true if [responseBody] matches the unclaimed-resource signature
  /// for the given [cnameTarget].
  static bool isUnclaimed(String cnameTarget, String responseBody) {
    final lower = cnameTarget.toLowerCase();
    for (final entry in fingerprints.entries) {
      if (lower.contains(entry.value.cnamePattern)) {
        return responseBody.toLowerCase().contains(entry.value.bodySignature.toLowerCase());
      }
    }
    // Also check body against all signatures when CNAME is unknown
    return fingerprints.values.any(
      (fp) => responseBody.toLowerCase().contains(fp.bodySignature.toLowerCase()));
  }
}

class _TakeoverFingerprint {
  final String cnamePattern;
  final String bodySignature;
  final String severity;

  const _TakeoverFingerprint({
    required this.cnamePattern,
    required this.bodySignature,
    required this.severity,
  });
}
