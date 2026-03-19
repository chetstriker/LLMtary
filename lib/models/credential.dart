/// A credential discovered during exploitation — stored in the credential bank
/// for cross-vulnerability reuse and report inclusion.
class DiscoveredCredential {
  final String service;       // e.g. "ssh", "mysql", "http", "smb"
  final String host;          // target address where credential was found
  final String username;
  final String secret;        // password, hash, API key, token, etc.
  final String secretType;    // "password", "ntlm_hash", "api_key", "jwt", "private_key"
  final String sourceVuln;    // problem name of the vulnerability that found this
  final DateTime discoveredAt;

  const DiscoveredCredential({
    required this.service,
    required this.host,
    required this.username,
    required this.secret,
    required this.secretType,
    required this.sourceVuln,
    required this.discoveredAt,
  });

  /// Human-readable one-liner for injection into prompts.
  String toPromptLine() =>
      '[$service on $host] $username : $secret ($secretType) — found via "$sourceVuln"';

  /// Used to avoid storing duplicate credentials.
  String get fingerprint => '${service.toLowerCase()}|${host.toLowerCase()}|${username.toLowerCase()}|${secret.toLowerCase()}';

  Map<String, dynamic> toMap() => {
        'service': service,
        'host': host,
        'username': username,
        'secret': secret,
        'secretType': secretType,
        'sourceVuln': sourceVuln,
        'discoveredAt': discoveredAt.toIso8601String(),
      };

  factory DiscoveredCredential.fromMap(Map<String, dynamic> map) =>
      DiscoveredCredential(
        service: map['service'] ?? '',
        host: map['host'] ?? '',
        username: map['username'] ?? '',
        secret: map['secret'] ?? '',
        secretType: map['secretType'] ?? 'password',
        sourceVuln: map['sourceVuln'] ?? '',
        discoveredAt: DateTime.tryParse(map['discoveredAt'] ?? '') ?? DateTime.now(),
      );
}
