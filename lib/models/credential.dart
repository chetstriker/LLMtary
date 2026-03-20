/// Where the credential value came from — used to prevent LLM hallucinations
/// from polluting the credential bank with unverified guesses.
enum CredentialSource {
  /// The exact credential string appeared verbatim in actual command output.
  extractedFromOutput,
  /// The LLM inferred or guessed this credential without seeing it in output.
  inferred,
}

/// A credential discovered during exploitation — stored in the credential bank
/// for cross-vulnerability reuse and report inclusion.
class DiscoveredCredential {
  final int? id;              // DB row id (null for new, unsaved credentials)
  final int? projectId;       // associated project id
  final String service;       // e.g. "ssh", "mysql", "http", "smb"
  final String host;          // target address where credential was found
  final String username;
  final String secret;        // password, hash, API key, token, etc.
  final String secretType;    // "password", "ntlm_hash", "api_key", "jwt", "private_key"
  final String sourceVuln;    // problem name of the vulnerability that found this
  final DateTime discoveredAt;
  /// Whether this credential was actually seen in command output vs LLM-inferred.
  final CredentialSource credentialSource;

  const DiscoveredCredential({
    this.id,
    this.projectId,
    required this.service,
    required this.host,
    required this.username,
    required this.secret,
    required this.secretType,
    required this.sourceVuln,
    required this.discoveredAt,
    this.credentialSource = CredentialSource.extractedFromOutput,
  });

  bool get isVerified => credentialSource == CredentialSource.extractedFromOutput;

  /// Human-readable one-liner for injection into prompts.
  String toPromptLine() {
    final sourceTag = isVerified ? '[CONFIRMED from output]' : '[INFERRED — not verified]';
    return '[$service on $host] $username : $secret ($secretType) $sourceTag — found via "$sourceVuln"';
  }

  /// Used to avoid storing duplicate credentials.
  String get fingerprint => '${service.toLowerCase()}|${host.toLowerCase()}|${username.toLowerCase()}|${secret.toLowerCase()}';

  Map<String, dynamic> toMap() => {
        'project_id': projectId,
        'service': service,
        'host': host,
        'username': username,
        'secret': secret,
        'secret_type': secretType,
        'source_vuln': sourceVuln,
        'discovered_at': discoveredAt.toIso8601String(),
        'credential_source': credentialSource.name,
      };

  factory DiscoveredCredential.fromMap(Map<String, dynamic> map) =>
      DiscoveredCredential(
        id: map['id'] as int?,
        projectId: map['project_id'] as int?,
        service: map['service'] as String? ?? '',
        host: map['host'] as String? ?? '',
        username: map['username'] as String? ?? '',
        secret: map['secret'] as String? ?? '',
        secretType: map['secret_type'] as String? ?? map['secretType'] as String? ?? 'password',
        sourceVuln: map['source_vuln'] as String? ?? map['sourceVuln'] as String? ?? '',
        discoveredAt: DateTime.tryParse(map['discovered_at'] as String? ?? map['discoveredAt'] as String? ?? '') ?? DateTime.now(),
        credentialSource: CredentialSource.values.firstWhere(
          (e) => e.name == (map['credential_source'] as String? ?? ''),
          orElse: () => CredentialSource.extractedFromOutput,
        ),
      );
}
