class TokenUsage {
  final int? id;
  final int projectId;
  final int targetId;
  final String phase;
  final int tokensSent;
  final int tokensReceived;
  final DateTime recordedAt;

  const TokenUsage({
    this.id,
    required this.projectId,
    this.targetId = 0,
    required this.phase,
    required this.tokensSent,
    required this.tokensReceived,
    required this.recordedAt,
  });

  Map<String, dynamic> toMap() => {
    'id': id,
    'project_id': projectId,
    'target_id': targetId,
    'phase': phase,
    'tokens_sent': tokensSent,
    'tokens_received': tokensReceived,
    'recorded_at': recordedAt.toIso8601String(),
  };

  factory TokenUsage.fromMap(Map<String, dynamic> map) => TokenUsage(
    id: map['id'] as int?,
    projectId: map['project_id'] as int? ?? 0,
    targetId: map['target_id'] as int? ?? 0,
    phase: map['phase'] as String? ?? '',
    tokensSent: map['tokens_sent'] as int? ?? 0,
    tokensReceived: map['tokens_received'] as int? ?? 0,
    recordedAt: DateTime.tryParse(map['recorded_at'] as String? ?? '') ?? DateTime.now(),
  );
}
