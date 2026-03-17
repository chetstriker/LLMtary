class CommandLog {
  final DateTime timestamp;
  final String command;
  final String output;
  final int exitCode;
  final int? vulnerabilityIndex;
  final int projectId;
  final int targetId;

  CommandLog({
    required this.timestamp,
    required this.command,
    required this.output,
    required this.exitCode,
    this.vulnerabilityIndex,
    this.projectId = 0,
    this.targetId = 0,
  });

  Map<String, dynamic> toMap() => {
    'timestamp': timestamp.toIso8601String(),
    'command': command,
    'output': output,
    'exitCode': exitCode,
    'vulnerabilityIndex': vulnerabilityIndex,
    'projectId': projectId,
    'targetId': targetId,
  };

  factory CommandLog.fromMap(Map<String, dynamic> map) => CommandLog(
    timestamp: DateTime.parse(map['timestamp'] as String),
    command: map['command'] as String,
    output: map['output'] as String,
    exitCode: map['exitCode'] as int,
    vulnerabilityIndex: map['vulnerabilityIndex'] as int?,
    projectId: map['projectId'] as int? ?? 0,
    targetId: map['targetId'] as int? ?? 0,
  );
}
