class CommandLog {
  final DateTime timestamp;
  final String command;
  final String output;
  final int exitCode;
  final int? vulnerabilityIndex; // Track which vulnerability this command is for

  CommandLog({
    required this.timestamp,
    required this.command,
    required this.output,
    required this.exitCode,
    this.vulnerabilityIndex,
  });

  Map<String, dynamic> toMap() => {
    'timestamp': timestamp.toIso8601String(),
    'command': command,
    'output': output,
    'exitCode': exitCode,
    'vulnerabilityIndex': vulnerabilityIndex,
  };

  factory CommandLog.fromMap(Map<String, dynamic> map) => CommandLog(
    timestamp: DateTime.parse(map['timestamp'] as String),
    command: map['command'] as String,
    output: map['output'] as String,
    exitCode: map['exitCode'] as int,
    vulnerabilityIndex: map['vulnerabilityIndex'] as int?,
  );
}
