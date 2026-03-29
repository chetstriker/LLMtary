enum TargetStatus { pending, scanning, complete, excluded, down }

class Target {
  int? id;
  int? projectId;
  final String address;
  String jsonFilePath;
  String summary;
  TargetStatus status;
  bool analysisComplete;
  bool executionComplete;
  /// True when analysis completed but produced 0 vulnerability findings.
  bool noFindings;
  /// Stores the device classification result (e.g. 'router', 'workstation', 'webServer').
  /// Populated after recon completes via DeviceClassifier.
  String? classifiedAs;

  Target({
    this.id,
    this.projectId,
    required this.address,
    this.jsonFilePath = '',
    this.summary = '',
    this.status = TargetStatus.pending,
    this.analysisComplete = false,
    this.executionComplete = false,
    this.noFindings = false,
    this.classifiedAs,
  });

  Map<String, dynamic> toMap() => {
    'id': id,
    'projectId': projectId ?? 0,
    'address': address,
    'jsonFilePath': jsonFilePath,
    'summary': summary,
    'status': status.name,
    'analysisComplete': analysisComplete ? 1 : 0,
    'executionComplete': executionComplete ? 1 : 0,
    if (classifiedAs != null) 'classifiedAs': classifiedAs,
  };

  factory Target.fromMap(Map<String, dynamic> map) => Target(
    id: map['id'] as int?,
    projectId: map['projectId'] as int?,
    address: map['address'] as String,
    jsonFilePath: map['jsonFilePath'] as String? ?? '',
    summary: map['summary'] as String? ?? '',
    status: TargetStatus.values.firstWhere(
      (e) => e.name == map['status'],
      orElse: () => TargetStatus.pending,
    ),
    analysisComplete: (map['analysisComplete'] as int? ?? 0) == 1,
    executionComplete: (map['executionComplete'] as int? ?? 0) == 1,
    classifiedAs: map['classifiedAs'] as String?,
  );
}
