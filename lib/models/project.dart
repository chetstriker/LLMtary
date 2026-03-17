class Project {
  final int? id;
  final String name;
  final String folderPath;
  final DateTime createdAt;
  final DateTime lastOpenedAt;
  final bool scanComplete;
  final bool analysisComplete;
  final bool hasResults;

  Project({
    this.id,
    required this.name,
    required this.folderPath,
    required this.createdAt,
    required this.lastOpenedAt,
    this.scanComplete = false,
    this.analysisComplete = false,
    this.hasResults = false,
  });

  Map<String, dynamic> toMap() => {
    'id': id,
    'name': name,
    'folderPath': folderPath,
    'createdAt': createdAt.toIso8601String(),
    'lastOpenedAt': lastOpenedAt.toIso8601String(),
    'scanComplete': scanComplete ? 1 : 0,
    'analysisComplete': analysisComplete ? 1 : 0,
    'hasResults': hasResults ? 1 : 0,
  };

  factory Project.fromMap(Map<String, dynamic> map) => Project(
    id: map['id'] as int?,
    name: map['name'] as String,
    folderPath: map['folderPath'] as String,
    createdAt: DateTime.parse(map['createdAt'] as String),
    lastOpenedAt: DateTime.parse(map['lastOpenedAt'] as String),
    scanComplete: (map['scanComplete'] as int? ?? 0) == 1,
    analysisComplete: (map['analysisComplete'] as int? ?? 0) == 1,
    hasResults: (map['hasResults'] as int? ?? 0) == 1,
  );

  Project copyWith({
    bool? scanComplete,
    bool? analysisComplete,
    bool? hasResults,
    DateTime? lastOpenedAt,
  }) => Project(
    id: id,
    name: name,
    folderPath: folderPath,
    createdAt: createdAt,
    lastOpenedAt: lastOpenedAt ?? this.lastOpenedAt,
    scanComplete: scanComplete ?? this.scanComplete,
    analysisComplete: analysisComplete ?? this.analysisComplete,
    hasResults: hasResults ?? this.hasResults,
  );
}
