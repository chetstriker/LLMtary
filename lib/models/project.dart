class Project {
  final int? id;
  final String name;
  final String folderPath;
  final DateTime createdAt;
  final DateTime lastOpenedAt;
  final bool scanComplete;
  final bool analysisComplete;
  final bool hasResults;
  final DateTime? firstAnalysisAt;
  final DateTime? lastExecutionAt;
  final String? reportTitle;
  final String? pentesterName;
  final String? executiveSummary;
  final String? methodology;
  final String? riskRatingModel;
  final String? conclusion;
  /// Newline-separated list of in-scope targets (IPs, CIDRs, FQDNs, wildcards, or "*" for all).
  final String? scope;
  /// Newline-separated list of explicitly out-of-scope targets.
  final String? scopeExclusions;
  /// Free-text rules of engagement notes (e.g. "no DoS", "no lockouts").
  final String? scopeNotes;

  Project({
    this.id,
    required this.name,
    required this.folderPath,
    required this.createdAt,
    required this.lastOpenedAt,
    this.scanComplete = false,
    this.analysisComplete = false,
    this.hasResults = false,
    this.firstAnalysisAt,
    this.lastExecutionAt,
    this.reportTitle,
    this.pentesterName,
    this.executiveSummary,
    this.methodology,
    this.riskRatingModel,
    this.conclusion,
    this.scope,
    this.scopeExclusions,
    this.scopeNotes,
  });

  /// Parsed in-scope list (non-empty lines only).
  List<String> get scopeList =>
      (scope ?? '').split('\n').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();

  /// Parsed exclusion list (non-empty lines only).
  List<String> get exclusionList =>
      (scopeExclusions ?? '').split('\n').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();

  Map<String, dynamic> toMap() => {
    'id': id,
    'name': name,
    'folderPath': folderPath,
    'createdAt': createdAt.toIso8601String(),
    'lastOpenedAt': lastOpenedAt.toIso8601String(),
    'scanComplete': scanComplete ? 1 : 0,
    'analysisComplete': analysisComplete ? 1 : 0,
    'hasResults': hasResults ? 1 : 0,
    'first_analysis_at': firstAnalysisAt?.toIso8601String(),
    'last_execution_at': lastExecutionAt?.toIso8601String(),
    'report_title': reportTitle,
    'pentester_name': pentesterName,
    'executive_summary': executiveSummary,
    'methodology': methodology,
    'risk_rating_model': riskRatingModel,
    'conclusion': conclusion,
    'scope': scope,
    'scope_exclusions': scopeExclusions,
    'scope_notes': scopeNotes,
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
    firstAnalysisAt: DateTime.tryParse(map['first_analysis_at'] as String? ?? ''),
    lastExecutionAt: DateTime.tryParse(map['last_execution_at'] as String? ?? ''),
    reportTitle: map['report_title'] as String?,
    pentesterName: map['pentester_name'] as String?,
    executiveSummary: map['executive_summary'] as String?,
    methodology: map['methodology'] as String?,
    riskRatingModel: map['risk_rating_model'] as String?,
    conclusion: map['conclusion'] as String?,
    scope: map['scope'] as String?,
    scopeExclusions: map['scope_exclusions'] as String?,
    scopeNotes: map['scope_notes'] as String?,
  );

  Project copyWith({
    bool? scanComplete,
    bool? analysisComplete,
    bool? hasResults,
    DateTime? lastOpenedAt,
    DateTime? firstAnalysisAt,
    DateTime? lastExecutionAt,
    String? reportTitle,
    String? pentesterName,
    String? executiveSummary,
    String? methodology,
    String? riskRatingModel,
    String? conclusion,
    String? scope,
    String? scopeExclusions,
    String? scopeNotes,
  }) => Project(
    id: id,
    name: name,
    folderPath: folderPath,
    createdAt: createdAt,
    lastOpenedAt: lastOpenedAt ?? this.lastOpenedAt,
    scanComplete: scanComplete ?? this.scanComplete,
    analysisComplete: analysisComplete ?? this.analysisComplete,
    hasResults: hasResults ?? this.hasResults,
    firstAnalysisAt: firstAnalysisAt ?? this.firstAnalysisAt,
    lastExecutionAt: lastExecutionAt ?? this.lastExecutionAt,
    reportTitle: reportTitle ?? this.reportTitle,
    pentesterName: pentesterName ?? this.pentesterName,
    executiveSummary: executiveSummary ?? this.executiveSummary,
    methodology: methodology ?? this.methodology,
    riskRatingModel: riskRatingModel ?? this.riskRatingModel,
    conclusion: conclusion ?? this.conclusion,
    scope: scope ?? this.scope,
    scopeExclusions: scopeExclusions ?? this.scopeExclusions,
    scopeNotes: scopeNotes ?? this.scopeNotes,
  );
}
