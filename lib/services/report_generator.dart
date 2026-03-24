import '../models/vulnerability.dart';
import '../models/project.dart';
import '../models/target.dart';
import '../models/credential.dart';
import '../models/command_log.dart';
import '../models/llm_settings.dart';
import '../utils/cvss_calculator.dart';

/// Generates professional penetration test reports from collected findings.
///
/// Supports HTML (primary), Markdown, and CSV export formats.
class ReportGenerator {
  // ---------------------------------------------------------------------------
  // Public entry points
  // ---------------------------------------------------------------------------

  /// Generate a full HTML penetration test report.
  static String generateHtml({
    required Project project,
    required List<Target> targets,
    required List<Vulnerability> vulnerabilities,
    List<DiscoveredCredential> credentials = const [],
    List<CommandLog> commandLogs = const [],
    List<String> scope = const [],
    LLMSettings? llmSettings,
    DateTime? startDate,
    DateTime? endDate,
    String? attackNarrative,
    bool confirmedOnly = true,
  }) {
    final vulnsToReport = confirmedOnly
        ? vulnerabilities.where((v) => v.status == VulnerabilityStatus.confirmed).toList()
        : vulnerabilities;
    final sorted = _sortedVulns(vulnsToReport);
    final byTarget = _groupByTarget(sorted, targets);
    final stats = _computeStats(sorted);
    final date = _formatDate(DateTime.now());
    final reportTitle = project.reportTitle?.isNotEmpty == true
        ? project.reportTitle!
        : project.name;
    final preparedBy = project.pentesterName?.isNotEmpty == true
        ? project.pentesterName!
        : 'PenExecute';
    final proofByCommand = _buildProofIndex(commandLogs);
    final effectiveScope = scope.isNotEmpty
        ? scope
        : targets.map((t) => t.address).toSet().toList()..sort();

    return '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Penetration Test Report — ${_esc(reportTitle)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #f5f5f5; color: #222; font-size: 14px; }
    .page { max-width: 1100px; margin: 0 auto; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,.15); }
    /* Cover */
    .cover { background: #1a1a2e; color: #fff; padding: 60px 48px 48px; }
    .cover h1 { font-size: 32px; font-weight: 700; margin-bottom: 8px; }
    .cover .subtitle { font-size: 18px; color: #a0aec0; margin-bottom: 32px; }
    .cover .meta { display: flex; gap: 40px; }
    .cover .meta-item label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #718096; }
    .cover .meta-item p { font-size: 15px; color: #e2e8f0; margin-top: 2px; }
    /* Sections */
    section { padding: 40px 48px; border-bottom: 1px solid #e8e8e8; }
    h2 { font-size: 22px; font-weight: 600; color: #1a1a2e; margin-bottom: 20px; padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }
    h3 { font-size: 16px; font-weight: 600; color: #2d3748; margin: 20px 0 10px; }
    /* Summary cards */
    .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .stat-card { border-radius: 8px; padding: 16px 20px; text-align: center; }
    .stat-card .count { font-size: 36px; font-weight: 700; line-height: 1; }
    .stat-card .label { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
    .critical { background: #fff5f5; border: 1px solid #fed7d7; color: #c53030; }
    .high { background: #fffaf0; border: 1px solid #fbd38d; color: #c05621; }
    .medium { background: #fffff0; border: 1px solid #faf089; color: #975a16; }
    .low { background: #f0fff4; border: 1px solid #9ae6b4; color: #276749; }
    .info { background: #ebf8ff; border: 1px solid #90cdf4; color: #2b6cb0; }
    /* Findings table */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #2d3748; color: #fff; padding: 10px 12px; text-align: left; font-weight: 600; }
    tr:nth-child(even) td { background: #f7fafc; }
    td { padding: 9px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .badge-CRITICAL { background: #c53030; color: #fff; }
    .badge-HIGH { background: #c05621; color: #fff; }
    .badge-MEDIUM { background: #975a16; color: #fff; }
    .badge-LOW { background: #276749; color: #fff; }
    .badge-CONFIRMED { background: #276749; color: #fff; }
    .badge-NOT_VULNERABLE { background: #718096; color: #fff; }
    .badge-UNDETERMINED { background: #975a16; color: #fff; }
    .badge-PENDING { background: #2b6cb0; color: #fff; }
    /* Finding detail cards */
    .finding-card { border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 24px; overflow: hidden; }
    .finding-header { padding: 14px 20px; display: flex; align-items: center; gap: 12px; }
    .finding-header.sev-CRITICAL { background: #fff5f5; border-bottom: 3px solid #c53030; }
    .finding-header.sev-HIGH { background: #fffaf0; border-bottom: 3px solid #c05621; }
    .finding-header.sev-MEDIUM { background: #fffff0; border-bottom: 3px solid #d69e2e; }
    .finding-header.sev-LOW { background: #f0fff4; border-bottom: 3px solid #38a169; }
    .finding-header h4 { font-size: 15px; font-weight: 600; flex: 1; }
    .finding-body { padding: 16px 20px; }
    .finding-body dl { display: grid; grid-template-columns: 140px 1fr; gap: 8px 16px; }
    .finding-body dt { font-weight: 600; color: #4a5568; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; padding-top: 2px; }
    .finding-body dd { color: #2d3748; }
    pre { background: #1a202c; color: #a0aec0; padding: 14px 16px; border-radius: 6px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 8px 0; }
    .cvss-vector { font-family: monospace; font-size: 12px; background: #edf2f7; padding: 4px 8px; border-radius: 4px; }
    .cred-table td { font-family: monospace; font-size: 12px; }
    .toc a { text-decoration: none; color: #2b6cb0; }
    .toc a:hover { text-decoration: underline; }
    .toc li { margin-bottom: 4px; }
    /* Proof of exploitation */
    .proof-block { margin-top: 8px; border-radius: 6px; overflow: hidden; border: 1px solid #2d3748; }
    .proof-block summary { background: #2d3748; color: #a0aec0; padding: 6px 12px; cursor: pointer; font-size: 12px; font-weight: 600; user-select: none; }
    .proof-block summary:hover { background: #3a4a5c; }
    .proof-meta { background: #0a0d1a; color: #718096; font-size: 11px; padding: 6px 12px; font-family: monospace; border-bottom: 1px solid #2d3748; }
    .proof-output { background: #0a0d1a; color: #a0aec0; padding: 12px 16px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 0; }
    /* Assessment overview */
    .overview-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .overview-item label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: #718096; display: block; margin-bottom: 4px; }
    .overview-item p { font-size: 14px; color: #2d3748; font-weight: 500; }
    .scope-list { margin: 0; padding-left: 20px; }
    .scope-list li { font-family: monospace; font-size: 13px; color: #2d3748; margin-bottom: 2px; }
    /* LLM config box */
    .llm-config { background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; font-size: 13px; }
    .llm-config dl { display: grid; grid-template-columns: 140px 1fr; gap: 4px 16px; }
    .llm-config dt { font-weight: 600; color: #4a5568; font-size: 12px; text-transform: uppercase; letter-spacing: .5px; }
    .llm-config dd { color: #2d3748; font-family: monospace; }
    @media print {
      body { background: #fff; }
      .page { box-shadow: none; }
    }
  </style>
</head>
<body>
<div class="page">

<!-- COVER -->
<div class="cover">
  <h1>${_esc(reportTitle)}</h1>
  <div class="subtitle">${_esc(project.name)}</div>
  <div class="meta">
    <div class="meta-item"><label>Report Date</label><p>$date</p></div>
    <div class="meta-item"><label>Prepared By</label><p>${_esc(preparedBy)}</p></div>
    <div class="meta-item"><label>Assessment Start</label><p>${startDate != null ? _formatDate(startDate) : '—'}</p></div>
    <div class="meta-item"><label>Assessment End</label><p>${endDate != null ? _formatDate(endDate) : '—'}</p></div>
    <div class="meta-item"><label>Targets Assessed</label><p>${targets.length}</p></div>
    <div class="meta-item"><label>Total Findings</label><p>${sorted.length}${confirmedOnly ? ' (confirmed only)' : ''}</p></div>
  </div>
</div>

<!-- ASSESSMENT OVERVIEW -->
<section id="overview">
  <h2>Assessment Overview</h2>
  <div class="overview-grid">
    <div class="overview-item"><label>Assessment Started</label><p>${startDate != null ? _formatDateLong(startDate) : '—'}</p></div>
    <div class="overview-item"><label>Last Execution</label><p>${endDate != null ? _formatDateLong(endDate) : '—'}</p></div>
    ${startDate != null && endDate != null ? '<div class="overview-item"><label>Duration</label><p>${_formatDuration(startDate, endDate)}</p></div>' : ''}
    <div class="overview-item"><label>Targets Assessed</label><p>${effectiveScope.length}</p></div>
  </div>
  ${effectiveScope.isNotEmpty ? '<h3>Scope</h3><ul class="scope-list">${effectiveScope.map(_esc).map((a) => '<li>$a</li>').join('\n    ')}</ul>' : ''}
</section>

${llmSettings != null && llmSettings.provider.name != 'none' ? '''
<!-- ASSESSMENT CONFIGURATION -->
<section id="assessment-config">
  <h2>Assessment Configuration</h2>
  <div class="llm-config">
    <dl>
      <dt>Provider</dt><dd>${_esc(llmSettings.provider.name)}</dd>
      <dt>Model</dt><dd>${_esc(llmSettings.modelName)}</dd>
      <dt>Temperature</dt><dd>${llmSettings.temperature}</dd>
      <dt>Max Tokens</dt><dd>${llmSettings.maxTokens}</dd>
    </dl>
    <p style="margin-top:8px;font-size:12px;color:#718096;">API keys and credentials are not included in this report.</p>
  </div>
</section>
''' : ''}

<!-- EXECUTIVE SUMMARY -->
<section id="summary">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card critical"><div class="count">${stats['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="count">${stats['HIGH']}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="count">${stats['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="count">${stats['LOW']}</div><div class="label">Low</div></div>
  </div>
  ${project.executiveSummary?.isNotEmpty == true ? _paragraphs(project.executiveSummary!) : _executiveSummaryText(stats, targets.length)}
</section>

${project.methodology?.isNotEmpty == true ? '''
<!-- METHODOLOGY AND SCOPE -->
<section id="methodology">
  <h2>Methodology and Scope</h2>
  ${_paragraphs(project.methodology!)}
</section>
''' : ''}

${project.riskRatingModel?.isNotEmpty == true ? '''
<!-- RISK RATING MODEL -->
<section id="risk-rating">
  <h2>Risk Rating Model</h2>
  ${_paragraphs(project.riskRatingModel!)}
</section>
''' : ''}

${attackNarrative != null && attackNarrative.isNotEmpty ? '''
<!-- ATTACK NARRATIVE -->
<section id="attack-narrative">
  <h2>Attack Narrative</h2>
  ${_renderNarrative(attackNarrative)}
</section>
''' : ''}

<!-- FINDINGS SUMMARY TABLE -->
<section id="findings-table">
  <h2>Findings Summary</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Title</th><th>Target</th><th>Severity</th><th>Status</th><th>CVE</th><th>CVSS</th></tr>
    </thead>
    <tbody>
      ${_findingsTableRows(sorted)}
    </tbody>
  </table>
</section>

<!-- DETAILED FINDINGS -->
<section id="findings-detail">
  <h2>Detailed Findings</h2>
  ${_detailedFindings(sorted, proofByCommand)}
</section>

${credentials.isNotEmpty ? _credentialsSection(credentials) : ''}

<!-- TARGETS -->
<section id="targets">
  <h2>Assessed Targets</h2>
  ${_targetsSection(byTarget)}
</section>

${project.conclusion?.isNotEmpty == true ? '''
<!-- CONCLUSION -->
<section id="conclusion">
  <h2>Conclusion</h2>
  ${_paragraphs(project.conclusion!)}
</section>
''' : ''}

</div>
</body>
</html>''';
  }

  /// Generate a Markdown report.
  static String generateMarkdown({
    required Project project,
    required List<Target> targets,
    required List<Vulnerability> vulnerabilities,
    List<DiscoveredCredential> credentials = const [],
    List<CommandLog> commandLogs = const [],
    List<String> scope = const [],
    LLMSettings? llmSettings,
    DateTime? startDate,
    DateTime? endDate,
    String? attackNarrative,
    bool confirmedOnly = true,
  }) {
    final vulnsToReport = confirmedOnly
        ? vulnerabilities.where((v) => v.status == VulnerabilityStatus.confirmed).toList()
        : vulnerabilities;
    final sorted = _sortedVulns(vulnsToReport);
    final stats = _computeStats(sorted);
    final date = _formatDate(DateTime.now());
    final reportTitle = project.reportTitle?.isNotEmpty == true
        ? project.reportTitle!
        : project.name;
    final preparedBy = project.pentesterName?.isNotEmpty == true
        ? project.pentesterName!
        : 'PenExecute';
    final proofByCommand = _buildProofIndex(commandLogs);
    final effectiveScope = scope.isNotEmpty
        ? scope
        : targets.map((t) => t.address).toSet().toList()..sort();
    final buf = StringBuffer();

    buf.writeln('# $reportTitle');
    buf.writeln();
    buf.writeln('**Date:** $date  ');
    buf.writeln('**Prepared by:** $preparedBy  ');
    buf.writeln('**Targets:** ${targets.length}  ');
    if (startDate != null) buf.writeln('**Assessment Start:** ${_formatDate(startDate)}  ');
    if (endDate != null) buf.writeln('**Assessment End:** ${_formatDate(endDate)}  ');
    buf.writeln();

    buf.writeln();
    buf.writeln('## Assessment Overview');
    buf.writeln();
    buf.writeln('| Field | Value |');
    buf.writeln('|-------|-------|');
    buf.writeln('| Started | ${startDate != null ? _formatDateLong(startDate) : "—"} |');
    buf.writeln('| Last Execution | ${endDate != null ? _formatDateLong(endDate) : "—"} |');
    if (startDate != null && endDate != null) {
      buf.writeln('| Duration | ${_formatDuration(startDate, endDate)} |');
    }
    buf.writeln('| Scope | ${effectiveScope.join(", ")} |');
    buf.writeln();

    if (llmSettings != null && llmSettings.provider.name != 'none') {
      buf.writeln('## Assessment Configuration');
      buf.writeln();
      buf.writeln('| Field | Value |');
      buf.writeln('|-------|-------|');
      buf.writeln('| Provider | ${llmSettings.provider.name} |');
      buf.writeln('| Model | ${llmSettings.modelName} |');
      buf.writeln('| Temperature | ${llmSettings.temperature} |');
      buf.writeln('| Max Tokens | ${llmSettings.maxTokens} |');
      buf.writeln();
    }

    buf.writeln('## Executive Summary');
    buf.writeln();
    buf.writeln('| Severity | Count |');
    buf.writeln('|----------|-------|');
    for (final sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      buf.writeln('| $sev | ${stats[sev]} |');
    }
    buf.writeln();
    if (project.executiveSummary?.isNotEmpty == true) {
      buf.writeln(project.executiveSummary);
      buf.writeln();
    }

    if (project.methodology?.isNotEmpty == true) {
      buf.writeln('## Methodology and Scope');
      buf.writeln();
      buf.writeln(project.methodology);
      buf.writeln();
    }

    if (project.riskRatingModel?.isNotEmpty == true) {
      buf.writeln('## Risk Rating Model');
      buf.writeln();
      buf.writeln(project.riskRatingModel);
      buf.writeln();
    }

    if (attackNarrative != null && attackNarrative.isNotEmpty) {
      buf.writeln('## Attack Narrative');
      buf.writeln();
      buf.writeln(attackNarrative);
      buf.writeln();
    }

    buf.writeln('## Findings Summary');
    buf.writeln();
    buf.writeln('| # | Title | Target | Severity | Status | CVE |');
    buf.writeln('|---|-------|--------|----------|--------|-----|');
    for (int i = 0; i < sorted.length; i++) {
      final v = sorted[i];
      buf.writeln('| ${i + 1} | ${v.problem} | ${v.targetAddress} | ${v.severity} | ${_statusLabel(v.status)} | ${v.cve.isEmpty ? '—' : v.cve} |');
    }
    buf.writeln();

    buf.writeln('## Detailed Findings');
    buf.writeln();
    for (int i = 0; i < sorted.length; i++) {
      final v = sorted[i];
      buf.writeln('### ${i + 1}. ${v.problem}');
      buf.writeln();
      buf.writeln('- **Severity:** ${v.severity}');
      buf.writeln('- **Status:** ${_statusLabel(v.status)}');
      buf.writeln('- **Target:** ${v.targetAddress}');
      if (v.cve.isNotEmpty) buf.writeln('- **CVE:** ${v.cve}');
      buf.writeln('- **Type:** ${v.vulnerabilityType}');
      buf.writeln('- **CVSS Vector:** ${_cvssVector(v)}');
      buf.writeln();
      buf.writeln('**Description:**');
      buf.writeln();
      buf.writeln(v.description);
      buf.writeln();
      if (v.evidence.isNotEmpty) {
        buf.writeln('**Evidence:**');
        buf.writeln('```');
        buf.writeln(v.evidence);
        buf.writeln('```');
        buf.writeln();
      }
      if (v.proofCommand != null && v.proofCommand!.isNotEmpty) {
        buf.writeln('**Proof Command:**');
        buf.writeln('```bash');
        buf.writeln(v.proofCommand);
        buf.writeln('```');
        buf.writeln();
        final proofLog = proofByCommand[v.proofCommand!.trim()];
        if (proofLog != null) {
          final output = proofLog.output.length > 3000
              ? '${proofLog.output.substring(0, 3000)}\n... [truncated]'
              : proofLog.output;
          buf.writeln('**Proof Output** (executed ${_formatDate(proofLog.timestamp)}, exit ${proofLog.exitCode}):');
          buf.writeln('```');
          buf.writeln(output);
          buf.writeln('```');
          buf.writeln();
        }
      }
      buf.writeln('**Recommendation:** ${v.recommendation}');
      buf.writeln();
      buf.writeln('---');
      buf.writeln();
    }

    if (credentials.isNotEmpty) {
      buf.writeln('## Discovered Credentials');
      buf.writeln();
      buf.writeln('| Service | Host | Username | Type | Source |');
      buf.writeln('|---------|------|----------|------|--------|');
      for (final c in credentials) {
        buf.writeln('| ${c.service} | ${c.host} | ${c.username} | ${c.secretType} | ${c.sourceVuln} |');
      }
      buf.writeln();
    }

    if (project.conclusion?.isNotEmpty == true) {
      buf.writeln('## Conclusion');
      buf.writeln();
      buf.writeln(project.conclusion);
      buf.writeln();
    }

    return buf.toString();
  }

  /// Generate a CSV export for remediation tracking.
  /// CSV always includes all findings (confirmedOnly=false by default) with a
  /// Status column so the full set can be used for triage.
  static String generateCsv({
    required List<Vulnerability> vulnerabilities,
    List<CommandLog> commandLogs = const [],
    bool confirmedOnly = false,
  }) {
    final vulnsToReport = confirmedOnly
        ? vulnerabilities.where((v) => v.status == VulnerabilityStatus.confirmed).toList()
        : vulnerabilities;
    final sorted = _sortedVulns(vulnsToReport);
    final proofByCommand = _buildProofIndex(commandLogs);
    final buf = StringBuffer();
    buf.writeln('ID,Title,Target,CVE,Severity,Status,Status Reason,Type,CVSS Vector,Recommendation,Proof Output');
    for (int i = 0; i < sorted.length; i++) {
      final v = sorted[i];
      final proofLog = v.proofCommand != null && v.proofCommand!.isNotEmpty
          ? proofByCommand[v.proofCommand!.trim()]
          : null;
      final rawOut = proofLog?.output ?? '';
      final proofOutput = rawOut.replaceAll('\n', ' | ')
          .substring(0, rawOut.length > 1000 ? 1000 : rawOut.length);
      buf.writeln([
        i + 1,
        _csvEsc(v.problem),
        _csvEsc(v.targetAddress),
        _csvEsc(v.cve),
        v.severity,
        _statusLabel(v.status),
        _csvEsc(v.statusReason),
        _csvEsc(v.vulnerabilityType),
        _csvEsc(_cvssVector(v)),
        _csvEsc(v.recommendation),
        _csvEsc(proofOutput),
      ].join(','));
    }
    return buf.toString();
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  static List<Vulnerability> _sortedVulns(List<Vulnerability> vulns) {
    final order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3};
    final copy = List<Vulnerability>.from(vulns);
    copy.sort((a, b) {
      final sevCmp = (order[a.severity] ?? 4).compareTo(order[b.severity] ?? 4);
      if (sevCmp != 0) return sevCmp;
      // Confirmed before others at same severity
      if (a.status == VulnerabilityStatus.confirmed && b.status != VulnerabilityStatus.confirmed) return -1;
      if (b.status == VulnerabilityStatus.confirmed && a.status != VulnerabilityStatus.confirmed) return 1;
      return a.problem.compareTo(b.problem);
    });
    return copy;
  }

  static Map<String, int> _computeStats(List<Vulnerability> vulns) {
    final stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0};
    for (final v in vulns) {
      final sev = v.severity.toUpperCase();
      if (stats.containsKey(sev)) stats[sev] = stats[sev]! + 1;
    }
    return stats;
  }

  static Map<String, List<Vulnerability>> _groupByTarget(
      List<Vulnerability> vulns, List<Target> targets) {
    final map = <String, List<Vulnerability>>{};
    for (final v in vulns) {
      map.putIfAbsent(v.targetAddress, () => []).add(v);
    }
    return map;
  }

  static String _formatDate(DateTime dt) =>
      '${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')}';

  /// Convert plain text (paragraphs separated by blank lines) to HTML <p> tags.
  /// Renders an attack narrative string that may contain `### Heading` lines
  /// into HTML, converting headings to `<h3>` and paragraphs to `<p>`.
  static String _renderNarrative(String text) {
    final buf = StringBuffer();
    for (final block in text.split(RegExp(r'\n\n+'))) {
      final trimmed = block.trim();
      if (trimmed.isEmpty) continue;
      if (trimmed.startsWith('### ')) {
        buf.write('<h3>${_esc(trimmed.substring(4).trim())}</h3>\n  ');
      } else {
        buf.write('<p>${_esc(trimmed).replaceAll('\n', '<br>')}</p>\n  ');
      }
    }
    return buf.toString();
  }

  static String _paragraphs(String text) => text
      .split(RegExp(r'\n\n+'))
      .where((p) => p.trim().isNotEmpty)
      .map((p) => '<p>${_esc(p.trim()).replaceAll('\n', '<br>')}</p>')
      .join('\n  ');

  static String _esc(String s) => s
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;');

  static String _csvEsc(String s) {
    final escaped = s.replaceAll('"', '""').replaceAll('\n', ' ');
    return '"$escaped"';
  }

  static String _statusLabel(VulnerabilityStatus s) => switch (s) {
        VulnerabilityStatus.confirmed => 'CONFIRMED',
        VulnerabilityStatus.notVulnerable => 'NOT_VULNERABLE',
        VulnerabilityStatus.undetermined => 'UNDETERMINED',
        VulnerabilityStatus.pending => 'PENDING',
      };

  static String _statusBadge(VulnerabilityStatus s) {
    final label = _statusLabel(s);
    return '<span class="badge badge-$label">$label</span>';
  }

  static String _sevBadge(String sev) =>
      '<span class="badge badge-${sev.toUpperCase()}">${_esc(sev)}</span>';

  static String _cvssVector(Vulnerability v) {
    final score = CvssCalculator.calculate(v);
    final vec = CvssCalculator.vectorString(v);
    return score != null ? '${score.toStringAsFixed(1)} $vec' : vec;
  }

  static String _executiveSummaryText(Map<String, int> stats, int targetCount) {
    final critical = stats['CRITICAL']!;
    final high = stats['HIGH']!;
    final total = stats.values.fold(0, (a, b) => a + b);
    if (total == 0) return '<p>No vulnerabilities were identified during this assessment.</p>';
    final urgentCount = critical + high;
    return '''<p>This assessment of <strong>$targetCount target(s)</strong> identified <strong>$total vulnerabilities</strong>.
${urgentCount > 0 ? '<strong>$urgentCount finding(s) are rated High or Critical severity</strong> and should be remediated immediately.' : 'No critical or high severity findings were identified.'}
${critical > 0 ? ' $critical <strong>Critical</strong> severity finding(s) represent immediate risk of compromise and require priority attention.' : ''}</p>''';
  }

  static String _findingsTableRows(List<Vulnerability> vulns) {
    final buf = StringBuffer();
    for (int i = 0; i < vulns.length; i++) {
      final v = vulns[i];
      final cvssVec = _cvssVector(v);
      buf.writeln('''      <tr>
        <td>${i + 1}</td>
        <td><a href="#finding-$i">${_esc(v.problem)}</a></td>
        <td>${_esc(v.targetAddress)}</td>
        <td>${_sevBadge(v.severity)}</td>
        <td>${_statusBadge(v.status)}</td>
        <td>${v.cve.isNotEmpty ? _esc(v.cve) : '—'}</td>
        <td><span class="cvss-vector">$cvssVec</span></td>
      </tr>''');
    }
    return buf.toString();
  }

  static String _detailedFindings(
      List<Vulnerability> vulns, Map<String, CommandLog> proofByCommand) {
    final buf = StringBuffer();
    for (int i = 0; i < vulns.length; i++) {
      final v = vulns[i];
      final sev = v.severity.toUpperCase();
      final proofLog = v.proofCommand != null && v.proofCommand!.isNotEmpty
          ? proofByCommand[v.proofCommand!.trim()]
          : null;
      final proofBlock = proofLog != null
          ? '''          <dt>Proof Output</dt><dd>
            <details class="proof-block">
              <summary>&#9658; Proof of Exploitation — click to expand</summary>
              <div class="proof-meta">Executed: ${_formatDate(proofLog.timestamp)} &middot; Exit code: ${proofLog.exitCode}</div>
              <pre class="proof-output">${_esc(proofLog.output.length > 3000 ? '${proofLog.output.substring(0, 3000)}\n... [truncated]' : proofLog.output)}</pre>
            </details>
          </dd>'''
          : '';
      buf.writeln('''    <div class="finding-card" id="finding-$i">
      <div class="finding-header sev-$sev">
        <h4>${_esc(v.problem)}</h4>
        ${_sevBadge(v.severity)}
        ${_statusBadge(v.status)}
      </div>
      <div class="finding-body">
        <dl>
          <dt>Target</dt><dd>${_esc(v.targetAddress)}</dd>
          ${v.cve.isNotEmpty ? '<dt>CVE</dt><dd>${_esc(v.cve)}</dd>' : ''}
          <dt>Type</dt><dd>${_esc(v.vulnerabilityType)}</dd>
          <dt>Attack Vector</dt><dd>${_esc(v.attackVector)}</dd>
          <dt>CVSS Vector</dt><dd><span class="cvss-vector">${_cvssVector(v)}</span></dd>
          <dt>Description</dt><dd>${_esc(v.description).replaceAll('\n', '<br>')}</dd>
          ${v.evidence.isNotEmpty ? '<dt>Evidence</dt><dd><pre>${_esc(v.evidence)}</pre></dd>' : ''}
          ${v.proofCommand != null && v.proofCommand!.isNotEmpty ? '<dt>Proof Command</dt><dd><pre>${_esc(v.proofCommand!)}</pre></dd>' : ''}
          $proofBlock
          <dt>Recommendation</dt><dd>${_esc(v.recommendation).replaceAll('\n', '<br>')}</dd>
        </dl>
      </div>
    </div>''');
    }
    return buf.toString();
  }

  static String _credentialsSection(List<DiscoveredCredential> creds) => '''
<section id="credentials">
  <h2>Discovered Credentials</h2>
  <p style="color:#c53030;font-weight:600;margin-bottom:16px;">&#9888; Handle this section with care — contains sensitive authentication material.</p>
  <table class="cred-table">
    <thead>
      <tr><th>Service</th><th>Host</th><th>Username</th><th>Type</th><th>Source Finding</th></tr>
    </thead>
    <tbody>
      ${creds.map((c) => '''      <tr>
        <td>${_esc(c.service)}</td>
        <td>${_esc(c.host)}</td>
        <td>${_esc(c.username)}</td>
        <td>${_esc(c.secretType)}</td>
        <td>${_esc(c.sourceVuln)}</td>
      </tr>''').join('\n')}
    </tbody>
  </table>
</section>''';

  static String _targetsSection(Map<String, List<Vulnerability>> byTarget) {
    if (byTarget.isEmpty) return '<p>No targets assessed.</p>';
    final buf = StringBuffer();
    for (final entry in byTarget.entries) {
      final addr = entry.key;
      final vulns = entry.value;
      final stats = _computeStats(vulns);
      buf.writeln('''    <div style="margin-bottom:24px;padding:16px;border:1px solid #e2e8f0;border-radius:8px;">
      <h3>${_esc(addr)}</h3>
      <p style="margin:8px 0;color:#4a5568;">
        ${vulns.length} finding(s):
        ${stats['CRITICAL']! > 0 ? '<span class="badge badge-CRITICAL">${stats['CRITICAL']} Critical</span> ' : ''}
        ${stats['HIGH']! > 0 ? '<span class="badge badge-HIGH">${stats['HIGH']} High</span> ' : ''}
        ${stats['MEDIUM']! > 0 ? '<span class="badge badge-MEDIUM">${stats['MEDIUM']} Medium</span> ' : ''}
        ${stats['LOW']! > 0 ? '<span class="badge badge-LOW">${stats['LOW']} Low</span>' : ''}
      </p>
    </div>''');
    }
    return buf.toString();
  }

  /// Build an index of command logs keyed by trimmed command string for O(1) lookup.
  static Map<String, CommandLog> _buildProofIndex(List<CommandLog> logs) {
    final index = <String, CommandLog>{};
    for (final log in logs) {
      final key = log.command.trim();
      if (key.isNotEmpty) index[key] = log;
    }
    return index;
  }

  /// Format a DateTime as "19 March 2026 at 14:30".
  static String _formatDateLong(DateTime dt) {
    const months = [
      '', 'January', 'February', 'March', 'April', 'May', 'June',
      'July', 'August', 'September', 'October', 'November', 'December'
    ];
    final h = dt.hour.toString().padLeft(2, '0');
    final m = dt.minute.toString().padLeft(2, '0');
    return '${dt.day} ${months[dt.month]} ${dt.year} at $h:$m';
  }

  /// Format the duration between two DateTimes as "X days, Y hours, Z minutes".
  static String _formatDuration(DateTime start, DateTime end) {
    final diff = end.difference(start).abs();
    final days = diff.inDays;
    final hours = diff.inHours.remainder(24);
    final minutes = diff.inMinutes.remainder(60);
    final parts = <String>[];
    if (days > 0) parts.add('$days day${days == 1 ? '' : 's'}');
    if (hours > 0) parts.add('$hours hour${hours == 1 ? '' : 's'}');
    if (minutes > 0 || parts.isEmpty) parts.add('$minutes minute${minutes == 1 ? '' : 's'}');
    return parts.join(', ');
  }
}
