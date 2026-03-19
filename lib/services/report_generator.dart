import '../models/vulnerability.dart';
import '../models/project.dart';
import '../models/target.dart';
import '../models/credential.dart';
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
  }) {
    final sorted = _sortedVulns(vulnerabilities);
    final byTarget = _groupByTarget(sorted, targets);
    final stats = _computeStats(sorted);
    final date = _formatDate(DateTime.now());

    return '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Penetration Test Report — ${_esc(project.name)}</title>
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
  <h1>Penetration Test Report</h1>
  <div class="subtitle">${_esc(project.name)}</div>
  <div class="meta">
    <div class="meta-item"><label>Report Date</label><p>$date</p></div>
    <div class="meta-item"><label>Targets Assessed</label><p>${targets.length}</p></div>
    <div class="meta-item"><label>Total Findings</label><p>${vulnerabilities.length}</p></div>
    <div class="meta-item"><label>Generated By</label><p>PenExecute</p></div>
  </div>
</div>

<!-- EXECUTIVE SUMMARY -->
<section id="summary">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-card critical"><div class="count">${stats['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat-card high"><div class="count">${stats['HIGH']}</div><div class="label">High</div></div>
    <div class="stat-card medium"><div class="count">${stats['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat-card low"><div class="count">${stats['LOW']}</div><div class="label">Low</div></div>
  </div>
  ${_executiveSummaryText(stats, targets.length)}
</section>

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
  ${_detailedFindings(sorted)}
</section>

${credentials.isNotEmpty ? _credentialsSection(credentials) : ''}

<!-- TARGETS -->
<section id="targets">
  <h2>Assessed Targets</h2>
  ${_targetsSection(byTarget)}
</section>

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
  }) {
    final sorted = _sortedVulns(vulnerabilities);
    final stats = _computeStats(sorted);
    final date = _formatDate(DateTime.now());
    final buf = StringBuffer();

    buf.writeln('# Penetration Test Report — ${project.name}');
    buf.writeln();
    buf.writeln('**Date:** $date  ');
    buf.writeln('**Targets:** ${targets.length}  ');
    buf.writeln('**Generated by:** PenExecute');
    buf.writeln();

    buf.writeln('## Executive Summary');
    buf.writeln();
    buf.writeln('| Severity | Count |');
    buf.writeln('|----------|-------|');
    for (final sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      buf.writeln('| $sev | ${stats[sev]} |');
    }
    buf.writeln();

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

    return buf.toString();
  }

  /// Generate a CSV export for remediation tracking.
  static String generateCsv({
    required List<Vulnerability> vulnerabilities,
  }) {
    final sorted = _sortedVulns(vulnerabilities);
    final buf = StringBuffer();
    buf.writeln('ID,Title,Target,CVE,Severity,Status,Type,CVSS Vector,Recommendation');
    for (int i = 0; i < sorted.length; i++) {
      final v = sorted[i];
      buf.writeln([
        i + 1,
        _csvEsc(v.problem),
        _csvEsc(v.targetAddress),
        _csvEsc(v.cve),
        v.severity,
        _statusLabel(v.status),
        _csvEsc(v.vulnerabilityType),
        _csvEsc(_cvssVector(v)),
        _csvEsc(v.recommendation),
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

  static String _detailedFindings(List<Vulnerability> vulns) {
    final buf = StringBuffer();
    for (int i = 0; i < vulns.length; i++) {
      final v = vulns[i];
      final sev = v.severity.toUpperCase();
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
}
