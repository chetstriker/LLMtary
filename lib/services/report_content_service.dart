import '../models/llm_settings.dart';
import '../models/vulnerability.dart';
import '../utils/device_utils.dart';
import '../widgets/app_state.dart';
import 'llm_service.dart';
import 'prompt_templates.dart';

/// Assembles report narrative prompts from AppState data and calls LlmService
/// to generate each section. All methods are static — no persistent state.
class ReportContentService {
  /// Call the LLM with [prompt] and return the plain-text response.
  ///
  /// Uses a slightly elevated max_tokens (2048) to allow full paragraphs.
  /// The security-expert system prompt is disabled — report writing requires
  /// a professional writing persona, not a hacking persona.
  static Future<String> generateSection({
    required String prompt,
    required LLMSettings settings,
  }) async {
    final writeSettings = LLMSettings(
      provider: settings.provider,
      baseUrl: settings.baseUrl,
      apiKey: settings.apiKey,
      modelName: settings.modelName,
      temperature: 0.45, // slightly higher for more natural prose
      maxTokens: 2048,
      timeoutSeconds: settings.timeoutSeconds,
    );
    final svc = LLMService();
    final response = await svc.sendMessage(
      writeSettings,
      prompt,
      useSystemPrompt: false,
    );
    return response.trim();
  }

  // ---------------------------------------------------------------------------
  // Prompt builders — read from AppState and delegate to PromptTemplates
  // ---------------------------------------------------------------------------

  static String buildExecutiveSummaryPrompt(AppState state) {
    final project = state.currentProject;
    final vulns = state.vulnerabilities;
    final targets = state.targets;

    final counts = _countBySeverity(vulns);
    final confirmed = vulns.where((v) => v.status == VulnerabilityStatus.confirmed).length;
    final topFindings = vulns
        .where((v) => v.severity == 'CRITICAL' || v.severity == 'HIGH')
        .take(10)
        .map((v) => '${v.problem} — ${v.severity} — ${_statusLabel(v.status)}')
        .toList();

    return PromptTemplates.reportExecutiveSummaryPrompt(
      projectName: project?.name ?? 'Penetration Test',
      targetCount: targets.length,
      criticalCount: counts['CRITICAL'] ?? 0,
      highCount: counts['HIGH'] ?? 0,
      mediumCount: counts['MEDIUM'] ?? 0,
      lowCount: counts['LOW'] ?? 0,
      confirmedCount: confirmed,
      totalVulnCount: vulns.length,
      startDate: _formatDate(project?.firstAnalysisAt),
      endDate: _formatDate(project?.lastExecutionAt),
      targetAddresses: targets.map((t) => t.address).toList(),
      topFindingSummaries: topFindings,
    );
  }

  static String buildMethodologyPrompt(AppState state) {
    final project = state.currentProject;
    final targets = state.targets;
    final vulns = state.vulnerabilities;

    final addresses = targets.map((t) => t.address).toList();
    final hasInternal = addresses.any(
        (a) => DeviceUtils.classifyTarget(a) == TargetScope.internal);
    final hasExternal = addresses.any(
        (a) => DeviceUtils.classifyTarget(a) == TargetScope.external);
    final hasWeb = vulns.any((v) =>
        v.vulnerabilityType.toLowerCase().contains('web') ||
        v.vulnerabilityType.toLowerCase().contains('http') ||
        v.vulnerabilityType.toLowerCase().contains('xss') ||
        v.vulnerabilityType.toLowerCase().contains('sql') ||
        v.vulnerabilityType.toLowerCase().contains('injection'));
    final hasAd = vulns.any((v) =>
        v.vulnerabilityType.toLowerCase().contains('active directory') ||
        v.vulnerabilityType.toLowerCase().contains('kerberos') ||
        v.vulnerabilityType.toLowerCase().contains('ldap') ||
        v.description.toLowerCase().contains('active directory'));

    return PromptTemplates.reportMethodologyPrompt(
      projectName: project?.name ?? 'Penetration Test',
      targetAddresses: addresses,
      hasInternalTargets: hasInternal,
      hasExternalTargets: hasExternal,
      hasWebTargets: hasWeb,
      hasAdTargets: hasAd,
      targetCount: targets.length,
      startDate: _formatDate(project?.firstAnalysisAt),
      endDate: _formatDate(project?.lastExecutionAt),
    );
  }

  static String buildRiskRatingPrompt(AppState state) {
    final vulns = state.vulnerabilities;
    final counts = _countBySeverity(vulns);
    final hasCvss = vulns.any((v) => v.cvssScore != null);

    return PromptTemplates.reportRiskRatingPrompt(
      criticalCount: counts['CRITICAL'] ?? 0,
      highCount: counts['HIGH'] ?? 0,
      mediumCount: counts['MEDIUM'] ?? 0,
      lowCount: counts['LOW'] ?? 0,
      hasCvssScores: hasCvss,
    );
  }

  /// Builds a detailed finding narrative prompt for a single vulnerability.
  /// Includes CVSS vector/score, PoC output, and reproduction steps when available.
  static String buildVulnerabilityDetailPrompt(Vulnerability v) {
    final cvssLine = v.cvssScore != null
        ? 'CVSS v3.1 Score: ${v.cvssScore!.toStringAsFixed(1)} — Vector: ${v.cvssVector}'
        : '';
    final pocSection = v.proofOutput != null && v.proofOutput!.isNotEmpty
        ? '\n\nPROOF OF EXPLOITATION (command output excerpt):\n'
          '${v.proofOutput!.length > 800 ? v.proofOutput!.substring(0, 800) + "\n...[truncated]" : v.proofOutput}'
        : '';
    final stepsSection = v.reproductionSteps != null && v.reproductionSteps!.isNotEmpty
        ? '\n\nREPRODUCTION STEPS:\n${v.reproductionSteps}'
        : '';
    final confirmedLine = v.confirmedAt != null
        ? 'Confirmed at: ${v.confirmedAt!.toIso8601String()}'
        : '';

    return '''Write a professional penetration test finding section for the following confirmed vulnerability. Use formal report language appropriate for a technical audience. Include a brief description of the issue, its technical impact, and reference the proof of exploitation if provided.

FINDING: ${v.problem}
SEVERITY: ${v.severity}
CONFIDENCE: ${v.confidence}
${cvssLine.isNotEmpty ? cvssLine + '\n' : ''}${confirmedLine.isNotEmpty ? confirmedLine + '\n' : ''}VULNERABILITY TYPE: ${v.vulnerabilityType}
CVE: ${v.cve.isNotEmpty ? v.cve : 'N/A'}
TARGET: ${v.targetAddress}

TECHNICAL DESCRIPTION:
${v.description}

EVIDENCE:
${v.evidence}

STATUS REASON:
${v.statusReason}
${pocSection}${stepsSection}

RECOMMENDATION:
${v.recommendation}

BUSINESS RISK:
${v.businessRisk}

Write 2–4 paragraphs covering: (1) what the vulnerability is and where it was found, (2) how it was confirmed and what the proof shows, (3) the business risk if exploited, (4) remediation priority. Do NOT include a heading — the caller adds section headings. Output plain text only.''';
  }

  /// Produces a formatted plain-text PoC block for inclusion in the technical
  /// appendix of a report. Returns an empty string if no PoC data is available.
  static String formatPocAppendixEntry(Vulnerability v, int index) {
    if (v.status != VulnerabilityStatus.confirmed) return '';
    final buf = StringBuffer();
    buf.writeln('--- Finding #$index: ${v.problem} ---');
    buf.writeln('Severity : ${v.severity}');
    if (v.cvssScore != null) {
      buf.writeln('CVSS     : ${v.cvssScore!.toStringAsFixed(1)} (${v.cvssVector})');
    }
    if (v.cve.isNotEmpty) buf.writeln('CVE      : ${v.cve}');
    buf.writeln('Target   : ${v.targetAddress}');
    if (v.confirmedAt != null) {
      buf.writeln('Confirmed: ${_formatDate(v.confirmedAt)}');
    }
    if (v.proofCommand != null && v.proofCommand!.isNotEmpty &&
        v.proofCommand != 'Analysis Conclusion' &&
        v.proofCommand != 'Initial Evidence Analysis') {
      buf.writeln('\nProof Command:');
      buf.writeln('  ${v.proofCommand}');
    }
    if (v.proofOutput != null && v.proofOutput!.isNotEmpty) {
      buf.writeln('\nProof Output (excerpt):');
      final excerpt = v.proofOutput!.length > 1000
          ? v.proofOutput!.substring(0, 1000) + '\n...[truncated]'
          : v.proofOutput!;
      for (final line in excerpt.split('\n')) {
        buf.writeln('  $line');
      }
    }
    if (v.reproductionSteps != null && v.reproductionSteps!.isNotEmpty) {
      buf.writeln('\nReproduction Steps:');
      buf.writeln(v.reproductionSteps);
    }
    buf.writeln();
    return buf.toString();
  }

  /// Builds the attack narrative prompt using all confirmed findings.
  /// Returns null if there are no confirmed findings to narrate.
  static String? buildAttackNarrativePrompt(AppState state) {
    final confirmed = state.vulnerabilities
        .where((v) => v.status == VulnerabilityStatus.confirmed)
        .toList();
    if (confirmed.isEmpty) return null;

    final targets = state.targets;
    final targetContext = targets.map((t) => t.address).join(', ');

    return PromptTemplates.attackNarrativePrompt(
      confirmedFindings: confirmed,
      targetContext: targetContext,
    );
  }

  static String buildConclusionPrompt(AppState state) {
    final project = state.currentProject;
    final vulns = state.vulnerabilities;
    final counts = _countBySeverity(vulns);
    final confirmed = vulns.where((v) => v.status == VulnerabilityStatus.confirmed).length;
    final topFindings = vulns
        .where((v) => v.severity == 'CRITICAL' || v.severity == 'HIGH')
        .take(5)
        .map((v) => '${v.problem} — ${v.severity} — ${_statusLabel(v.status)}')
        .toList();

    return PromptTemplates.reportConclusionPrompt(
      projectName: project?.name ?? 'Penetration Test',
      totalVulnCount: vulns.length,
      confirmedCount: confirmed,
      criticalCount: counts['CRITICAL'] ?? 0,
      highCount: counts['HIGH'] ?? 0,
      topFindingSummaries: topFindings,
      endDate: _formatDate(project?.lastExecutionAt),
    );
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  static Map<String, int> _countBySeverity(List<Vulnerability> vulns) {
    final counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0};
    for (final v in vulns) {
      final sev = v.severity.toUpperCase();
      if (counts.containsKey(sev)) counts[sev] = counts[sev]! + 1;
    }
    return counts;
  }

  static String _statusLabel(VulnerabilityStatus s) => switch (s) {
        VulnerabilityStatus.confirmed => 'Confirmed',
        VulnerabilityStatus.notVulnerable => 'Not Vulnerable',
        VulnerabilityStatus.undetermined => 'Undetermined',
        VulnerabilityStatus.pending => 'Pending',
      };

  static String? _formatDate(DateTime? dt) {
    if (dt == null) return null;
    return '${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')}';
  }
}
