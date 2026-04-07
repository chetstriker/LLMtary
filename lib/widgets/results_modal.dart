import 'dart:io';
import 'package:flutter/material.dart';
import '../utils/file_dialog.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';

class ConfirmedResult {
  final Vulnerability vuln;
  final String address;
  final String proofOutput;
  final String proofDescription;
  final String proofCommand;

  ConfirmedResult({
    required this.vuln,
    required this.address,
    required this.proofOutput,
    required this.proofDescription,
    required this.proofCommand,
  });
}

class ResultsModal extends StatelessWidget {
  final List<ConfirmedResult> results;
  final String projectName;

  const ResultsModal({super.key, required this.results, this.projectName = 'LLMtary'});

  static Future<void> show(
    BuildContext context,
    List<Vulnerability> vulnerabilities,
    List<CommandLog> commandLogs,
    String targetAddress, {
    String projectName = 'LLMtary',
  }) {
    final confirmed = vulnerabilities
        .where((v) => v.status == VulnerabilityStatus.confirmed)
        .toList();

    final results = confirmed.map((vuln) {
      final vulnIdx = vulnerabilities.indexOf(vuln);

      // Find the proof log: prefer PROOF: prefix, then Analysis Conclusion, then Initial Evidence
      final proofLog = commandLogs
          .where((l) => l.vulnerabilityIndex == vulnIdx)
          .where((l) =>
              l.command.startsWith('PROOF:') ||
              l.command.contains('Analysis Conclusion') ||
              l.command.contains('Initial Evidence Analysis'))
          .fold<CommandLog?>(null, (best, log) {
        if (best == null) return log;
        if (log.command.startsWith('PROOF:')) return log;
        return best;
      });

      // Extract address+port from problem text or fall back to target address
      final portMatch = RegExp(r'port\s+(\d+)', caseSensitive: false).firstMatch(vuln.problem);
      final port = portMatch?.group(1);
      final address = port != null ? '$targetAddress:$port' : targetAddress;

      final proofOutput = proofLog?.output ?? vuln.evidence;
      final proofDescription = vuln.statusReason.isNotEmpty
          ? vuln.statusReason
          : 'Vulnerability confirmed through active testing.';

      // Extract the actual proof command from the log command field (strip PROOF: prefix)
      final rawProofCommand = proofLog?.command ?? '';
      final proofCommand = rawProofCommand.startsWith('PROOF:')
          ? rawProofCommand.substring(6).trim()
          : rawProofCommand;

      return ConfirmedResult(
        vuln: vuln,
        address: address,
        proofOutput: proofOutput,
        proofDescription: proofDescription,
        proofCommand: proofCommand,
      );
    }).toList();

    return showDialog(
      context: context,
      barrierDismissible: true,
      builder: (_) => ResultsModal(results: results, projectName: projectName),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: const Color(0xFF0A0E27),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: const Color(0xFF00F5FF).withOpacity(0.3)),
      ),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 900, maxHeight: 700),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            _buildHeader(context),
            Expanded(
              child: results.isEmpty
                  ? _buildEmpty()
                  : ListView.separated(
                      padding: const EdgeInsets.all(16),
                      itemCount: results.length,
                      separatorBuilder: (_, __) => const SizedBox(height: 12),
                      itemBuilder: (_, i) => _ResultCard(result: results[i]),
                    ),
            ),
            _buildFooter(context),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
      decoration: BoxDecoration(
        color: const Color(0xFF1A1F3A),
        borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
        border: Border(bottom: BorderSide(color: const Color(0xFF00F5FF).withOpacity(0.2))),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              gradient: const LinearGradient(colors: [Color(0xFF00F5FF), Color(0xFF0080FF)]),
              borderRadius: BorderRadius.circular(6),
            ),
            child: const Icon(Icons.verified, color: Colors.white, size: 16),
          ),
          const SizedBox(width: 12),
          Text(
            'Confirmed Vulnerabilities (${results.length})',
            style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16),
          ),
          const Spacer(),
          IconButton(
            icon: const Icon(Icons.close, color: Colors.white54, size: 20),
            onPressed: () => Navigator.of(context).pop(),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
        ],
      ),
    );
  }

  Widget _buildEmpty() {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.check_circle_outline, color: Colors.green, size: 48),
          SizedBox(height: 12),
          Text('No confirmed vulnerabilities found.',
              style: TextStyle(color: Colors.white70, fontSize: 14)),
        ],
      ),
    );
  }

  Widget _buildFooter(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      decoration: BoxDecoration(
        color: const Color(0xFF1A1F3A),
        borderRadius: const BorderRadius.vertical(bottom: Radius.circular(12)),
        border: Border(top: BorderSide(color: const Color(0xFF00F5FF).withOpacity(0.2))),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          if (results.isNotEmpty)
            ElevatedButton.icon(
              icon: const Icon(Icons.download, size: 16),
              label: const Text('Export CSV'),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF00F5FF),
                foregroundColor: Colors.black,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              ),
              onPressed: () => _exportCsv(context),
            ),
          const SizedBox(width: 8),
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close', style: TextStyle(color: Colors.white54)),
          ),
        ],
      ),
    );
  }

  Future<void> _exportCsv(BuildContext context) async {
    final rows = <String>[
      '"Vulnerability","CVE","Type","Severity","Address","Proof Command","Proof Output","Proof Description","Abuse Example","Recommendation"',
      ...results.map((r) => [
            _csv(r.vuln.problem),
            _csv(r.vuln.cve),
            _csv(r.vuln.vulnerabilityType),
            _csv(r.vuln.severity),
            _csv(r.address),
            _csv(r.proofCommand),
            _csv(r.proofOutput),
            _csv(r.proofDescription),
            _csv(_abuseExample(r.vuln)),
            _csv(r.vuln.recommendation),
          ].join(',')),
    ];

    final safe = projectName.replaceAll(RegExp(r'[^\w\-]'), '_');
    final ts = DateTime.now().toIso8601String().substring(0, 16).replaceAll(':', '-');
    final path = await FileDialog.saveFile(
      dialogTitle: 'Save Results',
      fileName: '${safe}_Results_$ts.csv',
    );
    if (path != null) {
      await File(path).writeAsString(rows.join('\n'));
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Results exported successfully')),
        );
      }
    }
  }

  String _csv(String value) => '"${value.replaceAll('"', '""').replaceAll('\n', ' ')}"';

  String _abuseExample(Vulnerability v) {
    // Extract abuse example from description — look for payload/command hints
    final desc = v.description;
    // Try to pull out a concrete command or payload from the description
    final cmdMatch = RegExp(r'(?:e\.g\.|example:|payload:|command:)\s*([^\n.]+)', caseSensitive: false).firstMatch(desc);
    if (cmdMatch != null) return cmdMatch.group(1)?.trim() ?? desc;
    // Fall back to first sentence of description
    final firstSentence = desc.split(RegExp(r'(?<=[.!?])\s+')).first;
    return firstSentence.length > 300 ? '${firstSentence.substring(0, 300)}...' : firstSentence;
  }
}

class _ResultCard extends StatefulWidget {
  final ConfirmedResult result;
  const _ResultCard({required this.result});

  @override
  State<_ResultCard> createState() => _ResultCardState();
}

class _ResultCardState extends State<_ResultCard> {
  bool _proofExpanded = false;
  bool _stepsExpanded = false;

  @override
  Widget build(BuildContext context) {
    final r = widget.result;
    final severityColor = _severityColor(r.vuln.severity);

    return Container(
      decoration: BoxDecoration(
        color: const Color(0xFF1A1F3A),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: severityColor.withOpacity(0.4)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header row
          Padding(
            padding: const EdgeInsets.all(14),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: severityColor.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(color: severityColor.withValues(alpha: 0.5)),
                  ),
                  child: Text(r.vuln.severity,
                      style: TextStyle(color: severityColor, fontSize: 11, fontWeight: FontWeight.bold)),
                ),
                if (r.vuln.cvssScore != null) ...[
                  const SizedBox(width: 6),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0A0E27),
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(color: severityColor.withValues(alpha: 0.4)),
                    ),
                    child: Text(
                      'CVSS ${r.vuln.cvssScore!.toStringAsFixed(1)}',
                      style: TextStyle(color: severityColor, fontSize: 11, fontFamily: 'monospace'),
                    ),
                  ),
                ],
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(r.vuln.problem,
                          style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 14)),
                      const SizedBox(height: 2),
                      Row(
                        children: [
                          const Icon(Icons.location_on, color: Color(0xFF00F5FF), size: 12),
                          const SizedBox(width: 4),
                          Text(r.address,
                              style: const TextStyle(color: Color(0xFF00F5FF), fontSize: 12, fontFamily: 'monospace')),
                          if (r.vuln.cve.isNotEmpty) ...[
                            const SizedBox(width: 12),
                            Text(r.vuln.cve,
                                style: const TextStyle(color: Colors.orange, fontSize: 12)),
                          ],
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const Divider(color: Color(0xFF2A2F4A), height: 1),
          // Proof command
          if (r.proofCommand.isNotEmpty &&
              r.proofCommand != 'Initial Evidence Analysis' &&
              r.proofCommand != 'Analysis Conclusion')
            Padding(
              padding: const EdgeInsets.fromLTRB(14, 8, 14, 0),
              child: _Section(
                label: 'PROOF COMMAND',
                icon: Icons.terminal,
                iconColor: const Color(0xFFFFCC00),
                child: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF0A0E27),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: SelectableText(
                    r.proofCommand,
                    style: const TextStyle(
                        color: Color(0xFFFFCC00), fontSize: 12, fontFamily: 'monospace'),
                  ),
                ),
              ),
            ),
          // Proof description
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 10, 14, 0),
            child: _Section(
              label: 'PROOF',
              icon: Icons.verified_outlined,
              iconColor: Colors.green,
              child: Text(r.proofDescription,
                  style: const TextStyle(color: Colors.white70, fontSize: 13)),
            ),
          ),
          // Proof output (collapsible)
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 8, 14, 0),
            child: _Section(
              label: 'COMMAND OUTPUT',
              icon: Icons.terminal,
              iconColor: const Color(0xFF00F5FF),
              trailing: TextButton(
                onPressed: () => setState(() => _proofExpanded = !_proofExpanded),
                style: TextButton.styleFrom(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                  minimumSize: Size.zero,
                  tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                ),
                child: Text(_proofExpanded ? 'Collapse' : 'Expand',
                    style: const TextStyle(color: Color(0xFF00F5FF), fontSize: 11)),
              ),
              child: AnimatedCrossFade(
                duration: const Duration(milliseconds: 200),
                crossFadeState: _proofExpanded ? CrossFadeState.showSecond : CrossFadeState.showFirst,
                firstChild: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF0A0E27),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Text(
                    r.proofOutput.length > 300
                        ? '${r.proofOutput.substring(0, 300)}...'
                        : r.proofOutput,
                    style: const TextStyle(color: Colors.green, fontSize: 12, fontFamily: 'monospace'),
                    maxLines: 4,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                secondChild: Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0xFF0A0E27),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: SelectableText(
                    r.proofOutput,
                    style: const TextStyle(color: Colors.green, fontSize: 12, fontFamily: 'monospace'),
                  ),
                ),
              ),
            ),
          ),
          // Reproduction steps (shown when available)
          if (r.vuln.reproductionSteps != null && r.vuln.reproductionSteps!.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(14, 8, 14, 0),
              child: _Section(
                label: 'REPRODUCTION STEPS',
                icon: Icons.format_list_numbered,
                iconColor: const Color(0xFF00CCFF),
                trailing: TextButton(
                  onPressed: () => setState(() => _stepsExpanded = !_stepsExpanded),
                  style: TextButton.styleFrom(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                    minimumSize: Size.zero,
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  ),
                  child: Text(_stepsExpanded ? 'Collapse' : 'Expand',
                      style: const TextStyle(color: Color(0xFF00CCFF), fontSize: 11)),
                ),
                child: AnimatedCrossFade(
                  duration: const Duration(milliseconds: 200),
                  crossFadeState: _stepsExpanded ? CrossFadeState.showSecond : CrossFadeState.showFirst,
                  firstChild: Text(
                    r.vuln.reproductionSteps!.split('\n').first,
                    style: const TextStyle(color: Colors.white60, fontSize: 12),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  secondChild: SelectableText(
                    r.vuln.reproductionSteps!,
                    style: const TextStyle(color: Colors.white70, fontSize: 13, height: 1.6),
                  ),
                ),
              ),
            ),
          // Abuse example
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 8, 14, 14),
            child: _Section(
              label: 'ABUSE EXAMPLE',
              icon: Icons.warning_amber_rounded,
              iconColor: Colors.orange,
              child: Text(
                _abuseExample(r.vuln),
                style: const TextStyle(color: Colors.white70, fontSize: 13),
              ),
            ),
          ),
        ],
      ),
    );
  }

  String _abuseExample(Vulnerability v) {
    final desc = v.description;
    final cmdMatch = RegExp(r'(?:e\.g\.|example:|payload:|command:)\s*([^\n.]+)', caseSensitive: false).firstMatch(desc);
    if (cmdMatch != null) return cmdMatch.group(1)?.trim() ?? desc;
    final firstSentence = desc.split(RegExp(r'(?<=[.!?])\s+')).first;
    return firstSentence.length > 400 ? '${firstSentence.substring(0, 400)}...' : firstSentence;
  }

  Color _severityColor(String severity) => switch (severity.toUpperCase()) {
        'CRITICAL' => const Color(0xFFFF4444),
        'HIGH' => const Color(0xFFFF8800),
        'MEDIUM' => const Color(0xFFFFCC00),
        _ => const Color(0xFF44BB44),
      };
}

class _Section extends StatelessWidget {
  final String label;
  final IconData icon;
  final Color iconColor;
  final Widget child;
  final Widget? trailing;

  const _Section({
    required this.label,
    required this.icon,
    required this.iconColor,
    required this.child,
    this.trailing,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(icon, color: iconColor, size: 13),
            const SizedBox(width: 5),
            Text(label,
                style: TextStyle(
                    color: iconColor, fontSize: 11, fontWeight: FontWeight.bold, letterSpacing: 0.8)),
            if (trailing != null) ...[const Spacer(), trailing!],
          ],
        ),
        const SizedBox(height: 5),
        child,
      ],
    );
  }
}
