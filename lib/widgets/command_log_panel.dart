import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/vulnerability.dart';
import 'app_state.dart';

/// Color palette for vulnerability indicators across panels.
const vulnColors = [
  Color(0xFFFF0080), // Pink
  Color(0xFF00F5FF), // Cyan
  Color(0xFF00FF88), // Green
  Color(0xFFFFAA00), // Orange
  Color(0xFF8B5CF6), // Purple
  Color(0xFFFF6B00), // Red-Orange
  Color(0xFF00D9FF), // Light Blue
  Color(0xFFFFC700), // Yellow
];

Color getVulnColor(int index) => vulnColors[index % vulnColors.length];

class CommandLogPanel extends StatefulWidget {
  final ScrollController scrollController;
  final VoidCallback onExport;

  const CommandLogPanel({
    super.key,
    required this.scrollController,
    required this.onExport,
  });

  @override
  State<CommandLogPanel> createState() => _CommandLogPanelState();
}

class _CommandLogPanelState extends State<CommandLogPanel> {
  final _focusNode = FocusNode();
  bool _autoScroll = true;

  @override
  void dispose() {
    _focusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, state, _) {
        return Container(
          margin: const EdgeInsets.fromLTRB(8, 0, 8, 8),
          decoration: BoxDecoration(
            color: const Color(0xFF0A0E27),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
          ),
          child: Column(
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [const Color(0xFF00F5FF).withOpacity(0.1), Colors.transparent],
                  ),
                  borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.terminal, color: Color(0xFF00F5FF), size: 16),
                    const SizedBox(width: 8),
                    const Text('COMMAND LOG', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                    const Spacer(),
                    Transform.scale(
                      scale: 0.7,
                      child: Checkbox(
                        value: _autoScroll,
                        onChanged: (v) => setState(() => _autoScroll = v ?? true),
                        activeColor: const Color(0xFF00F5FF),
                      ),
                    ),
                    const Text('Auto-scroll', style: TextStyle(color: Colors.white70, fontSize: 10)),
                    const SizedBox(width: 8),
                    IconButton(
                      icon: const Icon(Icons.download, color: Color(0xFF00F5FF), size: 18),
                      onPressed: widget.onExport,
                      tooltip: 'Export Logs',
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: state.commandLogs.isEmpty
                    ? Center(
                        child: Text('No commands executed yet', style: TextStyle(color: Colors.white.withOpacity(0.3), fontSize: 12)),
                      )
                    : SelectableRegion(
                        focusNode: _focusNode,
                        selectionControls: materialTextSelectionControls,
                        child: ListView.builder(
                          controller: widget.scrollController,
                          padding: const EdgeInsets.all(8),
                          itemCount: state.commandLogs.length,
                          itemBuilder: (context, i) {
                            if (_autoScroll && i == 0) {
                              WidgetsBinding.instance.addPostFrameCallback((_) {
                                if (widget.scrollController.hasClients) {
                                  widget.scrollController.jumpTo(0);
                                }
                              });
                            }
                            final reversedIndex = state.commandLogs.length - 1 - i;
                            final log = state.commandLogs[reversedIndex];
                            final vulnIdx = log.vulnerabilityIndex ?? -1;
                            final vuln = vulnIdx >= 0 && vulnIdx < state.vulnerabilities.length ? state.vulnerabilities[vulnIdx] : null;
                            final isProof = vuln != null &&
                                ((vuln.proofCommand == log.command) ||
                                    (log.command.contains('Initial Evidence Analysis')) ||
                                    (log.command.contains('Analysis Conclusion'))) &&
                                (vuln.status == VulnerabilityStatus.confirmed || vuln.status == VulnerabilityStatus.notVulnerable);

                            final vulnColor = vulnIdx >= 0 ? getVulnColor(vulnIdx) : const Color(0xFF00F5FF);

                            return Container(
                              margin: const EdgeInsets.only(bottom: 12),
                              decoration: BoxDecoration(
                                color: isProof ? vulnColor.withOpacity(0.15) : const Color(0xFF1A1F3A).withOpacity(0.5),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(
                                  color: isProof ? vulnColor : const Color(0xFF00F5FF).withOpacity(0.2),
                                  width: isProof ? 2 : 1,
                                ),
                              ),
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                                    decoration: BoxDecoration(
                                      gradient: LinearGradient(
                                        colors: [const Color(0xFF00F5FF).withOpacity(0.2), Colors.transparent],
                                      ),
                                      borderRadius: const BorderRadius.vertical(top: Radius.circular(8)),
                                    ),
                                    child: Row(
                                      crossAxisAlignment: CrossAxisAlignment.center,
                                      children: [
                                        if (vulnIdx >= 0) ...[
                                          Container(
                                            width: 20,
                                            height: 20,
                                            decoration: BoxDecoration(
                                              color: getVulnColor(vulnIdx).withOpacity(0.2),
                                              shape: BoxShape.circle,
                                              border: Border.all(color: getVulnColor(vulnIdx), width: 1.5),
                                            ),
                                            child: Center(
                                              child: Text(
                                                '${vulnIdx + 1}',
                                                style: TextStyle(color: getVulnColor(vulnIdx), fontSize: 9, fontWeight: FontWeight.bold),
                                              ),
                                            ),
                                          ),
                                          const SizedBox(width: 6),
                                          if (isProof) ...[
                                            Icon(Icons.verified, color: vulnColor, size: 12),
                                            const SizedBox(width: 4),
                                            Text('PROOF', style: TextStyle(color: vulnColor, fontWeight: FontWeight.bold, fontSize: 8)),
                                            const SizedBox(width: 8),
                                          ],
                                        ],
                                        const Icon(Icons.terminal, color: Color(0xFF00F5FF), size: 12),
                                        const SizedBox(width: 6),
                                        Text(
                                          '[${log.timestamp.toString().substring(11, 19)}]',
                                          style: const TextStyle(color: Color(0xFF00F5FF), fontFamily: 'monospace', fontSize: 9),
                                        ),
                                        const SizedBox(width: 6),
                                        Expanded(
                                          child: Text(
                                            log.command,
                                            style: const TextStyle(
                                              color: Color(0xFF00F5FF),
                                              fontFamily: 'monospace',
                                              fontSize: 10,
                                              fontWeight: FontWeight.bold,
                                            ),
                                            maxLines: 1,
                                            overflow: TextOverflow.ellipsis,
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                  if (log.output.isNotEmpty) ...[
                                    Container(
                                      padding: const EdgeInsets.all(10),
                                      decoration: BoxDecoration(
                                        color: const Color(0xFF0A0E27).withOpacity(0.5),
                                        borderRadius: const BorderRadius.vertical(bottom: Radius.circular(8)),
                                      ),
                                      child: Column(
                                        crossAxisAlignment: CrossAxisAlignment.start,
                                        children: [
                                          Row(
                                            children: [
                                              Icon(
                                                log.exitCode == 0 ? Icons.check_circle : Icons.error,
                                                color: log.exitCode == 0 ? const Color(0xFF00FF88) : const Color(0xFFFF6B00),
                                                size: 12,
                                              ),
                                              const SizedBox(width: 6),
                                              Text(
                                                'Exit Code: ${log.exitCode}',
                                                style: TextStyle(
                                                  color: log.exitCode == 0 ? const Color(0xFF00FF88) : const Color(0xFFFF6B00),
                                                  fontSize: 9,
                                                  fontWeight: FontWeight.bold,
                                                ),
                                              ),
                                            ],
                                          ),
                                          const SizedBox(height: 6),
                                          const Divider(color: Color(0xFF00F5FF), height: 1, thickness: 0.5),
                                          const SizedBox(height: 6),
                                          Text(
                                            log.output.length > 5000
                                                ? '${log.output.substring(0, 2500)}\n\n... [${log.output.length - 5000} chars truncated] ...\n\n${log.output.substring(log.output.length - 2500)}'
                                                : log.output,
                                            style: const TextStyle(
                                              color: Color(0xFFCCCCCC),
                                              fontFamily: 'monospace',
                                              fontSize: 10,
                                              height: 1.4,
                                            ),
                                          ),
                                        ],
                                      ),
                                    ),
                                  ],
                                ],
                              ),
                            );
                          },
                        ),
                      ),
              ),
            ],
          ),
        );
      },
    );
  }
}
