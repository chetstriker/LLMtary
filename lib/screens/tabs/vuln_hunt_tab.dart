import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../models/vulnerability.dart';
import '../../widgets/app_state.dart';
import '../../widgets/vulnerability_table.dart';
import '../../widgets/stats_bar.dart';
import '../../widgets/target_progress_list.dart';
import '../../widgets/tabbed_log_panel.dart';
import 'scope_recon_tab.dart' show CompletionDialog;

class VulnHuntTab extends StatelessWidget {
  final bool isAnalyzing;
  final bool isExecuting;
  final VoidCallback onAnalyze;
  final void Function(Vulnerability, bool) onToggleSelection;
  final void Function(int) onScrollToProof;
  final Future<void> Function() onExportLogs;
  final Future<void> Function(AppState) onExportPrompts;
  final Future<void> Function(AppState) onExportDebug;
  final Set<String> analyzingAddresses;

  const VulnHuntTab({
    super.key,
    required this.isAnalyzing,
    required this.isExecuting,
    required this.onAnalyze,
    required this.onToggleSelection,
    required this.onScrollToProof,
    required this.onExportLogs,
    required this.onExportPrompts,
    required this.onExportDebug,
    this.analyzingAddresses = const {},
  });

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, appState, _) {
        final activeTargets = appState.targets
            .where((t) => t.status.name == 'complete')
            .toList();
        return Row(
          children: [
            // Left: TargetProgressList
            SizedBox(
              width: 280,
              child: TargetProgressList(
                targets: activeTargets,
                activeAddresses: analyzingAddresses,
              ),
            ),
            // Center: StatsBar + VulnerabilityTable with PulsatingButton on ANALYZE
            Expanded(
              child: Column(
                children: [
                  const StatsBar(),
                  Expanded(
                    child: _AnalyzeTableWrapper(
                      isAnalyzing: isAnalyzing,
                      isExecuting: isExecuting,
                      onAnalyze: onAnalyze,
                      onToggleSelection: onToggleSelection,
                      onScrollToProof: onScrollToProof,
                      analyzeEnabled: appState.scanComplete,
                    ),
                  ),
                ],
              ),
            ),
            // Right: TabbedLogPanel
            TabbedLogPanel(
              onExportLogs: onExportLogs,
              onExportDebug: onExportDebug,
              onExportPrompts: onExportPrompts,
            ),
          ],
        );
      },
    );
  }
}

class _AnalyzeTableWrapper extends StatelessWidget {
  final bool isAnalyzing;
  final bool isExecuting;
  final VoidCallback onAnalyze;
  final void Function(Vulnerability, bool) onToggleSelection;
  final void Function(int) onScrollToProof;
  final bool analyzeEnabled;

  const _AnalyzeTableWrapper({
    required this.isAnalyzing,
    required this.isExecuting,
    required this.onAnalyze,
    required this.onToggleSelection,
    required this.onScrollToProof,
    required this.analyzeEnabled,
  });

  @override
  Widget build(BuildContext context) {
    // Wrap the ANALYZE button area with PulsatingButton via a custom onAnalyze wrapper
    return VulnerabilityTable(
      isExecuting: isExecuting,
      onExecuteSelected: () {},
      onToggleSelection: onToggleSelection,
      onScrollToProof: onScrollToProof,
      onAnalyze: onAnalyze,
      isAnalyzing: isAnalyzing,
      analyzeEnabled: analyzeEnabled,
      executeEnabled: false,
      showExecuteButton: false,
      showCheckboxes: false,
    );
  }
}

/// Shows the analysis completion dialog. Called from _MainScreenState after _analyzeDevice completes.
void showAnalysisCompleteDialog(BuildContext context, AppState appState, int vulnCount, int targetCount) {
  showDialog(
    context: context,
    barrierDismissible: true,
    builder: (ctx) => CompletionDialog(
      title: 'Analysis Complete',
      icon: Icons.search,
      body: '$vulnCount vulnerabilities found across $targetCount target(s). Navigate to the PROOF / EXPLOIT tab, select vulnerabilities, and press EXECUTE SELECTED to continue.',
      actionLabel: 'GO TO PROOF / EXPLOIT',
      onAction: () {
        Navigator.of(ctx).pop();
        appState.setActiveTab(2);
      },
    ),
  );
}
