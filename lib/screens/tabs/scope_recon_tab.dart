import 'dart:async';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../database/database_helper.dart';
import '../../models/target.dart';
import '../../widgets/app_state.dart';
import '../../widgets/target_input_panel.dart';
import '../../services/recon_service.dart';
import '../../widgets/stats_bar.dart';
import '../../widgets/tabbed_log_panel.dart';
import '../../widgets/pulsating_button.dart';

class ScopeReconTab extends StatefulWidget {
  final bool isAnalyzing;
  final bool isExecuting;
  final Completer<String?> Function() onApprovalNeeded;
  final Future<bool> Function() onEnsurePassword;
  final Future<String?> Function(String) onInstallPasswordNeeded;
  final Future<void> Function() onExportLogs;
  final Future<void> Function(AppState) onExportPrompts;
  final Future<void> Function(AppState) onExportDebug;

  const ScopeReconTab({
    super.key,
    required this.isAnalyzing,
    required this.isExecuting,
    required this.onApprovalNeeded,
    required this.onEnsurePassword,
    required this.onInstallPasswordNeeded,
    required this.onExportLogs,
    required this.onExportPrompts,
    required this.onExportDebug,
  });

  @override
  State<ScopeReconTab> createState() => _ScopeReconTabState();
}

class _ScopeReconTabState extends State<ScopeReconTab> {
  final Set<String> _activeAddresses = {};
  final _targetPanelKey = GlobalKey<TargetInputPanelState>();
  bool _starting = false; // true for the brief gap between GO press and first UI update
  bool _scanStopped = false; // true after user presses STOP mid-scan

  // Scope field controllers — mirror ScopeConfigDialog
  late final TextEditingController _scopeCtrl;
  late final TextEditingController _exclusionsCtrl;
  late final TextEditingController _notesCtrl;

  @override
  void initState() {
    super.initState();
    _scopeCtrl = TextEditingController();
    _exclusionsCtrl = TextEditingController();
    _notesCtrl = TextEditingController();
    WidgetsBinding.instance.addPostFrameCallback((_) => _loadScope());
  }

  @override
  void dispose() {
    _scopeCtrl.dispose();
    _exclusionsCtrl.dispose();
    _notesCtrl.dispose();
    super.dispose();
  }

  void _loadScope() {
    if (!mounted) return;
    final project = context.read<AppState>().currentProject;
    if (project == null) return;
    _scopeCtrl.text = project.scope ?? '';
    _exclusionsCtrl.text = project.scopeExclusions ?? '';
    _notesCtrl.text = project.scopeNotes ?? '';
    if (mounted) setState(() {});
  }

  Future<void> _saveScope() async {
    final appState = context.read<AppState>();
    final project = appState.currentProject;
    if (project?.id == null) return;
    final scope = _scopeCtrl.text.trim().isEmpty ? null : _scopeCtrl.text.trim();
    final exclusions = _exclusionsCtrl.text.trim().isEmpty ? null : _exclusionsCtrl.text.trim();
    final notes = _notesCtrl.text.trim().isEmpty ? null : _notesCtrl.text.trim();
    await DatabaseHelper.updateProjectScope(project!.id!, scope: scope, scopeExclusions: exclusions, scopeNotes: notes);
    appState.updateCurrentProject(project.copyWith(scope: scope, scopeExclusions: exclusions, scopeNotes: notes));
  }

  void _onScopeChanged() {
    _saveScope();
    if (mounted) setState(() {}); // re-evaluate ADD TO QUEUE button visibility
  }

  Future<void> _addToQueue() async {
    final panelState = _targetPanelKey.currentState;
    if (panelState == null) return;
    final appState = context.read<AppState>();
    final allAddresses = ReconService.parseTargetInput(_scopeCtrl.text);
    final existingAddrs = appState.targets.map((t) => t.address).toSet();
    final novel = allAddresses.where((a) => !existingAddrs.contains(a)).toList();
    if (novel.isEmpty) return;
    await panelState.addAddressesToQueue(novel);
    setState(() {});
  }

  void _onScanComplete(AppState appState) {
    _activeAddresses.clear();
    final done = appState.targets.where((t) => t.status == TargetStatus.complete).length;
    _showCompletionDialog(appState, done);
  }

  void _showCompletionDialog(AppState appState, int count) {
    final hasTargets = count > 0;
    showDialog(
      context: context,
      barrierDismissible: true,
      builder: (ctx) => CompletionDialog(
        title: hasTargets ? 'Recon Complete' : 'Recon Finished',
        icon: hasTargets ? Icons.radar : Icons.info_outline,
        body: hasTargets
            ? '$count active target(s) discovered. Navigate to the VULN / HUNT tab and press ANALYZE to continue.'
            : 'Recon finished but no active targets were found. All hosts may be down, filtered, or excluded. Check the debug log for details.',
        actionLabel: hasTargets ? 'GO TO VULN / HUNT' : 'OK',
        onAction: () {
          Navigator.of(ctx).pop();
          if (hasTargets) appState.setActiveTab(1);
        },
      ),
    );
    if (hasTargets) {
      // Auto-advance after 5 seconds
      Future.delayed(const Duration(seconds: 5), () {
        if (mounted) appState.setActiveTab(1);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, appState, _) {
        final hasTargets = appState.targets.isNotEmpty ||
            _scopeCtrl.text.trim().isNotEmpty;
        final panelState = _targetPanelKey.currentState;
        final isScanning = panelState?.isScanning ?? false;
        return Row(
          children: [
            // Left panel: project name + scope fields (+ GO button when scanning)
            Flexible(
              flex: 2,
              child: Column(
                children: [
                  Expanded(
                    child: _ScopePanel(
                      projectName: appState.currentProjectName,
                      scopeCtrl: _scopeCtrl,
                      exclusionsCtrl: _exclusionsCtrl,
                      notesCtrl: _notesCtrl,
                      onChanged: _onScopeChanged,
                      onPickFile: () async {
                        await panelState?.pickFileIntoController(_scopeCtrl);
                        _saveScope();
                        setState(() {});
                      },
                      isScanning: isScanning,
                      hasTargets: hasTargets,
                      isExecuting: widget.isExecuting,
                      isAnalyzing: widget.isAnalyzing,
                      scanStopped: _scanStopped,
                      showAddToQueue: !isScanning &&
                          _scopeCtrl.text.trim().isNotEmpty &&
                          ReconService.parseTargetInput(_scopeCtrl.text)
                              .any((a) => !appState.targets.map((t) => t.address).contains(a)),
                      onGo: () {
                        setState(() {
                          _starting = true;
                          _scanStopped = false;
                        });
                        _targetPanelKey.currentState?.startScan(_scopeCtrl.text);
                      },
                      onStop: () {
                        setState(() {
                          _starting = false;
                          _scanStopped = true;
                        });
                        _targetPanelKey.currentState?.stopScan();
                      },
                      onAddToQueue: _addToQueue,
                    ),
                  ),
                  // Hidden TargetInputPanel — holds scan logic, renders nothing
                  TargetInputPanel(
                    key: _targetPanelKey,
                    llmSettings: appState.llmSettings,
                    requireApproval: appState.requireApproval,
                    adminPassword: appState.adminPassword,
                    scopeNotes: appState.currentProject?.scopeNotes,
                    onPasswordNeeded: widget.onEnsurePassword,
                    onInstallPasswordNeeded: widget.onInstallPasswordNeeded,
                    onApprovalNeeded: (command) async {
                        if (!appState.requireApproval) return 'once';
                        final completer = widget.onApprovalNeeded();
                        appState.setPendingCommand(command);
                        return await completer.future;
                      },
                    onProgress: (msg) {
                      appState.addDebugLog(msg);
                      final match = RegExp(r'^\[([^\]]+)\]').firstMatch(msg);
                      if (match != null) {
                        setState(() => _activeAddresses.add(match.group(1)!));
                      }
                    },
                    onPromptResponse: (p, r) => appState.addPromptLog(p, r),
                    onCommandExecuted: (cmd, output) async => await appState.loadCommandLogs(),
                    onTargetsDiscovered: (targets) async {
                      if (_starting && mounted) setState(() => _starting = false);
                      await appState.setTargets(targets);
                    },
                    onTargetDeleted: (target) => appState.deleteTarget(target),
                    onScanComplete: () {
                      if (mounted) setState(() => _starting = false);
                      appState.setScanComplete(true);
                      _onScanComplete(appState);
                    },
                    targets: appState.targets,
                    existingTargets: appState.targets,
                    selectedTarget: appState.selectedTarget,
                    onTargetSelected: (t) => appState.selectTarget(t),
                    projectName: appState.currentProjectName,
                    projectId: appState.currentProject?.id ?? 0,
                    getTargetId: (addr) => appState.targets
                        .firstWhere((t) => t.address == addr, orElse: () => Target(address: addr))
                        .id ?? 0,
                  ),
                ],
              ),
            ),
            // Center: StatsBar + ReconCenterPanel
            Flexible(
              flex: 5,
              child: Column(
                children: [
                  StatsBar(
                    extraCard: Consumer<AppState>(
                      builder: (context, state, _) {
                        final reconComplete = state.targets
                            .where((t) => t.status == TargetStatus.complete)
                            .length;
                        return StatCard(
                          label: 'RECON COMPLETE',
                          value: reconComplete,
                          color: const Color(0xFF3DFFA0),
                          icon: Icons.check_circle_outline,
                        );
                      },
                    ),
                  ),
                  Expanded(
                    child: _ReconCenterPanel(
                      targets: appState.targets,
                      activeAddresses: _activeAddresses,
                      isScanning: isScanning,
                      starting: _starting,
                      hasTargets: hasTargets,
                      isDisabled: widget.isExecuting || widget.isAnalyzing,
                      onGo: () {
                        setState(() {
                          _starting = true;
                          _scanStopped = false;
                        });
                        _targetPanelKey.currentState?.startScan(_scopeCtrl.text);
                      },
                      onRetry: (addr) {
                        final panelState = _targetPanelKey.currentState;
                        if (panelState == null) return;
                        panelState.retryTarget(addr);
                        if (!panelState.isScanning) {
                          // Show RESUME so the user knows to kick off the queue.
                          setState(() => _scanStopped = true);
                        }
                      },
                    ),
                  ),
                ],
              ),
            ),
            // Right panel: TabbedLogPanel
            Flexible(
              flex: 2,
              child: TabbedLogPanel(
                onExportLogs: widget.onExportLogs,
                onExportDebug: widget.onExportDebug,
                onExportPrompts: widget.onExportPrompts,
              ),
            ),
          ],
        );
      },
    );
  }
}

/// Inline scope configuration panel — surfaces the three scope fields directly
/// without requiring the user to open a dialog.
class _ScopePanel extends StatelessWidget {
  final String projectName;
  final TextEditingController scopeCtrl;
  final TextEditingController exclusionsCtrl;
  final TextEditingController notesCtrl;
  final VoidCallback onChanged;
  final VoidCallback onPickFile;
  final bool isScanning;
  final bool hasTargets;
  final bool isExecuting;
  final bool isAnalyzing;
  final bool scanStopped;
  final bool showAddToQueue;
  final VoidCallback onGo;
  final VoidCallback? onStop;
  final VoidCallback? onAddToQueue;
  static const _purple = Color(0xFF7C5CFC);
  static const _hint = Color(0xFF8892B0);
  static const _card = Color(0xFF161929);
  static const _dark = Color(0xFF0D0F1A);

  const _ScopePanel({
    required this.projectName,
    required this.scopeCtrl,
    required this.exclusionsCtrl,
    required this.notesCtrl,
    required this.onChanged,
    required this.onPickFile,
    required this.isScanning,
    required this.hasTargets,
    required this.isExecuting,
    required this.isAnalyzing,
    required this.scanStopped,
    required this.showAddToQueue,
    required this.onGo,
    this.onStop,
    this.onAddToQueue,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.fromLTRB(8, 8, 8, 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _card,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: _purple.withValues(alpha: 0.18)),
      ),
      child: SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Project name at top of left panel
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
              margin: const EdgeInsets.only(bottom: 12),
              decoration: BoxDecoration(
                color: _purple.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: _purple.withValues(alpha: 0.25)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.folder_open, color: _purple, size: 14),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      projectName,
                      style: const TextStyle(
                          color: Colors.white,
                          fontWeight: FontWeight.w700,
                          fontSize: 13,
                          letterSpacing: 0.3),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
            ),
            Row(
              children: [
                const Icon(Icons.shield_outlined, color: _purple, size: 14),
                const SizedBox(width: 6),
                const Expanded(
                  child: Text('IN-SCOPE TARGETS',
                      style: TextStyle(
                          color: _purple,
                          fontWeight: FontWeight.bold,
                          fontSize: 10,
                          letterSpacing: 1)),
                ),
                Tooltip(
                  message: 'Import addresses from a .txt file\n(one address per line)',
                  child: IconButton(
                    onPressed: isScanning ? null : onPickFile,
                    icon: const Icon(Icons.upload_file, size: 16, color: _purple),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 24, minHeight: 24),
                    splashRadius: 16,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            _field(scopeCtrl,
                'IPs, hostnames, CIDRs\ne.g. 192.168.1.0/24\n*.example.com\ncomma or newline separated',
                5),
            if (showAddToQueue) ...[
              const SizedBox(height: 8),
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: onAddToQueue,
                  icon: const Icon(Icons.playlist_add, size: 16, color: _purple),
                  label: const Text('ADD TO QUEUE',
                      style: TextStyle(
                          color: _purple,
                          fontWeight: FontWeight.bold,
                          fontSize: 12,
                          letterSpacing: 0.8)),
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    side: BorderSide(color: _purple.withValues(alpha: 0.5)),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10)),
                  ),
                ),
              ),
            ],
            const SizedBox(height: 16),
            _label('EXCLUSIONS'),
            const SizedBox(height: 6),
            _field(exclusionsCtrl, 'e.g. 192.168.1.100\nprod.example.com', 3),
            const SizedBox(height: 16),
            _label('RULES OF ENGAGEMENT'),
            const SizedBox(height: 6),
            _field(notesCtrl, 'e.g. No DoS, business hours only', 3),
            // Bottom action button: STOP while scanning, RESUME after stop
            if (isScanning) ...[
              const SizedBox(height: 14),
              Center(
                child: SizedBox(
                  width: 140,
                  height: 44,
                  child: ElevatedButton.icon(
                    onPressed: onStop,
                    icon: const Icon(Icons.stop, color: Colors.white, size: 16),
                    label: const Text('STOP',
                        style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 13)),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red.withValues(alpha: 0.7),
                      padding: const EdgeInsets.symmetric(vertical: 10),
                    ),
                  ),
                ),
              ),
            ] else if (scanStopped) ...[
              const SizedBox(height: 14),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: ElevatedButton.icon(
                  onPressed: onGo,
                  icon: const Icon(Icons.play_arrow_rounded, color: Colors.white, size: 18),
                  label: const Text('RESUME RECON',
                      style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _purple,
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _label(String text) => Text(text,
      style: const TextStyle(color: _hint, fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 0.8));

  Widget _field(TextEditingController ctrl, String hint, int minLines) => TextField(
    controller: ctrl,
    minLines: minLines,
    maxLines: minLines + 2,
    onChanged: (_) => onChanged(),
    style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontSize: 12),
    decoration: InputDecoration(
      hintText: hint,
      hintStyle: TextStyle(color: _hint.withValues(alpha: 0.4), fontSize: 11),
      filled: true,
      fillColor: _dark,
      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 14),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide(color: _purple.withValues(alpha: 0.2))),
      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide(color: _purple.withValues(alpha: 0.15))),
      focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide(color: _purple.withValues(alpha: 0.5))),
    ),
  );
}

// ---------------------------------------------------------------------------
// Center panel: target list + live command/debug feed
// ---------------------------------------------------------------------------

class _ReconCenterPanel extends StatelessWidget {
  final List<Target> targets;
  final Set<String> activeAddresses;
  final bool isScanning;
  final bool starting;
  final bool hasTargets;
  final bool isDisabled;
  final VoidCallback onGo;
  final void Function(String address)? onRetry;

  static const _purple = Color(0xFF7C5CFC);

  const _ReconCenterPanel({
    required this.targets,
    required this.activeAddresses,
    required this.isScanning,
    required this.starting,
    required this.hasTargets,
    required this.isDisabled,
    required this.onGo,
    this.onRetry,
  });

  @override
  Widget build(BuildContext context) {
    // Brief starting state: GO was pressed but targets not yet discovered
    if (targets.isEmpty && starting && !isScanning) {
      return _DottedBackground(
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const SizedBox(
                width: 52,
                height: 52,
                child: CircularProgressIndicator(color: _purple, strokeWidth: 3),
              ),
              const SizedBox(height: 20),
              const Text('STARTING RECON…',
                  style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w700, letterSpacing: 2)),
              const SizedBox(height: 8),
              const Text('Resolving targets and launching scans',
                  style: TextStyle(color: Colors.white38, fontSize: 12)),
            ],
          ),
        ),
      );
    }

    // Idle state: show dotted background with centered GO button
    if (targets.isEmpty && !isScanning) {
      return _DottedBackground(
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: _purple.withValues(alpha: 0.1),
                  shape: BoxShape.circle,
                  border: Border.all(color: _purple.withValues(alpha: 0.3), width: 1.5),
                ),
                child: const Icon(Icons.radar, color: _purple, size: 48),
              ),
              const SizedBox(height: 20),
              const Text(
                'READY TO SCAN',
                style: TextStyle(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 2),
              ),
              const SizedBox(height: 8),
              const Text(
                'Enter targets in the left panel and press GO',
                style: TextStyle(color: Colors.white38, fontSize: 13),
              ),
              const SizedBox(height: 32),
              SizedBox(
                width: 160,
                height: 52,
                child: Stack(
                  children: [
                    SizedBox.expand(
                      child: ElevatedButton.icon(
                        onPressed: isDisabled ? null : onGo,
                        icon: const Icon(Icons.play_arrow_rounded, color: Colors.white, size: 22),
                        label: const Text('GO',
                            style: TextStyle(
                                color: Colors.white,
                                fontWeight: FontWeight.w800,
                                fontSize: 16,
                                letterSpacing: 2)),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: _purple,
                          disabledBackgroundColor: _purple.withValues(alpha: 0.3),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                          elevation: 8,
                          shadowColor: _purple.withValues(alpha: 0.5),
                        ),
                      ),
                    ),
                    Positioned.fill(
                      child: IgnorePointer(
                        child: PulsatingButton(
                          active: hasTargets && !isDisabled,
                          child: const SizedBox.expand(),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      );
    }

    return Consumer<AppState>(
      builder: (context, appState, _) {
        final lastCommand = appState.commandLogs.isNotEmpty
            ? appState.commandLogs.last.command
            : null;
        final lastDebug = appState.debugLogs.isNotEmpty
            ? appState.debugLogs.last.message
            : null;

        return _DottedBackground(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1100),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    // Live feed — shown ABOVE the host list
                    if (lastCommand != null || lastDebug != null)
                      Padding(
                        padding: const EdgeInsets.only(bottom: 16),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            if (lastDebug != null) ...[
                              Text(
                                _extractPhase(lastDebug),
                                style: const TextStyle(
                                    color: _purple,
                                    fontSize: 15,
                                    fontWeight: FontWeight.bold,
                                    letterSpacing: 1.2),
                              ),
                              const SizedBox(height: 12),
                            ],
                            if (lastCommand != null) ...[
                              Text('CMD',
                                  style: TextStyle(
                                      color: _purple.withValues(alpha: 0.7),
                                      fontSize: 10,
                                      fontWeight: FontWeight.bold,
                                      letterSpacing: 1.2)),
                              const SizedBox(height: 4),
                              Text(
                                lastCommand,
                                style: const TextStyle(
                                    color: Colors.white,
                                    fontFamily: 'monospace',
                                    fontSize: 13,
                                    fontWeight: FontWeight.w600),
                                maxLines: 3,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ],
                            if (lastCommand != null && lastDebug != null)
                              const SizedBox(height: 12),
                            if (lastDebug != null) ...[
                              Text('STATUS',
                                  style: TextStyle(
                                      color: _purple.withValues(alpha: 0.7),
                                      fontSize: 10,
                                      fontWeight: FontWeight.bold,
                                      letterSpacing: 1.2)),
                              const SizedBox(height: 4),
                              Text(
                                lastDebug,
                                style: const TextStyle(
                                    color: Colors.white70,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w500),
                                maxLines: 3,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ],
                          ],
                        ),
                      ),
                    // Target cards — multi-column wrap based on available width
                    LayoutBuilder(
                      builder: (context, constraints) {
                        final availableWidth = constraints.maxWidth;
                        // Use 2+ columns when there's enough space
                        final columnCount = availableWidth > 900 ? 3
                            : availableWidth > 560 ? 2
                            : 1;
                        if (columnCount == 1) {
                          return Column(
                            children: targets.map((t) => _TargetRow(
                              target: t,
                              isActive: activeAddresses.contains(t.address),
                              onRetry: onRetry != null ? () => onRetry!(t.address) : null,
                            )).toList(),
                          );
                        }
                        // Multi-column: distribute targets across columns
                        final colWidth = (availableWidth - (columnCount - 1) * 12) / columnCount;
                        final cols = List.generate(columnCount, (_) => <Target>[]);
                        for (var i = 0; i < targets.length; i++) {
                          cols[i % columnCount].add(targets[i]);
                        }
                        return Row(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            for (var c = 0; c < columnCount; c++) ...[
                              if (c > 0) const SizedBox(width: 12),
                              SizedBox(
                                width: colWidth,
                                child: Column(
                                  children: cols[c].map((t) => _TargetRow(
                                    target: t,
                                    isActive: activeAddresses.contains(t.address),
                                    onRetry: onRetry != null ? () => onRetry!(t.address) : null,
                                  )).toList(),
                                ),
                              ),
                            ],
                          ],
                        );
                      },
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  /// Derives a short human-readable phase label from a recon progress message.
  static String _extractPhase(String msg) {
    final body = msg.replaceFirst(RegExp(r'^\[[^\]]+\]\s*'), '').toLowerCase();

    if (body.contains('osint') || body.contains('certificate transparency') ||
        body.contains('whois') || body.contains('shodan') || body.contains('github')) {
      return 'PASSIVE OSINT';
    }
    if (body.contains('host pre-sweep') || body.contains('nmap -sn') ||
        body.contains('pre-sweep') || body.contains('hosts are up') ||
        body.contains('checking which')) {
      return 'HOST DISCOVERY';
    }
    if (body.contains('baseline') || body.contains('top port scan') ||
        body.contains('host liveness') || body.contains('fast fallback')) {
      return 'BASELINE SCAN';
    }
    if (body.contains('ssl') || body.contains('tls') || body.contains('certificate')) {
      return 'SSL / TLS ANALYSIS';
    }
    if (body.contains('smb') || body.contains('netbios')) {
      return 'SMB ENUMERATION';
    }
    if (body.contains('dns') || body.contains('zone transfer') || body.contains('subdomain')) {
      return 'DNS ENUMERATION';
    }
    if (body.contains('snmp')) {
      return 'SNMP ENUMERATION';
    }
    if (body.contains('ldap') || body.contains('active directory') || body.contains('kerberos')) {
      return 'ACTIVE DIRECTORY';
    }
    if (body.contains('web') || body.contains('http') || body.contains('header') ||
        body.contains('fingerprint') || body.contains('directory') || body.contains('path')) {
      return 'WEB FINGERPRINTING';
    }
    if (body.contains('port scan') || body.contains('nmap') || body.contains('scanning')) {
      return 'PORT SCANNING';
    }
    if (body.contains('parsing output') || body.contains('merging') || body.contains('extracting')) {
      return 'PARSING OUTPUT';
    }
    if (body.contains('iteration')) {
      // Extract iteration number if present
      final iterMatch = RegExp(r'iteration (\d+)').firstMatch(body);
      if (iterMatch != null) return 'LLM ANALYSIS  ·  ITERATION ${iterMatch.group(1)}';
      return 'LLM ANALYSIS';
    }
    if (body.contains('running:')) {
      return 'EXECUTING COMMAND';
    }
    if (body.contains('concluded') || body.contains('excluded') || body.contains('saved findings')) {
      return 'FINALIZING';
    }
    return 'RECONNAISSANCE';
  }
}

class _TargetRow extends StatefulWidget {
  final Target target;
  final bool isActive;
  final VoidCallback? onRetry;

  const _TargetRow({required this.target, required this.isActive, this.onRetry});

  @override
  State<_TargetRow> createState() => _TargetRowState();
}

class _TargetRowState extends State<_TargetRow>
    with SingleTickerProviderStateMixin {
  late final AnimationController _pulse;
  late final Animation<double> _glow;

  static const _purple = Color(0xFF7C5CFC);
  static const _card = Color(0xFF161929);

  @override
  void initState() {
    super.initState();
    _pulse = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    )..repeat(reverse: true);
    _glow = Tween<double>(begin: 0.2, end: 0.8).animate(
      CurvedAnimation(parent: _pulse, curve: Curves.easeInOut),
    );
  }

  @override
  void dispose() {
    _pulse.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isActive = widget.isActive;
    final isExcluded = widget.target.status == TargetStatus.excluded;

    return AnimatedBuilder(
      animation: _glow,
      builder: (context, _) {
        final borderColor = isActive
            ? _purple.withValues(alpha: _glow.value)
            : _purple.withValues(alpha: 0.1);
        return Opacity(
          opacity: isExcluded ? 0.4 : 1.0,
          child: Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
            decoration: BoxDecoration(
              color: _card,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: borderColor, width: isActive ? 1.5 : 1.0),
              boxShadow: isActive
                  ? [BoxShadow(color: _purple.withValues(alpha: _glow.value * 0.3), blurRadius: 8)]
                  : null,
            ),
            child: Row(
              children: [
                if (isActive)
                  Padding(
                    padding: const EdgeInsets.only(right: 8),
                    child: SizedBox(
                      width: 12,
                      height: 12,
                      child: CircularProgressIndicator(
                        strokeWidth: 1.5,
                        color: _purple.withValues(alpha: _glow.value),
                      ),
                    ),
                  ),
                Expanded(
                  child: Text(
                    widget.target.address,
                    style: TextStyle(
                      color: isExcluded ? Colors.white38 : Colors.white,
                      fontFamily: 'monospace',
                      fontSize: 15,
                      fontWeight: FontWeight.w600,
                      decoration: isExcluded ? TextDecoration.lineThrough : null,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                _statusChip(widget.target),
                if (widget.target.status == TargetStatus.pending &&
                    widget.onRetry != null) ...[
                  const SizedBox(width: 4),
                  Tooltip(
                    message: 'Perform recon again',
                    child: IconButton(
                      onPressed: widget.onRetry,
                      icon: const Icon(Icons.refresh, size: 16, color: _purple),
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(minWidth: 24, minHeight: 24),
                    ),
                  ),
                ],
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _statusChip(Target target) {
    final (label, color) = switch (target.status) {
      TargetStatus.complete when target.executionComplete => ('DONE', const Color(0xFF3DFFA0)),
      TargetStatus.complete when target.analysisComplete => ('ANALYZED', _purple),
      TargetStatus.complete => ('SCANNED', const Color(0xFF3DFFA0)),
      TargetStatus.scanning => ('SCANNING', _purple),
      TargetStatus.excluded => ('EXCLUDED', Colors.white38),
      _ => ('PENDING', Colors.white24),
    };
    if (target.noFindings == true && target.status == TargetStatus.complete) {
      return _chip('NO FINDINGS', Colors.white38);
    }
    return _chip(label, color);
  }

  Widget _chip(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Text(label,
          style: TextStyle(
              color: color,
              fontSize: 10,
              fontWeight: FontWeight.bold,
              letterSpacing: 0.5)),
    );
  }
}

// ---------------------------------------------------------------------------
// Dotted background painter for center panels
// ---------------------------------------------------------------------------

class _DottedBackground extends StatelessWidget {
  final Widget child;
  const _DottedBackground({required this.child});

  @override
  Widget build(BuildContext context) {
    return CustomPaint(
      painter: _DotPainter(),
      child: child,
    );
  }
}

class _DotPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    const spacing = 28.0;
    const radius = 1.2;
    final paint = Paint()..color = const Color(0xFF1E2235);
    for (double x = spacing / 2; x < size.width; x += spacing) {
      for (double y = spacing / 2; y < size.height; y += spacing) {
        canvas.drawCircle(Offset(x, y), radius, paint);
      }
    }
  }

  @override
  bool shouldRepaint(_DotPainter old) => false;
}

// ---------------------------------------------------------------------------
// Shared completion dialog used by all three tabs
// ---------------------------------------------------------------------------

class CompletionDialog extends StatelessWidget {
  final String title;
  final IconData icon;
  final String body;
  final String actionLabel;
  final VoidCallback onAction;

  const CompletionDialog({
    super.key,
    required this.title,
    required this.icon,
    required this.body,
    required this.actionLabel,
    required this.onAction,
  });

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: const Color(0xFF161929),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: const Color(0xFF3DFFA0).withValues(alpha: 0.1),
                shape: BoxShape.circle,
              ),
              child: Icon(icon, color: const Color(0xFF3DFFA0), size: 40),
            ),
            const SizedBox(height: 16),
            Text(title, style: const TextStyle(color: Color(0xFF7C5CFC), fontSize: 20, fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            Text(body, style: const TextStyle(color: Colors.white70, fontSize: 14), textAlign: TextAlign.center),
            const SizedBox(height: 24),
            Container(
              decoration: BoxDecoration(
                gradient: const LinearGradient(colors: [Color(0xFF7C5CFC), Color(0xFF5B8DEF)]),
                borderRadius: BorderRadius.circular(10),
              ),
              child: ElevatedButton(
                onPressed: onAction,
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.transparent,
                  shadowColor: Colors.transparent,
                  padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 14),
                ),
                child: Text(actionLabel, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
