import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../utils/file_dialog.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/credential.dart';
import '../models/llm_provider.dart';
import '../models/target.dart';
import '../services/vulnerability_analyzer.dart';
import '../services/exploit_executor.dart';
import '../services/command_executor.dart';
import '../database/database_helper.dart';
import 'settings_screen.dart';
import '../widgets/app_state.dart';
import '../widgets/admin_password_dialog.dart';
import '../widgets/command_approval_widget.dart';
import '../widgets/results_modal.dart';
import '../utils/app_exceptions.dart';
import '../services/storage_service.dart';
import '../services/prompt_templates.dart';
import '../services/llm_service.dart';
import 'tabs/scope_recon_tab.dart';
import 'tabs/vuln_hunt_tab.dart' show VulnHuntTab, showAnalysisCompleteDialog;
import 'tabs/proof_exploit_tab.dart' show ProofExploitTab, showExecutionCompleteDialog;
import 'tabs/result_report_tab.dart';

class MainScreen extends StatefulWidget {
  const MainScreen({super.key});

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {
  bool _isAnalyzing = false;
  bool _isExecuting = false;
  final _logScrollController = ScrollController();
  Completer<String?>? _approvalCompleter;
  final Set<String> _analyzingAddresses = {};
  final Set<String> _executingAddresses = {};

  void _scrollToProof(int vulnIdx) async {
    final appState = context.read<AppState>();
    appState.addDebugLog('Scroll to proof requested for vulnerability #${vulnIdx + 1}');

    final logIndex = appState.commandLogs.indexWhere((log) {
      if (log.vulnerabilityIndex != vulnIdx) return false;
      final vuln = appState.vulnerabilities[vulnIdx];
      return (vuln.proofCommand == log.command) ||
          (log.command.contains('Initial Evidence Analysis')) ||
          (log.command.contains('Analysis Conclusion'));
    });

    if (logIndex == -1) {
      appState.addDebugLog('ERROR: No proof log found for vulnerability #${vulnIdx + 1}');
      return;
    }

    final itemHeight = 150.0;
    final targetOffset = logIndex * itemHeight;

    appState.addDebugLog('Scrolling to proof at index $logIndex for vulnerability #${vulnIdx + 1}');

    if (_logScrollController.hasClients) {
      await _logScrollController.animateTo(
        targetOffset.clamp(0.0, _logScrollController.position.maxScrollExtent),
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
      );
      appState.addDebugLog('Successfully scrolled to proof for vulnerability #${vulnIdx + 1}');
    } else {
      appState.addDebugLog('ERROR: Scroll controller not attached');
    }
  }

  @override
  void initState() {
    super.initState();
  }

  Future<bool> _ensureSessionPassword() async {
    final appState = context.read<AppState>();
    if (appState.sessionPasswordEntered) return true;
    final password = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const AdminPasswordDialog(),
    );
    if (password == null || password.isEmpty) return false;
    appState.setAdminPassword(password);
    return true;
  }

  /// Called mid-scan when a tool needs sudo and no cached credentials exist.
  /// Shows the password dialog, saves to appState, and returns the password.
  Future<String?> _onInstallPasswordNeeded(String prompt) async {
    final appState = context.read<AppState>();
    if (appState.sessionPasswordEntered) return appState.adminPassword;
    final password = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const AdminPasswordDialog(),
    );
    if (password == null || password.isEmpty) return null;
    appState.setAdminPassword(password);
    return password;
  }

  @override
  void dispose() {
    _logScrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D0F1A),
      appBar: _buildAppBar(),
      body: Stack(
        children: [
          Consumer<AppState>(
            builder: (context, appState, _) => AnimatedSwitcher(
              duration: const Duration(milliseconds: 180),
              child: IndexedStack(
                key: ValueKey(appState.activeTab),
                index: appState.activeTab,
              children: [
                ScopeReconTab(
                  isAnalyzing: _isAnalyzing,
                  isExecuting: _isExecuting,
                  onApprovalNeeded: () {
                    _approvalCompleter = Completer<String?>();
                    return _approvalCompleter!;
                  },
                  onEnsurePassword: _ensureSessionPassword,
                  onInstallPasswordNeeded: _onInstallPasswordNeeded,
                  onExportLogs: _exportLogs,
                  onExportPrompts: _exportPrompts,
                  onExportDebug: _exportDebug,
                ),
                VulnHuntTab(
                  isAnalyzing: _isAnalyzing,
                  isExecuting: _isExecuting,
                  onAnalyze: _analyzeDevice,
                  onToggleSelection: _toggleSelection,
                  onScrollToProof: _scrollToProof,
                  onExportLogs: _exportLogs,
                  onExportPrompts: _exportPrompts,
                  onExportDebug: _exportDebug,
                  analyzingAddresses: _analyzingAddresses,
                ),
                ProofExploitTab(
                  isAnalyzing: _isAnalyzing,
                  isExecuting: _isExecuting,
                  onExecuteSelected: _executeSelected,
                  onToggleSelection: _toggleSelection,
                  onScrollToProof: _scrollToProof,
                  onExportLogs: _exportLogs,
                  onExportPrompts: _exportPrompts,
                  onExportDebug: _exportDebug,
                  executingAddresses: _executingAddresses,
                ),
                const ResultReportTab(),
              ],
            ),
            ),
          ),
          // Execution status toast — bottom-center overlay
          Consumer<AppState>(
            builder: (context, appState, _) {
              final status = appState.executionStatus;
              return AnimatedSlide(
                offset: status.isEmpty ? const Offset(0, 1.5) : Offset.zero,
                duration: const Duration(milliseconds: 220),
                curve: Curves.easeOut,
                child: AnimatedOpacity(
                  opacity: status.isEmpty ? 0.0 : 1.0,
                  duration: const Duration(milliseconds: 180),
                  child: Align(
                    alignment: Alignment.bottomCenter,
                    child: Padding(
                      padding: const EdgeInsets.only(bottom: 16),
                      child: Container(
                        constraints: const BoxConstraints(maxWidth: 680),
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 9),
                        decoration: BoxDecoration(
                          color: const Color(0xFF0D0F1A),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: const Color(0xFFFFBB33).withValues(alpha: 0.6)),
                          boxShadow: [
                            BoxShadow(color: const Color(0xFFFFBB33).withValues(alpha: 0.12), blurRadius: 12, spreadRadius: 1),
                            BoxShadow(color: Colors.black.withValues(alpha: 0.5), blurRadius: 8),
                          ],
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const SizedBox(
                              width: 10,
                              height: 10,
                              child: CircularProgressIndicator(color: Color(0xFFFFBB33), strokeWidth: 1.5),
                            ),
                            const SizedBox(width: 10),
                            Flexible(
                              child: Text(
                                status,
                                style: const TextStyle(color: Color(0xFFFFBB33), fontSize: 11, fontFamily: 'monospace'),
                                overflow: TextOverflow.ellipsis,
                                maxLines: 1,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              );
            },
          ),
          _buildApprovalOverlay(),
        ],
      ),
    );
  }

  AppBar _buildAppBar() {
    return AppBar(
      backgroundColor: const Color(0xFF0A0C16),
      elevation: 0,
      toolbarHeight: 52,
      leading: IconButton(
        icon: const Icon(Icons.arrow_back, color: Color(0xFF7C5CFC)),
        onPressed: () {
          context.read<AppState>().setCurrentProject(null);
          Navigator.of(context).pop();
        },
        tooltip: 'Back to projects',
      ),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(7),
            decoration: BoxDecoration(
              gradient: const LinearGradient(colors: [Color(0xFF7C5CFC), Color(0xFF5B8DEF)]),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.security, color: Colors.white, size: 18),
          ),
          const SizedBox(width: 10),
          const Text('PenExecute',
              style: TextStyle(
                  color: Colors.white,
                  fontWeight: FontWeight.w700,
                  fontSize: 16,
                  letterSpacing: 0.5)),
          const SizedBox(width: 28),
          // Tab bar
          Flexible(
            child: Consumer<AppState>(
              builder: (context, state, _) => Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  _tabButton(state, 0, 'SCOPE / RECON'),
                  _tabButton(state, 1, 'VULN / HUNT'),
                  _tabButton(state, 2, 'PROOF / EXPLOIT'),
                  _tabButton(state, 3, 'RESULT / REPORT'),
                ],
              ),
            ),
          ),
        ],
      ),
      actions: [
        const SizedBox(width: 8),
        Container(
          margin: const EdgeInsets.symmetric(vertical: 8),
          padding: const EdgeInsets.symmetric(horizontal: 12),
          decoration: BoxDecoration(
            color: const Color(0xFF0D0F1A),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: const Color(0xFF7C5CFC).withValues(alpha: 0.3)),
          ),
          child: Row(
            children: [
              const Icon(Icons.verified_user, color: Color(0xFF7C5CFC), size: 16),
              const SizedBox(width: 8),
              const Text('Require Approval', style: TextStyle(color: Colors.white70, fontSize: 12)),
              const SizedBox(width: 8),
              Transform.scale(
                scale: 0.8,
                child: Switch(
                  value: context.watch<AppState>().requireApproval,
                  onChanged: (v) => context.read<AppState>().setRequireApproval(v),
                  activeThumbColor: const Color(0xFF7C5CFC),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(width: 8),
        IconButton(
          icon: const Icon(Icons.settings, color: Color(0xFF7C5CFC)),
          onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const SettingsScreen())),
        ),
        const SizedBox(width: 8),
      ],
    );
  }

  Widget _tabButton(AppState state, int index, String label) {
    final labels = ['SCOPE / RECON', 'VULN / HUNT', 'PROOF / EXPLOIT', 'RESULT / REPORT'];
    final unlocked = [state.tab1Unlocked, state.tab2Unlocked, state.tab3Unlocked, state.tab4Unlocked][index];
    final isActive = state.activeTab == index;
    return GestureDetector(
      onTap: unlocked ? () => state.setActiveTab(index) : null,
      child: _TabShape(
        isActive: isActive,
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (!unlocked) const Icon(Icons.lock, size: 10, color: Colors.white24),
            if (!unlocked) const SizedBox(width: 4),
            Text(
              labels[index],
              style: TextStyle(
                color: isActive ? Colors.white : unlocked ? Colors.white54 : Colors.white24,
                fontSize: 11,
                fontWeight: isActive ? FontWeight.w700 : FontWeight.w500,
                letterSpacing: 0.8,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildApprovalOverlay() {
    return Consumer<AppState>(
      builder: (context, state, _) {
        if (state.pendingCommand != null && _approvalCompleter != null) {
          return Positioned(
            bottom: 0,
            left: 0,
            right: 0,
            child: Center(
              child: CommandApprovalWidget(
                command: state.pendingCommand!,
                onAllowOnce: () {
                  _approvalCompleter?.complete('once');
                  _approvalCompleter = null;
                  state.setPendingCommand(null);
                },
                onAlwaysAllow: () {
                  _approvalCompleter?.complete('always');
                  _approvalCompleter = null;
                  state.setPendingCommand(null);
                },
                onDeny: () {
                  _approvalCompleter?.complete('deny');
                  _approvalCompleter = null;
                  state.setPendingCommand(null);
                },
              ),
            ),
          );
        }
        return const SizedBox.shrink();
      },
    );
  }

  // --- Business logic ---

  Future<void> _analyzeDevice() async {
    if (!await _ensureSessionPassword()) return;
    setState(() => _isAnalyzing = true);
    try {
      final appState = context.read<AppState>();

      if (appState.llmSettings.provider == LLMProvider.none) {
        throw const ConfigurationException('Please configure AI settings first');
      }
      if (appState.llmSettings.modelName.isEmpty) {
        throw const ConfigurationException('Please select a model in settings');
      }
      if (appState.llmSettings.provider.requiresBaseUrl && (appState.llmSettings.baseUrl == null || appState.llmSettings.baseUrl!.isEmpty)) {
        throw const ConfigurationException('Please configure base URL in settings');
      }
      if (appState.llmSettings.provider.requiresApiKey && (appState.llmSettings.apiKey == null || appState.llmSettings.apiKey!.isEmpty)) {
        throw const ConfigurationException('Please configure API key in settings');
      }

      final completedTargets = appState.targets.where((t) => t.status == TargetStatus.complete).toList();
      if (completedTargets.isEmpty) {
        throw const ConfigurationException('No scanned targets available to analyze');
      }

      // Only analyze targets not yet analyzed
      final targetsToAnalyze = completedTargets.where((t) => !t.analysisComplete).toList();
      if (targetsToAnalyze.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('All targets already analyzed')),
        );
        setState(() => _isAnalyzing = false);
        return;
      }

      // Record first analysis timestamp (only on first run for this project)
      final project = appState.currentProject;
      if (project?.id != null && project!.firstAnalysisAt == null) {
        final now = DateTime.now();
        await DatabaseHelper.updateProjectFirstAnalysis(project.id!, now);
        appState.updateCurrentProject(project.copyWith(firstAnalysisAt: now));
      }

      int analyzed = 0;
      // Phase A.1: Run up to 3 targets in parallel; process in batches.
      // Phase 6.1: Accumulate network context across batches for cross-target knowledge.
      // Context from completed batches feeds into subsequent batches (sequential order
      // within a batch uses the context available at batch start).
      const int analysisParallelism = 3;
      String sharedNetworkContext = '';

      for (int batchStart = 0; batchStart < targetsToAnalyze.length; batchStart += analysisParallelism) {
        final batch = targetsToAnalyze.skip(batchStart).take(analysisParallelism).toList();

        // A.2: Mark all batch targets as analyzing before firing futures
        for (final t in batch) {
          if (mounted) setState(() => _analyzingAddresses.add(t.address));
        }

        // Snapshot context at batch start — all targets in this batch share it.
        // Updated context from this batch feeds into the next batch.
        final batchNetworkContext = sharedNetworkContext;

        // Run all targets in this batch concurrently
        final batchResults = await Future.wait(
          batch.map((target) async {
            // A.2: Prefix status messages with target address for clarity in parallel runs
            appState.addDebugLog('[${target.address}] Starting vulnerability analysis...');
            appState.setExecutionStatus('[${target.address}] Analyzing...');
            try {
              final deviceJson = await File(target.jsonFilePath).readAsString();

              final analyzer = VulnerabilityAnalyzer(
                onPromptResponse: (prompt, response) {
                  appState.addPromptLog(prompt, response);
                },
                onTokensUsed: (sent, received) {
                  appState.recordTokenUsage('analyze', sent, received, targetId: target.id ?? 0);
                },
              );
              final vulns = await analyzer.analyzeDevice(
                deviceJson,
                appState.llmSettings,
                confirmedFindingsContext: appState.confirmedFindingsPromptBlock(target.address),
                networkContext: batchNetworkContext.isNotEmpty ? batchNetworkContext : null,
                onPhaseChange: (phase) => appState.setExecutionStatus('[${target.address}] $phase'),
                scopeList: appState.currentProject?.scopeList ?? [],
                exclusionList: appState.currentProject?.exclusionList ?? [],
              );

              appState.addDebugLog('[${target.address}] Found ${vulns.length} vulnerabilities');
              return (target: target, vulns: vulns, error: null as Object?);
            } on ScopeViolationException catch (e) {
              appState.addDebugLog('[${target.address}] Scope violation: $e — skipping');
              return (target: target, vulns: <Vulnerability>[], error: e as Object?);
            } catch (e) {
              appState.addDebugLog('[${target.address}] Analysis error (skipping): $e');
              return (target: target, vulns: <Vulnerability>[], error: e as Object?);
            }
          }),
        );

        // Process results sequentially (DB writes, state updates) after all futures complete
        for (final result in batchResults) {
          final target = result.target;
          final vulns = result.vulns;
          final error = result.error;

          if (mounted) setState(() => _analyzingAddresses.remove(target.address));

          if (error != null) {
            final msg = error is ScopeViolationException
                ? '[${target.address}] Out of scope: $error'
                : '[${target.address}] Analysis error (skipped): $error';
            if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
            continue;
          }

          if (vulns.isEmpty) {
            appState.addDebugLog('[${target.address}] Analysis complete: 0 findings');
            target.noFindings = true;
          } else {
            target.noFindings = false;
          }
          for (final v in vulns) {
            v.targetAddress = target.address;
            v.targetId = target.id;
            v.projectId = appState.currentProject?.id;
            await DatabaseHelper.insertVulnerability(v);
          }

          target.analysisComplete = true;
          await DatabaseHelper.updateTarget(target);
          analyzed++;

          // Phase 6.1: Accumulate network context from this target's findings
          final targetDeviceJson = await File(target.jsonFilePath).readAsString();
          final targetNetContext = VulnerabilityAnalyzer.extractNetworkContext(vulns, targetDeviceJson);
          if (targetNetContext.isNotEmpty) {
            sharedNetworkContext = sharedNetworkContext.isEmpty
                ? targetNetContext
                : '$sharedNetworkContext\n$targetNetContext';
            if (sharedNetworkContext.length > 3000) {
              sharedNetworkContext = sharedNetworkContext.substring(0, 3000);
            }
          }
        }

        appState.loadVulnerabilities();
        if (mounted) setState(() {});
      }

      appState.setAnalysisComplete(true);
      appState.setExecutionStatus('');
      if (mounted) {
        final totalVulns = appState.vulnerabilities.length;
        showAnalysisCompleteDialog(context, appState, totalVulns, analyzed);
      }
    } catch (e) {
      context.read<AppState>().addDebugLog('Error: $e');
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Error: $e')));
    } finally {
      setState(() => _isAnalyzing = false);
    }
  }

  void _toggleSelection(Vulnerability v, bool selected) {
    v.selected = selected;
    setState(() {});
  }

  Future<void> _executeSelected() async {
    if (!await _ensureSessionPassword()) return;
    final appState = context.read<AppState>();
    appState.addDebugLog('Execute Selected button clicked');

    final selected = appState.vulnerabilities.where((v) => v.selected).toList();
    appState.addDebugLog('Found ${selected.length} selected vulnerabilities');

    if (selected.isEmpty) {
      appState.addDebugLog('No vulnerabilities selected - aborting execution');
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please select at least one vulnerability to test')),
      );
      return;
    }

    // Filter out vulns whose target already has executionComplete
    final targetMap = {for (final t in appState.targets) t.address: t};
    final toExecute = selected.where((v) {
      final t = targetMap[v.targetAddress];
      return t == null || !t.executionComplete;
    }).toList();

    // Also skip individual vulns that already have a non-pending status
    final pendingVulns = toExecute.where((v) => v.status == VulnerabilityStatus.pending).toList();

    if (pendingVulns.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('All selected vulnerabilities already executed')),
      );
      return;
    }

    setState(() => _isExecuting = true);

    // --- Pre-flight checks (run once before all vulnerabilities) ---
    CommandExecutor.clearAllCaches();

    appState.addDebugLog('Running metasploit preflight check...');
    await ExploitExecutor.preflightMetasploit();
    appState.addDebugLog('Metasploit available: ${ExploitExecutor.metasploitAvailable}');

    try {
      final selectedTarget = appState.selectedTarget;
      if (selectedTarget != null) {
        final deviceJson = await File(selectedTarget.jsonFilePath).readAsString();
        await _bannerGrabUnknownPorts(deviceJson, appState);
      }
    } catch (e) {
      appState.addDebugLog('Banner grab preflight error: $e');
    }

    // Phase B.1: Group pending vulnerabilities by target address.
    // Each target's vulns will be run sequentially (to avoid port/auth contention
    // on the same host). Different targets run in parallel (up to 3 at a time).
    final vulnsByTarget = <String, List<Vulnerability>>{};
    for (final vuln in pendingVulns) {
      vulnsByTarget.putIfAbsent(vuln.targetAddress, () => []).add(vuln);
    }
    final targetAddresses = vulnsByTarget.keys.toList();

    // Phase B.2: Process batches of up to 3 targets in parallel.
    const int executionParallelism = 3;

    for (int batchStart = 0; batchStart < targetAddresses.length; batchStart += executionParallelism) {
      final batchAddrs = targetAddresses.skip(batchStart).take(executionParallelism).toList();

      // B.3: Mark all batch targets as executing before starting futures
      for (final addr in batchAddrs) {
        if (mounted) setState(() => _executingAddresses.add(addr));
      }

      // B.4: Show which targets are being tested in parallel
      final batchSummary = batchAddrs.map((a) {
        final count = vulnsByTarget[a]!.length;
        return '$a ($count vuln${count == 1 ? '' : 's'})';
      }).join(', ');
      appState.setExecutionStatus('Testing ${batchAddrs.length} target(s): $batchSummary');
      appState.addDebugLog('Phase B: Starting parallel execution — $batchSummary');

      // Run all targets in this batch concurrently; within each target, vulns are sequential
      await Future.wait(
        batchAddrs.map((targetAddr) async {
          final targetVulns = vulnsByTarget[targetAddr]!;

          for (final vuln in targetVulns) {
            // Lookup index each time (stable within the batch — loadVulnerabilities
            // is only called after the batch completes)
            final vulnIdx = appState.vulnerabilities.indexWhere((v) => v.id == vuln.id);
            if (vulnIdx == -1) {
              appState.addDebugLog('[${vuln.targetAddress}] Cannot find vuln id=${vuln.id} — skipping');
              continue;
            }
            appState.addDebugLog('[${vuln.targetAddress}] Testing: ${vuln.problem}');

            try {
              final targetForVulnLookup = appState.targets.firstWhere(
                (t) => t.address == vuln.targetAddress,
                orElse: () => appState.selectedTarget ?? appState.targets.first,
              );
              final deviceJson = targetForVulnLookup.jsonFilePath.isNotEmpty &&
                      await File(targetForVulnLookup.jsonFilePath).exists()
                  ? await File(targetForVulnLookup.jsonFilePath).readAsString()
                  : '{}';

              final vulnOutputDir = StorageService.toShellPath(
                await StorageService.getTargetPath(
                  appState.currentProjectName, targetForVulnLookup.address));

              final executor = ExploitExecutor(
                deviceData: deviceJson,
                vulnerabilityIndex: vulnIdx,
                outputDir: vulnOutputDir,
                onProgress: (msg) => appState.addDebugLog(msg),
                onCommandExecuted: (cmd, output, idx) async {
                  appState.addDebugLog('[${vuln.targetAddress}] Command: $cmd');
                  await appState.loadCommandLogs();
                  if (mounted) setState(() {});
                },
                onPromptResponse: (prompt, response) {
                  appState.addPromptLog(prompt, response);
                },
                onTokensUsed: (sent, received) {
                  final tid = appState.targets
                      .firstWhere((t) => t.address == vuln.targetAddress,
                          orElse: () => appState.selectedTarget ?? appState.targets.first)
                      .id ?? 0;
                  appState.recordTokenUsage('execute', sent, received, targetId: tid);
                },
                adminPassword: appState.adminPassword,
                onApprovalNeeded: (command) async {
                  if (!appState.requireApproval) return 'once';
                  _approvalCompleter = Completer<String?>();
                  appState.setPendingCommand(command);
                  return await _approvalCompleter!.future;
                },
                onPasswordNeeded: _onInstallPasswordNeeded,
                credentialBankContext: appState.credentialBankPromptBlock(vuln.targetAddress),
                confirmedFindingsContext: appState.confirmedFindingsPromptBlock(vuln.targetAddress),
                onCredentialsFound: (credMaps) {
                  // B.3: Credentials found on one target are immediately visible
                  // to subsequent vulns on that target (sequential within target)
                  for (final m in credMaps) {
                    final srcName = m['credentialSource'] ?? 'inferred';
                    final src = CredentialSource.values.firstWhere(
                      (e) => e.name == srcName,
                      orElse: () => CredentialSource.inferred,
                    );
                    appState.addCredential(DiscoveredCredential(
                      service: m['service'] ?? '',
                      host: m['host'] ?? vuln.targetAddress,
                      username: m['username'] ?? '',
                      secret: m['secret'] ?? '',
                      secretType: m['secretType'] ?? 'password',
                      sourceVuln: vuln.problem,
                      discoveredAt: DateTime.now(),
                      credentialSource: src,
                    ));
                  }
                },
                onPhaseUpdate: (iter, max, phase) {
                  // B.4: Include target address so parallel progress is distinguishable
                  final title = vuln.problem.length > 30
                      ? '${vuln.problem.substring(0, 30)}…'
                      : vuln.problem;
                  appState.setExecutionStatus(
                      '[${vuln.targetAddress}] $title: Iter $iter/$max — $phase');
                },
              );

              final targetId = appState.targets
                  .firstWhere((t) => t.address == vuln.targetAddress,
                      orElse: () => appState.selectedTarget ?? appState.targets.first)
                  .id ?? 0;
              final status = await executor.testVulnerability(
                vuln, appState.llmSettings, appState.requireApproval,
                projectId: appState.currentProject?.id ?? 0,
                targetId: targetId,
              );
              vuln.status = status;

              // B.4: Update overall completion count immediately as each vuln finishes
              appState.addDebugLog(
                  '[${vuln.targetAddress}] ${vuln.problem}: $status');

              // 2.4: Feed confirmed artifacts into subsequent tests for this target
              if (status == VulnerabilityStatus.confirmed) {
                appState.addConfirmedArtifact(vuln);
                // 2.7: Post-exploitation enumeration for high-value access
                final vtype = vuln.vulnerabilityType.toLowerCase();
                final vproblem = vuln.problem.toLowerCase();
                final isHighValueAccess = vtype.contains('rce') ||
                    vtype.contains('remote code') ||
                    vtype.contains('auth bypass') ||
                    vtype.contains('default credentials') ||
                    vtype.contains('command injection') ||
                    vproblem.contains('rce') ||
                    vproblem.contains('remote code execution') ||
                    vproblem.contains('command injection') ||
                    vproblem.contains('authentication bypass') ||
                    vproblem.contains('default credential');
                final postExploitAlreadyQueued = appState.vulnerabilities.any((v) =>
                    v.targetAddress == vuln.targetAddress &&
                    v.problem.startsWith('Post-Exploitation Enumeration'));
                if (isHighValueAccess && !postExploitAlreadyQueued) {
                  final postExploit = Vulnerability(
                    problem: 'Post-Exploitation Enumeration (via ${vuln.problem})',
                    description:
                        'A confirmed ${vuln.vulnerabilityType} was obtained against this target. '
                        'This pseudo-vulnerability drives post-exploitation enumeration to demonstrate '
                        'the full impact of the access achieved.\n\n'
                        'Objectives:\n'
                        '- Enumerate local users, groups, and privilege context\n'
                        '- Identify network interfaces, routes, and adjacent hosts\n'
                        '- Discover running services and listening ports\n'
                        '- Find readable files containing credentials, keys, or configuration\n'
                        '- Identify paths to privilege escalation if not already at highest privilege\n'
                        '- Document what an attacker could achieve from this foothold',
                    severity: 'CRITICAL',
                    confidence: 'HIGH',
                    evidence: 'Confirmed access via: ${vuln.problem}',
                    recommendation:
                        'Patch the confirmed vulnerability that granted access. Apply principle of least '
                        'privilege to limit what an attacker can enumerate post-compromise.',
                    vulnerabilityType: 'Privilege Escalation',
                    attackVector: vuln.attackVector,
                    attackComplexity: 'LOW',
                    privilegesRequired: 'LOW',
                    userInteraction: 'NONE',
                    scope: 'CHANGED',
                    confidentialityImpact: 'HIGH',
                    integrityImpact: 'HIGH',
                    availabilityImpact: 'HIGH',
                    targetAddress: vuln.targetAddress,
                    targetId: vuln.targetId,
                    projectId: vuln.projectId,
                    status: VulnerabilityStatus.pending,
                    selected: true,
                  );
                  await DatabaseHelper.insertVulnerability(postExploit);
                }
              }
              await DatabaseHelper.updateVulnerability(vuln);
            } catch (e) {
              appState.addDebugLog('[${vuln.problem}] Execution error (skipping): $e');
              if (mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(content: Text('[${vuln.targetAddress}] Execution error (skipped): $e')),
                );
              }
            }
          } // end sequential per-target loop
        }), // end per-target future
      ); // end Future.wait batch

      // After the batch completes: reload state, update UI, remove from executing set
      for (final addr in batchAddrs) {
        if (mounted) setState(() => _executingAddresses.remove(addr));
      }
      final selectedStates = {for (var v in appState.vulnerabilities) v.id: v.selected};
      await appState.loadVulnerabilities();
      for (var v in appState.vulnerabilities) {
        v.selected = selectedStates[v.id] ?? false;
      }
      await appState.loadCommandLogs();
      if (mounted) setState(() {});
    } // end batch loop

    // Phase 36.3: Post-execution exploit chain reasoning pass
    final confirmedVulns = appState.vulnerabilities
        .where((v) => v.status == VulnerabilityStatus.confirmed &&
            v.vulnerabilityType != 'AttackChain')
        .toList();
    if (confirmedVulns.length >= 2) {
      try {
        appState.setExecutionStatus('Reasoning about attack chains...');
        final llmService = LLMService(onPromptResponse: (p, r) => appState.addPromptLog(p, r));
        final chainPrompt = PromptTemplates.exploitChainReasoningPrompt(confirmedVulns);
        final chainResponse = await llmService.sendMessage(appState.llmSettings, chainPrompt);
        final chainVulns = VulnerabilityAnalyzer().parseChainResponse(chainResponse);
        final projectId = appState.currentProject?.id ?? 0;
        for (final cv in chainVulns) {
          final inserted = cv..projectId = projectId;
          final id = await DatabaseHelper.insertVulnerability(inserted);
          appState.addDebugLog('Added attack chain finding (id=$id): ${cv.problem}');
        }
        if (chainVulns.isNotEmpty) await appState.loadVulnerabilities();
      } catch (e) {
        appState.addDebugLog('Chain reasoning pass failed (non-fatal): $e');
      }
    }

    // Mark executionComplete on targets whose vulns were all just run
    final executedAddresses = pendingVulns.map((v) => v.targetAddress).toSet();
    for (final addr in executedAddresses) {
      final target = targetMap[addr];
      if (target != null) {
        final remaining = appState.vulnerabilities
            .where((v) => v.targetAddress == addr && v.status == VulnerabilityStatus.pending)
            .length;
        if (remaining == 0) {
          target.executionComplete = true;
          await DatabaseHelper.updateTarget(target);
        }
      }
    }

    // Record last execution timestamp
    final execProject = appState.currentProject;
    if (execProject?.id != null) {
      final now = DateTime.now();
      await DatabaseHelper.updateProjectLastExecution(execProject!.id!, now);
      appState.updateCurrentProject(execProject.copyWith(lastExecutionAt: now));
    }

    // Phase 1: Authenticated re-analysis — if new verified credentials were
    // discovered during execution, run a second analysis pass with auth context
    // for any targets that haven't been re-analyzed yet.
    if (appState.hasVerifiedCredentials) {
      for (final addr in executedAddresses) {
        if (!appState.hasAuthenticatedReanalysis(addr)) {
          await _runAuthenticatedReanalysis(appState, addr);
        }
      }
    }

    appState.setExecutionStatus('');
    setState(() { _isExecuting = false; _executingAddresses.clear(); });

    final confirmedCount = appState.vulnerabilities.where((v) => v.status == VulnerabilityStatus.confirmed).length;
    if (mounted) {
      showExecutionCompleteDialog(context, appState, confirmedCount, pendingVulns.length);
    }

    appState.setHasResults(true);
    if (mounted) _showResults(appState);
  }

  /// Phase 1: Runs a second VulnerabilityAnalyzer pass for [targetAddress]
  /// with the discovered credential bank injected as authenticated context.
  /// New findings are de-duplicated by problem name against existing vulns.
  Future<void> _runAuthenticatedReanalysis(AppState appState, String targetAddress) async {
    try {
      final target = appState.targets.firstWhere(
        (t) => t.address == targetAddress,
        orElse: () => throw StateError('target not found'),
      );
      if (target.jsonFilePath.isEmpty || !await File(target.jsonFilePath).exists()) return;

      appState.markAuthenticatedReanalysis(targetAddress);
      appState.setExecutionStatus('Authenticated re-analysis: $targetAddress...');
      appState.addDebugLog('Starting authenticated re-analysis for $targetAddress');

      final deviceJson = await File(target.jsonFilePath).readAsString();
      final analyzer = VulnerabilityAnalyzer(
        onPromptResponse: (p, r) => appState.addPromptLog(p, r),
        onTokensUsed: (sent, received) {
          appState.recordTokenUsage('analyze', sent, received);
        },
      );
      final authVulns = await analyzer.analyzeDevice(
        deviceJson,
        appState.llmSettings,
        credentialContext: appState.authenticatedContextBlock(),
        confirmedFindingsContext: appState.confirmedFindingsPromptBlock(targetAddress),
        scopeList: appState.currentProject?.scopeList ?? [],
        exclusionList: appState.currentProject?.exclusionList ?? [],
      );

      // Only persist findings whose problem doesn't already exist for this target
      final existingProblems = appState.vulnerabilities
          .where((v) => v.targetAddress == targetAddress)
          .map((v) => v.problem.toLowerCase().trim())
          .toSet();

      int added = 0;
      for (final v in authVulns) {
        if (existingProblems.contains(v.problem.toLowerCase().trim())) continue;
        v.targetAddress = targetAddress;
        v.targetId = target.id;
        v.projectId = appState.currentProject?.id;
        await DatabaseHelper.insertVulnerability(v);
        added++;
      }
      appState.addDebugLog('Authenticated re-analysis added $added new findings for $targetAddress');
      if (added > 0) await appState.loadVulnerabilities();
    } catch (e) {
      appState.addDebugLog('Authenticated re-analysis failed (non-fatal): $e');
    }
  }

  void _showResults(AppState appState) {
    final target = appState.selectedTarget;
    ResultsModal.show(
      context,
      appState.vulnerabilities,
      appState.commandLogs,
      target?.address ?? 'unknown',
      projectName: appState.currentProject?.name ?? 'PenExecute',
    );
  }

  /// Banner-grab ports with unknown/unidentified services before vulnerability testing.
  Future<void> _bannerGrabUnknownPorts(String deviceJson, AppState appState) async {
    try {
      final decoded = await Future(() {
        try { return (Map<String, dynamic>.from(Map.from(jsonDecode(deviceJson)))); } catch (_) { return null; }
      });
      if (decoded == null) return;

      final ports = (decoded['open_ports'] as List?) ?? [];
      final unknownPorts = <int>[];
      for (final p in ports) {
        final service = (p['service'] ?? '').toString().toLowerCase();
        final product = (p['product'] ?? '').toString();
        if ((service.isEmpty || service == 'unknown' || service == 'tcpwrapped') && product.isEmpty) {
          final port = p['port'];
          if (port is int) unknownPorts.add(port);
        }
      }

      if (unknownPorts.isEmpty) return;

      appState.addDebugLog('Banner-grabbing ${unknownPorts.length} unknown ports: ${unknownPorts.join(", ")}');
      final ip = decoded['device']?['ip_address'] ?? '';
      if (ip.isEmpty) return;

      // Batch nmap banner grab for all unknown ports at once
      final portList = unknownPorts.join(',');
      final cmd = 'nmap -sV --version-intensity 5 -p $portList $ip';
      final result = await CommandExecutor.executeCommand(cmd, false)
          .timeout(const Duration(seconds: 60));
      final output = (result['output'] ?? '').toString();
      appState.addDebugLog('Banner grab results:\n$output');

      final log = CommandLog(
        timestamp: DateTime.now(),
        command: cmd,
        output: output,
        exitCode: result['exitCode'] ?? -1,
        vulnerabilityIndex: -1,
      );
      await DatabaseHelper.insertCommandLog(log);
      await appState.loadCommandLogs();
    } catch (e) {
      appState.addDebugLog('Banner grab error: $e');
    }
  }

  /// Build a filesystem-safe export filename with project name, type, and timestamp.
  static String _buildExportFileName(String projectName, String exportType, String ext) {
    final safe = projectName.replaceAll(RegExp(r'[^\w\-]'), '_');
    final ts = DateTime.now().toIso8601String().substring(0, 16).replaceAll(':', '-');
    return '${safe}_${exportType}_$ts.$ext';
  }

  Future<void> _exportLogs() async {
    final appState = context.read<AppState>();
    final logs = appState.commandLogs;
    if (logs.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No command logs to export')),
      );
      return;
    }
    final content = logs.map((l) =>
      '[${l.timestamp.toString().substring(0, 19)}] Exit:${l.exitCode}\n'
      '> ${l.command}\n'
      '${l.output}'
    ).join('\n---\n\n');
    final projectName = appState.currentProject?.name ?? 'PenExecute';
    final path = await FileDialog.saveFile(
      dialogTitle: 'Save Command Logs',
      fileName: _buildExportFileName(projectName, 'CommandLogs', 'txt'),
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }

  Future<void> _exportPrompts(AppState state) async {
    final content = state.promptLogs.map((log) => '=== PROMPT ===\n${log.prompt}\n\n=== RESPONSE ===\n${log.response}\n').join('\n---\n\n');
    final projectName = state.currentProject?.name ?? 'PenExecute';
    final path = await FileDialog.saveFile(
      dialogTitle: 'Save Prompts',
      fileName: _buildExportFileName(projectName, 'PromptLogs', 'txt'),
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }

  Future<void> _exportDebug(AppState state) async {
    final content = state.debugLogs.map((log) => '[${log.timestamp.toString().substring(11, 19)}] ${log.message}').join('\n');
    final projectName = state.currentProject?.name ?? 'PenExecute';
    final path = await FileDialog.saveFile(
      dialogTitle: 'Save Debug Log',
      fileName: _buildExportFileName(projectName, 'DebugLogs', 'txt'),
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }

}

/// Custom tab shape: rectangle with a right-side triangular notch for the active tab.
class _TabShape extends StatelessWidget {
  final bool isActive;
  final Widget child;

  const _TabShape({required this.isActive, required this.child});

  @override
  Widget build(BuildContext context) {
    if (!isActive) {
      return Container(
        margin: const EdgeInsets.only(right: 2),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        child: child,
      );
    }
    return Container(
      margin: const EdgeInsets.only(right: 2),
      child: ClipPath(
        clipper: _TabClipper(),
        child: Container(
          color: const Color(0xFF7C5CFC).withValues(alpha: 0.18),
          padding: const EdgeInsets.only(left: 14, right: 22, top: 8, bottom: 8),
          child: child,
        ),
      ),
    );
  }
}

class _TabClipper extends CustomClipper<Path> {
  @override
  Path getClip(Size size) {
    const notch = 10.0;
    final path = Path()
      ..moveTo(0, 0)
      ..lineTo(size.width - notch, 0)
      ..lineTo(size.width, size.height / 2)
      ..lineTo(size.width - notch, size.height)
      ..lineTo(0, size.height)
      ..close();
    return path;
  }

  @override
  bool shouldReclip(_TabClipper old) => false;
}
