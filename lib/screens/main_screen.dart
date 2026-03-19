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
import '../services/report_generator.dart';
import '../services/command_executor.dart';
import '../database/database_helper.dart';
import 'settings_screen.dart';
import '../widgets/app_state.dart';
import '../widgets/admin_password_dialog.dart';
import '../widgets/command_approval_widget.dart';
import '../widgets/target_input_panel.dart';
import '../widgets/prompt_log_panel.dart';
import '../widgets/debug_log_panel.dart';
import '../widgets/command_log_panel.dart';
import '../widgets/vulnerability_table.dart';
import '../widgets/results_modal.dart';
import '../utils/app_exceptions.dart';
import '../services/storage_service.dart';

class MainScreen extends StatefulWidget {
  const MainScreen({super.key});

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {
  bool _isAnalyzing = false;
  bool _isExecuting = false;
  final _logScrollController = ScrollController();
  bool _showLeftPanel = true;
  bool _showRightPanel = true;
  double _vulnTableHeight = 250;
  Completer<String?>? _approvalCompleter;

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
      backgroundColor: const Color(0xFF0A0E27),
      appBar: _buildAppBar(),
      body: Stack(
        children: [
          Row(
            children: [
              if (_showLeftPanel)
                SizedBox(
                  width: 350,
                  child: Column(
                    children: [
                      Flexible(
                        child: Consumer<AppState>(
                        builder: (context, appState, _) => TargetInputPanel(
                          llmSettings: appState.llmSettings,
                          requireApproval: appState.requireApproval,
                          adminPassword: appState.adminPassword,
                          onPasswordNeeded: () => _ensureSessionPassword(),
                          onInstallPasswordNeeded: _onInstallPasswordNeeded,
                          onApprovalNeeded: appState.requireApproval
                              ? (command) async {
                                  _approvalCompleter = Completer<String?>();
                                  appState.setPendingCommand(command);
                                  return await _approvalCompleter!.future;
                                }
                              : null,
                          onProgress: (msg) => appState.addDebugLog(msg),
                          onPromptResponse: (p, r) => appState.addPromptLog(p, r),
                          onCommandExecuted: (cmd, output) async {
                            await appState.loadCommandLogs();
                          },
                          onTargetsDiscovered: (targets) async => await appState.setTargets(targets),
                          onTargetDeleted: (target) => appState.deleteTarget(target),
                          onScanComplete: () => appState.setScanComplete(true),
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
                      ),),
                      Flexible(child: PromptLogPanel(onExport: _exportPrompts)),
                    ],
                  ),
                ),
              Expanded(
                child: Column(
                  children: [
                    SizedBox(
                      height: _vulnTableHeight,
                      child: Consumer<AppState>(
                        builder: (context, appState, _) => VulnerabilityTable(
                          isExecuting: _isExecuting,
                          onExecuteSelected: _executeSelected,
                          onToggleSelection: _toggleSelection,
                          onScrollToProof: _scrollToProof,
                          onAnalyze: _analyzeDevice,
                          isAnalyzing: _isAnalyzing,
                          analyzeEnabled: appState.scanComplete,
                          executeEnabled: appState.analysisComplete,
                        ),
                      ),
                    ),
                    _buildResizeHandle(),
                    Expanded(
                      child: CommandLogPanel(
                        scrollController: _logScrollController,
                        onExport: _exportLogs,
                      ),
                    ),
                  ],
                ),
              ),
              if (_showRightPanel)
                SizedBox(
                  width: 350,
                  child: DebugLogPanel(onExport: _exportDebug),
                ),
            ],
          ),
          _buildApprovalOverlay(),
          _buildPanelToggleButtons(),
        ],
      ),
    );
  }

  AppBar _buildAppBar() {
    final appState = context.read<AppState>();
    return AppBar(
      backgroundColor: const Color(0xFF1A1F3A),
      elevation: 0,
      leading: IconButton(
        icon: const Icon(Icons.arrow_back, color: Color(0xFF00F5FF)),
        onPressed: () {
          context.read<AppState>().setCurrentProject(null);
          Navigator.of(context).pop();
        },
        tooltip: 'Back to projects',
      ),
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              gradient: const LinearGradient(colors: [Color(0xFF00F5FF), Color(0xFF0080FF)]),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.security, color: Colors.white, size: 20),
          ),
          const SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('PenExecute', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 18)),
              Text(appState.currentProjectName, style: const TextStyle(color: Color(0xFF00F5FF), fontSize: 11)),
            ],
          ),
        ],
      ),
      actions: [
        // 6.1: Execution status badge — shows current iteration/phase during testing
        Consumer<AppState>(
          builder: (context, appState, _) {
            final status = appState.executionStatus;
            if (status.isEmpty) return const SizedBox.shrink();
            return Container(
              margin: const EdgeInsets.symmetric(vertical: 10),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(
                color: const Color(0xFF0A0E27),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: const Color(0xFFFFAA00).withOpacity(0.6)),
              ),
              child: Text(status, style: const TextStyle(color: Color(0xFFFFAA00), fontSize: 10, fontFamily: 'monospace')),
            );
          },
        ),
        const SizedBox(width: 8),
        // 6.3: Credentials button — shows count badge and opens panel
        Consumer<AppState>(
          builder: (context, appState, _) {
            final count = appState.credentials.length;
            if (count == 0) return const SizedBox.shrink();
            return TextButton.icon(
              icon: const Icon(Icons.key, size: 16, color: Color(0xFF00FF88)),
              label: Text('CREDS ($count)', style: const TextStyle(color: Color(0xFF00FF88), fontSize: 12, fontWeight: FontWeight.bold, letterSpacing: 0.8)),
              onPressed: () => _showCredentials(appState),
            );
          },
        ),
        const SizedBox(width: 4),
        Container(
          margin: const EdgeInsets.symmetric(vertical: 8),
          padding: const EdgeInsets.symmetric(horizontal: 12),
          decoration: BoxDecoration(
            color: const Color(0xFF0A0E27),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
          ),
          child: Row(
            children: [
              const Icon(Icons.verified_user, color: Color(0xFF00F5FF), size: 16),
              const SizedBox(width: 8),
              const Text('Require Approval', style: TextStyle(color: Colors.white70, fontSize: 12)),
              const SizedBox(width: 8),
              Transform.scale(
                scale: 0.8,
                child: Switch(
                  value: context.watch<AppState>().requireApproval,
                  onChanged: (v) {
                    context.read<AppState>().setRequireApproval(v);
                  },
                  activeThumbColor: const Color(0xFF00F5FF),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(width: 12),
        Consumer<AppState>(
          builder: (context, appState, _) => TextButton.icon(
            icon: Icon(
              Icons.bar_chart,
              size: 16,
              color: appState.hasResults ? const Color(0xFF00F5FF) : Colors.white24,
            ),
            label: Text(
              'RESULTS',
              style: TextStyle(
                color: appState.hasResults ? const Color(0xFF00F5FF) : Colors.white24,
                fontSize: 12,
                fontWeight: FontWeight.bold,
                letterSpacing: 0.8,
              ),
            ),
            onPressed: appState.hasResults
                ? () => _showResults(appState)
                : null,
          ),
        ),
        const SizedBox(width: 4),
        Consumer<AppState>(
          builder: (context, appState, _) => PopupMenuButton<String>(
            enabled: appState.hasResults,
            tooltip: 'Export Report',
            icon: Icon(
              Icons.download,
              size: 20,
              color: appState.hasResults ? const Color(0xFF00F5FF) : Colors.white24,
            ),
            onSelected: (format) => _exportReport(appState, format),
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'html', child: Text('Export HTML Report')),
              PopupMenuItem(value: 'md',   child: Text('Export Markdown Report')),
              PopupMenuItem(value: 'csv',  child: Text('Export CSV (Findings)')),
            ],
          ),
        ),
        const SizedBox(width: 4),
        IconButton(
          icon: const Icon(Icons.settings, color: Color(0xFF00F5FF)),
          onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const SettingsScreen())),
        ),
        const SizedBox(width: 8),
      ],
    );
  }

  Widget _buildResizeHandle() {
    return GestureDetector(
      onVerticalDragUpdate: (details) {
        setState(() {
          _vulnTableHeight = (_vulnTableHeight + details.delta.dy).clamp(150.0, 600.0);
        });
      },
      child: MouseRegion(
        cursor: SystemMouseCursors.resizeRow,
        child: Container(
          height: 8,
          color: Colors.transparent,
          alignment: Alignment.center,
          child: Container(
            width: 200,
            height: 8,
            decoration: BoxDecoration(
              color: const Color(0xFF00F5FF).withOpacity(0.1),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: const Color(0xFF00F5FF),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
          ),
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

  Widget _buildPanelToggleButtons() {
    return Stack(
      children: [
        Positioned(
          left: 14,
          bottom: 14,
          child: FloatingActionButton(
            heroTag: 'toggleLeft',
            mini: true,
            backgroundColor: const Color(0xFF1A1F3A),
            onPressed: () => setState(() => _showLeftPanel = !_showLeftPanel),
            child: Icon(_showLeftPanel ? Icons.chevron_right : Icons.chevron_left, color: const Color(0xFF00F5FF)),
          ),
        ),
        Positioned(
          right: 14,
          bottom: 14,
          child: FloatingActionButton(
            heroTag: 'toggleRight',
            mini: true,
            backgroundColor: const Color(0xFF1A1F3A),
            onPressed: () => setState(() => _showRightPanel = !_showRightPanel),
            child: Icon(_showRightPanel ? Icons.chevron_left : Icons.chevron_right, color: const Color(0xFF00F5FF)),
          ),
        ),
      ],
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

      for (final target in targetsToAnalyze) {
        appState.addDebugLog('Starting vulnerability analysis for ${target.address}...');

        final deviceJson = await File(target.jsonFilePath).readAsString();

        final analyzer = VulnerabilityAnalyzer(
          onPromptResponse: (prompt, response) {
            appState.addPromptLog(prompt, response);
          },
        );
        final vulns = await analyzer.analyzeDevice(
          deviceJson,
          appState.llmSettings,
          confirmedFindingsContext: appState.confirmedFindingsPromptBlock(target.address),
        );

        appState.addDebugLog('Found ${vulns.length} vulnerabilities for ${target.address}');
        for (final v in vulns) {
          v.targetAddress = target.address;
          v.targetId = target.id;
          v.projectId = appState.currentProject?.id;
          await DatabaseHelper.insertVulnerability(v);
          appState.addDebugLog('Added: ${v.problem}');
        }

        // Mark this target's analysis as complete
        target.analysisComplete = true;
        await DatabaseHelper.updateTarget(target);

        appState.loadVulnerabilities();
        if (mounted) setState(() {});
      }

      appState.setAnalysisComplete(true);
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

    for (var i = 0; i < pendingVulns.length; i++) {
      final vuln = pendingVulns[i];
      final vulnIdx = appState.vulnerabilities.indexWhere((v) => v.id == vuln.id);
      if (vulnIdx == -1) {
        appState.addDebugLog('ERROR - Could not find vulnerability with id=${vuln.id}');
        continue;
      }
      appState.addDebugLog('Processing vulnerability id=${vuln.id} at index=$vulnIdx');

      final selectedTarget = appState.selectedTarget;
      final deviceJson = selectedTarget != null
          ? await File(selectedTarget.jsonFilePath).readAsString()
          : '{}';

      final targetForVuln = appState.targets.firstWhere(
        (t) => t.address == vuln.targetAddress,
        orElse: () => appState.selectedTarget ?? appState.targets.first,
      );
      final vulnOutputDir = StorageService.toShellPath(
        await StorageService.getTargetPath(
          appState.currentProjectName, targetForVuln.address));

      final executor = ExploitExecutor(
        deviceData: deviceJson,
        vulnerabilityIndex: vulnIdx,
        outputDir: vulnOutputDir,
        onProgress: (msg) => appState.addDebugLog(msg),
        onCommandExecuted: (cmd, output, idx) async {
          appState.addDebugLog('Command executed: $cmd');
          await appState.loadCommandLogs();
          if (mounted) setState(() {});
        },
        onPromptResponse: (prompt, response) {
          appState.addPromptLog(prompt, response);
        },
        adminPassword: appState.adminPassword,
        onApprovalNeeded: appState.requireApproval
            ? (command) async {
                _approvalCompleter = Completer<String?>();
                appState.setPendingCommand(command);
                return await _approvalCompleter!.future;
              }
            : null,
        onPasswordNeeded: _onInstallPasswordNeeded,
        credentialBankContext: appState.credentialBankPromptBlock(vuln.targetAddress),
        confirmedFindingsContext: appState.confirmedFindingsPromptBlock(vuln.targetAddress),
        onCredentialsFound: (credMaps) {
          for (final m in credMaps) {
            appState.addCredential(DiscoveredCredential(
              service: m['service'] ?? '',
              host: m['host'] ?? vuln.targetAddress,
              username: m['username'] ?? '',
              secret: m['secret'] ?? '',
              secretType: m['secretType'] ?? 'password',
              sourceVuln: vuln.problem,
              discoveredAt: DateTime.now(),
            ));
          }
        },
        onPhaseUpdate: (iter, max, phase) {
          final title = vuln.problem.length > 30 ? '${vuln.problem.substring(0, 30)}…' : vuln.problem;
          appState.setExecutionStatus('$title: Iter $iter/$max — $phase');
        },
      );

      final targetId = appState.targets
          .firstWhere((t) => t.address == vuln.targetAddress, orElse: () => appState.selectedTarget ?? appState.targets.first)
          .id ?? 0;
      final status = await executor.testVulnerability(
        vuln, appState.llmSettings, appState.requireApproval,
        projectId: appState.currentProject?.id ?? 0,
        targetId: targetId,
      );
      vuln.status = status;
      // 2.4: Feed confirmed artifacts into the chain for subsequent vuln tests
      if (status == VulnerabilityStatus.confirmed) {
        appState.addConfirmedArtifact(vuln);
        // 2.7: Post-exploitation enumeration — queue a follow-on pseudo-vuln for RCE/auth bypass
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

      final selectedStates = {for (var v in appState.vulnerabilities) v.id: v.selected};
      await appState.loadVulnerabilities();
      for (var v in appState.vulnerabilities) {
        v.selected = selectedStates[v.id] ?? false;
      }

      await appState.loadCommandLogs();
      if (mounted) setState(() {});
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

    appState.setExecutionStatus('');
    setState(() => _isExecuting = false);

    appState.setHasResults(true);
    if (mounted) _showResults(appState);
  }

  void _showCredentials(AppState appState) {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1A1F3A),
        title: const Text('Discovered Credentials', style: TextStyle(color: Color(0xFF00FF88), fontWeight: FontWeight.bold)),
        content: SizedBox(
          width: 600,
          child: appState.credentials.isEmpty
              ? const Text('No credentials discovered yet.', style: TextStyle(color: Colors.white70))
              : SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: appState.credentials.map((c) => Container(
                      margin: const EdgeInsets.only(bottom: 8),
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: const Color(0xFF0A0E27),
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(color: const Color(0xFF00FF88).withValues(alpha: 0.3)),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('${c.service} @ ${c.host}', style: const TextStyle(color: Color(0xFF00FF88), fontFamily: 'monospace', fontSize: 12, fontWeight: FontWeight.bold)),
                          const SizedBox(height: 4),
                          Text('User: ${c.username}  |  ${c.secretType}: ${c.secret}', style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontSize: 12)),
                          Text('Source: ${c.sourceVuln}', style: const TextStyle(color: Colors.white38, fontSize: 11)),
                        ],
                      ),
                    )).toList(),
                  ),
                ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('CLOSE', style: TextStyle(color: Color(0xFF00F5FF)))),
        ],
      ),
    );
  }

  void _showResults(AppState appState) {
    final target = appState.selectedTarget;
    ResultsModal.show(
      context,
      appState.vulnerabilities,
      appState.commandLogs,
      target?.address ?? 'unknown',
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

  Future<void> _exportLogs() async {
    final logs = context.read<AppState>().commandLogs;
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
    final path = await FileDialog.saveFile(
      dialogTitle: 'Save Command Logs',
      fileName: 'PenExecute_CommandLogs.txt',
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }

  Future<void> _exportPrompts(AppState state) async {
    final content = state.promptLogs.map((log) => '=== PROMPT ===\n${log.prompt}\n\n=== RESPONSE ===\n${log.response}\n').join('\n---\n\n');
    final path = await FileDialog.saveFile(
      dialogTitle: 'Save Prompts',
      fileName: 'PenExecute_Prompts.txt',
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }

  Future<void> _exportDebug(AppState state) async {
    final content = state.debugLogs.map((log) => '[${log.timestamp.toString().substring(11, 19)}] ${log.message}').join('\n');
    final path = await FileDialog.saveFile(
      dialogTitle: 'Save Debug Log',
      fileName: 'PenExecute_Debug.txt',
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }

  Future<void> _exportReport(AppState state, String format) async {
    final vulns = state.vulnerabilities;
    if (vulns.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No findings to export')),
      );
      return;
    }
    final project = state.currentProject;
    if (project == null) return;

    final String content;
    final String fileName;
    switch (format) {
      case 'html':
        content = ReportGenerator.generateHtml(
          project: project,
          targets: state.targets,
          vulnerabilities: vulns,
          credentials: state.credentials.toList(),
        );
        fileName = '${project.name.replaceAll(' ', '_')}_Report.html';
      case 'md':
        content = ReportGenerator.generateMarkdown(
          project: project,
          targets: state.targets,
          vulnerabilities: vulns,
          credentials: state.credentials.toList(),
        );
        fileName = '${project.name.replaceAll(' ', '_')}_Report.md';
      case 'csv':
        content = ReportGenerator.generateCsv(vulnerabilities: vulns);
        fileName = '${project.name.replaceAll(' ', '_')}_Findings.csv';
      default:
        return;
    }

    final path = await FileDialog.saveFile(
      dialogTitle: 'Export Report',
      fileName: fileName,
    );
    if (path != null) {
      await File(path).writeAsString(content);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Report saved to $path')),
        );
      }
    }
  }
}
