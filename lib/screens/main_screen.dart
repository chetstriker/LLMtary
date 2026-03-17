import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
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
import '../widgets/target_input_panel.dart';
import '../widgets/prompt_log_panel.dart';
import '../widgets/debug_log_panel.dart';
import '../widgets/command_log_panel.dart';
import '../widgets/vulnerability_table.dart';
import '../widgets/results_modal.dart';
import '../constants/app_constants.dart';
import '../utils/app_exceptions.dart';

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
        final vulns = await analyzer.analyzeDevice(deviceJson, appState.llmSettings);

        appState.addDebugLog('Found ${vulns.length} vulnerabilities for ${target.address}');
        for (final v in vulns) {
          v.targetAddress = target.address;
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

      final executor = ExploitExecutor(
        deviceData: deviceJson,
        vulnerabilityIndex: vulnIdx,
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
      );

      final maxIterations = int.tryParse(await DatabaseHelper.getSetting(SettingsKeys.maxIterations) ?? '10') ?? 10;
      final status = await executor.testVulnerability(vuln, appState.llmSettings, appState.requireApproval, maxIterations);
      vuln.status = status;
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

    setState(() => _isExecuting = false);

    appState.setHasResults(true);
    if (mounted) _showResults(appState);
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
    final logs = await DatabaseHelper.getCommandLogs();
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
    final path = await FilePicker.platform.saveFile(
      dialogTitle: 'Save Command Logs',
      fileName: 'PenExecute_CommandLogs.txt',
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }

  Future<void> _exportPrompts(AppState state) async {
    final content = state.promptLogs.map((log) => '=== PROMPT ===\n${log.prompt}\n\n=== RESPONSE ===\n${log.response}\n').join('\n---\n\n');
    final path = await FilePicker.platform.saveFile(
      dialogTitle: 'Save Prompts',
      fileName: 'PenExecute_Prompts.txt',
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }

  Future<void> _exportDebug(AppState state) async {
    final content = state.debugLogs.map((log) => '[${log.timestamp.toString().substring(11, 19)}] ${log.message}').join('\n');
    final path = await FilePicker.platform.saveFile(
      dialogTitle: 'Save Debug Log',
      fileName: 'PenExecute_Debug.txt',
    );
    if (path != null) {
      await File(path).writeAsString(content);
    }
  }
}
