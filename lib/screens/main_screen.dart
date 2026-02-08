import 'dart:io';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../models/vulnerability.dart';
import '../models/llm_provider.dart';
import '../services/vulnerability_analyzer.dart';
import '../services/exploit_executor.dart';
import '../database/database_helper.dart';
import 'settings_screen.dart';
import '../widgets/app_state.dart';
import '../widgets/admin_password_dialog.dart';
import '../widgets/command_approval_widget.dart';
import '../widgets/device_input_panel.dart';
import '../widgets/prompt_log_panel.dart';
import '../widgets/debug_log_panel.dart';
import '../widgets/command_log_panel.dart';
import '../widgets/vulnerability_table.dart';
import '../constants/app_constants.dart';
import '../utils/app_exceptions.dart';

class MainScreen extends StatefulWidget {
  const MainScreen({super.key});

  @override
  State<MainScreen> createState() => _MainScreenState();
}

class _MainScreenState extends State<MainScreen> {
  final _deviceController = TextEditingController(text: '''{
  "device": {
    "id": 3556,
    "name": "192.168.50.53",
    "ip_address": "192.168.50.53",
    "mac_address": "04:17:B6:F2:4E:D1",
    "vendor": "Smart Innovation"
  },
  "open_ports": [
    {
      "port": 53,
      "protocol": "tcp",
      "service": "domain",
      "product": "dnsmasq",
      "version": "2.40"
    },
    {
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "product": "",
      "version": ""
    },
    {
      "port": 554,
      "protocol": "tcp",
      "service": "rtsp",
      "product": "",
      "version": ""
    },
    {
      "port": 9000,
      "protocol": "tcp",
      "service": "cslistener",
      "product": "",
      "version": ""
    }
  ],
  "nmap_scripts": [
    {
      "script_id": "vulners",
      "output": "High-severity CVEs (CVSS >= 7.0):\n  CVE-2017-14493 (CVSS 9.8)\n  CVE-2017-14492 (CVSS 9.8)\n  CVE-2017-14491 (CVSS 9.8)\n  CVE-2020-25682 (CVSS 8.3)\n  CVE-2020-25681 (CVSS 8.3)"
    }
  ]
}''');
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
    _initTempFolder();
  }

  Future<void> _initTempFolder() async {
    try {
      final tempDir = Directory('temp');
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
      await tempDir.create();
    } catch (e) {
      print('Temp folder init error: $e');
    }
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
                      DeviceInputPanel(
                        controller: _deviceController,
                        isAnalyzing: _isAnalyzing,
                        onAnalyze: _analyzeDevice,
                      ),
                      Expanded(child: PromptLogPanel(onExport: _exportPrompts)),
                    ],
                  ),
                ),
              Expanded(
                child: Column(
                  children: [
                    SizedBox(
                      height: _vulnTableHeight,
                      child: VulnerabilityTable(
                        isExecuting: _isExecuting,
                        onExecuteSelected: _executeSelected,
                        onToggleSelection: _toggleSelection,
                        onScrollToProof: _scrollToProof,
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
    return AppBar(
      backgroundColor: const Color(0xFF1A1F3A),
      elevation: 0,
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
          const Text('PenExecute', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 20)),
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

      appState.clearPromptLogs();
      appState.clearDebugLogs();
      appState.addDebugLog('Starting vulnerability analysis...');

      await DatabaseHelper.clearVulnerabilities();
      appState.loadVulnerabilities();
      if (mounted) setState(() {});

      final analyzer = VulnerabilityAnalyzer(
        onPromptResponse: (prompt, response) {
          appState.addPromptLog(prompt, response);
        },
      );
      final vulns = await analyzer.analyzeDevice(_deviceController.text, appState.llmSettings);

      appState.addDebugLog('Found ${vulns.length} vulnerabilities');
      for (final v in vulns) {
        await DatabaseHelper.insertVulnerability(v);
        appState.addDebugLog('Added: ${v.problem}');
      }

      appState.loadVulnerabilities();
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

    setState(() => _isExecuting = true);

    if (appState.adminPassword == null) {
      final password = await showDialog<String>(
        context: context,
        barrierDismissible: false,
        builder: (context) => const AdminPasswordDialog(),
      );

      if (password == null || password.isEmpty) {
        setState(() => _isExecuting = false);
        appState.addDebugLog('Execution cancelled - no admin password provided');
        return;
      }

      appState.setAdminPassword(password);
      appState.addDebugLog('Admin password set for session');
    }

    await DatabaseHelper.clearCommandLogs();
    await appState.loadCommandLogs();
    if (mounted) setState(() {});

    for (var i = 0; i < selected.length; i++) {
      final vuln = selected[i];
      final vulnIdx = appState.vulnerabilities.indexWhere((v) => v.id == vuln.id);
      if (vulnIdx == -1) {
        appState.addDebugLog('ERROR - Could not find vulnerability with id=${vuln.id}');
        continue;
      }
      appState.addDebugLog('Processing vulnerability id=${vuln.id} at index=$vulnIdx');

      final executor = ExploitExecutor(
        deviceData: _deviceController.text,
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

    setState(() => _isExecuting = false);
  }

  Future<void> _exportLogs() async {
    final logs = await DatabaseHelper.getCommandLogs();
    final content = logs.map((l) => '${l.timestamp}: ${l.command}\n${l.output}\n').join('\n---\n');
    print('Export logs: $content');
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
