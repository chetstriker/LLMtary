import 'dart:io';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:file_picker/file_picker.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/llm_provider.dart';
import '../services/vulnerability_analyzer.dart';
import '../services/exploit_executor.dart';
import '../database/database_helper.dart';
import 'settings_screen.dart';
import '../widgets/app_state.dart';
import '../widgets/admin_password_dialog.dart';
import '../widgets/command_approval_widget.dart';

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
  bool _requireApproval = true;
  bool _isAnalyzing = false;
  bool _isExecuting = false;
  final _logScrollController = ScrollController();
  final Map<int, GlobalKey> _proofKeys = {};
  bool _showLeftPanel = true;
  bool _showRightPanel = true;
  double _vulnTableHeight = 250;
  Completer<String?>? _approvalCompleter;
  bool _autoScrollPrompts = true;
  bool _autoScrollDebug = true;
  final _promptScrollController = ScrollController();
  final _debugScrollController = ScrollController();
  bool _selectAllVulns = false;
  final _tableHeaderScrollController = ScrollController();
  final _tableDataScrollController = ScrollController();
  
  static const _vulnColors = [
    Color(0xFFFF0080), // Pink
    Color(0xFF00F5FF), // Cyan
    Color(0xFF00FF88), // Green
    Color(0xFFFFAA00), // Orange
    Color(0xFF8B5CF6), // Purple
    Color(0xFFFF6B00), // Red-Orange
    Color(0xFF00D9FF), // Light Blue
    Color(0xFFFFC700), // Yellow
  ];
  
  Color _getVulnColor(int index) => _vulnColors[index % _vulnColors.length];
  
  void _scrollToProof(int vulnIdx) async {
    final appState = context.read<AppState>();
    appState.addDebugLog('Scroll to proof requested for vulnerability #${vulnIdx + 1}');
    
    final key = _proofKeys[vulnIdx];
    if (key == null) {
      appState.addDebugLog('ERROR: No proof key found for vulnerability #${vulnIdx + 1}');
      appState.addDebugLog('Available proof keys: ${_proofKeys.keys.map((k) => '#${k + 1}').join(', ')}');
      return;
    }
    
    // Wait for widget to be rendered
    await Future.delayed(const Duration(milliseconds: 100));
    
    if (key.currentContext == null) {
      appState.addDebugLog('WARNING: Proof key context not ready for vulnerability #${vulnIdx + 1}, retrying...');
      await Future.delayed(const Duration(milliseconds: 200));
    }
    
    if (key.currentContext == null) {
      appState.addDebugLog('ERROR: Proof key context still null for vulnerability #${vulnIdx + 1}');
      return;
    }
    
    try {
      appState.addDebugLog('Scrolling to proof for vulnerability #${vulnIdx + 1}');
      Scrollable.ensureVisible(
        key.currentContext!,
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
      );
      appState.addDebugLog('Successfully scrolled to proof for vulnerability #${vulnIdx + 1}');
    } catch (e) {
      appState.addDebugLog('ERROR: Failed to scroll to proof for vulnerability #${vulnIdx + 1}: $e');
    }
  }

  @override
  void initState() {
    super.initState();
    _initTempFolder();
    _loadApprovalSetting();
    
    _tableHeaderScrollController.addListener(() {
      if (_tableDataScrollController.hasClients && _tableDataScrollController.offset != _tableHeaderScrollController.offset) {
        _tableDataScrollController.jumpTo(_tableHeaderScrollController.offset);
      }
    });
    
    _tableDataScrollController.addListener(() {
      if (_tableHeaderScrollController.hasClients && _tableHeaderScrollController.offset != _tableDataScrollController.offset) {
        _tableHeaderScrollController.jumpTo(_tableDataScrollController.offset);
      }
    });
  }

  Future<void> _loadApprovalSetting() async {
    final setting = await DatabaseHelper.getSetting('require_approval');
    setState(() {
      _requireApproval = setting == null ? true : setting == 'true';
    });
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
    _promptScrollController.dispose();
    _debugScrollController.dispose();
    _tableHeaderScrollController.dispose();
    _tableDataScrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E27),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1A1F3A),
        elevation: 0,
        title: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFF00F5FF), Color(0xFF0080FF)],
                ),
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
                    value: _requireApproval,
                    onChanged: (v) {
                      setState(() => _requireApproval = v);
                      DatabaseHelper.saveSetting('require_approval', v.toString());
                    },
                    activeColor: const Color(0xFF00F5FF),
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
      ),
      body: Stack(
        children: [
          Row(
            children: [
              if (_showLeftPanel)
                SizedBox(
                  width: 350,
                  child: Column(
                    children: [
                      _buildDeviceInput(),
                      Expanded(child: _buildPromptLog()),
                    ],
                  ),
                ),
              Expanded(
                child: Column(
                  children: [
                    SizedBox(
                      height: _vulnTableHeight,
                      child: _buildVulnerabilityTable(),
                    ),
                    GestureDetector(
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
                    ),
                    Expanded(child: _buildCommandLog()),
                  ],
                ),
              ),
              if (_showRightPanel)
                SizedBox(
                  width: 350,
                  child: _buildDebugLog(),
                ),
            ],
          ),
          Consumer<AppState>(
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
          ),
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
      ),
    );
  }

  Widget _buildDeviceInput() {
    return Container(
      margin: const EdgeInsets.all(8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF1A1F3A),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
      ),
      child: Column(
        children: [
          TextField(
            controller: _deviceController,
            maxLines: 6,
            style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontSize: 10),
            decoration: InputDecoration(
              labelText: 'TARGET DEVICE DATA',
              labelStyle: const TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 10),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: Color(0xFF00F5FF)),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: const Color(0xFF00F5FF).withOpacity(0.3)),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: Color(0xFF00F5FF), width: 2),
              ),
              filled: true,
              fillColor: const Color(0xFF0A0E27),
              contentPadding: const EdgeInsets.all(8),
            ),
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: _isAnalyzing ? null : _analyzeDevice,
              icon: _isAnalyzing ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2)) : const Icon(Icons.radar, color: Colors.white, size: 16),
              label: Text(_isAnalyzing ? 'ANALYZING...' : 'ANALYZE', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFF00F5FF),
                padding: const EdgeInsets.symmetric(vertical: 12),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPromptLog() {
    return Consumer<AppState>(
      builder: (context, state, _) {
        return Container(
          margin: const EdgeInsets.fromLTRB(8, 0, 8, 8),
          decoration: BoxDecoration(
            color: const Color(0xFF1A1F3A),
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
                    const Icon(Icons.chat, color: Color(0xFF00F5FF), size: 16),
                    const SizedBox(width: 8),
                    const Text('PROMPTS', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.download, color: Color(0xFF00F5FF), size: 16),
                      onPressed: () => _exportPrompts(state),
                      tooltip: 'Export Prompts',
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(),
                    ),
                    const SizedBox(width: 8),
                    Transform.scale(
                      scale: 0.7,
                      child: Checkbox(
                        value: _autoScrollPrompts,
                        onChanged: (v) => setState(() => _autoScrollPrompts = v ?? true),
                        activeColor: const Color(0xFF00F5FF),
                      ),
                    ),
                    const Text('Auto-scroll', style: TextStyle(color: Colors.white70, fontSize: 10)),
                  ],
                ),
              ),
              Expanded(
                child: state.promptLogs.isEmpty
                    ? Center(child: Text('No prompts yet', style: TextStyle(color: Colors.white.withOpacity(0.3), fontSize: 12)))
                    : ListView.builder(
                        controller: _promptScrollController,
                        padding: const EdgeInsets.all(8),
                        itemCount: state.promptLogs.length,
                        itemBuilder: (context, i) {
                          if (_autoScrollPrompts && i == state.promptLogs.length - 1) {
                            WidgetsBinding.instance.addPostFrameCallback((_) {
                              if (_promptScrollController.hasClients) {
                                _promptScrollController.jumpTo(_promptScrollController.position.maxScrollExtent);
                              }
                            });
                          }
                          final log = state.promptLogs[i];
                          return Container(
                            margin: const EdgeInsets.only(bottom: 8),
                            decoration: BoxDecoration(
                              color: const Color(0xFF0A0E27),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.2)),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Container(
                                  padding: const EdgeInsets.all(8),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF00F5FF).withOpacity(0.1),
                                    borderRadius: const BorderRadius.vertical(top: Radius.circular(8)),
                                  ),
                                  child: Row(
                                    children: [
                                      const Icon(Icons.arrow_upward, color: Color(0xFF00F5FF), size: 12),
                                      const SizedBox(width: 4),
                                      const Text('PROMPT', style: TextStyle(color: Color(0xFF00F5FF), fontSize: 10, fontWeight: FontWeight.bold)),
                                    ],
                                  ),
                                ),
                                Padding(
                                  padding: const EdgeInsets.all(8),
                                  child: SelectableText(
                                    log.prompt,
                                    style: const TextStyle(color: Colors.white70, fontSize: 10, fontFamily: 'monospace'),
                                  ),
                                ),
                                Container(
                                  padding: const EdgeInsets.all(8),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF00FF88).withOpacity(0.1),
                                  ),
                                  child: Row(
                                    children: [
                                      const Icon(Icons.arrow_downward, color: Color(0xFF00FF88), size: 12),
                                      const SizedBox(width: 4),
                                      const Text('RESPONSE', style: TextStyle(color: Color(0xFF00FF88), fontSize: 10, fontWeight: FontWeight.bold)),
                                    ],
                                  ),
                                ),
                                Padding(
                                  padding: const EdgeInsets.all(8),
                                  child: SelectableText(
                                    log.response,
                                    style: const TextStyle(color: Colors.white70, fontSize: 10, fontFamily: 'monospace'),
                                  ),
                                ),
                              ],
                            ),
                          );
                        },
                      ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildDebugLog() {
    return Consumer<AppState>(
      builder: (context, state, _) {
        return Container(
          margin: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: const Color(0xFF1A1F3A),
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
                    const Icon(Icons.bug_report, color: Color(0xFF00F5FF), size: 16),
                    const SizedBox(width: 8),
                    const Text('DEBUG', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.download, color: Color(0xFF00F5FF), size: 16),
                      onPressed: () => _exportDebug(state),
                      tooltip: 'Export Debug',
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(),
                    ),
                    const SizedBox(width: 8),
                    Transform.scale(
                      scale: 0.7,
                      child: Checkbox(
                        value: _autoScrollDebug,
                        onChanged: (v) => setState(() => _autoScrollDebug = v ?? true),
                        activeColor: const Color(0xFF00F5FF),
                      ),
                    ),
                    const Text('Auto-scroll', style: TextStyle(color: Colors.white70, fontSize: 10)),
                  ],
                ),
              ),
              Expanded(
                child: state.debugLogs.isEmpty
                    ? Center(child: Text('No debug logs yet', style: TextStyle(color: Colors.white.withOpacity(0.3), fontSize: 12)))
                    : SelectableRegion(
                        focusNode: FocusNode(),
                        selectionControls: materialTextSelectionControls,
                        child: ListView.builder(
                          controller: _debugScrollController,
                          padding: const EdgeInsets.all(8),
                          itemCount: state.debugLogs.length,
                          itemBuilder: (context, i) {
                            if (_autoScrollDebug && i == state.debugLogs.length - 1) {
                              WidgetsBinding.instance.addPostFrameCallback((_) {
                                if (_debugScrollController.hasClients) {
                                  _debugScrollController.jumpTo(_debugScrollController.position.maxScrollExtent);
                                }
                              });
                            }
                            final log = state.debugLogs[i];
                            final isError = log.message.toLowerCase().contains('error') || log.message.toLowerCase().contains('exception') || log.message.toLowerCase().contains('failed');
                            return Container(
                              margin: const EdgeInsets.only(bottom: 4),
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: isError ? const Color(0xFFFF0080).withOpacity(0.15) : const Color(0xFF0A0E27),
                                borderRadius: BorderRadius.circular(4),
                                border: isError ? Border.all(color: const Color(0xFFFF0080), width: 1) : null,
                              ),
                              child: Text(
                                '[${log.timestamp.toString().substring(11, 19)}] ${log.message}',
                                style: TextStyle(
                                  color: isError ? const Color(0xFFFF0080) : Colors.white70,
                                  fontSize: 10,
                                  fontFamily: 'monospace',
                                  fontWeight: isError ? FontWeight.bold : FontWeight.normal,
                                ),
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

  Widget _buildVulnerabilityTable() {
    return Consumer<AppState>(
      builder: (context, state, _) {
        return Container(
          margin: const EdgeInsets.fromLTRB(8, 8, 8, 0),
          decoration: BoxDecoration(
            color: const Color(0xFF1A1F3A),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
          ),
          child: Column(
            children: [
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [const Color(0xFF00F5FF).withOpacity(0.1), Colors.transparent],
                  ),
                  borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                ),
                child: Column(
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Row(
                          children: [
                            const Icon(Icons.bug_report, color: Color(0xFF00F5FF), size: 20),
                            const SizedBox(width: 8),
                            Text('VULNERABILITIES DETECTED', style: const TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 14)),
                            const SizedBox(width: 12),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                              decoration: BoxDecoration(
                                color: const Color(0xFF00F5FF).withOpacity(0.2),
                                borderRadius: BorderRadius.circular(12),
                                border: Border.all(color: const Color(0xFF00F5FF)),
                              ),
                              child: Text('${state.vulnerabilities.length}', style: const TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold)),
                            ),
                          ],
                        ),
                        Container(
                          decoration: BoxDecoration(
                            gradient: const LinearGradient(
                              colors: [Color(0xFFFF0080), Color(0xFFFF0040)],
                            ),
                            borderRadius: BorderRadius.circular(8),
                            boxShadow: [
                              BoxShadow(
                                color: const Color(0xFFFF0080).withOpacity(0.5),
                                blurRadius: 15,
                              ),
                            ],
                          ),
                          child: ElevatedButton.icon(
                            onPressed: _isExecuting ? null : _executeSelected,
                            icon: _isExecuting ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2)) : const Icon(Icons.play_arrow, color: Colors.white),
                            label: Text(_isExecuting ? 'EXECUTING...' : 'EXECUTE SELECTED', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 12)),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: Colors.transparent,
                              shadowColor: Colors.transparent,
                              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                            ),
                          ),
                        ),
                      ],
                    ),
                    if (state.vulnerabilities.isNotEmpty) const SizedBox(height: 12),
                    if (state.vulnerabilities.isNotEmpty)
                      SingleChildScrollView(
                        controller: _tableHeaderScrollController,
                        scrollDirection: Axis.horizontal,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                          decoration: BoxDecoration(
                            color: const Color(0xFF0A0E27),
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Row(
                            children: [
                              SizedBox(
                                width: 48,
                                child: Checkbox(
                                  value: _selectAllVulns,
                                  onChanged: (val) {
                                    setState(() {
                                      _selectAllVulns = val ?? false;
                                      for (var v in state.vulnerabilities) {
                                        if (v.status == VulnerabilityStatus.pending || v.status == VulnerabilityStatus.undetermined) {
                                          v.selected = _selectAllVulns;
                                        }
                                      }
                                    });
                                  },
                                  activeColor: const Color(0xFF00F5FF),
                                ),
                              ),
                              const SizedBox(
                                width: 48,
                                child: Text('#', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11)),
                              ),
                              const SizedBox(
                                width: 80,
                                child: Text('STATUS', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11)),
                              ),
                              const SizedBox(
                                width: 120,
                                child: Text('TYPE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11)),
                              ),
                              const SizedBox(
                                width: 100,
                                child: Text('SEVERITY', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11)),
                              ),
                              const SizedBox(
                                width: 150,
                                child: Text('CVE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11)),
                              ),
                              const SizedBox(
                                width: 120,
                                child: Text('CONFIDENCE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11)),
                              ),
                              const SizedBox(
                                width: 300,
                                child: Text('VULNERABILITY', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11)),
                              ),
                            ],
                          ),
                        ),
                      ),
                  ],
                ),
              ),
              Expanded(
                child: state.vulnerabilities.isEmpty
                    ? Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(Icons.shield_outlined, size: 64, color: Colors.white.withOpacity(0.1)),
                            const SizedBox(height: 16),
                            Text('No vulnerabilities detected', style: TextStyle(color: Colors.white.withOpacity(0.3), fontSize: 16)),
                            const SizedBox(height: 8),
                            Text('Analyze a target to begin', style: TextStyle(color: Colors.white.withOpacity(0.2), fontSize: 12)),
                          ],
                        ),
                      )
                    : SingleChildScrollView(
                        scrollDirection: Axis.vertical,
                        child: SingleChildScrollView(
                          controller: _tableDataScrollController,
                          scrollDirection: Axis.horizontal,
                          child: Column(
                            children: state.vulnerabilities.asMap().entries.map((entry) {
                              final idx = entry.key;
                              final v = entry.value;
                              final color = _getVulnColor(idx);
                              final isTestable = v.status == VulnerabilityStatus.pending || v.status == VulnerabilityStatus.undetermined;
                              return Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
                                decoration: BoxDecoration(
                                  border: Border(bottom: BorderSide(color: const Color(0xFF00F5FF).withOpacity(0.1))),
                                ),
                                child: Row(
                                  children: [
                                    SizedBox(
                                      width: 48,
                                      child: Checkbox(
                                        value: v.selected,
                                        onChanged: isTestable ? (val) => _toggleSelection(v, val ?? false) : null,
                                        activeColor: const Color(0xFF00F5FF),
                                      ),
                                    ),
                                    SizedBox(
                                      width: 48,
                                      child: InkWell(
                                        onTap: () => _scrollToProof(idx),
                                        child: Container(
                                          width: 28,
                                          height: 28,
                                          decoration: BoxDecoration(
                                            color: color.withOpacity(0.2),
                                            shape: BoxShape.circle,
                                            border: Border.all(color: color, width: 2),
                                          ),
                                          child: Center(
                                            child: Text(
                                              '${idx + 1}',
                                              style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.bold),
                                            ),
                                          ),
                                        ),
                                      ),
                                    ),
                                    SizedBox(
                                      width: 80,
                                      child: _buildStatusIcon(v.status, v.statusReason, v.proofCommand, idx),
                                    ),
                                    SizedBox(
                                      width: 120,
                                      child: Text(v.vulnerabilityType.isEmpty ? '-' : v.vulnerabilityType, style: TextStyle(color: v.vulnerabilityType.isEmpty ? Colors.white30 : const Color(0xFF00F5FF), fontSize: 11)),
                                    ),
                                    SizedBox(
                                      width: 100,
                                      child: _buildSeverityBadge(v.severity),
                                    ),
                                    SizedBox(
                                      width: 150,
                                      child: Text(v.cve.isEmpty ? '-' : v.cve, style: TextStyle(color: v.cve.isEmpty ? Colors.white30 : const Color(0xFFFFAA00), fontSize: 11, fontFamily: 'monospace')),
                                    ),
                                    SizedBox(
                                      width: 120,
                                      child: Text(v.confidence, style: const TextStyle(color: Colors.white70, fontSize: 11)),
                                    ),
                                    SizedBox(
                                      width: 300,
                                      child: Text(v.problem, style: const TextStyle(color: Colors.white, fontSize: 12)),
                                    ),
                                  ],
                                ),
                              );
                            }).toList(),
                          ),
                        ),
                      ),
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildSeverityBadge(String severity) {
    Color color;
    switch (severity.toLowerCase()) {
      case 'critical':
        color = const Color(0xFFFF0040);
        break;
      case 'high':
        color = const Color(0xFFFF6B00);
        break;
      case 'medium':
        color = const Color(0xFFFFAA00);
        break;
      default:
        color = const Color(0xFF00FF88);
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.2),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color),
      ),
      child: Text(severity.toUpperCase(), style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.bold)),
    );
  }

  Widget _buildStatusIcon(VulnerabilityStatus status, String reason, String? proofCommand, int vulnIdx) {
    Widget icon;
    String tooltip;
    
    switch (status) {
      case VulnerabilityStatus.confirmed:
        icon = Container(
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(
            color: const Color(0xFFFF0040).withOpacity(0.2),
            shape: BoxShape.circle,
            border: Border.all(color: const Color(0xFFFF0040), width: 2),
          ),
          child: const Icon(Icons.warning, color: Color(0xFFFF0040), size: 16),
        );
        tooltip = 'CONFIRMED VULNERABLE\n${reason.isNotEmpty ? reason : "Vulnerability confirmed through testing"}';
        if (proofCommand != null && proofCommand.isNotEmpty) {
          tooltip += '\n\nProof Command:\n$proofCommand';
        }
        break;
      case VulnerabilityStatus.notVulnerable:
        icon = Container(
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(
            color: const Color(0xFF00FF88).withOpacity(0.2),
            shape: BoxShape.circle,
            border: Border.all(color: const Color(0xFF00FF88), width: 2),
          ),
          child: const Icon(Icons.check_circle, color: Color(0xFF00FF88), size: 16),
        );
        tooltip = 'NOT VULNERABLE\n${reason.isNotEmpty ? reason : "Target is not vulnerable"}';
        if (proofCommand != null && proofCommand.isNotEmpty) {
          tooltip += '\n\nProof Command:\n$proofCommand';
        }
        break;
      case VulnerabilityStatus.undetermined:
        icon = Container(
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(
            color: const Color(0xFFFFAA00).withOpacity(0.2),
            shape: BoxShape.circle,
            border: Border.all(color: const Color(0xFFFFAA00), width: 2),
          ),
          child: const Icon(Icons.help, color: Color(0xFFFFAA00), size: 16),
        );
        tooltip = 'UNDETERMINED\n${reason.isNotEmpty ? reason : "Unable to determine vulnerability status"}';
        break;
      default:
        icon = Container(
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(
            color: Colors.white.withOpacity(0.1),
            shape: BoxShape.circle,
            border: Border.all(color: Colors.white30, width: 2),
          ),
          child: const Icon(Icons.pending, color: Colors.white30, size: 16),
        );
        tooltip = 'PENDING\nNot yet tested';
    }
    
    return Tooltip(
      message: tooltip,
      preferBelow: false,
      child: InkWell(
        onTap: () => _scrollToProof(vulnIdx),
        child: icon,
      ),
    );
  }

  Widget _buildCommandLog() {
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
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.terminal, color: Color(0xFF00F5FF), size: 16),
                        const SizedBox(width: 8),
                        const Text('COMMAND LOG', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                      ],
                    ),
                    IconButton(
                      icon: const Icon(Icons.download, color: Color(0xFF00F5FF), size: 18),
                      onPressed: _exportLogs,
                      tooltip: 'Export Logs',
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
                        focusNode: FocusNode(),
                        selectionControls: materialTextSelectionControls,
                        child: ListView.builder(
                          controller: _logScrollController,
                          padding: const EdgeInsets.all(8),
                          itemCount: state.commandLogs.length,
                          itemBuilder: (context, i) {
                          final log = state.commandLogs[i];
                          final vulnIdx = log.vulnerabilityIndex ?? -1;
                          final vuln = vulnIdx >= 0 && vulnIdx < state.vulnerabilities.length ? state.vulnerabilities[vulnIdx] : null;
                          final isProof = vuln != null && 
                              ((vuln.proofCommand == log.command) || 
                               (log.command.contains('Initial Evidence Analysis')) || 
                               (log.command.contains('Analysis Conclusion'))) && 
                              (vuln.status == VulnerabilityStatus.confirmed || vuln.status == VulnerabilityStatus.notVulnerable);
                          
                          if (isProof) {
                            _proofKeys[vulnIdx] = GlobalKey();
                          }
                          
                          final vulnColor = vulnIdx >= 0 ? _getVulnColor(vulnIdx) : const Color(0xFF00F5FF);
                          
                          return Container(
                            key: isProof ? _proofKeys[vulnIdx] : null,
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
                                // Command header
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
                                  decoration: BoxDecoration(
                                    gradient: LinearGradient(
                                      colors: [
                                        const Color(0xFF00F5FF).withOpacity(0.2),
                                        Colors.transparent,
                                      ],
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
                                            color: _getVulnColor(vulnIdx).withOpacity(0.2),
                                            shape: BoxShape.circle,
                                            border: Border.all(color: _getVulnColor(vulnIdx), width: 1.5),
                                          ),
                                          child: Center(
                                            child: Text(
                                              '${vulnIdx + 1}',
                                              style: TextStyle(color: _getVulnColor(vulnIdx), fontSize: 9, fontWeight: FontWeight.bold),
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
                                // Response section
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
                                          log.output,
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

  Future<void> _analyzeDevice() async {
    setState(() => _isAnalyzing = true);
    try {
      final appState = context.read<AppState>();
      
      if (appState.llmSettings.provider == LLMProvider.none) {
        throw Exception('Please configure AI settings first');
      }
      
      if (appState.llmSettings.modelName.isEmpty) {
        throw Exception('Please select a model in settings');
      }
      
      if (appState.llmSettings.provider.requiresBaseUrl && (appState.llmSettings.baseUrl == null || appState.llmSettings.baseUrl!.isEmpty)) {
        throw Exception('Please configure base URL in settings');
      }
      
      if (appState.llmSettings.provider.requiresApiKey && (appState.llmSettings.apiKey == null || appState.llmSettings.apiKey!.isEmpty)) {
        throw Exception('Please configure API key in settings');
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
    
    // Request admin password if not already set
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
        onApprovalNeeded: _requireApproval ? (command) async {
          _approvalCompleter = Completer<String?>();
          appState.setPendingCommand(command);
          return await _approvalCompleter!.future;
        } : null,
      );
      
      final maxIterations = int.tryParse(await DatabaseHelper.getSetting('max_iterations') ?? '10') ?? 10;
      final status = await executor.testVulnerability(vuln, appState.llmSettings, _requireApproval, maxIterations);
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
