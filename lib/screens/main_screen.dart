import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/llm_provider.dart';
import '../services/vulnerability_analyzer.dart';
import '../services/exploit_executor.dart';
import '../database/database_helper.dart';
import 'settings_screen.dart';
import '../widgets/app_state.dart';

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
  bool _requireApproval = false;
  bool _isAnalyzing = false;
  bool _isExecuting = false;
  final _logScrollController = ScrollController();
  final Map<int, GlobalKey> _proofKeys = {}; // vulnIdx -> key
  
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
  
  void _scrollToProof(int vulnIdx) {
    final key = _proofKeys[vulnIdx];
    if (key?.currentContext != null) {
      Scrollable.ensureVisible(key!.currentContext!, duration: const Duration(milliseconds: 300), curve: Curves.easeInOut);
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
                    onChanged: (v) => setState(() => _requireApproval = v),
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
      body: Column(
        children: [
          _buildDeviceInput(),
          _buildVulnerabilityTable(),
          Expanded(
            child: _buildCommandLog(),
          ),
        ],
      ),
    );
  }

  Widget _buildDeviceInput() {
    return Container(
      margin: const EdgeInsets.all(16),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF1A1F3A),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
        boxShadow: [
          BoxShadow(
            color: const Color(0xFF00F5FF).withOpacity(0.1),
            blurRadius: 20,
            spreadRadius: 2,
          ),
        ],
      ),
      child: Row(
        children: [
          Expanded(
            child: TextField(
              controller: _deviceController,
              maxLines: 4,
              style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontSize: 12),
              decoration: InputDecoration(
                labelText: 'TARGET DEVICE DATA',
                labelStyle: const TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11),
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
              ),
            ),
          ),
          const SizedBox(width: 16),
          Container(
            decoration: BoxDecoration(
              gradient: const LinearGradient(
                colors: [Color(0xFF00F5FF), Color(0xFF0080FF)],
              ),
              borderRadius: BorderRadius.circular(8),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF00F5FF).withOpacity(0.5),
                  blurRadius: 20,
                  spreadRadius: 2,
                ),
              ],
            ),
            child: ElevatedButton.icon(
              onPressed: _isAnalyzing ? null : _analyzeDevice,
              icon: _isAnalyzing ? const SizedBox(width: 20, height: 20, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2)) : const Icon(Icons.radar, color: Colors.white),
              label: Text(_isAnalyzing ? 'ANALYZING...' : 'ANALYZE', style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.transparent,
                shadowColor: Colors.transparent,
                padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 20),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildVulnerabilityTable() {
    return Consumer<AppState>(
      builder: (context, state, _) {
        return Container(
          height: 300,
          margin: const EdgeInsets.symmetric(horizontal: 16),
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
                child: Row(
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
                        child: DataTable(
                          headingRowColor: MaterialStateProperty.all(const Color(0xFF0A0E27)),
                          dataRowColor: MaterialStateProperty.all(Colors.transparent),
                          dividerThickness: 0.5,
                          columns: const [
                            DataColumn(label: Text('', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11))),
                            DataColumn(label: Text('#', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11))),
                            DataColumn(label: Text('STATUS', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11))),
                            DataColumn(label: Text('VULNERABILITY', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11))),
                            DataColumn(label: Text('TYPE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11))),
                            DataColumn(label: Text('CVE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11))),
                            DataColumn(label: Text('SEVERITY', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11))),
                            DataColumn(label: Text('CONFIDENCE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11))),
                          ],
                          rows: state.vulnerabilities.asMap().entries.map((entry) {
                            final idx = entry.key;
                            final v = entry.value;
                            final color = _getVulnColor(idx);
                            return DataRow(
                              cells: [
                                DataCell(Checkbox(
                                  value: v.selected,
                                  onChanged: (val) => _toggleSelection(v, val ?? false),
                                  activeColor: const Color(0xFF00F5FF),
                                )),
                                DataCell(
                                  InkWell(
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
                                DataCell(_buildStatusIcon(v.status, v.statusReason, v.proofCommand)),
                                DataCell(Text(v.problem, style: const TextStyle(color: Colors.white, fontSize: 12))),
                                DataCell(Text(v.vulnerabilityType.isEmpty ? '-' : v.vulnerabilityType, style: TextStyle(color: v.vulnerabilityType.isEmpty ? Colors.white30 : const Color(0xFF00F5FF), fontSize: 11))),
                                DataCell(Text(v.cve.isEmpty ? '-' : v.cve, style: TextStyle(color: v.cve.isEmpty ? Colors.white30 : const Color(0xFFFFAA00), fontSize: 11, fontFamily: 'monospace'))),
                                DataCell(_buildSeverityBadge(v.severity)),
                                DataCell(Text(v.confidence, style: const TextStyle(color: Colors.white70, fontSize: 11))),
                              ],
                            );
                          }).toList(),
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

  Widget _buildStatusIcon(VulnerabilityStatus status, String reason, String? proofCommand) {
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
      child: icon,
    );
  }

  Widget _buildCommandLog() {
    return Consumer<AppState>(
      builder: (context, state, _) {
        return Container(
          margin: const EdgeInsets.all(16),
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
                    : ListView.builder(
                        controller: _logScrollController,
                        padding: const EdgeInsets.all(8),
                        itemCount: state.commandLogs.length,
                        itemBuilder: (context, i) {
                          final log = state.commandLogs[i];
                          final vulnIdx = log.vulnerabilityIndex ?? -1;
                          final vuln = vulnIdx >= 0 && vulnIdx < state.vulnerabilities.length ? state.vulnerabilities[vulnIdx] : null;
                          final isProof = vuln != null && vuln.proofCommand == log.command && (vuln.status == VulnerabilityStatus.confirmed || vuln.status == VulnerabilityStatus.notVulnerable);
                          final hasVulnIdx = vulnIdx != -1;
                          
                          if (isProof && !_proofKeys.containsKey(vulnIdx)) {
                            _proofKeys[vulnIdx] = GlobalKey();
                          }
                          
                          return Container(
                            key: isProof ? _proofKeys[vulnIdx] : null,
                            margin: const EdgeInsets.only(bottom: 12),
                            decoration: BoxDecoration(
                              color: isProof ? const Color(0xFF00F5FF).withOpacity(0.15) : const Color(0xFF1A1F3A).withOpacity(0.5),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: isProof ? const Color(0xFF00F5FF) : const Color(0xFF00F5FF).withOpacity(0.2),
                                width: isProof ? 2 : 1,
                              ),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                // Command header
                                Container(
                                  padding: const EdgeInsets.all(10),
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
                                    children: [
                                      if (hasVulnIdx) ...[
                                        Container(
                                          width: 24,
                                          height: 24,
                                          decoration: BoxDecoration(
                                            color: _getVulnColor(vulnIdx).withOpacity(0.2),
                                            shape: BoxShape.circle,
                                            border: Border.all(color: _getVulnColor(vulnIdx), width: 2),
                                          ),
                                          child: Center(
                                            child: Text(
                                              '${vulnIdx + 1}',
                                              style: TextStyle(color: _getVulnColor(vulnIdx), fontSize: 10, fontWeight: FontWeight.bold),
                                            ),
                                          ),
                                        ),
                                        const SizedBox(width: 8),
                                        if (isProof) ...[
                                          const Icon(Icons.verified, color: Color(0xFF00F5FF), size: 14),
                                          const SizedBox(width: 6),
                                          const Text('PROOF', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 9)),
                                          const SizedBox(width: 12),
                                        ],
                                      ],
                                      const Icon(Icons.terminal, color: Color(0xFF00F5FF), size: 14),
                                      const SizedBox(width: 8),
                                      Expanded(
                                        child: Text(
                                          log.command,
                                          style: const TextStyle(
                                            color: Color(0xFF00F5FF),
                                            fontFamily: 'monospace',
                                            fontSize: 11,
                                            fontWeight: FontWeight.bold,
                                          ),
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
      
      // Clear previous vulnerabilities
      await DatabaseHelper.clearVulnerabilities();
      appState.loadVulnerabilities();
      if (mounted) setState(() {});
      
      final analyzer = VulnerabilityAnalyzer();
      final vulns = await analyzer.analyzeDevice(_deviceController.text, appState.llmSettings);
      
      for (final v in vulns) {
        await DatabaseHelper.insertVulnerability(v);
      }
      
      appState.loadVulnerabilities();
    } catch (e) {
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
    setState(() => _isExecuting = true);
    final appState = context.read<AppState>();
    final selected = appState.vulnerabilities.where((v) => v.selected).toList();
    
    // Clear command logs before starting new test
    await DatabaseHelper.clearCommandLogs();
    await appState.loadCommandLogs();
    if (mounted) setState(() {});
    
    for (var i = 0; i < selected.length; i++) {
      final vuln = selected[i];
      final vulnIdx = appState.vulnerabilities.indexOf(vuln);
      final executor = ExploitExecutor(
        deviceData: _deviceController.text,
        vulnerabilityIndex: vulnIdx,
        onProgress: (msg) => print('DEBUG: $msg'),
        onCommandExecuted: (cmd, output, idx) async {
          print('DEBUG: Command executed: $cmd');
          print('DEBUG: Output: ${output.substring(0, output.length > 100 ? 100 : output.length)}...');
          await appState.loadCommandLogs();
          if (mounted) {
            setState(() {});
          }
        },
      );
      
      final maxIterations = int.tryParse(await DatabaseHelper.getSetting('max_iterations') ?? '10') ?? 10;
      final status = await executor.testVulnerability(vuln, appState.llmSettings, _requireApproval, maxIterations);
      vuln.status = status;
      vuln.selected = false; // Uncheck only this vulnerability
      await DatabaseHelper.updateVulnerability(vuln);
      await appState.loadVulnerabilities();
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
}
