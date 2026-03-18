import 'dart:io';
import 'package:flutter/material.dart';
import '../utils/file_dialog.dart';
import '../models/target.dart';
import '../services/recon_service.dart';
import '../models/llm_settings.dart';

class TargetInputPanel extends StatefulWidget {
  final LLMSettings llmSettings;
  final bool requireApproval;
  final String? adminPassword;
  final Future<bool> Function()? onPasswordNeeded;
  final Future<String?> Function(String)? onInstallPasswordNeeded;
  final Future<String?> Function(String)? onApprovalNeeded;
  final Function(String) onProgress;
  final Function(String, String) onPromptResponse;
  final Function(String, String)? onCommandExecuted;
  final Future<void> Function(List<Target>) onTargetsDiscovered;
  final Future<void> Function(Target)? onTargetDeleted;
  final VoidCallback? onScanComplete;
  final List<Target> targets;
  final List<Target> existingTargets;
  final Target? selectedTarget;
  final Function(Target) onTargetSelected;
  final String projectName;
  final int projectId;
  final int Function(String address)? getTargetId;

  const TargetInputPanel({
    super.key,
    required this.llmSettings,
    required this.requireApproval,
    this.adminPassword,
    this.onPasswordNeeded,
    this.onInstallPasswordNeeded,
    this.onApprovalNeeded,
    required this.onProgress,
    required this.onPromptResponse,
    this.onCommandExecuted,
    required this.onTargetsDiscovered,
    this.onTargetDeleted,
    this.onScanComplete,
    required this.targets,
    this.existingTargets = const [],
    required this.selectedTarget,
    required this.onTargetSelected,
    this.projectName = 'default',
    this.projectId = 0,
    this.getTargetId,
  });

  @override
  State<TargetInputPanel> createState() => _TargetInputPanelState();
}

class _TargetInputPanelState extends State<TargetInputPanel> {
  final _inputController = TextEditingController();
  bool _isScanning = false;
  String _statusMessage = '';

  // Live target list built during scanning (mutable so we can update status)
  final List<Target> _liveTargets = [];

  static const _cyan = Color(0xFF00F5FF);
  static const _bg = Color(0xFF1A1F3A);
  static const _darkBg = Color(0xFF0A0E27);

  @override
  void initState() {
    super.initState();
    // Seed live list from already-persisted targets so they show on restore
    for (final t in widget.existingTargets) {
      if (!_liveTargets.any((l) => l.address == t.address)) {
        _liveTargets.add(t);
      }
    }
  }

  @override
  void dispose() {
    _inputController.dispose();
    super.dispose();
  }

  Future<void> _pickFile() async {
    final result = await FileDialog.pickFiles(
      dialogTitle: 'Open target list',
      allowedExtensions: ['txt'],
    );
    if (result != null && result.files.single.path != null) {
      final content = await File(result.files.single.path!).readAsString();
      _inputController.text = content
          .trim()
          .split('\n')
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty)
          .join('\n');
    }
  }

  Future<void> _startScan() async {
    final input = _inputController.text.trim();
    if (input.isEmpty) return;

    if (widget.adminPassword == null && widget.onPasswordNeeded != null) {
      final ok = await widget.onPasswordNeeded!();
      if (!ok) return;
    }

    setState(() {
      _isScanning = true;
      _statusMessage = 'Parsing targets...';
      _liveTargets.clear();
    });

    // Seed live list with already-complete targets from DB so they show immediately
    for (final existing in widget.existingTargets) {
      if (existing.status == TargetStatus.complete) {
        _liveTargets.add(existing);
      }
    }
    await widget.onTargetsDiscovered(List.from(_liveTargets));

    try {
      final addresses = ReconService.parseTargetInput(input);
      if (addresses.isEmpty) {
        setState(() {
          _statusMessage = 'No valid addresses found';
          _isScanning = false;
        });
        return;
      }

      // Only scan addresses not already complete in DB
      final alreadyDone = widget.existingTargets
          .where((t) => t.status == TargetStatus.complete)
          .map((t) => t.address)
          .toSet();
      final toScan = addresses.where((a) => !alreadyDone.contains(a)).toList();

      // Add pending entries for addresses that still need scanning
      for (final addr in toScan) {
        if (!_liveTargets.any((t) => t.address == addr)) {
          _liveTargets.add(Target(address: addr, status: TargetStatus.pending));
        }
      }

      if (toScan.isEmpty) {
        final completeCount = _liveTargets.where((t) => t.status == TargetStatus.complete).length;
        setState(() {
          _statusMessage = '$completeCount target(s) already scanned — nothing new to scan';
          _isScanning = false;
        });
        if (completeCount > 0) widget.onScanComplete?.call();
        return;
      }

      setState(() => _statusMessage = 'Scanning ${toScan.length} new target(s)...');

      for (int i = 0; i < toScan.length; i++) {
        final addr = toScan[i];
        _updateTargetStatus(addr, TargetStatus.scanning);

        final recon = ReconService(
          settings: widget.llmSettings,
          requireApproval: widget.requireApproval,
          adminPassword: widget.adminPassword,
          onApprovalNeeded: widget.onApprovalNeeded,
          onPasswordNeeded: widget.onInstallPasswordNeeded,
          onCommandExecuted: widget.onCommandExecuted,
          onProgress: (msg) {
            widget.onProgress(msg);
            if (mounted) setState(() => _statusMessage = msg);
          },
          onPromptResponse: widget.onPromptResponse,
        );

        final filePath = await recon.reconTarget(
          addr, widget.projectName,
          projectId: widget.projectId,
          targetId: widget.getTargetId?.call(addr) ?? 0,
        );

        if (filePath != null) {
          _updateTargetStatus(addr, TargetStatus.complete, jsonFilePath: filePath);
        } else {
          _updateTargetStatus(addr, TargetStatus.excluded);
        }

        final useful = _liveTargets.where((t) => t.status == TargetStatus.complete).toList();
        await widget.onTargetsDiscovered(List.from(useful));
      }

      final completeCount = _liveTargets.where((t) => t.status == TargetStatus.complete).length;
      setState(() {
        _statusMessage = completeCount == 0
            ? 'No useful targets found'
            : '$completeCount of ${addresses.length} target(s) ready';
        _isScanning = false;
      });
      if (completeCount > 0) widget.onScanComplete?.call();
    } catch (e) {
      setState(() {
        _statusMessage = 'Error: $e';
        _isScanning = false;
      });
    }
  }

  void _updateTargetStatus(String address, TargetStatus status, {String? jsonFilePath}) {
    final idx = _liveTargets.indexWhere((t) => t.address == address);
    if (idx == -1) return;
    _liveTargets[idx].status = status;
    if (jsonFilePath != null) _liveTargets[idx].jsonFilePath = jsonFilePath;
    if (mounted) setState(() {});
  }

  Future<void> _deleteTarget(Target target) async {
    setState(() => _liveTargets.removeWhere((t) => t.address == target.address));
    await widget.onTargetDeleted?.call(target);
    final useful = _liveTargets.where((t) => t.status == TargetStatus.complete).toList();
    await widget.onTargetsDiscovered(List.from(useful));
  }

  void _reset() {
    setState(() {
      _liveTargets.clear();
      _statusMessage = '';
      _inputController.clear();
    });
    widget.onTargetsDiscovered([]);
  }

  Color _statusColor(TargetStatus status) {
    switch (status) {
      case TargetStatus.complete:
        return const Color(0xFF00FF88);
      case TargetStatus.scanning:
        return _cyan;
      case TargetStatus.excluded:
        return Colors.white24;
      case TargetStatus.pending:
        return Colors.white38;
    }
  }

  IconData _statusIcon(TargetStatus status) {
    switch (status) {
      case TargetStatus.complete:
        return Icons.check_circle;
      case TargetStatus.scanning:
        return Icons.radar;
      case TargetStatus.excluded:
        return Icons.remove_circle_outline;
      case TargetStatus.pending:
        return Icons.circle_outlined;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.all(8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _bg,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: _cyan.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Input area (always visible) ───────────────────────────────────
          const Text('TARGET SCOPE',
              style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 10)),
          const SizedBox(height: 6),
          TextField(
            controller: _inputController,
            maxLines: 3,
            enabled: !_isScanning,
            style: const TextStyle(
                color: Colors.white, fontFamily: 'monospace', fontSize: 10),
            decoration: InputDecoration(
              hintText: 'IP, hostname, CIDR (192.168.1.0/24), comma or newline separated',
              hintStyle: const TextStyle(color: Colors.white38, fontSize: 9),
              border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: const BorderSide(color: _cyan)),
              enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: _cyan.withOpacity(0.3))),
              focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: const BorderSide(color: _cyan, width: 2)),
              disabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide(color: _cyan.withOpacity(0.1))),
              filled: true,
              fillColor: _darkBg,
              contentPadding: const EdgeInsets.all(8),
            ),
          ),
          const SizedBox(height: 6),
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: _isScanning ? null : _startScan,
                  icon: _isScanning
                      ? const SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(
                              color: Colors.white, strokeWidth: 2))
                      : const Icon(Icons.radar, color: Colors.white, size: 14),
                  label: Text(
                    _isScanning ? 'SCANNING...' : 'GO',
                    style: const TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                        fontSize: 12),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _cyan,
                    disabledBackgroundColor: _cyan.withOpacity(0.3),
                    padding: const EdgeInsets.symmetric(vertical: 10),
                  ),
                ),
              ),
              const SizedBox(width: 6),
              OutlinedButton.icon(
                onPressed: _isScanning ? null : _pickFile,
                icon: const Icon(Icons.upload_file, size: 14, color: _cyan),
                label: const Text('FILE',
                    style: TextStyle(color: _cyan, fontSize: 10)),
                style: OutlinedButton.styleFrom(
                  side: BorderSide(color: _cyan.withOpacity(0.5)),
                  padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 10),
                ),
              ),
            ],
          ),

          // ── Live target list ──────────────────────────────────────────────
          if (_liveTargets.isNotEmpty) ...[
            const SizedBox(height: 10),
            const Text('TARGETS',
                style: TextStyle(
                    color: _cyan, fontWeight: FontWeight.bold, fontSize: 10)),
            const SizedBox(height: 6),
            Flexible(
              child: ListView.builder(
                shrinkWrap: true,
                itemCount: _liveTargets.length,
                itemBuilder: (context, index) {
                  final t = _liveTargets[index];
                  final color = _statusColor(t.status);
                  final isSelectable = t.status == TargetStatus.complete;
                  final isSelected = widget.selectedTarget?.address == t.address;
                  final isScanning = t.status == TargetStatus.scanning;

                  return GestureDetector(
                    onTap: isSelectable ? () => widget.onTargetSelected(t) : null,
                    child: Container(
                      margin: const EdgeInsets.only(bottom: 4),
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
                      decoration: BoxDecoration(
                        color: isSelected ? _cyan.withOpacity(0.12) : _darkBg,
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(
                            color: isSelected ? _cyan : color.withOpacity(0.4)),
                      ),
                      child: Row(
                        children: [
                          isScanning
                              ? SizedBox(
                                  width: 14,
                                  height: 14,
                                  child: CircularProgressIndicator(
                                      color: color, strokeWidth: 2))
                              : Icon(_statusIcon(t.status), size: 14, color: color),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              t.address,
                              style: TextStyle(
                                  color: isSelectable ? Colors.white : Colors.white38,
                                  fontSize: 10,
                                  fontFamily: 'monospace'),
                            ),
                          ),
                          if (isSelected)
                            const Icon(Icons.chevron_right, size: 12, color: _cyan),
                          if (!isScanning)
                            GestureDetector(
                              onTap: () => _deleteTarget(t),
                              child: const Padding(
                                padding: EdgeInsets.only(left: 6),
                                child: Icon(Icons.close, size: 12, color: Colors.white24),
                              ),
                            ),
                        ],
                      ),
                    ),
                  );
                },
              ),
            ),
          ],

          // ── Status message ────────────────────────────────────────────────
          if (_statusMessage.isNotEmpty) ...[
            const SizedBox(height: 4),
            Text(
              _statusMessage,
              style: const TextStyle(color: Colors.white38, fontSize: 9),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ],
      ),
    );
  }
}
