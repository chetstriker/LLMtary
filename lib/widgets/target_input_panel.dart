import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../utils/device_utils.dart';
import '../utils/file_dialog.dart';
import '../utils/scope_validator.dart';
import '../models/target.dart';
import '../services/recon_service.dart';
import '../models/llm_settings.dart';
import 'app_state.dart';

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
  State<TargetInputPanel> createState() => TargetInputPanelState();
}

class TargetInputPanelState extends State<TargetInputPanel> {
  bool _isScanning = false;
  String _statusMessage = '';

  // Live target list built during scanning (mutable so we can update status)
  final List<Target> _liveTargets = [];

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
    super.dispose();
  }

  /// Public entry point called by the GO button in [_ScopePanel].
  Future<void> startScan(String scopeInput) async {
    await _startScan(scopeInput);
  }

  Future<void> _startScan(String externalInput) async {
    final appState = context.read<AppState>();
    String input = externalInput.trim();

    if (input.isEmpty) {
      final scopeList = appState.currentProject?.scopeList ?? [];
      if (scopeList.isNotEmpty) input = scopeList.join('\n');
    }
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

    // Seed with already-complete targets
    for (final existing in widget.existingTargets) {
      if (existing.status == TargetStatus.complete) _liveTargets.add(existing);
    }

    try {
      final addresses = ReconService.parseTargetInput(input);
      if (addresses.isEmpty) {
        setState(() { _statusMessage = 'No valid addresses found'; _isScanning = false; });
        return;
      }

      final alreadyDone = widget.existingTargets
          .where((t) => t.status == TargetStatus.complete)
          .map((t) => t.address)
          .toSet();
      List<String> toScan = addresses.where((a) => !alreadyDone.contains(a)).toList();

      final exclusionList = appState.currentProject?.exclusionList ?? [];
      if (exclusionList.isNotEmpty) {
        final excluded = toScan.where((a) {
          final r = ScopeValidator.validate(a, ['*'], exclusionList);
          return r == ScopeResult.excluded;
        }).toList();
        if (excluded.isNotEmpty) {
          for (final addr in excluded) widget.onProgress('[$addr] Excluded by engagement scope — skipping');
          toScan = toScan.where((a) => !excluded.contains(a)).toList();
        }
      }

      // Add pending entries
      for (final addr in toScan) {
        if (!_liveTargets.any((t) => t.address == addr)) {
          _liveTargets.add(Target(address: addr, status: TargetStatus.pending));
        }
      }

      // Push ALL targets (including pending) to AppState immediately so the
      // stats bar shows the correct count as soon as GO is pressed.
      await widget.onTargetsDiscovered(List.from(_liveTargets));

      if (toScan.isEmpty) {
        final completeCount = _liveTargets.where((t) => t.status == TargetStatus.complete).length;
        setState(() {
          _statusMessage = '$completeCount target(s) already scanned — nothing new to scan';
          _isScanning = false;
        });
        if (completeCount > 0) widget.onScanComplete?.call();
        return;
      }

      // Fast parallel host-alive pre-sweep
      List<String> aliveHosts = toScan;
      if (toScan.length > 1) {
        setState(() => _statusMessage = 'Checking which of ${toScan.length} hosts are up...');
        widget.onProgress('Host pre-sweep: running nmap -sn on ${toScan.length} targets...');
        final nmapResult = await _nmapPingSweep(toScan, widget.onProgress);
        if (nmapResult != null) {
          // nmap ran successfully — its result is definitive, no ping fallback
          aliveHosts = nmapResult;
        } else {
          // nmap unavailable or failed — fall back to parallel pings
          widget.onProgress('nmap unavailable — falling back to parallel ping...');
          final aliveResults = await Future.wait(
            toScan.map((addr) => ReconService.quickHostAlive(addr).then((up) => MapEntry(addr, up))),
          );
          aliveHosts = aliveResults.where((e) => e.value).map((e) => e.key).toList();
        }
        final deadHosts = toScan.where((a) => !aliveHosts.contains(a)).toList();
        for (final addr in deadHosts) {
          final dead = _liveTargets.firstWhere(
            (t) => t.address == addr,
            orElse: () => Target(address: addr),
          );
          _liveTargets.removeWhere((t) => t.address == addr);
          await widget.onTargetDeleted?.call(dead);
          widget.onProgress('[$addr] Pre-sweep: host is down — skipping');
        }
        // Push pruned list back to sync any remaining state changes
        await widget.onTargetsDiscovered(List.from(_liveTargets));
        if (aliveHosts.isEmpty) {
          setState(() {
            _statusMessage = 'No hosts responded — all ${toScan.length} target(s) appear down';
            _isScanning = false;
          });
          return;
        }
        widget.onProgress('Pre-sweep complete: ${aliveHosts.length}/${toScan.length} hosts are up');
        setState(() => _statusMessage = '${aliveHosts.length}/${toScan.length} hosts up — starting recon...');
      }

      setState(() => _statusMessage = 'Scanning ${aliveHosts.length} target(s)...');

      final firstScope = aliveHosts.isNotEmpty
          ? DeviceUtils.classifyTarget(aliveHosts.first)
          : TargetScope.internal;
      final concurrency = firstScope == TargetScope.external ? 2 : 4;

      for (int batchStart = 0; batchStart < aliveHosts.length; batchStart += concurrency) {
        final batch = aliveHosts.skip(batchStart).take(concurrency).toList();
        for (final addr in batch) _updateTargetStatus(addr, TargetStatus.scanning);

        final batchResults = await Future.wait(batch.map((addr) async {
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
            onTokensUsed: (sent, received) {
              // Use the captured appState reference — safe across async gaps.
              appState.recordTokenUsage('recon', sent, received);
            },
          );
          return MapEntry(
            addr,
            await recon.reconTarget(
              addr, widget.projectName,
              projectId: widget.projectId,
              targetId: widget.getTargetId?.call(addr) ?? 0,
            ),
          );
        }));

        for (final entry in batchResults) {
          final addr = entry.key;
          final filePath = entry.value;
          if (filePath != null) {
            _updateTargetStatus(addr, TargetStatus.complete, jsonFilePath: filePath);
          } else {
            _updateTargetStatus(addr, TargetStatus.excluded);
          }
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
      setState(() { _statusMessage = 'Error: $e'; _isScanning = false; });
    }
  }

  /// Run a single nmap -sn sweep over all [addresses] and return the live ones.
  /// Returns null if nmap is unavailable or the sweep fails (caller should
  /// fall back to ping). Returns an empty list if nmap ran successfully but
  /// found no live hosts (caller should NOT fall back — result is definitive).
  static Future<List<String>?> _nmapPingSweep(
    List<String> addresses,
    void Function(String) onProgress,
  ) async {
    try {
      final result = await Process.run(
        'nmap',
        ['-sn', '-T4', '--open', '-oG', '-', ...addresses],
      ).timeout(const Duration(minutes: 3));
      if (result.exitCode != 0) return null;
      final output = result.stdout as String;
      if (output.isEmpty) return null;
      final alive = RegExp(r'Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\s')
          .allMatches(output)
          .map((m) => m.group(1)!)
          .toList();
      onProgress('nmap -sn found ${alive.length}/${addresses.length} live hosts');
      return alive;
    } catch (_) {
      return null;
    }
  }

  void _updateTargetStatus(String address, TargetStatus status, {String? jsonFilePath}) {
    final idx = _liveTargets.indexWhere((t) => t.address == address);
    if (idx == -1) return;
    _liveTargets[idx].status = status;
    if (jsonFilePath != null) _liveTargets[idx].jsonFilePath = jsonFilePath;
    if (mounted) setState(() {});
  }

  /// Called by [_ScopePanel] via [onPickFile] to load a file into the scope field.
  Future<void> pickFileIntoController(TextEditingController scopeCtrl) async {
    final result = await FileDialog.pickFiles(
      dialogTitle: 'Open target list',
      allowedExtensions: ['txt'],
    );
    if (result != null && result.files.single.path != null) {
      final content = await File(result.files.single.path!).readAsString();
      final lines = content
          .trim()
          .split('\n')
          .map((l) => l.trim())
          .where((l) => l.isNotEmpty)
          .join('\n');
      final existing = scopeCtrl.text.trim();
      scopeCtrl.text = existing.isEmpty ? lines : '$existing\n$lines';
    }
  }

  bool get isScanning => _isScanning;
  String get statusMessage => _statusMessage;

  @override
  Widget build(BuildContext context) => const SizedBox.shrink();
}
