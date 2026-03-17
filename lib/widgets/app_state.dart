import 'dart:io';
import 'package:flutter/foundation.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/llm_settings.dart';
import '../models/llm_provider.dart';
import '../models/target.dart';
import '../models/project.dart';
import '../database/database_helper.dart';
import '../constants/app_constants.dart';
import '../services/storage_service.dart';

class PromptLog {
  final String prompt;
  final String response;
  final DateTime timestamp;
  PromptLog(this.prompt, this.response, this.timestamp);
}

class DebugLog {
  final String message;
  final DateTime timestamp;
  DebugLog(this.message, this.timestamp);
}

class AppState extends ChangeNotifier {
  List<Vulnerability> _vulnerabilities = [];
  List<CommandLog> _commandLogs = [];
  LLMSettings _llmSettings = LLMSettings.defaultSettings();
  final List<PromptLog> _promptLogs = [];
  final List<DebugLog> _debugLogs = [];
  String? _adminPassword;
  String? _pendingCommand;
  bool _requireApproval = true;
  bool _hasResults = false;
  List<Target> _targets = [];
  Target? _selectedTarget;
  bool _scanComplete = false;
  bool _analysisComplete = false;
  Project? _currentProject;

  List<Vulnerability> get vulnerabilities => _vulnerabilities;
  List<CommandLog> get commandLogs => _commandLogs;
  LLMSettings get llmSettings => _llmSettings;
  List<PromptLog> get promptLogs => _promptLogs;
  List<DebugLog> get debugLogs => _debugLogs;
  String? get adminPassword => _adminPassword;
  String? get pendingCommand => _pendingCommand;
  bool get requireApproval => _requireApproval;
  bool get hasResults => _hasResults;
  List<Target> get targets => _targets;
  Target? get selectedTarget => _selectedTarget;
  bool get scanComplete => _scanComplete;
  bool get analysisComplete => _analysisComplete;
  bool get sessionPasswordEntered => _adminPassword != null && _adminPassword!.isNotEmpty;
  Project? get currentProject => _currentProject;
  String get currentProjectName => _currentProject?.name ?? 'default';
  int get _projectId => _currentProject?.id ?? 0;
  int get _activeTargetId => _selectedTarget?.id ?? 0;

  Future<void> setCurrentProject(Project? project) async {
    _currentProject = project;
    _adminPassword = null;
    _targets = [];
    _selectedTarget = null;
    _vulnerabilities = [];
    _commandLogs = [];
    _promptLogs.clear();
    _debugLogs.clear();
    _scanComplete = false;
    _analysisComplete = false;
    _hasResults = false;
    if (project != null) await loadProjectData();
    notifyListeners();
  }

  Future<void> loadProjectData() async {
    final project = _currentProject;
    if (project == null) return;

    _targets = await DatabaseHelper.getTargets(project.id!);

    // Verify JSON files still exist; exclude targets whose files are missing
    for (final t in _targets) {
      if (t.status == TargetStatus.complete && t.jsonFilePath.isNotEmpty) {
        if (!await File(t.jsonFilePath).exists()) {
          t.status = TargetStatus.excluded;
          await DatabaseHelper.updateTarget(t);
          addDebugLog('Warning: JSON file missing for ${t.address}, marked excluded');
        }
      }
    }

    // Derive flags after targets are loaded
    _scanComplete = project.scanComplete || _targets.any((t) => t.status == TargetStatus.complete);
    _analysisComplete = project.analysisComplete || _targets.any((t) => t.analysisComplete);
    _hasResults = project.hasResults;

    _vulnerabilities = await DatabaseHelper.getVulnerabilities();
    _commandLogs = await DatabaseHelper.getCommandLogs();

    final promptMaps = await DatabaseHelper.getPromptLogs(project.id!);
    _promptLogs.clear();
    for (final m in promptMaps) {
      _promptLogs.add(PromptLog(
        m['prompt'] as String,
        m['response'] as String,
        DateTime.parse(m['timestamp'] as String),
      ));
    }

    final debugMaps = await DatabaseHelper.getDebugLogs(project.id!);
    _debugLogs.clear();
    for (final m in debugMaps) {
      _debugLogs.add(DebugLog(
        m['message'] as String,
        DateTime.parse(m['timestamp'] as String),
      ));
    }

    notifyListeners();
  }

  Future<void> setTargets(List<Target> targets) async {
    // Merge: keep existing DB targets, add/update with newly scanned ones
    final existingByAddress = {for (final t in _targets) t.address: t};
    for (final t in targets) {
      final existing = existingByAddress[t.address];
      if (existing != null && existing.id != null) {
        // Already in DB — update status and file path
        existing.status = t.status;
        existing.jsonFilePath = t.jsonFilePath;
        await DatabaseHelper.updateTarget(existing);
        existingByAddress[t.address] = existing;
      } else if (existing == null || existing.id == null) {
        // New target — insert into DB
        if (_projectId > 0) {
          final id = await DatabaseHelper.insertTarget(_projectId, t);
          t.id = id;
          t.projectId = _projectId;
        }
        existingByAddress[t.address] = t;
      }
    }
    _targets = existingByAddress.values.toList();
    notifyListeners();
  }

  void setScanComplete(bool value) {
    _scanComplete = value;
    if (value && _projectId > 0) {
      DatabaseHelper.updateProjectFlags(_projectId, scanComplete: true);
    }
    notifyListeners();
  }

  void setAnalysisComplete(bool value) {
    _analysisComplete = value;
    if (value && _projectId > 0) {
      DatabaseHelper.updateProjectFlags(_projectId, analysisComplete: true);
    }
    notifyListeners();
  }

  Future<void> addTarget(Target target) async {
    if (_projectId > 0) {
      // Check if this address already exists in DB to avoid duplicates
      final existing = _targets.firstWhere(
        (t) => t.address == target.address,
        orElse: () => target,
      );
      if (existing.id != null) {
        // Already persisted — just update status
        existing.status = target.status;
        existing.jsonFilePath = target.jsonFilePath;
        await DatabaseHelper.updateTarget(existing);
        notifyListeners();
        return;
      }
      final id = await DatabaseHelper.insertTarget(_projectId, target);
      target.id = id;
      target.projectId = _projectId;
    }
    if (!_targets.any((t) => t.address == target.address)) {
      _targets.add(target);
    }
    notifyListeners();
  }

  Future<void> deleteTarget(Target target) async {
    _targets.removeWhere((t) => t.address == target.address);
    if (target.id != null) {
      final db = await DatabaseHelper.database;
      await db.delete('vulnerabilities', where: 'targetId = ?', whereArgs: [target.id]);
      await db.delete('command_logs', where: 'targetId = ?', whereArgs: [target.id]);
      await db.delete('prompt_logs', where: 'targetId = ?', whereArgs: [target.id]);
      await db.delete('debug_logs', where: 'targetId = ?', whereArgs: [target.id]);
      await db.delete('targets', where: 'id = ?', whereArgs: [target.id]);
    }
    if (_selectedTarget?.address == target.address) _selectedTarget = null;
    _vulnerabilities.removeWhere((v) => v.targetAddress == target.address);
    if (_targets.isEmpty) {
      _scanComplete = false;
      _analysisComplete = false;
    }
    notifyListeners();
  }

  Future<void> updateTargetStatus(Target target) async {
    if (target.id != null) {
      await DatabaseHelper.updateTarget(target);
    }
  }

  void selectTarget(Target? target) {
    _selectedTarget = target;
    notifyListeners();
  }

  void setAdminPassword(String password) {
    _adminPassword = password;
  }

  void setPendingCommand(String? command) {
    _pendingCommand = command;
    notifyListeners();
  }

  void setHasResults(bool value) {
    _hasResults = value;
    if (value && _projectId > 0) {
      DatabaseHelper.updateProjectFlags(_projectId, hasResults: true);
    }
    notifyListeners();
  }

  void setRequireApproval(bool value) {
    _requireApproval = value;
    DatabaseHelper.saveSetting(SettingsKeys.requireApproval, value.toString());
    notifyListeners();
  }

  Future<void> initialize() async {
    await loadLLMSettings();
    final approvalSetting = await DatabaseHelper.getSetting(SettingsKeys.requireApproval);
    _requireApproval = approvalSetting == null ? true : approvalSetting == 'true';
    final customPath = await DatabaseHelper.getSetting(SettingsKeys.storageBasePath);
    if (customPath != null && customPath.isNotEmpty) {
      StorageService.setCustomBasePath(customPath);
    }
    notifyListeners();
  }

  Future<void> loadVulnerabilities() async {
    _vulnerabilities = await DatabaseHelper.getVulnerabilities();
    notifyListeners();
  }

  Future<void> loadCommandLogs() async {
    _commandLogs = await DatabaseHelper.getCommandLogs();
    notifyListeners();
  }

  Future<void> loadLLMSettings() async {
    final currentProvider = await DatabaseHelper.getSetting('current_provider');
    if (currentProvider != null) {
      final providerSettings = await DatabaseHelper.getProviderSettings(currentProvider);
      if (providerSettings != null) {
        _llmSettings = LLMSettings(
          provider: LLMProvider.values.firstWhere((e) => e.name == currentProvider, orElse: () => LLMProvider.none),
          baseUrl: providerSettings['baseUrl'] as String?,
          apiKey: providerSettings['apiKey'] as String?,
          modelName: providerSettings['modelName'] as String? ?? '',
          temperature: (providerSettings['temperature'] as num?)?.toDouble() ?? 0.22,
          maxTokens: providerSettings['maxTokens'] as int? ?? 32000,
          timeoutSeconds: providerSettings['timeoutSeconds'] as int? ?? 180,
        );
      }
    }
    notifyListeners();
  }

  Future<void> updateLLMSettings(LLMSettings settings) async {
    _llmSettings = settings;
    await DatabaseHelper.saveSetting('current_provider', settings.provider.name);
    await DatabaseHelper.saveProviderSettings(settings.provider.name, {
      'baseUrl': settings.baseUrl,
      'apiKey': settings.apiKey,
      'modelName': settings.modelName,
      'temperature': settings.temperature,
      'maxTokens': settings.maxTokens,
      'timeoutSeconds': settings.timeoutSeconds,
    });
    notifyListeners();
  }

  void addPromptLog(String prompt, String response) {
    _promptLogs.add(PromptLog(prompt, response, DateTime.now()));
    if (_projectId > 0) {
      DatabaseHelper.insertPromptLog(_projectId, _activeTargetId, prompt, response);
    }
    notifyListeners();
  }

  void addDebugLog(String message) {
    print('DEBUG: $message');
    _debugLogs.add(DebugLog(message, DateTime.now()));
    if (_projectId > 0) {
      DatabaseHelper.insertDebugLog(_projectId, _activeTargetId, message);
    }
    notifyListeners();
  }

  void clearPromptLogs() {
    _promptLogs.clear();
    notifyListeners();
  }

  void clearDebugLogs() {
    _debugLogs.clear();
    notifyListeners();
  }
}
