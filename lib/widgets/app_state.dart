import 'dart:convert';
import 'package:flutter/foundation.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/llm_settings.dart';
import '../database/database_helper.dart';

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

  List<Vulnerability> get vulnerabilities => _vulnerabilities;
  List<CommandLog> get commandLogs => _commandLogs;
  LLMSettings get llmSettings => _llmSettings;
  List<PromptLog> get promptLogs => _promptLogs;
  List<DebugLog> get debugLogs => _debugLogs;
  String? get adminPassword => _adminPassword;
  String? get pendingCommand => _pendingCommand;
  bool get requireApproval => _requireApproval;

  void setAdminPassword(String password) {
    _adminPassword = password;
  }

  void setPendingCommand(String? command) {
    _pendingCommand = command;
    notifyListeners();
  }

  void setRequireApproval(bool value) {
    _requireApproval = value;
    DatabaseHelper.saveSetting('require_approval', value.toString());
    notifyListeners();
  }

  Future<void> initialize() async {
    await DatabaseHelper.clearVulnerabilities();
    await DatabaseHelper.clearCommandLogs();
    await loadLLMSettings();
    await loadVulnerabilities();
    await loadCommandLogs();
    
    final approvalSetting = await DatabaseHelper.getSetting('require_approval');
    _requireApproval = approvalSetting == null ? true : approvalSetting == 'true';
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
    final settingsJson = await DatabaseHelper.getSetting('llm_settings');
    if (settingsJson != null) {
      _llmSettings = LLMSettings.fromJson(json.decode(settingsJson));
    }
    notifyListeners();
  }

  Future<void> updateLLMSettings(LLMSettings settings) async {
    _llmSettings = settings;
    await DatabaseHelper.saveSetting('llm_settings', json.encode(settings.toJson()));
    notifyListeners();
  }

  void addPromptLog(String prompt, String response) {
    _promptLogs.add(PromptLog(prompt, response, DateTime.now()));
    notifyListeners();
  }

  void addDebugLog(String message) {
    _debugLogs.add(DebugLog(message, DateTime.now()));
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
