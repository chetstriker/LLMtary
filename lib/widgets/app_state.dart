import 'dart:convert';
import 'package:flutter/foundation.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/llm_settings.dart';
import '../models/llm_provider.dart';
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
    // Save current provider
    await DatabaseHelper.saveSetting('current_provider', settings.provider.name);
    // Save provider-specific settings
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
    notifyListeners();
  }

  void addDebugLog(String message) {
    print('DEBUG: $message');
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
