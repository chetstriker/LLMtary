import 'dart:convert';
import 'package:flutter/foundation.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/llm_settings.dart';
import '../database/database_helper.dart';

class AppState extends ChangeNotifier {
  List<Vulnerability> _vulnerabilities = [];
  List<CommandLog> _commandLogs = [];
  LLMSettings _llmSettings = LLMSettings.defaultSettings();

  List<Vulnerability> get vulnerabilities => _vulnerabilities;
  List<CommandLog> get commandLogs => _commandLogs;
  LLMSettings get llmSettings => _llmSettings;

  Future<void> initialize() async {
    await DatabaseHelper.clearVulnerabilities();
    await DatabaseHelper.clearCommandLogs();
    await loadLLMSettings();
    await loadVulnerabilities();
    await loadCommandLogs();
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
}
