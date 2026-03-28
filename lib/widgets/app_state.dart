import 'dart:io';
import 'package:flutter/foundation.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/llm_settings.dart';
import '../models/llm_provider.dart';
import '../models/target.dart';
import '../models/project.dart';
import '../models/credential.dart';
import '../database/database_helper.dart';
import '../constants/app_constants.dart';
import '../services/storage_service.dart';
import '../services/background_process_manager.dart';

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
  final List<DiscoveredCredential> _credentials = [];
  final Set<String> _credentialFingerprints = {};
  final List<Map<String, String>> _confirmedArtifacts = [];
  /// Tracks which target addresses have already received an authenticated
  /// re-analysis pass so we don't re-run it on every subsequent execution.
  final Set<String> _authenticatedReanalysisTargets = {};
  String _executionStatus = '';
  String? _adminPassword;
  String? _pendingCommand;
  bool _requireApproval = true;
  bool _hasResults = false;
  List<Target> _targets = [];
  Target? _selectedTarget;
  bool _scanComplete = false;
  bool _analysisComplete = false;
  Project? _currentProject;

  // Token accumulators
  int _tokensSentTotal = 0;
  int _tokensReceivedTotal = 0;
  int _tokensSentRecon = 0;
  int _tokensReceivedRecon = 0;
  int _tokensSentAnalyze = 0;
  int _tokensReceivedAnalyze = 0;
  int _tokensSentExecute = 0;
  int _tokensReceivedExecute = 0;
  int _tokensSentReport = 0;
  int _tokensReceivedReport = 0;

  List<Vulnerability> get vulnerabilities => _vulnerabilities;
  List<CommandLog> get commandLogs => _commandLogs;
  List<String> get projectScope =>
      _targets.map((t) => t.address).toSet().toList()..sort();
  LLMSettings get llmSettings => _llmSettings;
  List<PromptLog> get promptLogs => _promptLogs;
  List<DebugLog> get debugLogs => _debugLogs;
  List<DiscoveredCredential> get credentials => List.unmodifiable(_credentials);
  List<Map<String, String>> get confirmedArtifacts => List.unmodifiable(_confirmedArtifacts);
  String get executionStatus => _executionStatus;
  String? get adminPassword => _adminPassword;
  String? get pendingCommand => _pendingCommand;
  bool get requireApproval => _requireApproval;
  bool get hasResults => _hasResults;
  List<Target> get targets => _targets;
  Target? get selectedTarget => _selectedTarget;
  bool get scanComplete => _scanComplete;
  bool get analysisComplete => _analysisComplete;
  bool get sessionPasswordEntered => _adminPassword != null && _adminPassword!.isNotEmpty;
  // Tab navigation
  int _activeTab = 0;

  int get activeTab => _activeTab;

  void setActiveTab(int index) {
    _activeTab = index;
    notifyListeners();
  }

  bool get tab1Unlocked => true;
  bool get tab2Unlocked => scanComplete;
  bool get tab3Unlocked => analysisComplete;
  bool get tab4Unlocked => hasResults || analysisComplete;

  Project? get currentProject => _currentProject;
  String get currentProjectName => _currentProject?.name ?? 'default';
  int get _projectId => _currentProject?.id ?? 0;
  int get _activeTargetId => _selectedTarget?.id ?? 0;

  int get tokensSentTotal => _tokensSentTotal;
  int get tokensReceivedTotal => _tokensReceivedTotal;
  int get tokensSentRecon => _tokensSentRecon;
  int get tokensReceivedRecon => _tokensReceivedRecon;
  int get tokensSentAnalyze => _tokensSentAnalyze;
  int get tokensReceivedAnalyze => _tokensReceivedAnalyze;
  int get tokensSentExecute => _tokensSentExecute;
  int get tokensReceivedExecute => _tokensReceivedExecute;
  int get tokensSentReport => _tokensSentReport;
  int get tokensReceivedReport => _tokensReceivedReport;

  void recordTokenUsage(String phase, int sent, int received, {int targetId = 0}) {
    _tokensSentTotal += sent;
    _tokensReceivedTotal += received;
    switch (phase) {
      case 'recon':   _tokensSentRecon += sent;   _tokensReceivedRecon += received;
      case 'analyze': _tokensSentAnalyze += sent; _tokensReceivedAnalyze += received;
      case 'execute': _tokensSentExecute += sent; _tokensReceivedExecute += received;
      case 'report':  _tokensSentReport += sent;  _tokensReceivedReport += received;
    }
    if (_projectId > 0) {
      DatabaseHelper.insertTokenUsage(
        _projectId, targetId > 0 ? targetId : _activeTargetId, phase, sent, received);
    }
    notifyListeners();
  }

  /// Add a credential to the bank, deduplicating by fingerprint.
  /// Only verified (extracted_from_output) credentials are persisted to DB.
  /// Inferred credentials are kept in memory for prompt injection but not saved.
  void addCredential(DiscoveredCredential cred) {
    final fp = cred.fingerprint;
    if (_credentialFingerprints.contains(fp)) return;
    _credentialFingerprints.add(fp);
    _credentials.add(cred);
    // Only persist credentials that were actually observed in command output
    if (cred.isVerified && _currentProject?.id != null) {
      DatabaseHelper.insertCredential(cred, _currentProject!.id!);
    }
    notifyListeners();
  }

  /// Return all credentials as a formatted prompt block for LLM injection.
  /// Verified creds are labeled [CONFIRMED from output]; inferred are labeled
  /// [INFERRED — not verified] so the LLM knows to treat them with less certainty.
  String credentialBankPromptBlock(String host) {
    if (_credentials.isEmpty) return '';
    final verified = _credentials.where((c) => c.isVerified).toList();
    final inferred = _credentials.where((c) => !c.isVerified).toList();
    final buf = StringBuffer('## CREDENTIAL BANK — previously discovered credentials for this project:\n');
    if (verified.isNotEmpty) {
      buf.writeln('### Confirmed credentials (seen in command output — high confidence):');
      for (final c in verified) { buf.writeln('  - ${c.toPromptLine()}'); }
    }
    if (inferred.isNotEmpty) {
      buf.writeln('### Inferred credentials (LLM-suggested, not yet verified — try but do not assume valid):');
      for (final c in inferred) { buf.writeln('  - ${c.toPromptLine()}'); }
    }
    buf.writeln('Try confirmed credentials against this target first.');
    return buf.toString();
  }

  /// Record a confirmed vulnerability's artifacts for cross-vuln chaining.
  void addConfirmedArtifact(Vulnerability vuln) {
    if (vuln.status != VulnerabilityStatus.confirmed) return;
    final evidence = vuln.statusReason.isNotEmpty ? vuln.statusReason : vuln.evidence;
    _confirmedArtifacts.add({
      'problem': vuln.problem,
      'type': vuln.vulnerabilityType,
      'target': vuln.targetAddress,
      'evidence': evidence.length > 300 ? evidence.substring(0, 300) : evidence,
      'accessSurface': _deriveAccessSurface(vuln),
    });
    notifyListeners();
  }

  String _deriveAccessSurface(Vulnerability vuln) {
    final t = vuln.vulnerabilityType.toLowerCase();
    if (t.contains('rce') || t.contains('command injection')) {
      return 'OS command execution on ${vuln.targetAddress} — enumerate users, files, running processes, network connections, and credentials.';
    } else if (t.contains('sqli') || t.contains('sql injection')) {
      return 'Database query access on ${vuln.targetAddress} — extract schemas, user tables, hashed passwords, and session tokens.';
    } else if (t.contains('auth bypass') || t.contains('default credential')) {
      return 'Authenticated session on ${vuln.targetAddress} — attempt privilege escalation, access admin functions, and enumerate internal resources.';
    } else if (t.contains('lfi') || t.contains('path traversal')) {
      return 'File read access on ${vuln.targetAddress} — read /etc/passwd, SSH private keys, app config files, and database credentials.';
    } else if (t.contains('ssrf')) {
      return 'Server-side request forgery on ${vuln.targetAddress} — probe internal services, cloud metadata endpoints, and internal network ranges.';
    } else if (t.contains('privilege escalation')) {
      return 'Elevated privilege access on ${vuln.targetAddress} — attempt root/SYSTEM access from current user context.';
    }
    return 'Vulnerability confirmed on ${vuln.targetAddress} — use as a stepping stone for chained attacks.';
  }

  /// Build a prompt block describing confirmed findings on [targetAddress]
  /// that subsequent vulnerability tests can chain from.
  String confirmedFindingsPromptBlock(String targetAddress) {
    final relevant = _confirmedArtifacts.where((a) => a['target'] == targetAddress).toList();
    if (relevant.isEmpty) return '';
    final lines = relevant.map((a) =>
        '  - [${a['type']}] ${a['problem']}: ${a['evidence']}\n    Access surface: ${a['accessSurface'] ?? ''}').join('\n');
    return '''
## CONFIRMED FINDINGS ON THIS TARGET (chain from these):
$lines
NOTE: Use these as stepping stones. If RCE is confirmed, enumerate further (users, files, creds). If credentials were found, try them on every other service. If LFI was confirmed, read config files for database credentials and SSH keys.
''';
  }

  /// Returns true if an authenticated re-analysis has already been run for [targetAddress].
  bool hasAuthenticatedReanalysis(String targetAddress) =>
      _authenticatedReanalysisTargets.contains(targetAddress);

  /// Mark that an authenticated re-analysis has been triggered for [targetAddress].
  void markAuthenticatedReanalysis(String targetAddress) {
    _authenticatedReanalysisTargets.add(targetAddress);
  }

  /// Returns true if there are any verified credentials relevant for re-analysis.
  bool get hasVerifiedCredentials =>
      _credentials.any((c) => c.isVerified);

  /// Build a credential context block for authenticated re-analysis prompts.
  /// Only includes verified credentials (seen in command output).
  String authenticatedContextBlock() {
    final verified = _credentials.where((c) => c.isVerified).toList();
    if (verified.isEmpty) return '';
    final lines = verified.map((c) => '  - ${c.toPromptLine()}').join('\n');
    return '''
## AUTHENTICATED CONTEXT — confirmed credentials discovered during this engagement:
$lines

You are now performing an AUTHENTICATED analysis pass. In addition to unauthenticated findings, generate findings that require these credentials:
- Authenticated SMB share enumeration: list shares, test read/write access, look for sensitive files
- Authenticated LDAP enumeration: group memberships, AdminSDHolder, ACLs, GPO objects, Kerberoastable SPNs, AS-REP roastable accounts
- Authenticated web application testing: post-login attack surface, privilege escalation within the app, IDOR with a valid session, admin functionality exposure
- Lateral movement: where can these credentials be reused? Test against all other services on this target and note cross-target reuse potential
Raise confidence to HIGH for any finding where these credentials directly enable the attack.
''';
  }

  /// Update the current execution status string shown in the UI.
  void setExecutionStatus(String status) {
    _executionStatus = status;
    notifyListeners();
  }

  void updateCurrentProject(Project project) {
    _currentProject = project;
    notifyListeners();
  }

  /// Stop all background listener processes (Responder, ntlmrelayx, etc.).
  /// Called when switching projects or on app shutdown.
  Future<void> stopAllListeners() async {
    await BackgroundProcessManager().stopAll();
  }

  Future<void> setCurrentProject(Project? project) async {
    await BackgroundProcessManager().stopAll();
    _currentProject = project;
    _adminPassword = null;
    _targets = [];
    _selectedTarget = null;
    _vulnerabilities = [];
    _commandLogs = [];
    _promptLogs.clear();
    _debugLogs.clear();
    _credentials.clear();
    _credentialFingerprints.clear();
    _confirmedArtifacts.clear();
    _executionStatus = '';
    _scanComplete = false;
    _analysisComplete = false;
    _hasResults = false;
    _tokensSentTotal = 0;
    _tokensReceivedTotal = 0;
    _tokensSentRecon = 0;
    _tokensReceivedRecon = 0;
    _tokensSentAnalyze = 0;
    _tokensReceivedAnalyze = 0;
    _tokensSentExecute = 0;
    _tokensReceivedExecute = 0;
    _tokensSentReport = 0;
    _tokensReceivedReport = 0;
    _activeTab = 0;
    if (project != null) await loadProjectData();
    notifyListeners();
  }

  Future<void> loadProjectData() async {
    final project = _currentProject;
    if (project == null) return;

    _targets = await DatabaseHelper.getTargets(project.id!);

    // Verify JSON files still exist; only exclude targets that haven't been analyzed yet
    for (final t in _targets) {
      if (t.status == TargetStatus.complete && t.jsonFilePath.isNotEmpty && !t.analysisComplete) {
        if (!await File(t.jsonFilePath).exists()) {
          t.status = TargetStatus.excluded;
          await DatabaseHelper.updateTarget(t);
          addDebugLog('Warning: JSON file missing for ${t.address}, marked excluded');
        }
      }
    }

    // Derive flags after targets are loaded
    _scanComplete = project.scanComplete || _targets.any((t) => t.status == TargetStatus.complete || t.analysisComplete);
    _analysisComplete = project.analysisComplete || _targets.any((t) => t.analysisComplete);
    _hasResults = project.hasResults;

    _vulnerabilities = await DatabaseHelper.getVulnerabilities(project.id!);
    _commandLogs = await DatabaseHelper.getCommandLogs(project.id!);

    // Recompute hasResults from actual vulnerability data in case the stored
    // flag is stale (e.g. after import or if execution completed without
    // setting the flag).
    if (!_hasResults && _vulnerabilities.any((v) => v.status == VulnerabilityStatus.confirmed)) {
      _hasResults = true;
      DatabaseHelper.updateProjectFlags(_projectId, hasResults: true);
    }

    final savedCreds = await DatabaseHelper.getCredentialsByProject(project.id!);
    _credentials.clear();
    _credentialFingerprints.clear();
    for (final c in savedCreds) {
      _credentials.add(c);
      _credentialFingerprints.add(c.fingerprint);
    }

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

    // Load persisted token totals
    final totals = await DatabaseHelper.getTokenTotals(project.id!);
    _tokensSentTotal = totals['totalSent'] ?? 0;
    _tokensReceivedTotal = totals['totalReceived'] ?? 0;
    _tokensSentRecon = totals['reconSent'] ?? 0;
    _tokensReceivedRecon = totals['reconReceived'] ?? 0;
    _tokensSentAnalyze = totals['analyzeSent'] ?? 0;
    _tokensReceivedAnalyze = totals['analyzeReceived'] ?? 0;
    _tokensSentExecute = totals['executeSent'] ?? 0;
    _tokensReceivedExecute = totals['executeReceived'] ?? 0;
    _tokensSentReport = totals['reportSent'] ?? 0;
    _tokensReceivedReport = totals['reportReceived'] ?? 0;

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

  Future<void> removeTargetByAddress(String address) async {
    final target = _targets.firstWhere(
      (t) => t.address == address,
      orElse: () => Target(address: address),
    );
    if (target.id != null) {
      await deleteTarget(target);
    } else {
      _targets.removeWhere((t) => t.address == address);
      notifyListeners();
    }
    addDebugLog('Removed target $address — host unreachable');
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
    if (_currentProject?.id == null) return;
    _vulnerabilities = await DatabaseHelper.getVulnerabilities(_currentProject!.id!);
    notifyListeners();
  }

  Future<void> loadCommandLogs() async {
    if (_currentProject?.id == null) return;
    _commandLogs = await DatabaseHelper.getCommandLogs(_currentProject!.id!);
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
