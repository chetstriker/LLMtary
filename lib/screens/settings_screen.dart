import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:dropdown_button2/dropdown_button2.dart';
import '../utils/file_dialog.dart';
import '../models/llm_provider.dart';
import '../models/llm_settings.dart';
import '../services/llm_service.dart';
import '../services/storage_service.dart';
import '../widgets/app_state.dart';
import '../database/database_helper.dart';
import '../constants/app_constants.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  late LLMProvider _selectedProvider;
  final _baseUrlController = TextEditingController();
  final _apiKeyController = TextEditingController();
  final _modelController = TextEditingController();
  final _modelSearchController = TextEditingController();
  double _temperature = ConfigDefaults.temperature;
  int _maxTokens = ConfigDefaults.maxTokens;
  int _timeoutSeconds = ConfigDefaults.timeoutSeconds;
  int _maxIterationsWithCve = 30;
  int _maxIterationsNoCve = 15;
  List<String> _availableModels = [];
  bool _isLoadingModels = false;
  final _llmService = LLMService();
  List<String> _whitelistedCommands = [];
  String _storagePath = '';

  @override
  void initState() {
    super.initState();
    final settings = context.read<AppState>().llmSettings;
    _selectedProvider = settings.provider;
    _baseUrlController.text = settings.baseUrl ?? '';
    _apiKeyController.text = settings.apiKey ?? '';
    _modelController.text = settings.modelName;
    _temperature = settings.temperature;
    _maxTokens = settings.maxTokens;
    _timeoutSeconds = settings.timeoutSeconds;
    _maxIterationsWithCve = settings.maxIterationsWithCve;
    _maxIterationsNoCve = settings.maxIterationsNoCve;
    _loadWhitelist();
    _loadStoragePath();
  }

  Future<void> _loadStoragePath() async {
    final path = await StorageService.getBasePath();
    if (mounted) setState(() => _storagePath = path);
  }

  Future<void> _changeStoragePath() async {
    final picked = await FileDialog.getDirectoryPath(dialogTitle: 'Select PenExecute storage folder');
    if (picked == null) return;
    StorageService.setCustomBasePath(picked);
    await DatabaseHelper.saveSetting(SettingsKeys.storageBasePath, picked);
    setState(() => _storagePath = picked);
  }

  Future<void> _loadWhitelist() async {
    final db = await DatabaseHelper.database;
    final results = await db.query('command_whitelist', orderBy: 'command ASC');
    setState(() {
      _whitelistedCommands = results.map((r) => r['command'] as String).toList();
    });
  }

  @override
  void dispose() {
    _baseUrlController.dispose();
    _apiKeyController.dispose();
    _modelController.dispose();
    _modelSearchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E27),
      appBar: AppBar(
        backgroundColor: const Color(0xFF1A1F3A),
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: Color(0xFF00F5FF)),
          onPressed: () => Navigator.pop(context),
        ),
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
              child: const Icon(Icons.settings, color: Colors.white, size: 20),
            ),
            const SizedBox(width: 12),
            const Text('AI Configuration', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 20)),
          ],
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Left column — AI Configuration
            Expanded(
              flex: 3,
              child: Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: const Color(0xFF1A1F3A),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('AI PROVIDER', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 14, letterSpacing: 1)),
                  const SizedBox(height: 16),
              Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF0A0E27),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                ),
                child: DropdownButton<LLMProvider>(
                  value: _selectedProvider,
                  isExpanded: true,
                  dropdownColor: const Color(0xFF1A1F3A),
                  style: const TextStyle(color: Colors.white),
                  underline: const SizedBox(),
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  items: LLMProvider.values.map((p) => DropdownMenuItem(value: p, child: Text(p.displayName))).toList(),
                  onChanged: (v) async {
                    if (v != null) {
                      setState(() {
                        _selectedProvider = v;
                      });
                      // Load saved settings for this provider
                      final providerSettings = await DatabaseHelper.getProviderSettings(v.name);
                      setState(() {
                        if (providerSettings != null) {
                          _baseUrlController.text = providerSettings['baseUrl'] as String? ?? (v.requiresBaseUrl ? v.defaultBaseUrl : '');
                          _apiKeyController.text = providerSettings['apiKey'] as String? ?? '';
                          _modelController.text = providerSettings['modelName'] as String? ?? '';
                          _temperature = (providerSettings['temperature'] as num?)?.toDouble() ?? 0.22;
                          _maxTokens = providerSettings['maxTokens'] as int? ?? 4096;
                          _timeoutSeconds = providerSettings['timeoutSeconds'] as int? ?? 240;
                        } else {
                          _baseUrlController.text = v.requiresBaseUrl ? v.defaultBaseUrl : '';
                          _apiKeyController.text = '';
                          _modelController.text = '';
                          _temperature = ConfigDefaults.temperature;
                          _maxTokens = ConfigDefaults.maxTokens;
                          _timeoutSeconds = ConfigDefaults.timeoutSeconds;
                        }
                        _availableModels = [];
                      });
                    }
                  },
                ),
              ),
              const SizedBox(height: 24),
              if (_selectedProvider.requiresBaseUrl) ...[
                const Text('BASE URL', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                const SizedBox(height: 12),
                TextField(
                  controller: _baseUrlController,
                  style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
                  decoration: InputDecoration(
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
                const SizedBox(height: 24),
              ],
              if (_selectedProvider.requiresApiKey) ...[
                const Text('API KEY', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                const SizedBox(height: 12),
                TextField(
                  controller: _apiKeyController,
                  obscureText: true,
                  style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
                  decoration: InputDecoration(
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
                const SizedBox(height: 24),
              ],
              if (_selectedProvider.supportsOptionalApiKey) ...[
                const Text('API KEY (Optional)', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                const SizedBox(height: 12),
                TextField(
                  controller: _apiKeyController,
                  obscureText: true,
                  style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
                  decoration: InputDecoration(
                    hintText: 'For MCP access',
                    hintStyle: TextStyle(color: Colors.white.withOpacity(0.3)),
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
                const SizedBox(height: 24),
              ],
              Row(
                children: [
                  const Text('MODEL', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                  const Spacer(),
                  Container(
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                        colors: [Color(0xFF00F5FF), Color(0xFF0080FF)],
                      ),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Material(
                      color: Colors.transparent,
                      child: InkWell(
                        onTap: _isLoadingModels ? null : _loadModels,
                        borderRadius: BorderRadius.circular(6),
                        child: Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                          child: Row(
                            children: [
                              _isLoadingModels
                                  ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2))
                                  : const Icon(Icons.refresh, color: Colors.white, size: 14),
                              const SizedBox(width: 6),
                              const Text('REFRESH', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 10)),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              _availableModels.isEmpty
                  ? TextField(
                      controller: _modelController,
                      style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
                      decoration: InputDecoration(
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
                    )
                  : Container(
                      decoration: BoxDecoration(
                        color: const Color(0xFF0A0E27),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                      ),
                      child: DropdownButtonHideUnderline(
                        child: DropdownButton2<String>(
                          isExpanded: true,
                          hint: const Text('Select Model', style: TextStyle(color: Colors.white70)),
                          value: _availableModels.contains(_modelController.text) ? _modelController.text : null,
                          items: _availableModels.map((model) => DropdownMenuItem(value: model, child: Text(model, style: const TextStyle(color: Colors.white)))).toList(),
                          onChanged: (v) {
                            if (v != null) {
                              setState(() => _modelController.text = v);
                            }
                          },
                          buttonStyleData: const ButtonStyleData(height: 50, padding: EdgeInsets.symmetric(horizontal: 12)),
                          dropdownStyleData: DropdownStyleData(
                            maxHeight: 300,
                            decoration: BoxDecoration(
                              color: const Color(0xFF1A1F3A),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                            ),
                          ),
                          dropdownSearchData: DropdownSearchData(
                            searchController: _modelSearchController,
                            searchInnerWidgetHeight: 50,
                            searchInnerWidget: Container(
                              padding: const EdgeInsets.all(8),
                              child: TextField(
                                controller: _modelSearchController,
                                style: const TextStyle(color: Colors.white),
                                decoration: InputDecoration(
                                  hintText: 'Search models...',
                                  hintStyle: const TextStyle(color: Colors.white38),
                                  border: OutlineInputBorder(
                                    borderRadius: BorderRadius.circular(8),
                                    borderSide: BorderSide(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                                  ),
                                  filled: true,
                                  fillColor: const Color(0xFF0A0E27),
                                ),
                              ),
                            ),
                            searchMatchFn: (item, searchValue) => item.value.toString().toLowerCase().contains(searchValue.toLowerCase()),
                          ),
                          onMenuStateChange: (isOpen) {
                            if (!isOpen) _modelSearchController.clear();
                          },
                        ),
                      ),
                    ),
              const SizedBox(height: 24),
              const Text('TEMPERATURE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: SliderTheme(
                      data: SliderThemeData(
                        activeTrackColor: const Color(0xFF00F5FF),
                        inactiveTrackColor: const Color(0xFF00F5FF).withOpacity(0.2),
                        thumbColor: const Color(0xFF00F5FF),
                        overlayColor: const Color(0xFF00F5FF).withOpacity(0.2),
                      ),
                      child: Slider(
                        value: _temperature,
                        min: 0,
                        max: 2,
                        onChanged: (v) => setState(() => _temperature = v),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0A0E27),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                    ),
                    child: Text(_temperature.toStringAsFixed(2), style: const TextStyle(color: Color(0xFF00F5FF), fontFamily: 'monospace', fontWeight: FontWeight.bold)),
                  ),
                ],
              ),
              const SizedBox(height: 24),
              const Text('MAX TOKENS', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
              const SizedBox(height: 12),
              TextField(
                controller: TextEditingController(text: _maxTokens.toString()),
                keyboardType: TextInputType.number,
                style: const TextStyle(color: Colors.white, fontFamily: 'monospace'),
                decoration: InputDecoration(
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
                onChanged: (v) => _maxTokens = int.tryParse(v) ?? 4096,
              ),
              const SizedBox(height: 24),
              const Text('TIMEOUT', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: SliderTheme(
                      data: SliderThemeData(
                        activeTrackColor: const Color(0xFF00F5FF),
                        inactiveTrackColor: const Color(0xFF00F5FF).withOpacity(0.2),
                        thumbColor: const Color(0xFF00F5FF),
                        overlayColor: const Color(0xFF00F5FF).withOpacity(0.2),
                      ),
                      child: Slider(
                        value: _timeoutSeconds.toDouble(),
                        min: 10,
                        max: 360,
                        divisions: 35,
                        onChanged: (v) => setState(() => _timeoutSeconds = v.round()),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0A0E27),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                    ),
                    child: Text('${_timeoutSeconds}s', style: const TextStyle(color: Color(0xFF00F5FF), fontFamily: 'monospace', fontWeight: FontWeight.bold)),
                  ),
                ],
              ),
              const SizedBox(height: 24),
              const Text('MAX ITERATIONS (WITH CVE)', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
              const SizedBox(height: 4),
              const Text('Exploitation loop cap for findings with a known CVE ID', style: TextStyle(color: Color(0xFF8892B0), fontSize: 11)),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: SliderTheme(
                      data: SliderThemeData(
                        activeTrackColor: const Color(0xFF00F5FF),
                        inactiveTrackColor: const Color(0xFF00F5FF).withOpacity(0.2),
                        thumbColor: const Color(0xFF00F5FF),
                        overlayColor: const Color(0xFF00F5FF).withOpacity(0.2),
                      ),
                      child: Slider(
                        value: _maxIterationsWithCve.toDouble(),
                        min: 10,
                        max: 60,
                        divisions: 50,
                        onChanged: (v) => setState(() => _maxIterationsWithCve = v.round()),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0A0E27),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                    ),
                    child: Text('$_maxIterationsWithCve', style: const TextStyle(color: Color(0xFF00F5FF), fontFamily: 'monospace', fontWeight: FontWeight.bold)),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              const Text('MAX ITERATIONS (NO CVE)', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
              const SizedBox(height: 4),
              const Text('Exploitation loop cap for generic findings without a CVE ID', style: TextStyle(color: Color(0xFF8892B0), fontSize: 11)),
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: SliderTheme(
                      data: SliderThemeData(
                        activeTrackColor: const Color(0xFF00F5FF),
                        inactiveTrackColor: const Color(0xFF00F5FF).withOpacity(0.2),
                        thumbColor: const Color(0xFF00F5FF),
                        overlayColor: const Color(0xFF00F5FF).withOpacity(0.2),
                      ),
                      child: Slider(
                        value: _maxIterationsNoCve.toDouble(),
                        min: 5,
                        max: 60,
                        divisions: 55,
                        onChanged: (v) => setState(() => _maxIterationsNoCve = v.round()),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: const Color(0xFF0A0E27),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                    ),
                    child: Text('$_maxIterationsNoCve', style: const TextStyle(color: Color(0xFF00F5FF), fontFamily: 'monospace', fontWeight: FontWeight.bold)),
                  ),
                ],
              ),
              const SizedBox(height: 32),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
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
                      onPressed: _saveSettings,
                      icon: const Icon(Icons.save, color: Colors.white),
                      label: const Text('SAVE SETTINGS', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.transparent,
                        shadowColor: Colors.transparent,
                        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
                      ),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Container(
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(
                        colors: [Color(0xFF00FF88), Color(0xFF00CC66)],
                      ),
                      borderRadius: BorderRadius.circular(8),
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFF00FF88).withOpacity(0.3),
                          blurRadius: 15,
                        ),
                      ],
                    ),
                    child: ElevatedButton.icon(
                      onPressed: _modelController.text.isEmpty ? null : _testIntegration,
                      icon: const Icon(Icons.play_arrow, color: Colors.white),
                      label: const Text('TEST', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.transparent,
                        shadowColor: Colors.transparent,
                        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
                      ),
                    ),
                  ),
                ],
              ),
                ],
              ),
            ),
          ),
            // Right column — Storage + Command Whitelist
            const SizedBox(width: 16),
            Expanded(
              flex: 2,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: const Color(0xFF1A1F3A),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('STORAGE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 14, letterSpacing: 1)),
                const SizedBox(height: 16),
                const Text('BASE PATH', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                const SizedBox(height: 8),
                Row(
                  children: [
                    Expanded(
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                        decoration: BoxDecoration(
                          color: const Color(0xFF0A0E27),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.2)),
                        ),
                        child: Text(
                          _storagePath.isEmpty ? 'Loading...' : _storagePath,
                          style: const TextStyle(color: Colors.white70, fontFamily: 'monospace', fontSize: 11),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    ElevatedButton(
                      onPressed: _changeStoragePath,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF1A1F3A),
                        side: const BorderSide(color: Color(0xFF00F5FF)),
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                      ),
                      child: const Text('CHANGE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11)),
                    ),
                  ],
                ),
                const SizedBox(height: 20),
                const Text('CREATE DEBUG LOG', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                const SizedBox(height: 4),
                const Text('Write all debug output to debug.log in the storage directory. Session only — resets to off on restart.', style: TextStyle(color: Color(0xFF8892B0), fontSize: 11)),
                const SizedBox(height: 8),
                Consumer<AppState>(
                  builder: (context, appState, _) => Row(
                    children: [
                      Switch(
                        value: appState.createDebugLog,
                        onChanged: (v) => appState.setCreateDebugLog(v),
                        activeColor: const Color(0xFF00F5FF),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        appState.createDebugLog ? 'Enabled — writing to debug.log' : 'Disabled',
                        style: TextStyle(
                          color: appState.createDebugLog ? const Color(0xFF00F5FF) : Colors.white38,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
            const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: const Color(0xFF1A1F3A),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('COMMAND WHITELIST', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 14, letterSpacing: 1)),
                const SizedBox(height: 16),
                _whitelistedCommands.isEmpty
                    ? Center(
                        child: Padding(
                          padding: const EdgeInsets.all(16),
                          child: Text('No whitelisted commands', style: TextStyle(color: Colors.white.withOpacity(0.3), fontSize: 12)),
                        ),
                      )
                    : ListView.builder(
                        shrinkWrap: true,
                        physics: const NeverScrollableScrollPhysics(),
                        itemCount: _whitelistedCommands.length,
                        itemBuilder: (context, i) {
                          final command = _whitelistedCommands[i];
                          return Container(
                            margin: const EdgeInsets.only(bottom: 8),
                            padding: const EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: const Color(0xFF0A0E27),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.2)),
                            ),
                            child: Row(
                              children: [
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF00F5FF).withOpacity(0.2),
                                    borderRadius: BorderRadius.circular(4),
                                  ),
                                  child: Text(
                                    command.toUpperCase(),
                                    style: const TextStyle(
                                      color: Color(0xFF00F5FF),
                                      fontFamily: 'monospace',
                                      fontWeight: FontWeight.bold,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                                const Spacer(),
                                IconButton(
                                  icon: const Icon(Icons.delete, color: Color(0xFFFF0080), size: 20),
                                  onPressed: () async {
                                    final db = await DatabaseHelper.database;
                                    await db.delete('command_whitelist', where: 'LOWER(command) = ?', whereArgs: [command.toLowerCase()]);
                                    _loadWhitelist();
                                  },
                                  tooltip: 'Remove from whitelist',
                                ),
                              ],
                            ),
                          );
                        },
                      ),
              ],
            ),
          ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _loadModels() async {
    setState(() => _isLoadingModels = true);
    try {
      final settings = LLMSettings(
        provider: _selectedProvider,
        baseUrl: _baseUrlController.text.trim(),
        apiKey: _apiKeyController.text.trim(),
        modelName: '',
      );
      print('DEBUG: Fetching models for ${_selectedProvider.displayName}');
      final models = await _llmService.fetchAvailableModels(settings);
      print('DEBUG: Received ${models.length} models');
      
      // Ensure we always have at least fallback models
      final finalModels = models.isEmpty ? _getFallbackModels() : models;
      print('DEBUG: Final model count: ${finalModels.length}');
      
      if (mounted) {
        setState(() {
          _availableModels = finalModels;
          _isLoadingModels = false;
        });
        print('DEBUG: State updated with ${_availableModels.length} models');
      }
    } catch (e) {
      print('DEBUG: Error loading models: $e');
      if (mounted) {
        setState(() {
          _availableModels = _getFallbackModels();
          _isLoadingModels = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to load models: $e')));
      }
    }
  }
  
  List<String> _getFallbackModels() {
    switch (_selectedProvider) {
      case LLMProvider.ollama:
        return ['llama2', 'mistral', 'codellama'];
      case LLMProvider.lmStudio:
        return ['local-model'];
      case LLMProvider.claude:
        return ['claude-opus-4-5-20251101', 'claude-sonnet-4-5-20250929', 'claude-haiku-4-5-20251001'];
      case LLMProvider.chatGPT:
        return ['gpt-4o', 'gpt-4-turbo', 'gpt-4', 'gpt-3.5-turbo'];
      case LLMProvider.gemini:
        return ['gemini-1.5-pro', 'gemini-1.5-flash', 'gemini-pro'];
      case LLMProvider.openRouter:
        return ['anthropic/claude-3.5-sonnet', 'openai/gpt-4o', 'google/gemini-pro-1.5', 'meta-llama/llama-3.1-70b-instruct'];
      default:
        return [];
    }
  }

  Future<void> _testIntegration() async {
    final settings = LLMSettings(
      provider: _selectedProvider,
      baseUrl: _baseUrlController.text.trim().isEmpty ? _selectedProvider.defaultBaseUrl : _baseUrlController.text.trim(),
      apiKey: _apiKeyController.text.trim(),
      modelName: _modelController.text,
      temperature: _temperature,
      maxTokens: _maxTokens,
    );
    
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => _TestDialog(settings: settings, llmService: LLMService(enableDebugLogging: true)),
    );
  }

  void _saveSettings() {
    final settings = LLMSettings(
      provider: _selectedProvider,
      baseUrl: _baseUrlController.text.trim().isEmpty ? _selectedProvider.defaultBaseUrl : _baseUrlController.text.trim(),
      apiKey: _apiKeyController.text,
      modelName: _modelController.text,
      temperature: _temperature,
      maxTokens: _maxTokens,
      timeoutSeconds: _timeoutSeconds,
      maxIterationsWithCve: _maxIterationsWithCve,
      maxIterationsNoCve: _maxIterationsNoCve,
    );
    
    context.read<AppState>().updateLLMSettings(settings);
    Navigator.pop(context);
  }
}

class _TestDialog extends StatefulWidget {
  final LLMSettings settings;
  final LLMService llmService;

  const _TestDialog({required this.settings, required this.llmService});

  @override
  State<_TestDialog> createState() => _TestDialogState();
}

class _TestDialogState extends State<_TestDialog> {
  bool _isTesting = false;
  String _result = '';

  @override
  void initState() {
    super.initState();
    _runTest();
  }

  Future<void> _runTest() async {
    setState(() {
      _isTesting = true;
      _result = 'Connecting to ${widget.settings.provider.displayName}...\n';
    });

    try {
      final response = await widget.llmService.sendMessage(widget.settings, 'What is your name and version? Respond concisely.');
      setState(() {
        _result += '\nSuccess!\n\nResponse:\n$response';
        _isTesting = false;
      });
    } catch (e) {
      setState(() {
        _result += '\nError:\n$e';
        _isTesting = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: const Color(0xFF1A1F3A),
      title: Row(
        children: [
          const Icon(Icons.play_circle, color: Color(0xFF00F5FF)),
          const SizedBox(width: 8),
          const Text('Test AI Integration', style: TextStyle(color: Colors.white)),
        ],
      ),
      content: SizedBox(
        width: 500,
        height: 300,
        child: Column(
          children: [
            Expanded(
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: const Color(0xFF0A0E27),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
                ),
                child: SingleChildScrollView(
                  child: SelectableText(
                    _result.isEmpty ? 'Waiting...' : _result,
                    style: const TextStyle(color: Color(0xFF00FF88), fontFamily: 'monospace', fontSize: 12),
                  ),
                ),
              ),
            ),
            if (_isTesting) const Padding(padding: EdgeInsets.only(top: 16), child: CircularProgressIndicator(color: Color(0xFF00F5FF))),
          ],
        ),
      ),
      actions: [
        Container(
          decoration: BoxDecoration(
            gradient: const LinearGradient(
              colors: [Color(0xFF00F5FF), Color(0xFF0080FF)],
            ),
            borderRadius: BorderRadius.circular(8),
          ),
          child: TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('CLOSE', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold)),
          ),
        ),
      ],
    );
  }
}
