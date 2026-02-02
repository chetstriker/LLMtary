import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:dropdown_button2/dropdown_button2.dart';
import '../models/llm_provider.dart';
import '../models/llm_settings.dart';
import '../services/llm_service.dart';
import '../widgets/app_state.dart';
import '../database/database_helper.dart';

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
  double _temperature = 0.7;
  int _maxTokens = 4000;
  int _maxIterations = 10;
  List<String> _availableModels = [];
  bool _isLoadingModels = false;
  final _llmService = LLMService();

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
    _loadMaxIterations();
  }

  Future<void> _loadMaxIterations() async {
    final value = await DatabaseHelper.getSetting('max_iterations');
    setState(() => _maxIterations = int.tryParse(value ?? '10') ?? 10);
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
        child: Container(
          padding: const EdgeInsets.all(24),
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
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('AI PROVIDER', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
              const SizedBox(height: 12),
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
                  onChanged: (v) {
                    if (v != null) {
                      setState(() {
                        _selectedProvider = v;
                        if (v.requiresBaseUrl) {
                          _baseUrlController.text = v.defaultBaseUrl;
                        }
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
                onChanged: (v) => _maxTokens = int.tryParse(v) ?? 4000,
              ),
              const SizedBox(height: 24),
              Tooltip(
                message: 'Controls the maximum tries or attempts the LLM can perform on each vulnerability before giving up',
                child: const Text('MAX ITERATIONS', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
              ),
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
                        value: _maxIterations.toDouble(),
                        min: 1,
                        max: 25,
                        divisions: 24,
                        onChanged: (v) => setState(() => _maxIterations = v.round()),
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
                    child: Text('$_maxIterations', style: const TextStyle(color: Color(0xFF00F5FF), fontFamily: 'monospace', fontWeight: FontWeight.bold)),
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
      final models = await _llmService.fetchAvailableModels(settings);
      setState(() {
        _availableModels = models;
        _isLoadingModels = false;
      });
    } catch (e) {
      setState(() => _isLoadingModels = false);
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed to load models: $e')));
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
      builder: (context) => _TestDialog(settings: settings, llmService: _llmService),
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
    );
    
    context.read<AppState>().updateLLMSettings(settings);
    DatabaseHelper.saveSetting('max_iterations', _maxIterations.toString());
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
