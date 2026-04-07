import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:dropdown_button2/dropdown_button2.dart';
import '../models/llm_provider.dart';
import '../models/llm_settings.dart';
import '../services/llm_service.dart';
import '../widgets/app_state.dart';
import '../constants/app_constants.dart';

/// First-launch LLM configuration wizard.
/// Shows a three-step flow: choose provider → configure → test & save.
class LlmSetupWizard extends StatefulWidget {
  const LlmSetupWizard({super.key});

  @override
  State<LlmSetupWizard> createState() => _LlmSetupWizardState();
}

class _LlmSetupWizardState extends State<LlmSetupWizard> {
  int _step = 0;
  LLMProvider _provider = LLMProvider.ollama;
  final _baseUrlCtrl = TextEditingController();
  final _apiKeyCtrl = TextEditingController();
  final _modelCtrl = TextEditingController();
  final _modelSearchCtrl = TextEditingController();
  final _modelNotifier = ValueNotifier<String?>(null);
  List<String> _models = [];
  bool _loadingModels = false;
  bool _testing = false;
  bool _testPassed = false;
  String _testResult = '';
  final _llmService = LLMService(enableDebugLogging: false);

  static const _bg = Color(0xFF0A0E27);
  static const _card = Color(0xFF1A1F3A);
  static const _cyan = Color(0xFF00F5FF);
  static const _green = Color(0xFF00FF88);

  @override
  void initState() {
    super.initState();
    _baseUrlCtrl.text = _provider.defaultBaseUrl;
  }

  @override
  void dispose() {
    _baseUrlCtrl.dispose();
    _apiKeyCtrl.dispose();
    _modelCtrl.dispose();
    _modelSearchCtrl.dispose();
    _modelNotifier.dispose();
    super.dispose();
  }

  void _onProviderChanged(LLMProvider p) {
    setState(() {
      _provider = p;
      _baseUrlCtrl.text = p.requiresBaseUrl ? p.defaultBaseUrl : '';
      _apiKeyCtrl.clear();
      _modelCtrl.clear();
      _modelNotifier.value = null;
      _models = [];
      _testPassed = false;
      _testResult = '';
    });
  }

  Future<void> _loadModels() async {
    setState(() => _loadingModels = true);
    try {
      final settings = LLMSettings(
        provider: _provider,
        baseUrl: _baseUrlCtrl.text.trim(),
        apiKey: _apiKeyCtrl.text.trim(),
        modelName: '',
      );
      final models = await _llmService.fetchAvailableModels(settings);
      if (mounted) {
        setState(() { _models = models; _loadingModels = false; });
        _modelNotifier.value = models.contains(_modelCtrl.text) ? _modelCtrl.text : null;
      }
    } catch (_) {
      if (mounted) setState(() => _loadingModels = false);
    }
  }

  Future<void> _runTest() async {
    setState(() { _testing = true; _testPassed = false; _testResult = 'Connecting...'; });
    try {
      final settings = LLMSettings(
        provider: _provider,
        baseUrl: _baseUrlCtrl.text.trim().isEmpty ? _provider.defaultBaseUrl : _baseUrlCtrl.text.trim(),
        apiKey: _apiKeyCtrl.text.trim(),
        modelName: _modelCtrl.text.trim(),
        temperature: ConfigDefaults.temperature,
        maxTokens: ConfigDefaults.maxTokens,
        timeoutSeconds: ConfigDefaults.timeoutSeconds,
      );
      final response = await _llmService.sendMessage(settings, 'Reply with exactly: OK');
      setState(() {
        _testPassed = true;
        _testResult = 'Connected ✓\n\n${response.length > 200 ? response.substring(0, 200) : response}';
        _testing = false;
      });
    } catch (e) {
      setState(() { _testResult = 'Error: $e'; _testing = false; });
    }
  }

  void _save() {
    final settings = LLMSettings(
      provider: _provider,
      baseUrl: _baseUrlCtrl.text.trim().isEmpty ? _provider.defaultBaseUrl : _baseUrlCtrl.text.trim(),
      apiKey: _apiKeyCtrl.text.trim(),
      modelName: _modelCtrl.text.trim(),
      temperature: ConfigDefaults.temperature,
      maxTokens: ConfigDefaults.maxTokens,
      timeoutSeconds: ConfigDefaults.timeoutSeconds,
    );
    context.read<AppState>().updateLLMSettings(settings);
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: _bg,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: SizedBox(
        width: 520,
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(colors: [_cyan, Color(0xFF0080FF)]),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.smart_toy, color: Colors.white, size: 20),
                ),
                const SizedBox(width: 12),
                const Text('Configure AI Provider', style: TextStyle(color: Colors.white, fontSize: 20, fontWeight: FontWeight.bold)),
              ]),
              const SizedBox(height: 8),
              Text('Step ${_step + 1} of 3', style: const TextStyle(color: Colors.white38, fontSize: 12)),
              const SizedBox(height: 24),
              _buildStep(),
              const SizedBox(height: 24),
              _buildActions(),
              const SizedBox(height: 8),
              Center(
                child: TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: const Text('Skip for now', style: TextStyle(color: Colors.white24, fontSize: 12)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildStep() {
    switch (_step) {
      case 0: return _buildStep1();
      case 1: return _buildStep2();
      case 2: return _buildStep3();
      default: return const SizedBox();
    }
  }

  Widget _buildStep1() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('CHOOSE PROVIDER', style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 12, letterSpacing: 1)),
        const SizedBox(height: 12),
        Container(
          decoration: BoxDecoration(
            color: _card,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: _cyan.withValues(alpha: 0.3)),
          ),
          child: DropdownButton<LLMProvider>(
            value: _provider,
            isExpanded: true,
            dropdownColor: _card,
            style: const TextStyle(color: Colors.white),
            underline: const SizedBox(),
            padding: const EdgeInsets.symmetric(horizontal: 12),
            items: LLMProvider.values
                .where((p) => p != LLMProvider.none)
                .map((p) => DropdownMenuItem(value: p, child: Text(p.displayName)))
                .toList(),
            onChanged: (v) { if (v != null) _onProviderChanged(v); },
          ),
        ),
        const SizedBox(height: 16),
        _providerHint(),
      ],
    );
  }

  Widget _providerHint() {
    final hints = <LLMProvider, String>{
      LLMProvider.ollama: 'Runs locally. Start Ollama first: ollama serve',
      LLMProvider.lmStudio: 'Runs locally. Start LM Studio and enable the local server.',
      LLMProvider.claude: 'Cloud API. Requires an Anthropic API key.',
      LLMProvider.chatGPT: 'Cloud API. Requires an OpenAI API key.',
      LLMProvider.gemini: 'Cloud API. Requires a Google AI Studio API key.',
      LLMProvider.openRouter: 'Cloud API. Access many models with one OpenRouter key.',
      LLMProvider.custom: 'Any OpenAI-compatible endpoint. Configure base URL and key.',
    };
    final hint = hints[_provider] ?? '';
    if (hint.isEmpty) return const SizedBox();
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _cyan.withValues(alpha: 0.05),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: _cyan.withValues(alpha: 0.2)),
      ),
      child: Text(hint, style: const TextStyle(color: Colors.white54, fontSize: 12)),
    );
  }

  Widget _buildStep2() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('CONFIGURE', style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 12, letterSpacing: 1)),
        const SizedBox(height: 16),
        if (_provider.requiresBaseUrl) ...[
          const Text('BASE URL', style: TextStyle(color: Colors.white54, fontSize: 11, fontWeight: FontWeight.bold)),
          const SizedBox(height: 6),
          _textField(_baseUrlCtrl),
          const SizedBox(height: 16),
        ],
        if (_provider.requiresApiKey || _provider.supportsOptionalApiKey) ...[
          Text(_provider.requiresApiKey ? 'API KEY' : 'API KEY (Optional)',
              style: const TextStyle(color: Colors.white54, fontSize: 11, fontWeight: FontWeight.bold)),
          const SizedBox(height: 6),
          _textField(_apiKeyCtrl, obscure: true),
          const SizedBox(height: 16),
        ],
        Row(children: [
          const Text('MODEL', style: TextStyle(color: Colors.white54, fontSize: 11, fontWeight: FontWeight.bold)),
          const Spacer(),
          TextButton.icon(
            onPressed: _loadingModels ? null : _loadModels,
            icon: _loadingModels
                ? const SizedBox(width: 12, height: 12, child: CircularProgressIndicator(color: _cyan, strokeWidth: 2))
                : const Icon(Icons.refresh, color: _cyan, size: 14),
            label: const Text('Refresh', style: TextStyle(color: _cyan, fontSize: 11)),
          ),
        ]),
        const SizedBox(height: 6),
        _models.isEmpty
            ? _textField(_modelCtrl, hint: 'e.g. llama3, gpt-4o, claude-3-5-sonnet-20241022')
            : Container(
                decoration: BoxDecoration(
                  color: _card,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: _cyan.withValues(alpha: 0.3)),
                ),
                child: DropdownButtonHideUnderline(
                  child: DropdownButton2<String>(
                    isExpanded: true,
                    hint: const Text('Select model', style: TextStyle(color: Colors.white38)),
                    valueListenable: _modelNotifier,
                    items: _models.map((m) => DropdownItem(value: m, child: Text(m, style: const TextStyle(color: Colors.white)))).toList(),
                    onChanged: (v) { if (v != null) { setState(() => _modelCtrl.text = v); _modelNotifier.value = v; } },
                    buttonStyleData: const ButtonStyleData(height: 48, padding: EdgeInsets.symmetric(horizontal: 12)),
                    dropdownStyleData: DropdownStyleData(
                      maxHeight: 280,
                      decoration: BoxDecoration(
                        color: _card,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: _cyan.withValues(alpha: 0.3)),
                      ),
                    ),
                    dropdownSearchData: DropdownSearchData(
                      searchController: _modelSearchCtrl,
                      searchBarWidgetHeight: 48,
                      searchBarWidget: Padding(
                        padding: const EdgeInsets.all(8),
                        child: TextField(
                          controller: _modelSearchCtrl,
                          style: const TextStyle(color: Colors.white),
                          decoration: InputDecoration(
                            hintText: 'Search...',
                            hintStyle: const TextStyle(color: Colors.white38),
                            border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide(color: _cyan.withValues(alpha: 0.3))),
                            filled: true, fillColor: _bg,
                          ),
                        ),
                      ),
                      searchMatchFn: (item, q) => item.value.toString().toLowerCase().contains(q.toLowerCase()),
                    ),
                    onMenuStateChange: (open) { if (!open) _modelSearchCtrl.clear(); },
                  ),
                ),
              ),
      ],
    );
  }

  Widget _buildStep3() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('TEST & SAVE', style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 12, letterSpacing: 1)),
        const SizedBox(height: 16),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: _card,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: _testPassed ? _green.withValues(alpha: 0.5) : _cyan.withValues(alpha: 0.2)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (_testPassed)
                const Row(children: [
                  Icon(Icons.check_circle, color: _green, size: 20),
                  SizedBox(width: 8),
                  Text('Connection successful', style: TextStyle(color: _green, fontWeight: FontWeight.bold)),
                ]),
              if (_testResult.isNotEmpty) ...[
                const SizedBox(height: 8),
                Text(_testResult, style: const TextStyle(color: Colors.white54, fontSize: 11, fontFamily: 'monospace')),
              ],
              if (_testResult.isEmpty && !_testing)
                const Text('Press "Test Connection" to verify your settings.', style: TextStyle(color: Colors.white38, fontSize: 12)),
              if (_testing)
                const Padding(
                  padding: EdgeInsets.only(top: 8),
                  child: LinearProgressIndicator(color: _cyan, backgroundColor: Colors.white12),
                ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            onPressed: _testing ? null : _runTest,
            icon: const Icon(Icons.wifi_tethering, size: 16),
            label: const Text('Test Connection'),
            style: OutlinedButton.styleFrom(
              foregroundColor: _cyan,
              side: const BorderSide(color: _cyan),
              padding: const EdgeInsets.symmetric(vertical: 12),
            ),
          ),
        ),
      ],
    );
  }

  Widget _textField(TextEditingController ctrl, {bool obscure = false, String? hint}) {
    return TextField(
      controller: ctrl,
      obscureText: obscure,
      style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontSize: 13),
      decoration: InputDecoration(
        hintText: hint,
        hintStyle: const TextStyle(color: Colors.white24),
        filled: true,
        fillColor: _card,
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: _cyan)),
        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide(color: _cyan.withValues(alpha: 0.3))),
        focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: const BorderSide(color: _cyan, width: 2)),
      ),
    );
  }

  Widget _buildActions() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.end,
      children: [
        if (_step > 0)
          TextButton(
            onPressed: () => setState(() => _step--),
            child: const Text('Back', style: TextStyle(color: Colors.white54)),
          ),
        const SizedBox(width: 8),
        if (_step < 2)
          ElevatedButton(
            onPressed: _canAdvance() ? () => setState(() => _step++) : null,
            style: ElevatedButton.styleFrom(
              backgroundColor: _cyan,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            ),
            child: const Text('Next', style: TextStyle(fontWeight: FontWeight.bold)),
          ),
        if (_step == 2)
          ElevatedButton(
            onPressed: _testPassed ? _save : null,
            style: ElevatedButton.styleFrom(
              backgroundColor: _green,
              foregroundColor: Colors.black,
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            ),
            child: const Text('Save & Continue', style: TextStyle(fontWeight: FontWeight.bold)),
          ),
      ],
    );
  }

  bool _canAdvance() {
    if (_step == 0) return true;
    if (_step == 1) return _modelCtrl.text.trim().isNotEmpty;
    return false;
  }
}
