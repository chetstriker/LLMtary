import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../../models/vulnerability.dart';
import '../../widgets/app_state.dart';
import '../../widgets/stats_bar.dart';
import '../../database/database_helper.dart';
import '../../models/command_log.dart';
import '../../services/report_generator.dart';
import '../../services/report_content_service.dart';
import '../../utils/file_dialog.dart';

class ResultReportTab extends StatelessWidget {
  const ResultReportTab({super.key});

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, appState, _) => Column(
        children: [
          const StatsBar(),
          Expanded(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(child: _InlineReportForm(appState: appState)),
                const SizedBox(width: 350, child: _TokenStatsPanel()),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Inline report form — always visible, no dialog needed
// ---------------------------------------------------------------------------

class _InlineReportForm extends StatefulWidget {
  final AppState appState;
  const _InlineReportForm({required this.appState});

  @override
  State<_InlineReportForm> createState() => _InlineReportFormState();
}

class _InlineReportFormState extends State<_InlineReportForm> {
  final _formKey = GlobalKey<FormState>();
  late final TextEditingController _titleCtrl;
  late final TextEditingController _pentesterCtrl;
  late final TextEditingController _execSummaryCtrl;
  late final TextEditingController _methodologyCtrl;
  late final TextEditingController _riskRatingCtrl;
  late final TextEditingController _conclusionCtrl;

  DateTime? _startDate;
  DateTime? _endDate;
  String _format = 'html';
  bool _confirmedOnly = true;
  bool _savingReport = false;
  final Map<String, bool> _generating = {
    'executiveSummary': false,
    'methodology': false,
    'riskRating': false,
    'conclusion': false,
  };

  bool get _anyGenerating => _generating.values.any((v) => v) || _savingReport;

  static const _cyan = Color(0xFF00F5FF);
  static const _card = Color(0xFF1A1F3A);
  static const _dark = Color(0xFF0A0E27);

  @override
  void initState() {
    super.initState();
    final project = widget.appState.currentProject;
    _titleCtrl = TextEditingController(text: project?.reportTitle ?? project?.name ?? '');
    _pentesterCtrl = TextEditingController(text: project?.pentesterName ?? '');
    _execSummaryCtrl = TextEditingController(text: project?.executiveSummary ?? '');
    _methodologyCtrl = TextEditingController(text: project?.methodology ?? '');
    _riskRatingCtrl = TextEditingController(text: project?.riskRatingModel ?? '');
    _conclusionCtrl = TextEditingController(text: project?.conclusion ?? '');
    _startDate = project?.firstAnalysisAt;
    _endDate = project?.lastExecutionAt;
  }

  @override
  void dispose() {
    _titleCtrl.dispose();
    _pentesterCtrl.dispose();
    _execSummaryCtrl.dispose();
    _methodologyCtrl.dispose();
    _riskRatingCtrl.dispose();
    _conclusionCtrl.dispose();
    super.dispose();
  }

  Future<void> _generate(String key, String prompt, TextEditingController ctrl) async {
    setState(() => _generating[key] = true);
    try {
      final text = await ReportContentService.generateSection(
        prompt: prompt,
        settings: widget.appState.llmSettings,
      );
      ctrl.text = text;
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Generation failed: $e')));
    } finally {
      if (mounted) setState(() => _generating[key] = false);
    }
  }

  Future<void> _pickDate({required bool isStart}) async {
    final initial = isStart ? (_startDate ?? DateTime.now()) : (_endDate ?? DateTime.now());
    final picked = await showDatePicker(
      context: context,
      initialDate: initial,
      firstDate: DateTime(2020),
      lastDate: DateTime(2030),
      builder: (ctx, child) => Theme(
        data: Theme.of(ctx).copyWith(
          colorScheme: const ColorScheme.dark(primary: _cyan, onPrimary: Colors.black, surface: Color(0xFF1E1E2E), onSurface: Colors.white),
        ),
        child: child!,
      ),
    );
    if (picked != null) setState(() { if (isStart) _startDate = picked; else _endDate = picked; });
  }

  Future<void> _onGenerate() async {
    if (!_formKey.currentState!.validate()) return;
    final project = widget.appState.currentProject;
    if (project?.id != null) {
      await DatabaseHelper.updateProjectReportFields(
        project!.id!,
        reportTitle: _titleCtrl.text.trim(),
        pentesterName: _pentesterCtrl.text.trim(),
        executiveSummary: _execSummaryCtrl.text.trim(),
        methodology: _methodologyCtrl.text.trim(),
        riskRatingModel: _riskRatingCtrl.text.trim(),
        conclusion: _conclusionCtrl.text.trim(),
      );
    }

    final slug = _titleCtrl.text.trim().replaceAll(RegExp(r'[^a-zA-Z0-9]+'), '_').replaceAll(RegExp(r'^_+|_+$'), '');
    final fileName = switch (_format) {
      'html' => '${slug}_Report.html',
      'md'   => '${slug}_Report.md',
      'csv'  => '${slug}_Findings.csv',
      _      => '${slug}_Report.html',
    };
    final path = await FileDialog.saveFile(dialogTitle: 'Save Report', fileName: fileName);
    if (path == null || !mounted) return;

    setState(() => _savingReport = true);
    try {
      final updatedProject = (project ?? widget.appState.currentProject!).copyWith(
        reportTitle: _titleCtrl.text.trim(),
        pentesterName: _pentesterCtrl.text.trim(),
        executiveSummary: _execSummaryCtrl.text.trim(),
        methodology: _methodologyCtrl.text.trim(),
        riskRatingModel: _riskRatingCtrl.text.trim(),
        conclusion: _conclusionCtrl.text.trim(),
      );
      final commandLogs = updatedProject.id != null
          ? await DatabaseHelper.getCommandLogs(updatedProject.id!)
          : <CommandLog>[];

      String? attackNarrative;
      if (_format != 'csv') {
        final narrativePrompt = ReportContentService.buildAttackNarrativePrompt(widget.appState);
        if (narrativePrompt != null) {
          try { attackNarrative = await ReportContentService.generateSection(prompt: narrativePrompt, settings: widget.appState.llmSettings); } catch (_) {}
        }
      }

      final content = switch (_format) {
        'html' => ReportGenerator.generateHtml(project: updatedProject, targets: widget.appState.targets, vulnerabilities: widget.appState.vulnerabilities, credentials: widget.appState.credentials.toList(), commandLogs: commandLogs, scope: widget.appState.projectScope, llmSettings: widget.appState.llmSettings, startDate: _startDate, endDate: _endDate, attackNarrative: attackNarrative, confirmedOnly: _confirmedOnly),
        'md'   => ReportGenerator.generateMarkdown(project: updatedProject, targets: widget.appState.targets, vulnerabilities: widget.appState.vulnerabilities, credentials: widget.appState.credentials.toList(), commandLogs: commandLogs, scope: widget.appState.projectScope, llmSettings: widget.appState.llmSettings, startDate: _startDate, endDate: _endDate, attackNarrative: attackNarrative, confirmedOnly: _confirmedOnly),
        'csv'  => ReportGenerator.generateCsv(vulnerabilities: widget.appState.vulnerabilities, commandLogs: commandLogs, confirmedOnly: false),
        _      => '',
      };

      await File(path).writeAsString(content);
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Report saved')));
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Report generation failed: $e')));
    } finally {
      if (mounted) setState(() => _savingReport = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final appState = widget.appState;
    final vulns = appState.vulnerabilities;
    final confirmed = vulns.where((v) => v.status == VulnerabilityStatus.confirmed).length;
    final notVuln = vulns.where((v) => v.status == VulnerabilityStatus.notVulnerable).length;
    final undetermined = vulns.where((v) => v.status == VulnerabilityStatus.undetermined).length;
    final pending = vulns.where((v) => v.status == VulnerabilityStatus.pending).length;
    final critical = vulns.where((v) => v.status == VulnerabilityStatus.confirmed && v.severity.toUpperCase() == 'CRITICAL').length;
    final high = vulns.where((v) => v.status == VulnerabilityStatus.confirmed && v.severity.toUpperCase() == 'HIGH').length;
    final medium = vulns.where((v) => v.status == VulnerabilityStatus.confirmed && v.severity.toUpperCase() == 'MEDIUM').length;
    final low = vulns.where((v) => v.status == VulnerabilityStatus.confirmed && v.severity.toUpperCase() == 'LOW').length;

    return Form(
      key: _formKey,
      child: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          // Results summary
          const Text('RESULTS SUMMARY', style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 12, letterSpacing: 1)),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8, runSpacing: 8,
            children: [
              _statCard('CONFIRMED', confirmed, const Color(0xFF00FF88)),
              _statCard('NOT VULN', notVuln, Colors.white54),
              _statCard('UNDETERMINED', undetermined, const Color(0xFFFFAA00)),
              _statCard('PENDING', pending, Colors.white24),
              _statCard('CRITICAL', critical, const Color(0xFFFF0040)),
              _statCard('HIGH', high, const Color(0xFFFF6B00)),
              _statCard('MEDIUM', medium, const Color(0xFFFFAA00)),
              _statCard('LOW', low, _cyan),
              _statCard('CREDS', appState.credentials.length, const Color(0xFF00FF88)),
            ],
          ),
          const SizedBox(height: 24),

          // Authorship
          const Text('REPORT CONFIGURATION', style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 12, letterSpacing: 1)),
          const SizedBox(height: 12),
          _sectionCard('Authorship', [
            _field(_titleCtrl, 'Report Title', validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null),
            const SizedBox(height: 10),
            _field(_pentesterCtrl, "Pentester's Name", validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null),
          ]),
          const SizedBox(height: 10),

          // Dates
          _sectionCard('Assessment Dates', [
            Row(children: [
              Expanded(child: _datePicker('Start Date', _startDate, isStart: true)),
              const SizedBox(width: 10),
              Expanded(child: _datePicker('End Date', _endDate, isStart: false)),
            ]),
          ]),
          const SizedBox(height: 10),

          // Narrative sections
          _narrativeCard('executiveSummary', 'Executive Summary', _execSummaryCtrl,
              () => ReportContentService.buildExecutiveSummaryPrompt(appState)),
          const SizedBox(height: 10),
          _narrativeCard('methodology', 'Methodology & Scope', _methodologyCtrl,
              () => ReportContentService.buildMethodologyPrompt(appState)),
          const SizedBox(height: 10),
          _narrativeCard('riskRating', 'Risk Rating Model', _riskRatingCtrl,
              () => ReportContentService.buildRiskRatingPrompt(appState)),
          const SizedBox(height: 10),
          _narrativeCard('conclusion', 'Conclusion', _conclusionCtrl,
              () => ReportContentService.buildConclusionPrompt(appState)),
          const SizedBox(height: 20),

          // Format + generate
          _sectionCard('Generate', [
            Row(children: [
              const Text('Format:', style: TextStyle(color: Colors.white54, fontSize: 12)),
              const SizedBox(width: 8),
              _formatChip('html', 'HTML'),
              const SizedBox(width: 6),
              _formatChip('md', 'Markdown'),
              const SizedBox(width: 6),
              _formatChip('csv', 'CSV'),
              const Spacer(),
              Row(children: [
                Checkbox(value: _confirmedOnly, onChanged: (v) => setState(() => _confirmedOnly = v ?? true), activeColor: _cyan, side: const BorderSide(color: Colors.white38)),
                const Text('Confirmed only', style: TextStyle(color: Colors.white54, fontSize: 12)),
              ]),
            ]),
            const SizedBox(height: 12),
            if (_savingReport)
              const Row(children: [
                SizedBox(width: 16, height: 16, child: CircularProgressIndicator(color: _cyan, strokeWidth: 2)),
                SizedBox(width: 12),
                Text('Generating report…', style: TextStyle(color: Colors.white54, fontSize: 13)),
              ])
            else
              AnimatedBuilder(
                animation: Listenable.merge([_titleCtrl, _pentesterCtrl]),
                builder: (_, __) {
                  final enabled = !_anyGenerating && _titleCtrl.text.trim().isNotEmpty && _pentesterCtrl.text.trim().isNotEmpty && appState.hasResults;
                  return SizedBox(
                    width: double.infinity,
                    child: ElevatedButton.icon(
                      onPressed: enabled ? _onGenerate : null,
                      icon: const Icon(Icons.download, size: 16),
                      label: const Text('Generate Report', style: TextStyle(fontWeight: FontWeight.bold)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: _cyan,
                        foregroundColor: Colors.black,
                        disabledBackgroundColor: _cyan.withValues(alpha: 0.2),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                      ),
                    ),
                  );
                },
              ),
          ]),
        ],
      ),
    );
  }

  Widget _statCard(String label, int value, Color color) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
    decoration: BoxDecoration(color: _card, borderRadius: BorderRadius.circular(8), border: Border.all(color: color.withValues(alpha: 0.3))),
    child: Column(mainAxisSize: MainAxisSize.min, children: [
      Text(value.toString(), style: TextStyle(color: color, fontSize: 20, fontWeight: FontWeight.bold, fontFamily: 'monospace')),
      Text(label, style: const TextStyle(color: Colors.white38, fontSize: 9, letterSpacing: 0.8)),
    ]),
  );

  Widget _sectionCard(String label, List<Widget> children) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(color: _card, borderRadius: BorderRadius.circular(8), border: Border.all(color: Colors.white12)),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(label.toUpperCase(), style: const TextStyle(color: _cyan, fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 1)),
      const SizedBox(height: 10),
      ...children,
    ]),
  );

  Widget _field(TextEditingController ctrl, String label, {String? Function(String?)? validator}) => TextFormField(
    controller: ctrl,
    validator: validator,
    style: const TextStyle(color: Colors.white, fontSize: 13),
    decoration: InputDecoration(
      labelText: label,
      labelStyle: const TextStyle(color: Colors.white38, fontSize: 12),
      filled: true, fillColor: _dark,
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: Colors.white12)),
      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: Colors.white12)),
      focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: _cyan, width: 1.5)),
    ),
  );

  Widget _datePicker(String label, DateTime? date, {required bool isStart}) {
    final display = date != null ? '${date.year}-${date.month.toString().padLeft(2,'0')}-${date.day.toString().padLeft(2,'0')}' : 'Not set';
    return InkWell(
      onTap: () => _pickDate(isStart: isStart),
      borderRadius: BorderRadius.circular(6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 10),
        decoration: BoxDecoration(color: _dark, borderRadius: BorderRadius.circular(6), border: Border.all(color: Colors.white12)),
        child: Row(children: [
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(label.toUpperCase(), style: const TextStyle(color: Colors.white38, fontSize: 9, letterSpacing: 0.8)),
            const SizedBox(height: 2),
            Text(display, style: TextStyle(color: date != null ? Colors.white : Colors.white38, fontSize: 13)),
          ])),
          const Icon(Icons.calendar_today, color: _cyan, size: 14),
        ]),
      ),
    );
  }

  Widget _narrativeCard(String key, String label, TextEditingController ctrl, String Function() promptBuilder) {
    final isGenerating = _generating[key] ?? false;
    return _sectionCard(label, [
      Row(mainAxisAlignment: MainAxisAlignment.end, children: [
        OutlinedButton.icon(
          onPressed: (isGenerating || _anyGenerating) ? null : () => _generate(key, promptBuilder(), ctrl),
          icon: isGenerating
              ? const SizedBox(width: 12, height: 12, child: CircularProgressIndicator(strokeWidth: 2, color: _cyan))
              : const Icon(Icons.auto_awesome, size: 12),
          label: Text(isGenerating ? 'Generating…' : 'Generate with AI'),
          style: OutlinedButton.styleFrom(foregroundColor: _cyan, side: const BorderSide(color: _cyan), padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6), textStyle: const TextStyle(fontSize: 11)),
        ),
      ]),
      const SizedBox(height: 6),
      TextField(
        controller: ctrl,
        minLines: 4,
        maxLines: 12,
        style: const TextStyle(color: Colors.white, fontSize: 12, height: 1.5),
        decoration: InputDecoration(
          hintText: 'Leave blank or click "Generate with AI" to populate…',
          hintStyle: const TextStyle(color: Colors.white24, fontSize: 12),
          filled: true, fillColor: _dark,
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: Colors.white12)),
          enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: Colors.white12)),
          focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6), borderSide: const BorderSide(color: _cyan, width: 1.5)),
        ),
      ),
    ]);
  }

  Widget _formatChip(String value, String label) {
    final selected = _format == value;
    return InkWell(
      onTap: () => setState(() => _format = value),
      borderRadius: BorderRadius.circular(20),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
        decoration: BoxDecoration(
          color: selected ? _cyan : Colors.transparent,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: selected ? _cyan : Colors.white24),
        ),
        child: Text(label, style: TextStyle(color: selected ? Colors.black : Colors.white54, fontSize: 11, fontWeight: selected ? FontWeight.bold : FontWeight.normal)),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Token stats panel
// ---------------------------------------------------------------------------

class _TokenStatsPanel extends StatefulWidget {
  const _TokenStatsPanel();

  @override
  State<_TokenStatsPanel> createState() => _TokenStatsPanelState();
}

class _TokenStatsPanelState extends State<_TokenStatsPanel> {
  Map<String, ({int sent, int received})> _byTarget = {};
  bool _loadingByTarget = false;

  Future<void> _refresh(AppState appState) async {
    if (appState.currentProject?.id == null) return;
    setState(() => _loadingByTarget = true);
    final result = await DatabaseHelper.getTokenTotalsByTarget(appState.currentProject!.id!);
    final targetMap = {for (final t in appState.targets) t.id.toString(): t.address};
    final mapped = <String, ({int sent, int received})>{};
    for (final entry in result.entries) {
      final addr = targetMap[entry.key] ?? 'Target ${entry.key}';
      mapped[addr] = entry.value;
    }
    if (mounted) setState(() { _byTarget = mapped; _loadingByTarget = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, appState, _) => Container(
        color: const Color(0xFF0D1230),
        child: Column(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              color: const Color(0xFF1A1F3A),
              child: Row(children: [
                const Text('TOKEN USAGE', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 11, letterSpacing: 1)),
                const Spacer(),
                IconButton(
                  icon: _loadingByTarget
                      ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(color: Color(0xFF00F5FF), strokeWidth: 2))
                      : const Icon(Icons.refresh, color: Color(0xFF00F5FF), size: 16),
                  onPressed: _loadingByTarget ? null : () => _refresh(appState),
                  tooltip: 'Refresh from DB',
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                ),
              ]),
            ),
            Expanded(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _sectionLabel('PROJECT TOTALS'),
                    _tokenRow('Total Sent', appState.tokensSentTotal),
                    _tokenRow('Total Received', appState.tokensReceivedTotal),
                    _tokenRow('Combined', appState.tokensSentTotal + appState.tokensReceivedTotal),
                    const Divider(color: Colors.white12, height: 20),
                    _sectionLabel('BY PHASE'),
                    _phaseRow('Recon', appState.tokensSentRecon, appState.tokensReceivedRecon),
                    _phaseRow('Analyze', appState.tokensSentAnalyze, appState.tokensReceivedAnalyze),
                    _phaseRow('Execute', appState.tokensSentExecute, appState.tokensReceivedExecute),
                    _phaseRow('Report', appState.tokensSentReport, appState.tokensReceivedReport),
                    if (_byTarget.isNotEmpty) ...[
                      const Divider(color: Colors.white12, height: 20),
                      _sectionLabel('BY TARGET'),
                      for (final entry in _byTarget.entries)
                        _phaseRow(
                          entry.key.length > 20 ? '${entry.key.substring(0, 18)}…' : entry.key,
                          entry.value.sent,
                          entry.value.received,
                        ),
                    ],
                    if (_byTarget.isEmpty) ...[
                      const SizedBox(height: 12),
                      GestureDetector(
                        onTap: () => _refresh(appState),
                        child: const Text('Tap refresh to load per-target breakdown', style: TextStyle(color: Colors.white24, fontSize: 11)),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _sectionLabel(String label) => Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: Text(label, style: const TextStyle(color: Color(0xFF00F5FF), fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 1)),
  );

  Widget _tokenRow(String label, int value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 3),
    child: Row(children: [
      Text(label, style: const TextStyle(color: Colors.white54, fontSize: 12)),
      const Spacer(),
      Text(_fmt(value), style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontSize: 12)),
    ]),
  );

  Widget _phaseRow(String label, int sent, int received) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 3),
    child: Row(children: [
      Expanded(child: Text(label, style: const TextStyle(color: Colors.white54, fontSize: 11), overflow: TextOverflow.ellipsis)),
      Text('↑${_fmt(sent)} ↓${_fmt(received)}', style: const TextStyle(color: Colors.white70, fontFamily: 'monospace', fontSize: 11)),
    ]),
  );

  static String _fmt(int n) {
    final s = n.toString();
    final buf = StringBuffer();
    for (var i = 0; i < s.length; i++) {
      if (i > 0 && (s.length - i) % 3 == 0) buf.write(',');
      buf.write(s[i]);
    }
    return buf.toString();
  }
}
