import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../../models/credential.dart';
import '../../models/vulnerability.dart';
import '../../widgets/app_state.dart';
import '../../widgets/stats_bar.dart';
import '../../database/database_helper.dart';
import '../../models/command_log.dart';
import '../../services/report_generator.dart';
import '../../services/report_content_service.dart';
import '../../utils/file_dialog.dart';

class ResultReportTab extends StatefulWidget {
  const ResultReportTab({super.key});

  @override
  State<ResultReportTab> createState() => _ResultReportTabState();
}

class _ResultReportTabState extends State<ResultReportTab> {
  static const _cyan = Color(0xFF00F5FF);
  static const _card = Color(0xFF1A1F3A);

  final _formKey2 = GlobalKey<_InlineReportFormState>();
  String _format = 'html';
  bool _confirmedOnly = true;
  bool _savingReport = false;

  Future<void> _onGenerate() async {
    await _formKey2.currentState?.doGenerate(
      _format,
      _confirmedOnly,
      onSavingChanged: (v) { if (mounted) setState(() => _savingReport = v); },
    );
  }

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
                Expanded(child: _InlineReportForm(key: _formKey2, appState: appState)),
                SizedBox(
                  width: 350,
                  child: _TokenStatsPanel(generateWidget: _buildGenerateCard(appState)),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildGenerateCard(AppState appState) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: const BoxDecoration(
        color: _card,
        border: Border(bottom: BorderSide(color: Colors.white12)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text('GENERATE', style: TextStyle(color: _cyan, fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 1)),
          const SizedBox(height: 10),
          Row(children: [
            const Text('Format:', style: TextStyle(color: Colors.white54, fontSize: 12)),
            const SizedBox(width: 8),
            _fmtChip('html', 'HTML'),
            const SizedBox(width: 6),
            _fmtChip('md', 'Markdown'),
            const SizedBox(width: 6),
            _fmtChip('csv', 'CSV'),
          ]),
          const SizedBox(height: 6),
          Row(children: [
            SizedBox(
              width: 20,
              height: 20,
              child: Checkbox(
                value: _confirmedOnly,
                onChanged: (v) => setState(() => _confirmedOnly = v ?? true),
                activeColor: _cyan,
                side: const BorderSide(color: Colors.white38),
                materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
              ),
            ),
            const SizedBox(width: 6),
            const Text('Confirmed only', style: TextStyle(color: Colors.white54, fontSize: 12)),
          ]),
          const SizedBox(height: 12),
          if (_savingReport)
            const Row(children: [
              SizedBox(width: 16, height: 16, child: CircularProgressIndicator(color: _cyan, strokeWidth: 2)),
              SizedBox(width: 10),
              Expanded(child: Text('Generating report…', style: TextStyle(color: Colors.white54, fontSize: 12))),
            ])
          else
            SizedBox(
              width: double.infinity,
              child: ElevatedButton.icon(
                onPressed: appState.hasResults && !_savingReport ? _onGenerate : null,
                icon: const Icon(Icons.download, size: 16),
                label: const Text('Generate Report', style: TextStyle(fontWeight: FontWeight.bold)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: _cyan,
                  foregroundColor: Colors.black,
                  disabledBackgroundColor: _cyan.withValues(alpha: 0.2),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                ),
              ),
            ),
        ],
      ),
    );
  }

  Widget _fmtChip(String value, String label) {
    final selected = _format == value;
    return InkWell(
      onTap: () => setState(() => _format = value),
      borderRadius: BorderRadius.circular(20),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
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
// Inline report form — always visible, no dialog needed
// ---------------------------------------------------------------------------

class _InlineReportForm extends StatefulWidget {
  final AppState appState;
  const _InlineReportForm({super.key, required this.appState});

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
  final Map<String, bool> _generating = {
    'executiveSummary': false,
    'methodology': false,
    'riskRating': false,
    'conclusion': false,
  };

  bool get _anyGenerating => _generating.values.any((v) => v);

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
        onTokensUsed: (sent, received) => widget.appState.recordTokenUsage('report', sent, received),
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

  /// Called by the parent tab's generate button. Public so _ResultReportTabState can invoke it.
  Future<void> doGenerate(String format, bool confirmedOnly, {required void Function(bool) onSavingChanged}) async {
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
    final fileName = switch (format) {
      'html' => '${slug}_Report.html',
      'md'   => '${slug}_Report.md',
      'csv'  => '${slug}_Findings.csv',
      _      => '${slug}_Report.html',
    };
    final path = await FileDialog.saveFile(dialogTitle: 'Save Report', fileName: fileName);
    if (path == null || !mounted) return;

    onSavingChanged(true);
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
      if (format != 'csv') {
        final narrativePrompt = ReportContentService.buildAttackNarrativePrompt(widget.appState);
        if (narrativePrompt != null) {
          try { attackNarrative = await ReportContentService.generateSection(prompt: narrativePrompt, settings: widget.appState.llmSettings, onTokensUsed: (s, r) => widget.appState.recordTokenUsage('report', s, r)); } catch (_) {}
        }
      }

      final content = switch (format) {
        'html' => ReportGenerator.generateHtml(project: updatedProject, targets: widget.appState.targets, vulnerabilities: widget.appState.vulnerabilities, credentials: widget.appState.credentials.toList(), commandLogs: commandLogs, scope: widget.appState.projectScope, llmSettings: widget.appState.llmSettings, startDate: _startDate, endDate: _endDate, attackNarrative: attackNarrative, confirmedOnly: confirmedOnly),
        'md'   => ReportGenerator.generateMarkdown(project: updatedProject, targets: widget.appState.targets, vulnerabilities: widget.appState.vulnerabilities, credentials: widget.appState.credentials.toList(), commandLogs: commandLogs, scope: widget.appState.projectScope, llmSettings: widget.appState.llmSettings, startDate: _startDate, endDate: _endDate, attackNarrative: attackNarrative, confirmedOnly: confirmedOnly),
        'csv'  => ReportGenerator.generateCsv(vulnerabilities: widget.appState.vulnerabilities, commandLogs: commandLogs, confirmedOnly: false),
        _      => '',
      };

      await File(path).writeAsString(content);
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Report saved')));
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Report generation failed: $e')));
    } finally {
      onSavingChanged(false);
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
          LayoutBuilder(builder: (context, constraints) {
            // Minimum readable card width: label "UNDETERMINED" at 9px needs ~72px.
            // 9 cards + 8 gaps of 6px = 48px overhead → threshold at 9 * 72 + 48 = 696px.
            final cards = [
              _statCard('CONFIRMED', confirmed, const Color(0xFF00FF88)),
              _statCard('NOT VULN', notVuln, Colors.white54),
              _statCard('UNDETERMINED', undetermined, const Color(0xFFFFAA00)),
              _statCard('PENDING', pending, Colors.white24),
              _statCard('CRITICAL', critical, const Color(0xFFFF0040)),
              _statCard('HIGH', high, const Color(0xFFFF6B00)),
              _statCard('MEDIUM', medium, const Color(0xFFFFAA00)),
              _statCard('LOW', low, _cyan),
              _statCard('CREDS', appState.credentials.length, const Color(0xFF00FF88),
                onTap: appState.credentials.isNotEmpty
                    ? () => _showCredentialsDialog(context, appState.credentials.toList())
                    : null),
            ];
            if (constraints.maxWidth >= 696) {
              // Wide enough: equal-width row
              return Row(
                children: [
                  for (int i = 0; i < cards.length; i++) ...[
                    if (i > 0) const SizedBox(width: 6),
                    Expanded(child: cards[i]),
                  ],
                ],
              );
            }
            // Narrow: wrap with fixed minimum card width
            return Wrap(
              spacing: 6,
              runSpacing: 6,
              children: cards.map((c) => SizedBox(width: 72, child: c)).toList(),
            );
          }),
          const SizedBox(height: 24),

          // Attack chains
          _AttackChainsSection(appState: appState),
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
        ],
      ),
    );
  }

  Widget _statCard(String label, int value, Color color, {VoidCallback? onTap}) {
    final card = Container(
      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 8),
      decoration: BoxDecoration(
        color: _card,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: onTap != null ? color.withValues(alpha: 0.6) : color.withValues(alpha: 0.3)),
      ),
      child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Text(value.toString(), textAlign: TextAlign.center, style: TextStyle(color: color, fontSize: 20, fontWeight: FontWeight.bold, fontFamily: 'monospace')),
        Text(label, textAlign: TextAlign.center, style: const TextStyle(color: Colors.white38, fontSize: 9, letterSpacing: 0.8)),
        if (onTap != null) ...[
          const SizedBox(height: 2),
          Icon(Icons.open_in_new, size: 9, color: color.withValues(alpha: 0.5)),
        ],
      ]),
    );
    if (onTap == null) return card;
    return InkWell(onTap: onTap, borderRadius: BorderRadius.circular(8), child: card);
  }

  void _showCredentialsDialog(BuildContext context, List<DiscoveredCredential> creds) {
    Widget credCell(String value, {bool isSecret = false}) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 6),
      child: SelectableText(
        value.isEmpty ? '—' : value,
        style: TextStyle(
          color: isSecret ? const Color(0xFFFFAA00) : Colors.white70,
          fontSize: 11,
          fontFamily: isSecret ? 'monospace' : null,
        ),
      ),
    );

    showDialog(
      context: context,
      builder: (ctx) => Dialog(
        backgroundColor: const Color(0xFF0A0E27),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12), side: const BorderSide(color: Color(0xFF00FF88), width: 1)),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 900, maxHeight: 600),
          child: Column(
            children: [
              // Header
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                decoration: const BoxDecoration(
                  color: Color(0xFF1A1F3A),
                  borderRadius: BorderRadius.vertical(top: Radius.circular(12)),
                ),
                child: Row(children: [
                  const Icon(Icons.key, color: Color(0xFF00FF88), size: 16),
                  const SizedBox(width: 8),
                  Text('CAPTURED CREDENTIALS (${creds.length})',
                      style: const TextStyle(color: Color(0xFF00FF88), fontWeight: FontWeight.bold, fontSize: 13, letterSpacing: 1)),
                  const Spacer(),
                  TextButton.icon(
                    onPressed: () {
                      final buf = StringBuffer('ADDRESS\tPORT/SERVICE\tUSERNAME\tPASSWORD/HASH\tTYPE\n');
                      for (final c in creds) {
                        buf.writeln('${c.host}\t${c.service}\t${c.username}\t${c.secret}\t${c.secretType}');
                      }
                      Clipboard.setData(ClipboardData(text: buf.toString()));
                      ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Credentials copied to clipboard')));
                    },
                    icon: const Icon(Icons.copy, size: 13),
                    label: const Text('Copy All', style: TextStyle(fontSize: 12)),
                    style: TextButton.styleFrom(foregroundColor: const Color(0xFF00FF88)),
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    onPressed: () => Navigator.of(ctx).pop(),
                    icon: const Icon(Icons.close, color: Colors.white38, size: 16),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(),
                  ),
                ]),
              ),
              // Table
              Expanded(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(16),
                  child: Table(
                    defaultVerticalAlignment: TableCellVerticalAlignment.middle,
                    columnWidths: const {
                      0: FlexColumnWidth(2),
                      1: FlexColumnWidth(2),
                      2: FlexColumnWidth(2),
                      3: FlexColumnWidth(3),
                      4: FlexColumnWidth(1.5),
                    },
                    children: [
                      TableRow(
                        decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: Colors.white12))),
                        children: ['ADDRESS', 'PORT / SERVICE', 'USERNAME', 'PASSWORD / HASH', 'TYPE'].map((h) =>
                          Padding(
                            padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 6),
                            child: Text(h, style: const TextStyle(color: Color(0xFF00F5FF), fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 0.8)),
                          )
                        ).toList(),
                      ),
                      ...creds.asMap().entries.map((e) => TableRow(
                        decoration: BoxDecoration(color: e.key.isOdd ? const Color(0xFF1A1F3A) : Colors.transparent),
                        children: [
                          credCell(e.value.host),
                          credCell(e.value.service),
                          credCell(e.value.username),
                          credCell(e.value.secret, isSecret: true),
                          credCell(e.value.secretType),
                        ],
                      )),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

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

}

// ---------------------------------------------------------------------------
// Attack chains panel
// ---------------------------------------------------------------------------

class _AttackChainsSection extends StatefulWidget {
  final AppState appState;
  const _AttackChainsSection({required this.appState});

  @override
  State<_AttackChainsSection> createState() => _AttackChainsSectionState();
}

class _AttackChainsSectionState extends State<_AttackChainsSection> {
  List<Map<String, dynamic>> _chains = [];
  bool _loading = false;
  int? _loadedProjectId;

  static const _cyan = Color(0xFF00F5FF);
  static const _card = Color(0xFF1A1F3A);
  static const _dark = Color(0xFF0A0E27);

  @override
  void didUpdateWidget(_AttackChainsSection oldWidget) {
    super.didUpdateWidget(oldWidget);
    final newId = widget.appState.currentProject?.id;
    if (newId != _loadedProjectId) _load(newId);
  }

  @override
  void initState() {
    super.initState();
    _load(widget.appState.currentProject?.id);
  }

  Future<void> _load(int? projectId) async {
    if (projectId == null) { setState(() { _chains = []; _loadedProjectId = null; }); return; }
    setState(() => _loading = true);
    final chains = await DatabaseHelper.getAttackChains(projectId);
    if (mounted) setState(() { _chains = chains; _loadedProjectId = projectId; _loading = false; });
  }

  Color _severityColor(String severity) => switch (severity.toUpperCase()) {
    'CRITICAL' => const Color(0xFFFF0040),
    'HIGH'     => const Color(0xFFFF6B00),
    'MEDIUM'   => const Color(0xFFFFAA00),
    'LOW'      => _cyan,
    _          => Colors.white38,
  };

  @override
  Widget build(BuildContext context) {
    // Re-check if project changed since last build (e.g. Consumer rebuild)
    final currentId = widget.appState.currentProject?.id;
    if (currentId != _loadedProjectId && !_loading) {
      Future.microtask(() => _load(currentId));
    }

    // Only render if there are chains or we're loading
    final attackChains = _chains.where((c) {
      final vt = (c['vulnerabilityType'] as String? ?? '');
      return vt == 'AttackChain';
    }).toList();

    // Also include any AppState vulns of type AttackChain (live, before DB flush)
    final liveChains = widget.appState.vulnerabilities
        .where((v) => v.vulnerabilityType == 'AttackChain')
        .toList();

    // Merge: prefer DB records, supplement with live ones not yet persisted
    final dbIds = {for (final c in attackChains) c['id'] as int?};
    for (final lv in liveChains) {
      if (!dbIds.contains(lv.id)) {
        attackChains.add({
          'id': lv.id,
          'problem': lv.problem,
          'severity': lv.severity,
          'description': lv.description,
          'evidence': lv.evidence,
          'targetAddress': lv.targetAddress,
          'vulnerabilityType': lv.vulnerabilityType,
        });
      }
    }

    if (!_loading && attackChains.isEmpty) return const SizedBox.shrink();

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(children: [
          const Text('ATTACK CHAINS', style: TextStyle(color: Color(0xFFFF6B00), fontWeight: FontWeight.bold, fontSize: 12, letterSpacing: 1)),
          const SizedBox(width: 8),
          if (_loading)
            const SizedBox(width: 12, height: 12, child: CircularProgressIndicator(color: Color(0xFFFF6B00), strokeWidth: 2))
          else
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(color: const Color(0xFFFF6B00).withValues(alpha: 0.2), borderRadius: BorderRadius.circular(10), border: Border.all(color: const Color(0xFFFF6B00).withValues(alpha: 0.5))),
              child: Text('${attackChains.length}', style: const TextStyle(color: Color(0xFFFF6B00), fontSize: 10, fontWeight: FontWeight.bold)),
            ),
          const Spacer(),
          IconButton(
            icon: const Icon(Icons.refresh, size: 14, color: Color(0xFFFF6B00)),
            onPressed: _loading ? null : () => _load(currentId),
            tooltip: 'Refresh chains',
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
        ]),
        const SizedBox(height: 8),
        ...attackChains.map((chain) => _ChainCard(chain: chain, severityColor: _severityColor(chain['severity'] as String? ?? ''), cardColor: _card, darkColor: _dark)),
      ],
    );
  }
}

class _ChainCard extends StatefulWidget {
  final Map<String, dynamic> chain;
  final Color severityColor;
  final Color cardColor;
  final Color darkColor;
  const _ChainCard({required this.chain, required this.severityColor, required this.cardColor, required this.darkColor});

  @override
  State<_ChainCard> createState() => _ChainCardState();
}

class _ChainCardState extends State<_ChainCard> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    final chain = widget.chain;
    final problem = chain['problem'] as String? ?? 'Attack Chain';
    final severity = (chain['severity'] as String? ?? 'UNKNOWN').toUpperCase();
    final description = chain['description'] as String? ?? '';
    final evidence = chain['evidence'] as String? ?? '';
    final target = chain['targetAddress'] as String? ?? '';
    final color = widget.severityColor;

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Container(
        decoration: BoxDecoration(
          color: widget.cardColor,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.4)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header row — always visible
            InkWell(
              onTap: () => setState(() => _expanded = !_expanded),
              borderRadius: const BorderRadius.vertical(top: Radius.circular(8)),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                child: Row(children: [
                  // Severity badge
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
                    decoration: BoxDecoration(color: color.withValues(alpha: 0.15), borderRadius: BorderRadius.circular(4), border: Border.all(color: color.withValues(alpha: 0.6))),
                    child: Text(severity, style: TextStyle(color: color, fontSize: 9, fontWeight: FontWeight.bold, letterSpacing: 0.8)),
                  ),
                  const SizedBox(width: 10),
                  // Chain icon
                  Icon(Icons.account_tree, size: 14, color: color.withValues(alpha: 0.7)),
                  const SizedBox(width: 6),
                  // Title
                  Expanded(child: Text(problem, style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w600), overflow: TextOverflow.ellipsis)),
                  // Target badge
                  if (target.isNotEmpty) ...[
                    const SizedBox(width: 6),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(color: Colors.white.withValues(alpha: 0.05), borderRadius: BorderRadius.circular(4), border: Border.all(color: Colors.white12)),
                      child: Text(target, style: const TextStyle(color: Colors.white38, fontSize: 9, fontFamily: 'monospace')),
                    ),
                  ],
                  const SizedBox(width: 6),
                  Icon(_expanded ? Icons.expand_less : Icons.expand_more, color: Colors.white38, size: 16),
                ]),
              ),
            ),

            // Expanded body
            if (_expanded) ...[
              const Divider(color: Colors.white12, height: 1),
              Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    if (description.isNotEmpty) ...[
                      const Text('CHAIN STEPS', style: TextStyle(color: Colors.white38, fontSize: 9, letterSpacing: 1, fontWeight: FontWeight.bold)),
                      const SizedBox(height: 6),
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(color: widget.darkColor, borderRadius: BorderRadius.circular(6), border: Border.all(color: Colors.white12)),
                        child: SelectableText(
                          description,
                          style: const TextStyle(color: Colors.white70, fontSize: 11, height: 1.6),
                        ),
                      ),
                    ],
                    if (evidence.isNotEmpty) ...[
                      const SizedBox(height: 10),
                      const Text('EVIDENCE', style: TextStyle(color: Colors.white38, fontSize: 9, letterSpacing: 1, fontWeight: FontWeight.bold)),
                      const SizedBox(height: 6),
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(color: widget.darkColor, borderRadius: BorderRadius.circular(6), border: Border.all(color: Colors.white12)),
                        child: SelectableText(
                          evidence,
                          style: const TextStyle(color: Colors.white54, fontSize: 11, fontStyle: FontStyle.italic, height: 1.5),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Token stats panel
// ---------------------------------------------------------------------------

class _TokenStatsPanel extends StatefulWidget {
  final Widget? generateWidget;
  const _TokenStatsPanel({this.generateWidget});

  @override
  State<_TokenStatsPanel> createState() => _TokenStatsPanelState();
}

class _TokenStatsPanelState extends State<_TokenStatsPanel> {
  Map<String, ({int sent, int received})> _byTarget = {};
  bool _loadingByTarget = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final appState = Provider.of<AppState>(context, listen: false);
      _refresh(appState);
    });
  }

  Future<void> _refresh(AppState appState) async {
    if (appState.currentProject?.id == null) return;
    setState(() => _loadingByTarget = true);
    final result = await DatabaseHelper.getTokenTotalsByTarget(appState.currentProject!.id!);
    final targetMap = {for (final t in appState.targets) t.id.toString(): t.address};
    final mapped = <String, ({int sent, int received})>{};
    for (final entry in result.entries) {
      if (entry.key == '0') continue; // skip phantom targetId=0 records
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
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Generate card — at the top, above token stats
              if (widget.generateWidget != null) widget.generateWidget!,
              // TOKEN USAGE header
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
              // Token stats content
              Padding(
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
                    if (_byTarget.isEmpty && !_loadingByTarget) ...[
                      const SizedBox(height: 12),
                      const Text('No per-target data yet', style: TextStyle(color: Colors.white24, fontSize: 11)),
                    ],
                  ],
                ),
              ),
            ],
          ),
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
