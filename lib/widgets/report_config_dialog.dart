import 'dart:io';
import 'package:flutter/material.dart';
import '../database/database_helper.dart';
import '../models/command_log.dart';
import '../services/report_content_service.dart';
import '../services/report_generator.dart';
import '../utils/file_dialog.dart';
import '../widgets/app_state.dart';

// ---------------------------------------------------------------------------
// Data class returned by the dialog when the user confirms generation
// ---------------------------------------------------------------------------

class ReportConfig {
  final String reportTitle;
  final String pentesterName;
  final DateTime? startDate;
  final DateTime? endDate;
  final String executiveSummary;
  final String methodology;
  final String riskRatingModel;
  final String conclusion;
  final String format; // 'html', 'md', 'csv'
  final bool confirmedOnly;

  const ReportConfig({
    required this.reportTitle,
    required this.pentesterName,
    this.startDate,
    this.endDate,
    required this.executiveSummary,
    required this.methodology,
    required this.riskRatingModel,
    required this.conclusion,
    required this.format,
    this.confirmedOnly = true,
  });
}

// ---------------------------------------------------------------------------
// Dialog widget
// ---------------------------------------------------------------------------

class ReportConfigDialog extends StatefulWidget {
  final AppState appState;

  const ReportConfigDialog({super.key, required this.appState});

  @override
  State<ReportConfigDialog> createState() => _ReportConfigDialogState();
}

class _ReportConfigDialogState extends State<ReportConfigDialog> {
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
  bool _savingReport = false; // Phase 11: progress indicator state

  // Per-field generation loading state
  final Map<String, bool> _generating = {
    'executiveSummary': false,
    'methodology': false,
    'riskRating': false,
    'conclusion': false,
  };

  bool get _anyGenerating => _generating.values.any((v) => v) || _savingReport;

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

  // ---------------------------------------------------------------------------
  // LLM generation helpers
  // ---------------------------------------------------------------------------

  Future<void> _generate(String key, String prompt, TextEditingController ctrl) async {
    setState(() => _generating[key] = true);
    try {
      final text = await ReportContentService.generateSection(
        prompt: prompt,
        settings: widget.appState.llmSettings,
      );
      ctrl.text = text;
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Generation failed: $e'),
            backgroundColor: Colors.red[800],
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _generating[key] = false);
    }
  }

  // ---------------------------------------------------------------------------
  // Date picker helper
  // ---------------------------------------------------------------------------

  Future<void> _pickDate({required bool isStart}) async {
    final initial = isStart
        ? (_startDate ?? DateTime.now())
        : (_endDate ?? DateTime.now());
    final picked = await showDatePicker(
      context: context,
      initialDate: initial,
      firstDate: DateTime(2020),
      lastDate: DateTime(2030),
      builder: (ctx, child) => Theme(
        data: Theme.of(ctx).copyWith(
          colorScheme: const ColorScheme.dark(
            primary: Color(0xFF00F5FF),
            onPrimary: Colors.black,
            surface: Color(0xFF1E1E2E),
            onSurface: Colors.white,
          ),
        ),
        child: child!,
      ),
    );
    if (picked == null) return;
    setState(() {
      if (isStart) {
        _startDate = picked;
      } else {
        _endDate = picked;
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Submit
  // ---------------------------------------------------------------------------

  Future<void> _onGenerate() async {
    if (!_formKey.currentState!.validate()) return;
    _endDate ??= DateTime.now();
    if (_startDate != null && _endDate != null && _endDate!.isBefore(_startDate!)) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Assessment end date must be on or after start date')),
      );
      return;
    }

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
      widget.appState.updateCurrentProject(
        project.copyWith(
          reportTitle: _titleCtrl.text.trim(),
          pentesterName: _pentesterCtrl.text.trim(),
          executiveSummary: _execSummaryCtrl.text.trim(),
          methodology: _methodologyCtrl.text.trim(),
          riskRatingModel: _riskRatingCtrl.text.trim(),
          conclusion: _conclusionCtrl.text.trim(),
        ),
      );
    }

    // Phase 11: Pick save path before showing progress (so user can cancel before generation starts)
    final format = _format;
    final slug = _titleCtrl.text.trim()
        .replaceAll(RegExp(r'[^a-zA-Z0-9]+'), '_')
        .replaceAll(RegExp(r'^_+|_+$'), '');
    final fileName = switch (format) {
      'html' => '${slug}_Report.html',
      'md'   => '${slug}_Report.md',
      'csv'  => '${slug}_Findings.csv',
      _      => '${slug}_Report.html',
    };
    final path = await FileDialog.saveFile(
      dialogTitle: 'Save Report',
      fileName: fileName,
    );
    if (path == null || !mounted) return;

    // Phase 11: Show progress indicator, keep dialog open
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
      if (format != 'csv') {
        final narrativePrompt = ReportContentService.buildAttackNarrativePrompt(widget.appState);
        if (narrativePrompt != null) {
          try {
            attackNarrative = await ReportContentService.generateSection(
              prompt: narrativePrompt,
              settings: widget.appState.llmSettings,
            );
          } catch (_) {}
        }
      }

      final confirmedOnly = _confirmedOnly;
      final content = switch (format) {
        'html' => ReportGenerator.generateHtml(
            project: updatedProject,
            targets: widget.appState.targets,
            vulnerabilities: widget.appState.vulnerabilities,
            credentials: widget.appState.credentials.toList(),
            commandLogs: commandLogs,
            scope: widget.appState.projectScope,
            llmSettings: widget.appState.llmSettings,
            startDate: _startDate,
            endDate: _endDate,
            attackNarrative: attackNarrative,
            confirmedOnly: confirmedOnly,
          ),
        'md' => ReportGenerator.generateMarkdown(
            project: updatedProject,
            targets: widget.appState.targets,
            vulnerabilities: widget.appState.vulnerabilities,
            credentials: widget.appState.credentials.toList(),
            commandLogs: commandLogs,
            scope: widget.appState.projectScope,
            llmSettings: widget.appState.llmSettings,
            startDate: _startDate,
            endDate: _endDate,
            attackNarrative: attackNarrative,
            confirmedOnly: confirmedOnly,
          ),
        'csv' => ReportGenerator.generateCsv(
            vulnerabilities: widget.appState.vulnerabilities,
            commandLogs: commandLogs,
            confirmedOnly: false,
          ),
        _ => '',
      };

      await File(path).writeAsString(content);
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        setState(() => _savingReport = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Report generation failed: $e'), backgroundColor: Colors.red[800]),
        );
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Build
  // ---------------------------------------------------------------------------

  static const Color _accent = Color(0xFF00F5FF);
  static const Color _surface = Color(0xFF1E1E2E);
  static const Color _cardBg = Color(0xFF252535);

  @override
  Widget build(BuildContext context) {
    final isNarrow = MediaQuery.of(context).size.width < 900;

    return Dialog(
      backgroundColor: _surface,
      insetPadding: const EdgeInsets.all(32),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: SizedBox(
        width: double.infinity,
        height: MediaQuery.of(context).size.height - 64,
        child: Column(
          children: [
            _buildHeader(),
            if (_anyGenerating)
              LinearProgressIndicator(
                color: _accent,
                backgroundColor: _accent.withValues(alpha: 0.15),
                minHeight: 2,
              ),
            Expanded(
              child: isNarrow
                  ? _buildNarrowLayout()
                  : _buildWideLayout(),
            ),
            _buildActionBar(),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      decoration: const BoxDecoration(
        color: Color(0xFF1A1A2E),
        borderRadius: BorderRadius.vertical(top: Radius.circular(12)),
        border: Border(bottom: BorderSide(color: Color(0xFF2A2A3E))),
      ),
      child: Row(
        children: [
          const Icon(Icons.description_outlined, color: _accent, size: 22),
          const SizedBox(width: 12),
          const Text(
            'Configure Report',
            style: TextStyle(
              color: Colors.white,
              fontSize: 18,
              fontWeight: FontWeight.w600,
            ),
          ),
          const Spacer(),
          IconButton(
            icon: const Icon(Icons.close, color: Colors.white54, size: 20),
            onPressed: _savingReport ? null : () => Navigator.of(context).pop(),
            tooltip: 'Cancel',
          ),
        ],
      ),
    );
  }

  Widget _buildWideLayout() {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          flex: 60,
          child: _buildForm(),
        ),
        const VerticalDivider(width: 1, color: Color(0xFF2A2A3E)),
        Expanded(
          flex: 40,
          child: _buildPreviewPanel(),
        ),
      ],
    );
  }

  Widget _buildNarrowLayout() => _buildForm();

  // ---------------------------------------------------------------------------
  // Form
  // ---------------------------------------------------------------------------

  Widget _buildForm() {
    return Form(
      key: _formKey,
      child: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          // --- Authorship card ---
          _card(
            label: 'Authorship',
            children: [
              _field(
                controller: _titleCtrl,
                label: 'Report Title',
                hint: 'e.g. Acme Corp External Pentest Q1 2026',
                maxLength: 120,
                validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null,
              ),
              const SizedBox(height: 12),
              _field(
                controller: _pentesterCtrl,
                label: "Pentester's Name",
                hint: 'Full name of the lead tester',
                maxLength: 80,
                validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null,
              ),
            ],
          ),
          const SizedBox(height: 12),

          // --- Dates card ---
          _card(
            label: 'Assessment Dates',
            children: [
              Row(
                children: [
                  Expanded(child: _datePicker(label: 'Start Date', date: _startDate, isStart: true)),
                  const SizedBox(width: 12),
                  Expanded(child: _datePicker(label: 'End Date', date: _endDate, isStart: false)),
                ],
              ),
            ],
          ),
          const SizedBox(height: 12),

          // --- Narrative section cards ---
          _narrativeCard(
            key: 'executiveSummary',
            label: 'Executive Summary',
            controller: _execSummaryCtrl,
            promptBuilder: () => ReportContentService.buildExecutiveSummaryPrompt(widget.appState),
          ),
          const SizedBox(height: 12),
          _narrativeCard(
            key: 'methodology',
            label: 'Methodology and Scope',
            controller: _methodologyCtrl,
            promptBuilder: () => ReportContentService.buildMethodologyPrompt(widget.appState),
          ),
          const SizedBox(height: 12),
          _narrativeCard(
            key: 'riskRating',
            label: 'Risk Rating Model',
            controller: _riskRatingCtrl,
            promptBuilder: () => ReportContentService.buildRiskRatingPrompt(widget.appState),
          ),
          const SizedBox(height: 12),
          _narrativeCard(
            key: 'conclusion',
            label: 'Conclusion',
            controller: _conclusionCtrl,
            promptBuilder: () => ReportContentService.buildConclusionPrompt(widget.appState),
          ),
          const SizedBox(height: 8),
        ],
      ),
    );
  }

  Widget _card({required String label, required List<Widget> children}) {
    return Container(
      decoration: BoxDecoration(
        color: _cardBg,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: const Color(0xFF2A2A3E)),
      ),
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label.toUpperCase(),
            style: const TextStyle(
              color: _accent,
              fontSize: 11,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.2,
            ),
          ),
          const SizedBox(height: 12),
          ...children,
        ],
      ),
    );
  }

  Widget _field({
    required TextEditingController controller,
    required String label,
    String? hint,
    int? maxLength,
    String? Function(String?)? validator,
    int minLines = 1,
    int maxLines = 1,
  }) {
    return TextFormField(
      controller: controller,
      style: const TextStyle(color: Colors.white, fontSize: 14),
      minLines: minLines,
      maxLines: maxLines,
      maxLength: maxLength,
      validator: validator,
      decoration: InputDecoration(
        labelText: label,
        hintText: hint,
        labelStyle: const TextStyle(color: Colors.white54, fontSize: 13),
        hintStyle: const TextStyle(color: Colors.white24, fontSize: 13),
        counterStyle: const TextStyle(color: Colors.white30, fontSize: 11),
        filled: true,
        fillColor: const Color(0xFF1A1A2E),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(6),
          borderSide: const BorderSide(color: Color(0xFF3A3A5E)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(6),
          borderSide: const BorderSide(color: Color(0xFF3A3A5E)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(6),
          borderSide: const BorderSide(color: _accent, width: 1.5),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(6),
          borderSide: const BorderSide(color: Colors.redAccent),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(6),
          borderSide: const BorderSide(color: Colors.redAccent, width: 1.5),
        ),
      ),
    );
  }

  Widget _datePicker({required String label, DateTime? date, required bool isStart}) {
    final display = date != null
        ? '${date.year}-${date.month.toString().padLeft(2, '0')}-${date.day.toString().padLeft(2, '0')}'
        : 'Not set';
    return InkWell(
      onTap: () => _pickDate(isStart: isStart),
      borderRadius: BorderRadius.circular(6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: const Color(0xFF1A1A2E),
          borderRadius: BorderRadius.circular(6),
          border: Border.all(color: const Color(0xFF3A3A5E)),
        ),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label.toUpperCase(),
                    style: const TextStyle(color: Colors.white38, fontSize: 10, letterSpacing: 0.8),
                  ),
                  const SizedBox(height: 2),
                  Text(
                    display,
                    style: TextStyle(
                      color: date != null ? Colors.white : Colors.white38,
                      fontSize: 14,
                    ),
                  ),
                ],
              ),
            ),
            const Icon(Icons.calendar_today, color: _accent, size: 16),
          ],
        ),
      ),
    );
  }

  Widget _narrativeCard({
    required String key,
    required String label,
    required TextEditingController controller,
    required String Function() promptBuilder,
  }) {
    final isGenerating = _generating[key] ?? false;
    final isCsv = _format == 'csv';

    return Opacity(
      opacity: isCsv ? 0.4 : 1.0,
      child: _card(
        label: label,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              const SizedBox.shrink(),
              Tooltip(
                message: isCsv
                    ? 'Narrative sections are not included in CSV exports'
                    : 'Draft this section using the LLM',
                child: OutlinedButton.icon(
                  onPressed: (isGenerating || _anyGenerating || isCsv)
                      ? null
                      : () => _generate(key, promptBuilder(), controller),
                  icon: isGenerating
                      ? const SizedBox(
                          width: 14,
                          height: 14,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: _accent,
                          ),
                        )
                      : const Icon(Icons.auto_awesome, size: 14),
                  label: Text(isGenerating ? 'Generating…' : 'Generate with AI'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: _accent,
                    side: const BorderSide(color: _accent),
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    textStyle: const TextStyle(fontSize: 12),
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          TextFormField(
            controller: controller,
            enabled: !isCsv,
            style: const TextStyle(color: Colors.white, fontSize: 13, height: 1.5),
            minLines: 5,
            maxLines: 20,
            decoration: InputDecoration(
              hintText: isCsv
                  ? 'Not used in CSV exports'
                  : 'Leave blank or click "Generate with AI" to populate…',
              hintStyle: const TextStyle(color: Colors.white24, fontSize: 13),
              filled: true,
              fillColor: const Color(0xFF1A1A2E),
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(6),
                borderSide: const BorderSide(color: Color(0xFF3A3A5E)),
              ),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(6),
                borderSide: const BorderSide(color: Color(0xFF3A3A5E)),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(6),
                borderSide: const BorderSide(color: _accent, width: 1.5),
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Preview panel
  // ---------------------------------------------------------------------------

  Widget _buildPreviewPanel() {
    return Container(
      color: const Color(0xFF1A1A2E),
      padding: const EdgeInsets.all(20),
      child: ListView(
        children: [
          const Text(
            'PREVIEW',
            style: TextStyle(
              color: _accent,
              fontSize: 11,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.2,
            ),
          ),
          const SizedBox(height: 16),
          _previewRow('Report Title', _titleCtrl.text.isEmpty ? '—' : _titleCtrl.text),
          _previewRow('Pentester', _pentesterCtrl.text.isEmpty ? '—' : _pentesterCtrl.text),
          _previewRow(
            'Start Date',
            _startDate != null
                ? '${_startDate!.year}-${_startDate!.month.toString().padLeft(2, '0')}-${_startDate!.day.toString().padLeft(2, '0')}'
                : '—',
          ),
          _previewRow(
            'End Date',
            _endDate != null
                ? '${_endDate!.year}-${_endDate!.month.toString().padLeft(2, '0')}-${_endDate!.day.toString().padLeft(2, '0')}'
                : '—',
          ),
          const Divider(color: Color(0xFF2A2A3E), height: 24),
          _previewSection('Executive Summary', _execSummaryCtrl.text),
          _previewSection('Methodology & Scope', _methodologyCtrl.text),
          _previewSection('Risk Rating Model', _riskRatingCtrl.text),
          _previewSection('Conclusion', _conclusionCtrl.text),
        ],
      ),
    );
  }

  Widget _previewRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 90,
            child: Text(label, style: const TextStyle(color: Colors.white38, fontSize: 12)),
          ),
          Expanded(
            child: Text(value, style: const TextStyle(color: Colors.white70, fontSize: 12)),
          ),
        ],
      ),
    );
  }

  Widget _previewSection(String label, String text) {
    final charCount = text.length;
    final isEmpty = text.trim().isEmpty;
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  label,
                  style: const TextStyle(color: Colors.white54, fontSize: 12, fontWeight: FontWeight.w600),
                ),
              ),
              Text(
                isEmpty ? 'empty' : '$charCount chars',
                style: TextStyle(
                  color: isEmpty ? Colors.white24 : _accent.withValues(alpha: 0.7),
                  fontSize: 11,
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          if (!isEmpty)
            Text(
              text.length > 120 ? '${text.substring(0, 120)}…' : text,
              style: const TextStyle(color: Colors.white38, fontSize: 11, height: 1.4),
            )
          else
            const Text('—', style: TextStyle(color: Colors.white24, fontSize: 11)),
        ],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // Action bar
  // ---------------------------------------------------------------------------

  Widget _buildActionBar() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
      decoration: const BoxDecoration(
        color: Color(0xFF1A1A2E),
        border: Border(top: BorderSide(color: Color(0xFF2A2A3E))),
        borderRadius: BorderRadius.vertical(bottom: Radius.circular(12)),
      ),
      child: Row(
        children: [
          // Format selector
          _buildFormatSelector(),
          const SizedBox(width: 12),
          // Confirmed-only toggle
          Row(
            children: [
              Checkbox(
                value: _confirmedOnly,
                onChanged: (v) => setState(() => _confirmedOnly = v ?? true),
                activeColor: _accent,
                side: const BorderSide(color: Colors.white38),
              ),
              const Text('Confirmed only', style: TextStyle(color: Colors.white54, fontSize: 12)),
            ],
          ),
          const Spacer(),
          TextButton(
            onPressed: _savingReport ? null : () => Navigator.of(context).pop(),
            style: TextButton.styleFrom(foregroundColor: Colors.white54),
            child: const Text('Cancel'),
          ),
          const SizedBox(width: 12),
          // Phase 11: Show loading indicator while saving, button otherwise
          if (_savingReport)
            const Row(
              children: [
                SizedBox(width: 16, height: 16,
                  child: CircularProgressIndicator(strokeWidth: 2, color: _accent)),
                SizedBox(width: 12),
                Text('Generating report…',
                  style: TextStyle(color: Colors.white54, fontSize: 13)),
              ],
            )
          else
          // Rebuild when text changes so the button enables/disables live
          AnimatedBuilder(
            animation: Listenable.merge([_titleCtrl, _pentesterCtrl]),
            builder: (_, _) {
              final enabled = !_anyGenerating &&
                  _titleCtrl.text.trim().isNotEmpty &&
                  _pentesterCtrl.text.trim().isNotEmpty;
              return FilledButton.icon(
                onPressed: enabled ? _onGenerate : null,
                icon: const Icon(Icons.download, size: 16),
                label: const Text('Generate Report'),
                style: FilledButton.styleFrom(
                  backgroundColor: _accent,
                  foregroundColor: Colors.black,
                  disabledBackgroundColor: _accent.withValues(alpha: 0.25),
                  disabledForegroundColor: Colors.black45,
                  padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  Widget _buildFormatSelector() {
    return Row(
      children: [
        const Text('Format:', style: TextStyle(color: Colors.white54, fontSize: 13)),
        const SizedBox(width: 8),
        _formatChip('html', 'HTML'),
        const SizedBox(width: 6),
        _formatChip('md', 'Markdown'),
        const SizedBox(width: 6),
        _formatChip('csv', 'CSV'),
      ],
    );
  }

  Widget _formatChip(String value, String label) {
    final selected = _format == value;
    return InkWell(
      onTap: () => setState(() => _format = value),
      borderRadius: BorderRadius.circular(20),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        decoration: BoxDecoration(
          color: selected ? _accent : Colors.transparent,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: selected ? _accent : const Color(0xFF3A3A5E)),
        ),
        child: Text(
          label,
          style: TextStyle(
            color: selected ? Colors.black : Colors.white54,
            fontSize: 12,
            fontWeight: selected ? FontWeight.w700 : FontWeight.normal,
          ),
        ),
      ),
    );
  }
}
