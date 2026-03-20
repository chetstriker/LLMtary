import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../database/database_helper.dart';
import 'app_state.dart';

/// Dialog for configuring engagement scope, exclusions, and rules of engagement.
class ScopeConfigDialog extends StatefulWidget {
  const ScopeConfigDialog({super.key});

  @override
  State<ScopeConfigDialog> createState() => _ScopeConfigDialogState();
}

class _ScopeConfigDialogState extends State<ScopeConfigDialog> {
  late final TextEditingController _scopeController;
  late final TextEditingController _exclusionsController;
  late final TextEditingController _notesController;

  static const _cyan = Color(0xFF00F5FF);
  static const _bg = Color(0xFF0A0E27);
  static const _hint = Color(0xFF8892B0);

  @override
  void initState() {
    super.initState();
    final project = context.read<AppState>().currentProject;
    _scopeController = TextEditingController(text: project?.scope ?? '');
    _exclusionsController = TextEditingController(text: project?.scopeExclusions ?? '');
    _notesController = TextEditingController(text: project?.scopeNotes ?? '');
  }

  @override
  void dispose() {
    _scopeController.dispose();
    _exclusionsController.dispose();
    _notesController.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    final appState = context.read<AppState>();
    final project = appState.currentProject;
    if (project == null) return;

    final scope = _scopeController.text.trim().isEmpty ? null : _scopeController.text.trim();
    final exclusions = _exclusionsController.text.trim().isEmpty ? null : _exclusionsController.text.trim();
    final notes = _notesController.text.trim().isEmpty ? null : _notesController.text.trim();

    await DatabaseHelper.updateProjectScope(project.id!, scope: scope, scopeExclusions: exclusions, scopeNotes: notes);
    final updated = project.copyWith(scope: scope, scopeExclusions: exclusions, scopeNotes: notes);
    appState.updateCurrentProject(updated);
    if (mounted) Navigator.pop(context);
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: _bg,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: _cyan.withValues(alpha: 0.4)),
      ),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 600, maxHeight: 700),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.shield_outlined, color: _cyan, size: 20),
                  const SizedBox(width: 8),
                  const Text(
                    'ENGAGEMENT SCOPE',
                    style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 16, letterSpacing: 1.5),
                  ),
                  const Spacer(),
                  IconButton(
                    icon: const Icon(Icons.close, color: _hint),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
              const Divider(color: Color(0xFF1E2340)),
              const SizedBox(height: 8),
              Expanded(
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _sectionLabel('IN-SCOPE TARGETS'),
                      const SizedBox(height: 4),
                      const Text(
                        'One per line. Supports: exact IP (192.168.1.1), CIDR (10.0.0.0/8), FQDN (example.com), wildcard (*.example.com), or * for all.',
                        style: TextStyle(color: _hint, fontSize: 11),
                      ),
                      const SizedBox(height: 8),
                      _textArea(_scopeController, 'e.g.\n192.168.1.0/24\n10.10.0.0/16\n*.example.com', 6),
                      const SizedBox(height: 20),
                      _sectionLabel('OUT-OF-SCOPE EXCLUSIONS'),
                      const SizedBox(height: 4),
                      const Text(
                        'Targets explicitly excluded from testing (overrides scope). Same format as above.',
                        style: TextStyle(color: _hint, fontSize: 11),
                      ),
                      const SizedBox(height: 8),
                      _textArea(_exclusionsController, 'e.g.\n192.168.1.100\nprod.example.com', 4),
                      const SizedBox(height: 20),
                      _sectionLabel('RULES OF ENGAGEMENT NOTES'),
                      const SizedBox(height: 4),
                      const Text(
                        'Free-text notes visible during analysis (e.g. "no DoS", "no account lockouts", "web apps only").',
                        style: TextStyle(color: _hint, fontSize: 11),
                      ),
                      const SizedBox(height: 8),
                      _textArea(_notesController, 'e.g.\nNo denial-of-service testing\nAvoid account lockouts\nBusiness hours only: 9am–5pm EST', 4),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => Navigator.pop(context),
                    child: const Text('CANCEL', style: TextStyle(color: _hint)),
                  ),
                  const SizedBox(width: 12),
                  ElevatedButton.icon(
                    onPressed: _save,
                    icon: const Icon(Icons.save, size: 16),
                    label: const Text('SAVE SCOPE'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: _cyan,
                      foregroundColor: Colors.black,
                      textStyle: const TextStyle(fontWeight: FontWeight.bold),
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

  Widget _sectionLabel(String text) => Text(
        text,
        style: const TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 12, letterSpacing: 1),
      );

  Widget _textArea(TextEditingController controller, String hint, int minLines) => TextField(
        controller: controller,
        maxLines: null,
        minLines: minLines,
        style: const TextStyle(color: Colors.white, fontFamily: 'monospace', fontSize: 13),
        decoration: InputDecoration(
          hintText: hint,
          hintStyle: TextStyle(color: _hint.withValues(alpha: 0.5), fontFamily: 'monospace', fontSize: 12),
          filled: true,
          fillColor: const Color(0xFF060A1A),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(6),
            borderSide: BorderSide(color: _cyan.withValues(alpha: 0.2)),
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(6),
            borderSide: BorderSide(color: _cyan.withValues(alpha: 0.2)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(6),
            borderSide: BorderSide(color: _cyan.withValues(alpha: 0.6)),
          ),
          contentPadding: const EdgeInsets.all(12),
        ),
      );
}
