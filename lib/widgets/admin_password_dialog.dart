import 'package:flutter/material.dart';

enum PasswordDialogMode { sessionAuth, exportConfirm, importSingle }

class AdminPasswordDialog extends StatefulWidget {
  final PasswordDialogMode mode;
  const AdminPasswordDialog({super.key, this.mode = PasswordDialogMode.sessionAuth});

  @override
  State<AdminPasswordDialog> createState() => _AdminPasswordDialogState();
}

class _AdminPasswordDialogState extends State<AdminPasswordDialog> {
  final _passwordController = TextEditingController();
  final _confirmController = TextEditingController();
  final _focusNode = FocusNode();
  bool _obscure1 = true;
  bool _obscure2 = true;
  String? _error;

  bool get _isExport => widget.mode == PasswordDialogMode.exportConfirm;
  bool get _isImport => widget.mode == PasswordDialogMode.importSingle;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _focusNode.requestFocus());
  }

  @override
  void dispose() {
    _passwordController.dispose();
    _confirmController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  void _submit() {
    final pw = _passwordController.text;
    if (pw.isEmpty) return;
    if (_isExport) {
      if (_confirmController.text != pw) {
        setState(() => _error = 'Passwords do not match');
        return;
      }
    }
    Navigator.of(context).pop(pw);
  }

  @override
  Widget build(BuildContext context) {
    final String title;
    final String subtitle;
    final String buttonLabel;
    final IconData icon;

    if (_isExport) {
      title = 'ENCRYPT EXPORT';
      subtitle = 'Set a password to encrypt the .penex file';
      buttonLabel = 'ENCRYPT & EXPORT';
      icon = Icons.lock_outline;
    } else if (_isImport) {
      title = 'DECRYPT IMPORT';
      subtitle = 'Enter the password for this .penex file';
      buttonLabel = 'DECRYPT & IMPORT';
      icon = Icons.lock_open;
    } else {
      title = 'ADMINISTRATOR ACCESS';
      subtitle = 'Enter your system password to execute privileged commands';
      buttonLabel = 'AUTHENTICATE';
      icon = Icons.security;
    }

    return Dialog(
      backgroundColor: Colors.transparent,
      child: Container(
        width: 450,
        padding: const EdgeInsets.all(32),
        decoration: BoxDecoration(
          gradient: const LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [Color(0xFF1A1F3A), Color(0xFF0A0E27)],
          ),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(color: const Color(0xFF00F5FF).withValues(alpha: 0.5), width: 2),
          boxShadow: [BoxShadow(color: const Color(0xFF00F5FF).withValues(alpha: 0.3), blurRadius: 30, spreadRadius: 5)],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                gradient: LinearGradient(colors: [
                  const Color(0xFF00F5FF).withValues(alpha: 0.2),
                  const Color(0xFF0080FF).withValues(alpha: 0.2),
                ]),
                shape: BoxShape.circle,
                border: Border.all(color: const Color(0xFF00F5FF), width: 2),
              ),
              child: Icon(icon, size: 48, color: const Color(0xFF00F5FF)),
            ),
            const SizedBox(height: 24),
            Text(title, style: const TextStyle(color: Color(0xFF00F5FF), fontSize: 20, fontWeight: FontWeight.bold, letterSpacing: 2)),
            const SizedBox(height: 8),
            Text(subtitle, textAlign: TextAlign.center, style: TextStyle(color: Colors.white.withValues(alpha: 0.7), fontSize: 13)),
            const SizedBox(height: 32),
            _buildPasswordField(_passwordController, _focusNode, 'Password', _obscure1, (v) => setState(() => _obscure1 = v)),
            if (_isExport) ...[
              const SizedBox(height: 16),
              _buildPasswordField(_confirmController, null, 'Confirm Password', _obscure2, (v) => setState(() => _obscure2 = v),
                  onSubmitted: (_) => _submit()),
            ],
            if (_error != null) ...[
              const SizedBox(height: 8),
              Text(_error!, style: const TextStyle(color: Color(0xFFFF0040), fontSize: 12)),
            ],
            const SizedBox(height: 32),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(),
                    style: OutlinedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 16),
                      side: BorderSide(color: Colors.white.withValues(alpha: 0.3)),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    ),
                    child: const Text('CANCEL', style: TextStyle(color: Colors.white70, fontWeight: FontWeight.bold, letterSpacing: 1)),
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Container(
                    decoration: BoxDecoration(
                      gradient: const LinearGradient(colors: [Color(0xFF00F5FF), Color(0xFF0080FF)]),
                      borderRadius: BorderRadius.circular(12),
                      boxShadow: [BoxShadow(color: const Color(0xFF00F5FF).withValues(alpha: 0.5), blurRadius: 15)],
                    ),
                    child: ElevatedButton(
                      onPressed: _submit,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.transparent,
                        shadowColor: Colors.transparent,
                        padding: const EdgeInsets.symmetric(vertical: 16),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                      ),
                      child: Text(buttonLabel, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, letterSpacing: 1)),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPasswordField(
    TextEditingController controller,
    FocusNode? focusNode,
    String label,
    bool obscure,
    void Function(bool) onToggle, {
    void Function(String)? onSubmitted,
  }) {
    return TextField(
      controller: controller,
      focusNode: focusNode,
      obscureText: obscure,
      onSubmitted: onSubmitted ?? (_) => _submit(),
      style: const TextStyle(color: Colors.white, fontSize: 16, letterSpacing: 2),
      decoration: InputDecoration(
        labelText: label,
        labelStyle: const TextStyle(color: Color(0xFF00F5FF), fontSize: 14),
        prefixIcon: const Icon(Icons.lock, color: Color(0xFF00F5FF)),
        suffixIcon: IconButton(
          icon: Icon(obscure ? Icons.visibility : Icons.visibility_off, color: const Color(0xFF00F5FF)),
          onPressed: () => onToggle(!obscure),
        ),
        filled: true,
        fillColor: const Color(0xFF0A0E27),
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF00F5FF))),
        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: BorderSide(color: const Color(0xFF00F5FF).withValues(alpha: 0.5))),
        focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: Color(0xFF00F5FF), width: 2)),
      ),
    );
  }
}
