import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'app_state.dart';

class DebugLogPanel extends StatefulWidget {
  final void Function(AppState state)? onExport;

  const DebugLogPanel({super.key, this.onExport});

  @override
  State<DebugLogPanel> createState() => _DebugLogPanelState();
}

class _DebugLogPanelState extends State<DebugLogPanel> {
  final _scrollController = ScrollController();
  final _focusNode = FocusNode();
  bool _autoScroll = true;

  @override
  void dispose() {
    _scrollController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, state, _) {
        return Container(
          margin: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: const Color(0xFF1A1F3A),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.3)),
          ),
          child: Column(
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [const Color(0xFF00F5FF).withOpacity(0.1), Colors.transparent],
                  ),
                  borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.bug_report, color: Color(0xFF00F5FF), size: 16),
                    const SizedBox(width: 8),
                    const Text('DEBUG', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                    const Spacer(),
                    if (widget.onExport != null)
                      IconButton(
                        icon: const Icon(Icons.download, color: Color(0xFF00F5FF), size: 16),
                        onPressed: () => widget.onExport!(state),
                        tooltip: 'Export Debug',
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(),
                      ),
                    const SizedBox(width: 8),
                    Transform.scale(
                      scale: 0.7,
                      child: Checkbox(
                        value: _autoScroll,
                        onChanged: (v) => setState(() => _autoScroll = v ?? true),
                        activeColor: const Color(0xFF00F5FF),
                      ),
                    ),
                    const Text('Auto-scroll', style: TextStyle(color: Colors.white70, fontSize: 10)),
                  ],
                ),
              ),
              Expanded(
                child: state.debugLogs.isEmpty
                    ? Center(child: Text('No debug logs yet', style: TextStyle(color: Colors.white.withOpacity(0.3), fontSize: 12)))
                    : SelectableRegion(
                        focusNode: _focusNode,
                        selectionControls: materialTextSelectionControls,
                        child: ListView.builder(
                          controller: _scrollController,
                          padding: const EdgeInsets.all(8),
                          itemCount: state.debugLogs.length,
                          itemBuilder: (context, i) {
                            if (_autoScroll && i == state.debugLogs.length - 1) {
                              WidgetsBinding.instance.addPostFrameCallback((_) {
                                if (_scrollController.hasClients) {
                                  _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
                                }
                              });
                            }
                            final log = state.debugLogs[i];
                            final isError = log.message.toLowerCase().contains('error') || log.message.toLowerCase().contains('exception') || log.message.toLowerCase().contains('failed');
                            return Container(
                              margin: const EdgeInsets.only(bottom: 4),
                              padding: const EdgeInsets.all(8),
                              decoration: BoxDecoration(
                                color: isError ? const Color(0xFFFF0080).withOpacity(0.15) : const Color(0xFF0A0E27),
                                borderRadius: BorderRadius.circular(4),
                                border: isError ? Border.all(color: const Color(0xFFFF0080), width: 1) : null,
                              ),
                              child: Text(
                                '[${log.timestamp.toString().substring(11, 19)}] ${log.message}',
                                style: TextStyle(
                                  color: isError ? const Color(0xFFFF0080) : Colors.white70,
                                  fontSize: 10,
                                  fontFamily: 'monospace',
                                  fontWeight: isError ? FontWeight.bold : FontWeight.normal,
                                ),
                              ),
                            );
                          },
                        ),
                      ),
              ),
            ],
          ),
        );
      },
    );
  }
}
