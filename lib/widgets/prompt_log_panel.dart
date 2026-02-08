import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'app_state.dart';

class PromptLogPanel extends StatefulWidget {
  final void Function(AppState state)? onExport;

  const PromptLogPanel({super.key, this.onExport});

  @override
  State<PromptLogPanel> createState() => _PromptLogPanelState();
}

class _PromptLogPanelState extends State<PromptLogPanel> {
  final _scrollController = ScrollController();
  bool _autoScroll = true;

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, state, _) {
        return Container(
          margin: const EdgeInsets.fromLTRB(8, 0, 8, 8),
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
                    const Icon(Icons.chat, color: Color(0xFF00F5FF), size: 16),
                    const SizedBox(width: 8),
                    const Text('PROMPTS', style: TextStyle(color: Color(0xFF00F5FF), fontWeight: FontWeight.bold, fontSize: 12)),
                    const Spacer(),
                    if (widget.onExport != null)
                      IconButton(
                        icon: const Icon(Icons.download, color: Color(0xFF00F5FF), size: 16),
                        onPressed: () => widget.onExport!(state),
                        tooltip: 'Export Prompts',
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
                child: state.promptLogs.isEmpty
                    ? Center(child: Text('No prompts yet', style: TextStyle(color: Colors.white.withOpacity(0.3), fontSize: 12)))
                    : ListView.builder(
                        controller: _scrollController,
                        padding: const EdgeInsets.all(8),
                        itemCount: state.promptLogs.length,
                        itemBuilder: (context, i) {
                          if (_autoScroll && i == state.promptLogs.length - 1) {
                            WidgetsBinding.instance.addPostFrameCallback((_) {
                              if (_scrollController.hasClients) {
                                _scrollController.jumpTo(_scrollController.position.maxScrollExtent);
                              }
                            });
                          }
                          final log = state.promptLogs[i];
                          return Container(
                            margin: const EdgeInsets.only(bottom: 8),
                            decoration: BoxDecoration(
                              color: const Color(0xFF0A0E27),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: const Color(0xFF00F5FF).withOpacity(0.2)),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Container(
                                  padding: const EdgeInsets.all(8),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF00F5FF).withOpacity(0.1),
                                    borderRadius: const BorderRadius.vertical(top: Radius.circular(8)),
                                  ),
                                  child: const Row(
                                    children: [
                                      Icon(Icons.arrow_upward, color: Color(0xFF00F5FF), size: 12),
                                      SizedBox(width: 4),
                                      Text('PROMPT', style: TextStyle(color: Color(0xFF00F5FF), fontSize: 10, fontWeight: FontWeight.bold)),
                                    ],
                                  ),
                                ),
                                Padding(
                                  padding: const EdgeInsets.all(8),
                                  child: SelectableText(
                                    log.prompt,
                                    style: const TextStyle(color: Colors.white70, fontSize: 10, fontFamily: 'monospace'),
                                  ),
                                ),
                                Container(
                                  padding: const EdgeInsets.all(8),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFF00FF88).withOpacity(0.1),
                                  ),
                                  child: const Row(
                                    children: [
                                      Icon(Icons.arrow_downward, color: Color(0xFF00FF88), size: 12),
                                      SizedBox(width: 4),
                                      Text('RESPONSE', style: TextStyle(color: Color(0xFF00FF88), fontSize: 10, fontWeight: FontWeight.bold)),
                                    ],
                                  ),
                                ),
                                Padding(
                                  padding: const EdgeInsets.all(8),
                                  child: SelectableText(
                                    log.response,
                                    style: const TextStyle(color: Colors.white70, fontSize: 10, fontFamily: 'monospace'),
                                  ),
                                ),
                              ],
                            ),
                          );
                        },
                      ),
              ),
            ],
          ),
        );
      },
    );
  }
}
