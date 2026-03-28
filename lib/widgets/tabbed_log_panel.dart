import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../widgets/app_state.dart';
import '../widgets/command_log_panel.dart' show getVulnColor;

/// Unified right-panel log viewer with COMMAND LOG / DEBUG / PROMPTS tabs.
class TabbedLogPanel extends StatefulWidget {
  final Future<void> Function()? onExportLogs;
  final Future<void> Function(AppState)? onExportDebug;
  final Future<void> Function(AppState)? onExportPrompts;

  const TabbedLogPanel({
    super.key,
    this.onExportLogs,
    this.onExportDebug,
    this.onExportPrompts,
  });

  @override
  State<TabbedLogPanel> createState() => _TabbedLogPanelState();
}

class _TabbedLogPanelState extends State<TabbedLogPanel> with SingleTickerProviderStateMixin {
  late TabController _tabController;

  static const _bg = Color(0xFF0A0E27);
  static const _card = Color(0xFF1A1F3A);
  static const _cyan = Color(0xFF00F5FF);

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 3, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 280,
      color: _card,
      child: Column(
        children: [
          Container(
            color: _bg,
            child: TabBar(
              controller: _tabController,
              labelColor: _cyan,
              unselectedLabelColor: Colors.white38,
              indicatorColor: _cyan,
              labelStyle: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold, letterSpacing: 0.8),
              tabs: const [
                Tab(text: 'COMMANDS'),
                Tab(text: 'DEBUG'),
                Tab(text: 'PROMPTS'),
              ],
            ),
          ),
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                _CommandLogTab(
                  onExport: widget.onExportLogs,
                ),
                _DebugLogTab(onExport: widget.onExportDebug),
                _PromptLogTab(onExport: widget.onExportPrompts),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _CommandLogTab extends StatefulWidget {
  final Future<void> Function()? onExport;

  const _CommandLogTab({this.onExport});

  @override
  State<_CommandLogTab> createState() => _CommandLogTabState();
}

class _CommandLogTabState extends State<_CommandLogTab> {
  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, state, _) {
        final logs = state.commandLogs.reversed.take(50).toList();
        return Column(
          children: [
            _exportBar('Export', () => widget.onExport?.call()),
            Expanded(
              child: logs.isEmpty
                  ? const Center(child: Text('No commands yet', style: TextStyle(color: Colors.white24, fontSize: 12)))
                  : ListView.builder(
                      padding: const EdgeInsets.all(8),
                      itemCount: logs.length,
                      itemBuilder: (ctx, i) {
                        final log = logs[i];
                        final color = log.vulnerabilityIndex != null
                            ? getVulnColor(log.vulnerabilityIndex!)
                            : Colors.white54;
                        return Container(
                          margin: const EdgeInsets.only(bottom: 4),
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: const Color(0xFF0A0E27),
                            borderRadius: BorderRadius.circular(4),
                            border: Border.all(color: color.withValues(alpha: 0.2)),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                '[${log.timestamp.toString().substring(11, 19)}]',
                                style: TextStyle(color: color.withValues(alpha: 0.6), fontFamily: 'monospace', fontSize: 9),
                              ),
                              Text('> ${log.command}', style: TextStyle(color: color, fontFamily: 'monospace', fontSize: 10, fontWeight: FontWeight.bold)),
                              if (log.output.isNotEmpty)
                                Text(
                                  log.output.length > 300 ? '${log.output.substring(0, 300)}...' : log.output,
                                  style: const TextStyle(color: Colors.white54, fontFamily: 'monospace', fontSize: 10),
                                ),
                            ],
                          ),
                        );
                      },
                    ),
            ),
          ],
        );
      },
    );
  }
}

class _DebugLogTab extends StatelessWidget {
  final Future<void> Function(AppState)? onExport;
  const _DebugLogTab({this.onExport});

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, state, _) {
        final logs = state.debugLogs.reversed.take(50).toList();
        return Column(
          children: [
            _exportBar('Export', () => onExport?.call(state)),
            Expanded(
              child: logs.isEmpty
                  ? const Center(child: Text('No debug logs', style: TextStyle(color: Colors.white24, fontSize: 12)))
                  : ListView.builder(
                      padding: const EdgeInsets.all(8),
                      itemCount: logs.length,
                      itemBuilder: (ctx, i) => Padding(
                        padding: const EdgeInsets.only(bottom: 2),
                        child: Text(
                          '[${logs[i].timestamp.toString().substring(11, 19)}] ${logs[i].message}',
                          style: const TextStyle(color: Colors.white54, fontFamily: 'monospace', fontSize: 10),
                        ),
                      ),
                    ),
            ),
          ],
        );
      },
    );
  }
}

class _PromptLogTab extends StatelessWidget {
  final Future<void> Function(AppState)? onExport;
  const _PromptLogTab({this.onExport});

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, state, _) {
        final logs = state.promptLogs.reversed.take(50).toList();
        return Column(
          children: [
            _exportBar('Export', () => onExport?.call(state)),
            Expanded(
              child: logs.isEmpty
                  ? const Center(child: Text('No prompts yet', style: TextStyle(color: Colors.white24, fontSize: 12)))
                  : ListView.builder(
                      padding: const EdgeInsets.all(8),
                      itemCount: logs.length,
                      itemBuilder: (ctx, i) => Container(
                        margin: const EdgeInsets.only(bottom: 6),
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: const Color(0xFF0A0E27),
                          borderRadius: BorderRadius.circular(4),
                          border: Border.all(color: const Color(0xFF00F5FF).withValues(alpha: 0.15)),
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              '[${logs[i].timestamp.toString().substring(11, 19)}]',
                              style: const TextStyle(color: Color(0xFF00F5FF), fontFamily: 'monospace', fontSize: 9, fontWeight: FontWeight.bold),
                            ),
                            const SizedBox(height: 2),
                            Text(
                              logs[i].prompt.length > 200 ? '${logs[i].prompt.substring(0, 200)}...' : logs[i].prompt,
                              style: const TextStyle(color: Color(0xFF00F5FF), fontFamily: 'monospace', fontSize: 9),
                            ),
                            const Divider(color: Colors.white12, height: 8),
                            Text(
                              logs[i].response.length > 200 ? '${logs[i].response.substring(0, 200)}...' : logs[i].response,
                              style: const TextStyle(color: Colors.white54, fontFamily: 'monospace', fontSize: 9),
                            ),
                          ],
                        ),
                      ),
                    ),
            ),
          ],
        );
      },
    );
  }
}

Widget _exportBar(String label, VoidCallback? onTap) {
  return Container(
    height: 28,
    color: const Color(0xFF0D1230),
    alignment: Alignment.centerRight,
    padding: const EdgeInsets.symmetric(horizontal: 8),
    child: GestureDetector(
      onTap: onTap,
      child: Text(label, style: const TextStyle(color: Color(0xFF00F5FF), fontSize: 10, fontWeight: FontWeight.bold)),
    ),
  );
}
