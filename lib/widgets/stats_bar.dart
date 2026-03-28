import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../models/target.dart';
import '../widgets/app_state.dart';

/// Horizontal row of stat cards shown at the top of each tab.
class StatsBar extends StatelessWidget {
  /// Optional extra card shown as the 4th stat (tab-specific context).
  final Widget? extraCard;

  const StatsBar({super.key, this.extraCard});

  @override
  Widget build(BuildContext context) {
    return Consumer<AppState>(
      builder: (context, state, _) {
        final activeTargets = state.targets.where((t) => t.status != TargetStatus.excluded).length;
        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          color: const Color(0xFF0A0C16),
          child: Row(
            children: [
              Expanded(child: StatCard(label: 'ACTIVE TARGETS', value: activeTargets, color: const Color(0xFF7C5CFC), icon: Icons.radar)),
              const SizedBox(width: 12),
              if (extraCard != null) ...[
                Expanded(child: extraCard!),
                const SizedBox(width: 12),
              ],
              Expanded(child: StatCard(label: 'TOKENS SENT', value: state.tokensSentTotal, color: const Color(0xFF5B8DEF), icon: Icons.upload_rounded)),
              const SizedBox(width: 12),
              Expanded(child: StatCard(label: 'TOKENS RECEIVED', value: state.tokensReceivedTotal, color: const Color(0xFF3DFFA0), icon: Icons.download_rounded)),
            ],
          ),
        );
      },
    );
  }
}

class StatCard extends StatelessWidget {
  final String label;
  final int value;
  final Color color;
  final IconData icon;

  const StatCard({required this.label, required this.value, required this.color, required this.icon});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: const Color(0xFF161929),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: color.withValues(alpha: 0.2)),
        boxShadow: [BoxShadow(color: color.withValues(alpha: 0.06), blurRadius: 12, offset: const Offset(0, 4))],
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: color.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(icon, color: color, size: 18),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(label,
                    style: TextStyle(
                        color: color.withValues(alpha: 0.7),
                        fontSize: 8,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0.6),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 1),
                const SizedBox(height: 2),
                TweenAnimationBuilder<int>(
                  tween: IntTween(begin: 0, end: value),
                  duration: const Duration(milliseconds: 400),
                  builder: (_, v, __) => Text(
                    _fmt(v),
                    style: const TextStyle(
                        color: Colors.white,
                        fontSize: 18,
                        fontWeight: FontWeight.w800,
                        fontFamily: 'monospace'),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 1,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

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
