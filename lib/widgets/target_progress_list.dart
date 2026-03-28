import 'package:flutter/material.dart';
import '../models/target.dart';

/// Scrollable list of target address cards with status chips and progress indicators.
class TargetProgressList extends StatelessWidget {
  final List<Target> targets;
  final Set<String> activeAddresses;

  const TargetProgressList({
    super.key,
    required this.targets,
    this.activeAddresses = const {},
  });

  @override
  Widget build(BuildContext context) {
    if (targets.isEmpty) {
      return const Center(
        child: Text('No targets yet', style: TextStyle(color: Colors.white24, fontSize: 12)),
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: targets.length,
      itemBuilder: (context, i) => _TargetCard(
        target: targets[i],
        isActive: activeAddresses.contains(targets[i].address),
      ),
    );
  }
}

class _TargetCard extends StatelessWidget {
  final Target target;
  final bool isActive;

  const _TargetCard({required this.target, required this.isActive});

  @override
  Widget build(BuildContext context) {
    final isExcluded = target.status == TargetStatus.excluded;

    return Opacity(
      opacity: isExcluded ? 0.4 : 1.0,
      child: Container(
        margin: const EdgeInsets.only(bottom: 6),
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: const Color(0xFF1A1F3A),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isActive
                ? const Color(0xFF00F5FF).withValues(alpha: 0.6)
                : const Color(0xFF00F5FF).withValues(alpha: 0.1),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    target.address,
                    style: TextStyle(
                      color: isExcluded ? Colors.white38 : Colors.white,
                      fontFamily: 'monospace',
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      decoration: isExcluded ? TextDecoration.lineThrough : null,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                _statusChip(),
              ],
            ),
            if (isActive) ...[
              const SizedBox(height: 6),
              const LinearProgressIndicator(
                color: Color(0xFF00F5FF),
                backgroundColor: Colors.white12,
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _statusChip() {
    final (label, color) = switch (target.status) {
      TargetStatus.complete when target.executionComplete => ('DONE', const Color(0xFF00FF88)),
      TargetStatus.complete when target.analysisComplete => ('ANALYZED', const Color(0xFF00F5FF)),
      TargetStatus.complete => ('SCANNED', const Color(0xFF00FF88)),
      TargetStatus.excluded => ('EXCLUDED', Colors.white38),
      _ => ('PENDING', Colors.white24),
    };
    if (target.noFindings == true && target.status == TargetStatus.complete) {
      return _chip('NO FINDINGS', Colors.white38);
    }
    return _chip(label, color);
  }

  Widget _chip(String label, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.4)),
      ),
      child: Text(label, style: TextStyle(color: color, fontSize: 9, fontWeight: FontWeight.bold, letterSpacing: 0.5)),
    );
  }
}
