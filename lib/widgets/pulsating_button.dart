import 'package:flutter/material.dart';

/// Wraps any child widget with a subtle scale + glow pulse animation.
/// When [active] is false, renders the child without animation.
class PulsatingButton extends StatefulWidget {
  final Widget child;
  final bool active;

  const PulsatingButton({super.key, required this.child, this.active = true});

  @override
  State<PulsatingButton> createState() => _PulsatingButtonState();
}

class _PulsatingButtonState extends State<PulsatingButton> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _scale;
  late Animation<double> _blur;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    );
    _scale = Tween<double>(begin: 1.0, end: 1.04).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOut),
    );
    _blur = Tween<double>(begin: 8.0, end: 20.0).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOut),
    );
    if (widget.active) _controller.repeat(reverse: true);
  }

  @override
  void didUpdateWidget(PulsatingButton oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.active && !_controller.isAnimating) {
      _controller.repeat(reverse: true);
    } else if (!widget.active && _controller.isAnimating) {
      _controller.stop();
      _controller.value = 0;
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.active) return widget.child;
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, child) => Transform.scale(
        scale: _scale.value,
        child: Container(
          decoration: BoxDecoration(
            boxShadow: [
              BoxShadow(
                color: const Color(0xFF00F5FF).withValues(alpha: 0.4),
                blurRadius: _blur.value,
                spreadRadius: 1,
              ),
            ],
          ),
          child: child,
        ),
      ),
      child: widget.child,
    );
  }
}
