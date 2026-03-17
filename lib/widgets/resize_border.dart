import 'package:flutter/material.dart';

/// Overlays thin transparent edge strips on top of all content so resize
/// cursors always show regardless of what child widgets are underneath.
class ResizeBorder extends StatelessWidget {
  const ResizeBorder({super.key, required this.child});
  final Widget child;

  static const double _z = 8.0; // edge zone width in logical pixels

  @override
  Widget build(BuildContext context) {
    return Stack(
      alignment: Alignment.topLeft,
      children: [
        child,
        // corners (must come after edges so they win hit-testing)
        _edge(left: 0,    top: 0,    width: _z, height: _z, cursor: SystemMouseCursors.resizeUpLeft),
        _edge(right: 0,   top: 0,    width: _z, height: _z, cursor: SystemMouseCursors.resizeUpRight),
        _edge(left: 0,    bottom: 0, width: _z, height: _z, cursor: SystemMouseCursors.resizeDownLeft),
        _edge(right: 0,   bottom: 0, width: _z, height: _z, cursor: SystemMouseCursors.resizeDownRight),
        // edges
        _edge(left: _z,  top: 0,    right: _z, height: _z, cursor: SystemMouseCursors.resizeUp),
        _edge(left: _z,  bottom: 0, right: _z, height: _z, cursor: SystemMouseCursors.resizeDown),
        _edge(left: 0,   top: _z,   width: _z, bottom: _z, cursor: SystemMouseCursors.resizeLeft),
        _edge(right: 0,  top: _z,   width: _z, bottom: _z, cursor: SystemMouseCursors.resizeRight),
      ],
    );
  }

  static Widget _edge({
    double? left, double? right, double? top, double? bottom,
    double? width, double? height,
    required MouseCursor cursor,
  }) {
    return Positioned(
      left: left, right: right, top: top, bottom: bottom,
      width: width, height: height,
      child: MouseRegion(
        cursor: cursor,
        opaque: false, // don't block clicks/taps on content beneath
      ),
    );
  }
}
