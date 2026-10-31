// Paints the QR modules the C library made, dark on light with a quiet
// zone so any scanner (Vigil included) picks it up.

import 'package:flutter/widgets.dart';

import '../core.dart';

class QrView extends StatelessWidget {
  const QrView({super.key, required this.code});

  final QrCode code;

  @override
  Widget build(BuildContext context) {
    return AspectRatio(
      aspectRatio: 1,
      child: RepaintBoundary(child: CustomPaint(painter: _QrPainter(code))),
    );
  }
}

class _QrPainter extends CustomPainter {
  const _QrPainter(this.code);

  final QrCode code;

  static const _quiet = 4;

  @override
  void paint(Canvas canvas, Size size) {
    final cells = code.side + _quiet * 2;
    final cell = size.shortestSide / cells;
    final dark = Paint()
      ..color = const Color(0xff000000)
      ..isAntiAlias = false;

    canvas.drawRect(
      Offset.zero & size,
      Paint()..color = const Color(0xffffffff),
    );

    for (var y = 0; y < code.side; y++) {
      for (var x = 0; x < code.side; x++) {
        if (!code.dark(x, y)) {
          continue;
        }

        // Overlap by a hair so there are no seams between modules.
        canvas.drawRect(
          Rect.fromLTWH(
            (x + _quiet) * cell,
            (y + _quiet) * cell,
            cell + 0.5,
            cell + 0.5,
          ),
          dark,
        );
      }
    }
  }

  @override
  bool shouldRepaint(covariant _QrPainter oldDelegate) =>
      oldDelegate.code != code;
}
