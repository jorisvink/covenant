// The small marks the app is drawn with: the cut corner, the crosses,
// the wordmark square and the line glyphs used as icons.

import 'dart:math' as math;

import 'package:flutter/widgets.dart';

import '../theme.dart';

Path cutPath(Size size, {double cut = Metrics.cut}) {
  return Path()
    ..moveTo(0, 0)
    ..lineTo(size.width - cut, 0)
    ..lineTo(size.width, cut)
    ..lineTo(size.width, size.height)
    ..lineTo(0, size.height)
    ..close();
}

class CutClipper extends CustomClipper<Path> {
  const CutClipper({this.cut = Metrics.cut});

  final double cut;

  @override
  Path getClip(Size size) => cutPath(size, cut: cut);

  @override
  bool shouldReclip(covariant CutClipper oldClipper) => oldClipper.cut != cut;
}

class CutPainter extends CustomPainter {
  const CutPainter({
    this.fill = Palette.bg2,
    this.stroke = Palette.line,
    this.cut = Metrics.cut,
  });

  final Color fill;
  final Color stroke;
  final double cut;

  @override
  void paint(Canvas canvas, Size size) {
    final path = cutPath(size, cut: cut);

    canvas.drawPath(path, Paint()..color = fill);
    canvas.drawPath(
      path,
      Paint()
        ..color = stroke
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1,
    );
  }

  @override
  bool shouldRepaint(covariant CutPainter oldDelegate) =>
      oldDelegate.fill != fill ||
      oldDelegate.stroke != stroke ||
      oldDelegate.cut != cut;
}

/// The outlined cross the site puts next to every rubric.
///
/// The svg path is M3.5 .5h4v3h3v4h-3v7h-4v-7h-3v-4h3z, filled with
/// the background and stroked in amber.
class RubricCross extends StatelessWidget {
  const RubricCross({super.key, this.fill = Palette.bg});

  final Color fill;

  @override
  Widget build(BuildContext context) {
    return CustomPaint(
      size: const Size(11, 15),
      painter: _RubricCrossPainter(fill),
    );
  }
}

class _RubricCrossPainter extends CustomPainter {
  const _RubricCrossPainter(this.fill);

  final Color fill;

  @override
  void paint(Canvas canvas, Size size) {
    final path = Path()
      ..moveTo(3.5, 0.5)
      ..relativeLineTo(4, 0)
      ..relativeLineTo(0, 3)
      ..relativeLineTo(3, 0)
      ..relativeLineTo(0, 4)
      ..relativeLineTo(-3, 0)
      ..relativeLineTo(0, 7)
      ..relativeLineTo(-4, 0)
      ..relativeLineTo(0, -7)
      ..relativeLineTo(-3, 0)
      ..relativeLineTo(0, -4)
      ..relativeLineTo(3, 0)
      ..close();

    canvas.drawPath(path, Paint()..color = fill);
    canvas.drawPath(
      path,
      Paint()
        ..color = Palette.amber
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1,
    );
  }

  @override
  bool shouldRepaint(covariant _RubricCrossPainter oldDelegate) =>
      oldDelegate.fill != fill;
}

class SolidCross extends StatelessWidget {
  const SolidCross({super.key, this.glow = 0, this.color = Palette.amber});

  final double glow;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return CustomPaint(
      size: const Size(9, 13),
      painter: _SolidCrossPainter(glow, color),
    );
  }
}

class _SolidCrossPainter extends CustomPainter {
  const _SolidCrossPainter(this.glow, this.color);

  final double glow;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Color.lerp(color, const Color(0xffffe9b3), glow * 0.7)!;

    if (glow > 0) {
      final halo = Paint()
        ..color = color.withValues(alpha: 0.9 * glow)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3.5);
      canvas.drawRect(const Rect.fromLTWH(3, 0, 3, 13), halo);
      canvas.drawRect(const Rect.fromLTWH(0, 3, 9, 3), halo);
    }

    canvas.drawRect(const Rect.fromLTWH(3, 0, 3, 13), paint);
    canvas.drawRect(const Rect.fromLTWH(0, 3, 9, 3), paint);
  }

  @override
  bool shouldRepaint(covariant _SolidCrossPainter oldDelegate) =>
      oldDelegate.glow != glow || oldDelegate.color != color;
}

class WordmarkSquare extends StatelessWidget {
  const WordmarkSquare({super.key, this.size = 15, this.glow = false});

  final double size;
  final bool glow;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        boxShadow: glow
            ? const [
                BoxShadow(
                  color: Color(0x59ffb000),
                  blurRadius: 14,
                  spreadRadius: 4,
                ),
              ]
            : null,
      ),
      child: const CustomPaint(painter: _WordmarkPainter()),
    );
  }
}

class _WordmarkPainter extends CustomPainter {
  const _WordmarkPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final unit = size.width / 48;
    final width = math.max(1.0, 2.5 * unit);
    final line = Paint()
      ..color = Palette.amber
      ..style = PaintingStyle.stroke
      ..strokeWidth = width;
    final solid = Paint()..color = Palette.amber;

    canvas.drawRect(
      Rect.fromLTWH(
        width / 2,
        width / 2,
        size.width - width,
        size.width - width,
      ),
      line,
    );

    canvas.drawPath(
      Path()
        ..moveTo(14 * unit, 14 * unit)
        ..lineTo(34 * unit, 14 * unit)
        ..lineTo(24 * unit, 33 * unit)
        ..close(),
      line,
    );

    for (final (x, y) in const [(9.0, 9.0), (29.0, 9.0), (19.0, 28.0)]) {
      canvas.drawRect(
        Rect.fromLTWH(x * unit, y * unit, 10 * unit, 10 * unit),
        solid,
      );
    }
  }

  @override
  bool shouldRepaint(covariant _WordmarkPainter oldDelegate) => false;
}

enum GlyphKind {
  flocks,
  keys,
  account,
  about,
  back,
  chevron,
  plus,
  close,
  shield,
  copy,
  device,
  qr,
  trash,
  refresh,
  lock,
  link,
  edit,
}

class Glyph extends StatelessWidget {
  const Glyph(this.kind, {super.key, this.size = 22, this.color = Palette.fg2});

  final GlyphKind kind;
  final double size;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return CustomPaint(
      size: Size.square(size),
      painter: _GlyphPainter(kind, color),
    );
  }
}

class _GlyphPainter extends CustomPainter {
  const _GlyphPainter(this.kind, this.color);

  final GlyphKind kind;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    canvas.scale(size.width / 24);

    final line = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.6
      ..strokeCap = StrokeCap.square
      ..strokeJoin = StrokeJoin.miter;
    final solid = Paint()..color = color;

    void poly(List<double> xy, {bool close = false}) {
      final path = Path()..moveTo(xy[0], xy[1]);
      for (var i = 2; i < xy.length; i += 2) {
        path.lineTo(xy[i], xy[i + 1]);
      }

      if (close) {
        path.close();
      }
      canvas.drawPath(path, line);
    }

    switch (kind) {
      case GlyphKind.flocks:
        canvas.drawRect(const Rect.fromLTWH(3, 3, 6, 6), line);
        canvas.drawRect(const Rect.fromLTWH(15, 3, 6, 6), line);
        canvas.drawRect(const Rect.fromLTWH(9, 15, 6, 6), line);
        canvas.drawRect(const Rect.fromLTWH(11, 17, 2, 2), solid);
        poly([9, 6, 15, 6]);
        poly([6, 9, 10, 15]);
        poly([18, 9, 14, 15]);
      case GlyphKind.keys:
        canvas.drawRect(const Rect.fromLTWH(3, 8, 8, 8), line);
        canvas.drawRect(const Rect.fromLTWH(6, 11, 2, 2), solid);
        poly([11, 12, 21, 12]);
        poly([17, 12, 17, 16]);
        poly([20, 12, 20, 15]);
      case GlyphKind.account:
        canvas.drawRect(const Rect.fromLTWH(9, 3, 6, 6), line);
        poly([4, 21, 4, 16, 8, 13, 16, 13, 20, 16, 20, 21]);
      case GlyphKind.about:
        poly([
          10,
          2,
          14,
          2,
          14,
          7,
          19,
          7,
          19,
          11,
          14,
          11,
          14,
          22,
          10,
          22,
          10,
          11,
          5,
          11,
          5,
          7,
          10,
          7,
        ], close: true);
      case GlyphKind.back:
        poly([15, 4, 7, 12, 15, 20]);
      case GlyphKind.chevron:
        poly([9, 5, 16, 12, 9, 19]);
      case GlyphKind.plus:
        poly([12, 4, 12, 20]);
        poly([4, 12, 20, 12]);
      case GlyphKind.close:
        poly([5, 5, 19, 19]);
        poly([19, 5, 5, 19]);
      case GlyphKind.shield:
        poly([12, 2, 20, 5, 20, 12, 12, 22, 4, 12, 4, 5], close: true);
        canvas.drawRect(const Rect.fromLTWH(11, 7, 2, 9), solid);
        canvas.drawRect(const Rect.fromLTWH(9, 9, 6, 2), solid);
      case GlyphKind.copy:
        canvas.drawRect(const Rect.fromLTWH(8, 8, 12, 13), line);
        poly([5, 16, 4, 16, 4, 3, 16, 3, 16, 4]);
      case GlyphKind.device:
        canvas.drawPath(
          cutPath(const Size(12, 18), cut: 3).shift(const Offset(6, 3)),
          line,
        );
        canvas.drawRect(const Rect.fromLTWH(11, 16, 2, 2), solid);
      case GlyphKind.qr:
        canvas.drawRect(const Rect.fromLTWH(3, 3, 7, 7), line);
        canvas.drawRect(const Rect.fromLTWH(14, 3, 7, 7), line);
        canvas.drawRect(const Rect.fromLTWH(3, 14, 7, 7), line);
        canvas.drawRect(const Rect.fromLTWH(5.5, 5.5, 2, 2), solid);
        canvas.drawRect(const Rect.fromLTWH(16.5, 5.5, 2, 2), solid);
        canvas.drawRect(const Rect.fromLTWH(5.5, 16.5, 2, 2), solid);
        canvas.drawRect(const Rect.fromLTWH(14, 14, 3, 3), solid);
        canvas.drawRect(const Rect.fromLTWH(18, 18, 3, 3), solid);
        canvas.drawRect(const Rect.fromLTWH(14, 18, 3, 3), solid);
      case GlyphKind.trash:
        poly([4, 6, 20, 6]);
        poly([9, 6, 9, 3, 15, 3, 15, 6]);
        poly([6, 6, 7, 21, 17, 21, 18, 6]);
        poly([10, 10, 10, 17]);
        poly([14, 10, 14, 17]);
      case GlyphKind.refresh:
        poly([4, 12, 4, 5, 17, 5]);
        poly([14, 2, 17, 5, 14, 8]);
        poly([20, 12, 20, 19, 7, 19]);
        poly([10, 16, 7, 19, 10, 22]);
      case GlyphKind.lock:
        canvas.drawRect(const Rect.fromLTWH(5, 11, 14, 10), line);
        poly([8, 11, 8, 6, 10, 4, 14, 4, 16, 6, 16, 11]);
        canvas.drawRect(const Rect.fromLTWH(11, 14, 2, 4), solid);
      case GlyphKind.link:
        poly([14, 4, 20, 4, 20, 10]);
        poly([20, 4, 11, 13]);
        poly([17, 14, 17, 20, 4, 20, 4, 7, 10, 7]);
      case GlyphKind.edit:
        poly([4, 20, 4, 16, 15, 5, 19, 9, 8, 20], close: true);
        poly([12, 8, 16, 12]);
    }
  }

  @override
  bool shouldRepaint(covariant _GlyphPainter oldDelegate) =>
      oldDelegate.kind != kind || oldDelegate.color != color;
}

class FinderPainter extends CustomPainter {
  const FinderPainter({this.length = 28});

  final double length;

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Palette.amber
      ..style = PaintingStyle.stroke
      ..strokeWidth = 3
      ..strokeCap = StrokeCap.square;
    final l = math.min(length, size.shortestSide / 3);
    final w = size.width;
    final h = size.height;

    canvas.drawPath(
      Path()
        ..moveTo(0, l)
        ..lineTo(0, 0)
        ..lineTo(l, 0)
        ..moveTo(w - l, 0)
        ..lineTo(w, 0)
        ..lineTo(w, l)
        ..moveTo(w, h - l)
        ..lineTo(w, h)
        ..lineTo(w - l, h)
        ..moveTo(l, h)
        ..lineTo(0, h)
        ..lineTo(0, h - l),
      paint,
    );
  }

  @override
  bool shouldRepaint(covariant FinderPainter oldDelegate) =>
      oldDelegate.length != length;
}
