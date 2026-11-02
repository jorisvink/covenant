import 'package:flutter/widgets.dart';

import '../app.dart';
import '../core.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/marks.dart';
import '../widgets/qr.dart';
import '../widgets/ui.dart';

class QrPage extends StatefulWidget {
  const QrPage({
    super.key,
    required this.code,
    required this.flock,
    required this.device,
    required this.kek,
    required this.name,
  });

  final QrCode code;
  final String flock;
  final String device;
  final int kek;
  final String name;

  @override
  State<QrPage> createState() => _QrPageState();
}

class _QrPageState extends State<QrPage> {
  bool _done = false;

  @override
  void dispose() {
    widget.code.wipe();
    super.dispose();
  }

  Future<void> _finish() async {
    final ok = await confirm(
      title: 'Scanned it?',
      text:
          'This QR code disappears for good. If the device did not pick it '
          'up, remove it from the flock and add it again.',
      action: 'Done',
    );

    if (ok) {
      setState(() => _done = true);
      navigatorKey.currentState?.pop();
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: _done,
      onPopInvokedWithResult: (popped, _) {
        if (!popped) {
          _finish();
        }
      },
      child: PushedPage(
        rubric: 'Scan with Vigil',
        title: widget.name,
        bottom: Btn(label: 'Done', expand: true, onTap: _finish),
        children: [
          const Text(
            'Open the Vigil app on the device and scan this code, it sets '
            'up everything the device needs.',
            style: Styles.body,
          ),
          const Notice(
            text:
                'It can take up to a minute before Reliquary accepts the new '
                'device, until then it cannot connect.',
          ),
          Panel(
            accent: true,
            padding: const EdgeInsets.all(14),
            child: CustomPaint(
              foregroundPainter: const FinderPainter(length: 22),
              child: Padding(
                padding: const EdgeInsets.all(10),
                child: QrView(code: widget.code),
              ),
            ),
          ),
          KeyList(
            rows: [('Device ID', widget.device), ('Flock', widget.flock)],
          ),
          const Notice(
            kind: NoticeKind.warn,
            text:
                'This code holds the KEK and cathedral keys of the device. '
                'Only show it to the device it is for.',
          ),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Glyph(GlyphKind.lock, size: 16, color: Palette.dim),
              const SizedBox(width: 8),
              Text(
                'SHOWN ONCE, NEVER STORED',
                style: Styles.rubric.copyWith(fontSize: 10),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
