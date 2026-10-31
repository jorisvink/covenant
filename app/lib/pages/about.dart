import 'package:flutter/widgets.dart';

import '../app.dart';
import '../core.dart';
import '../theme.dart';
import '../widgets/marks.dart';
import '../widgets/ui.dart';

class AboutPage extends StatelessWidget {
  const AboutPage({super.key});

  @override
  Widget build(BuildContext context) {
    return TabPage(
      index: 4,
      rubric: 'About',
      title: 'Covenant',
      children: [
        Panel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Covenant is a management tool for Reliquary instances',
                style: TextStyle(
                  fontFamily: Fonts.head,
                  fontSize: 19,
                  height: 1.35,
                  color: Palette.fg,
                ),
              ),
              const SizedBox(height: 16),
              Text('Copyright (c) 2026 Joris Vink', style: Styles.rubric),
              FutureBuilder<String>(
                future: Core.instance.version(),
                builder: (context, version) => Text(
                  'Covenant: ${version.data ?? '-'}',
                  style: Styles.rubric,
                ),
              ),
            ],
          ),
        ),
        const Text(
          'The keys protecting your devices in your flocks are made on this '
          'phone and never leave it. The Reliquary servers only receive '
          'encrypted key updates it cannot open, and each device gets its own '
          'key from the QR code you scan.',
          style: Styles.body,
        ),
        const Text(
          'Your devices meet at cathedrals, the Reliquary servers that help '
          'with discovery, connectability and key distribution. Everything '
          'between your devices is end-to-end encrypted, cathedrals cannot '
          'read any of it.',
          style: Styles.body,
        ),
        const GroupLabel('The Community', index: 1),
        LinkList(
          rows: [
            LinkRow(
              'sanctorum.se',
              () => open('https://sanctorum.se'),
              detail: 'The sanctum project',
            ),
            LinkRow(
              'The Reliquary',
              () => open('https://reliquary.se'),
              detail: 'The community network of cathedrals',
            ),
          ],
        ),
        const SizedBox(height: 10),
        Center(
          child: Column(
            children: [
              const SolidCross(),
              const SizedBox(height: 12),
              Text(
                'ITE, MISSA EST',
                style: Styles.rubric.copyWith(fontSize: 10),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
