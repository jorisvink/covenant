import 'package:flutter/widgets.dart';

import '../api.dart';
import '../app.dart';
import '../reliquary.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/marks.dart';
import '../widgets/ui.dart';
import 'flock.dart';

class FlocksPage extends StatefulWidget {
  const FlocksPage({super.key});

  @override
  State<FlocksPage> createState() => _FlocksPageState();
}

class _FlocksPageState extends State<FlocksPage> {
  Future<void> _refresh() async {
    try {
      await Reliquary.instance.refresh();
    } on ApiError catch (e) {
      notify(e.message);
    }
  }

  Future<void> _create() async {
    final ok = await confirm(
      title: 'Create a flock',
      text:
          'A flock is a private group of up to 255 of your devices that can '
          'reach each other. Next you set up its keys on this phone and add '
          'your devices.',
      action: 'Create',
    );

    if (!ok) {
      return;
    }

    try {
      final id = await wait(
        'Creating the flock',
        Reliquary.instance.createFlock,
      );
      notify('Flock created.', warn: false);
      push(FlockPage(id: id)).ignore();
    } on ApiError catch (e) {
      notify(e.message);
    }
  }

  List<Widget> _list(String label, List<Flock> flocks) {
    if (flocks.isEmpty) {
      return const [];
    }

    return [
      GroupLabel(
        label,
        trailing: Text('${flocks.length}', style: Styles.rubric),
      ),
      for (final f in flocks) FlockCard(flock: f),
    ];
  }

  @override
  Widget build(BuildContext context) {
    final r = Reliquary.instance;

    return ListenableBuilder(
      listenable: r,
      builder: (context, _) {
        final online = r.session != null;
        final external = [
          for (final f in r.flocks)
            if (flockState(f.id) == FlockState.external) f,
        ];
        final here = [
          for (final f in r.flocks)
            if (!external.contains(f)) f,
        ];

        return TabPage(
          index: 1,
          rubric: 'Flocks',
          title: 'Your flocks',
          glow: online && r.problem == null,
          actions: [
            if (online) ...[
              GlyphBtn(
                GlyphKind.refresh,
                label: 'Refresh',
                onTap: r.loading ? null : _refresh,
              ),
              GlyphBtn(GlyphKind.plus, label: 'Create a flock', onTap: _create),
            ],
          ],
          children: [
            if (!r.started)
              const SizedBox.shrink()
            else if (!online)
              EmptyState(
                glyph: GlyphKind.account,
                title: 'Not logged in',
                text:
                    'Create an account or log in to start connecting your '
                    'devices.',
                action: Btn(
                  label: 'Account',
                  onTap: () => goTab(NavTab.account),
                ),
              )
            else ...[
              if (r.problem != null)
                Notice(kind: NoticeKind.warn, text: r.problem!),
              if (r.flocks.isEmpty && !r.loading && r.problem == null)
                EmptyState(
                  glyph: GlyphKind.flocks,
                  title: 'No flocks yet',
                  text:
                      'A flock is a private group of your devices, like your '
                      'phone, laptop and computer at home, that can reach '
                      'each other from anywhere. Create one to get started.',
                  action: Btn(
                    label: 'Create a flock',
                    glyph: GlyphKind.plus,
                    onTap: _create,
                  ),
                ),
              if (r.flocks.isEmpty && r.loading)
                WorkPanel(text: 'Loading your flocks', progress: r.loaded),
              ..._list('Managed on this phone', here),
              ..._list('Managed externally', external),
            ],
          ],
        );
      },
    );
  }
}

class FlockCard extends StatelessWidget {
  const FlockCard({super.key, required this.flock});

  final Flock flock;

  @override
  Widget build(BuildContext context) {
    final r = Reliquary.instance;
    final ambry = r.ambry(flock.id);
    final state = flockState(flock.id);
    final name = r.flockName(flock.id);

    return Panel(
      accent: state == FlockState.ready,
      padding: const EdgeInsets.fromLTRB(16, 14, 10, 14),
      onTap: () => push(FlockPage(id: flock.id)),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 6,
                  runSpacing: 6,
                  children: [
                    if (state == FlockState.noKeks) const Tag('Set up needed'),
                    if (ambry != null)
                      Tag(ambryTag(ambry), accent: !ambry.expired),
                    if (flock.pending > 0) Tag('${flock.pending} pending'),
                  ],
                ),
                const SizedBox(height: 10),
                Text(
                  name ?? flock.id,
                  style: name == null
                      ? Styles.cardTitle.copyWith(fontFamily: Fonts.mono)
                      : Styles.cardTitle,
                  overflow: TextOverflow.ellipsis,
                ),
                if (name != null)
                  Text(
                    flock.id,
                    style: Styles.detail.copyWith(fontFamily: Fonts.mono),
                  ),
                const SizedBox(height: 3),
                Text(
                  flock.problem ??
                      (flock.devices == null
                          ? 'Loading devices…'
                          : state == FlockState.external
                          ? devicesText(flock.approved)
                          : '${devicesText(flock.approved)} · '
                                '${stateText(state)}'),
                  style: Styles.detail.copyWith(
                    color: state == FlockState.ready ? Palette.good : null,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const Glyph(GlyphKind.chevron, size: 18, color: Palette.dim),
        ],
      ),
    );
  }
}

enum FlockState { noKeks, external, noAmbry, expired, ready }

FlockState flockState(String flock) {
  final r = Reliquary.instance;
  final ambry = r.ambry(flock);

  if (r.external(flock)) {
    return FlockState.external;
  }

  if (!r.hasKeks(flock)) {
    return FlockState.noKeks;
  }

  if (ambry == null || !ambry.uploaded) {
    return FlockState.noAmbry;
  }

  if (ambry.expired) {
    return FlockState.expired;
  }

  return FlockState.ready;
}

String stateText(FlockState state) => switch (state) {
  FlockState.noKeks => 'set up needed',
  FlockState.external => 'managed externally',
  FlockState.noAmbry => 'secrets not sent',
  FlockState.expired => 'secrets expired',
  FlockState.ready => 'ready',
};

String devicesText(int n) => n == 1 ? '1 device' : '$n devices';

String ambryTag(AmbryNote ambry) {
  if (!ambry.uploaded) {
    return 'Secrets not sent';
  }

  if (ambry.expired) {
    return 'Secrets expired';
  }

  return 'Secrets valid ${ambry.daysLeft}d';
}
