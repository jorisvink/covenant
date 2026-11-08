import 'package:flutter/widgets.dart';

import '../api.dart';
import '../app.dart';
import '../core.dart';
import '../platform.dart';
import '../reliquary.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/marks.dart';
import '../widgets/ui.dart';
import 'device.dart';
import 'flocks.dart';
import 'provision.dart';

class FlockPage extends StatefulWidget {
  const FlockPage({super.key, required this.id});

  final String id;

  @override
  State<FlockPage> createState() => _FlockPageState();
}

class _FlockPageState extends State<FlockPage> {
  Reliquary get _r => Reliquary.instance;

  @override
  void initState() {
    super.initState();
    _r.refreshFlock(widget.id).ignore();
  }

  Future<void> _run(
    String text,
    Future<String> Function() work, {
    Future<void> Function()? after,
  }) async {
    final String done;

    try {
      done = await wait(text, work);
    } on CoreError catch (e) {
      if (!e.cancelled) {
        notify(e.message);
      }
      return;
    } on ApiError catch (e) {
      notify(e.message);
      return;
    }

    if (after != null) {
      await after();
    }

    notify(done, warn: false);
  }

  Future<void> _generate() async {
    final had = _r.hasKeks(widget.id);

    final ok = await confirm(
      title: had ? 'Reset all KEKs' : 'Set up KEKs',
      text: had
          ? 'This makes new KEKs for the whole flock. Every device stops '
                'working until you add it again with a new QR code.'
          : 'The Key-Encryption-Keys (KEKs) of this flock are made on this '
                '$here and locked away. The cathedrals never see them.',
      action: had ? 'Reset' : 'Set up',
    );

    if (!ok) {
      return;
    }

    final days = await chooseDays();
    if (days == null) {
      return;
    }

    await _run('Making the KEKs', () async {
      await _r.generate(widget.id, days);
      return 'The KEKs are set up, you can add devices now.';
    }, after: _allowReminders);
  }

  Future<void> _allowReminders() async {
    if (!(_r.ambry(widget.id)?.uploaded ?? false) ||
        !await _r.remindersFirst()) {
      return;
    }

    final ok = await confirm(
      title: 'Expiry reminders',
      text:
          'Covenant can remind you a few days before the encrypted secrets '
          'of a flock expire, so you can send new ones in time. Allow '
          'notifications to get these reminders.',
      action: 'Allow',
    );

    if (ok) {
      await _r.core.remindersAllow();
    }
  }

  Future<void> _bundle() async {
    final days = await chooseDays();
    if (days == null) {
      return;
    }

    await _run('Making new encrypted secrets', () async {
      final note = await _r.rebundle(widget.id, days);
      return 'Encrypted secrets sent, valid until '
          '${date(note.expiry)}.';
    }, after: _allowReminders);
  }

  Future<void> _forget() async {
    final ok = await confirm(
      title: 'Remove the KEKs',
      text:
          'Your devices keep working until the current encrypted secrets '
          'expire. After that nobody can send them new ones and the flock '
          'has to be set up again. This cannot be undone.',
      action: 'Remove',
    );

    if (ok) {
      await _run('Removing the KEKs', () async {
        await _r.forget(widget.id);
        return 'The KEKs are removed from this $here.';
      });
    }
  }

  Future<void> _delete() async {
    final ok = await confirm(
      title: 'Delete this flock',
      text:
          'The flock and all of its devices are deleted, and its KEKs are '
          'removed from this $here. This cannot be undone.',
      action: 'Delete',
    );

    if (ok) {
      await _run('Deleting the flock', () async {
        await _r.deleteFlock(widget.id);
        return 'Flock deleted.';
      }, after: () async => navigatorKey.currentState?.maybePop());
    }
  }

  Future<void> _rename() async {
    final name = await ask(
      title: 'Name this flock',
      text:
          'The name is only kept on this $here, Reliquary and your other '
          'devices never see it. Leave it empty to show the flock ID.',
      action: 'Save',
      initial: _r.flockName(widget.id) ?? '',
      hint: widget.id,
      maxLength: 64,
    );

    if (name != null) {
      await _r.nameFlock(widget.id, name);
    }
  }

  Future<void> _approve(Device d) async {
    await _run('Approving the device', () async {
      await _r.approve(widget.id, d.id);
      return 'Device approved.';
    });
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: _r,
      builder: (context, _) {
        final flock = _r.flock(widget.id) ?? Flock(widget.id);
        final keks = _r.keks(widget.id);
        final ambry = _r.ambry(widget.id);
        final state = flockState(widget.id);
        final devices = flock.devices ?? const <Device>[];
        final work = _r.work?.flock == widget.id ? _r.work : null;
        final external = state == FlockState.external;
        final pending = devices.where((d) => !d.approved).toList();
        final approved = devices.where((d) => d.approved).toList();
        var index = 0;

        return PushedPage(
          rubric: 'Flock',
          title: _r.flockLabel(widget.id),
          actions: [
            GlyphBtn(GlyphKind.edit, label: 'Rename', onTap: _rename),
            GlyphBtn(
              GlyphKind.refresh,
              label: 'Refresh',
              onTap: () => _r.refreshFlock(widget.id),
            ),
          ],
          children: [
            _Hero(
              flock: flock,
              state: state,
              onTap: keks == null ? _generate : () => addDevice(widget.id),
            ),
            if (external)
              const Notice(
                text:
                    'This flock is managed from somewhere else. You can see '
                    'it here, but not change it.',
              ),
            if (_r.vault?.invalidated ?? false)
              const Notice(
                kind: NoticeKind.warn,
                text:
                    'The KEKs on this phone cannot be opened anymore because '
                    'the screen lock was changed or removed. See the Keys '
                    'tab.',
              ),
            if (state == FlockState.noAmbry && keks != null && work == null)
              const Notice(
                kind: NoticeKind.warn,
                text:
                    'The encrypted secrets have not reached the cathedrals '
                    'yet, your devices cannot connect until they do. Send '
                    'them again below.',
              ),
            if (state == FlockState.expired && work == null)
              const Notice(
                kind: NoticeKind.warn,
                text:
                    'The encrypted secrets have expired, your devices cannot '
                    'reach each other. Send new ones below.',
              ),
            if (flock.problem != null)
              Notice(kind: NoticeKind.warn, text: flock.problem!),
            if (pending.isNotEmpty) ...[
              GroupLabel(
                'Waiting for approval',
                index: ++index,
                trailing: Text('${pending.length}', style: Styles.rubric),
              ),
              for (final d in pending)
                _DeviceCard(flock: widget.id, device: d, manage: !external),
            ],
            GroupLabel(
              'Devices',
              index: ++index,
              trailing: Text('${approved.length}', style: Styles.rubric),
            ),
            if (flock.devices == null && flock.problem == null)
              const Notice(text: 'Loading the devices…')
            else if (approved.isEmpty)
              Notice(
                text: keks == null
                    ? 'No devices yet. Set up the KEKs first, then add your '
                          'devices.'
                    : 'No devices yet. Tap Add a device and scan the QR code '
                          'with the Vigil app on the device.',
              )
            else
              for (final d in approved)
                _DeviceCard(flock: widget.id, device: d),
            GroupLabel('Key-Encryption-Keys (KEKs)', index: ++index),
            KeyList(
              rows: [
                (
                  'Stored',
                  keks == null ? 'Not on this $here' : 'On this $here',
                ),
                if (ambry != null) ...[
                  ('Valid until', '${date(ambry.expiry)}\n${_left(ambry)}'),
                  ('Sent', ambry.uploaded ? dateTime(ambry.made) : 'Not yet'),
                ],
              ],
            ),
            if (keks != null) ...[
              const Text(
                'Your devices get their keys from encrypted secrets via '
                'cathedrals that only they can open. These expire, so send new '
                'ones before they do.',
                style: Styles.detail,
              ),
              Btn(
                label: 'Send encrypted secrets',
                glyph: GlyphKind.refresh,
                kind: state == FlockState.ready
                    ? BtnKind.secondary
                    : BtnKind.primary,
                expand: true,
                onTap: _bundle,
              ),
            ],
            if (!external) ...[
              GroupLabel('Danger', index: ++index),
              Panel(
                padding: EdgeInsets.zero,
                child: Column(
                  children: [
                    if (keks != null) ...[
                      _DangerRow(
                        label: 'Reset all KEKs',
                        detail: 'Every device must be added again',
                        onTap: _generate,
                      ),
                      const Line(),
                      _DangerRow(
                        label: 'Remove the KEKs from this $here',
                        detail: 'You can no longer send encrypted secrets',
                        onTap: _forget,
                      ),
                      const Line(),
                    ],
                    _DangerRow(
                      label: 'Delete this flock',
                      detail: 'Together with all of its devices',
                      onTap: _delete,
                    ),
                  ],
                ),
              ),
            ],
          ],
        );
      },
    );
  }

  String _left(AmbryNote ambry) {
    if (ambry.expired) {
      return 'expired';
    }

    final days = ambry.daysLeft;
    return days == 1 ? '1 day left' : '$days days left';
  }
}

class _Hero extends StatelessWidget {
  const _Hero({required this.flock, required this.state, required this.onTap});

  final Flock flock;
  final FlockState state;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final live = switch (state) {
      FlockState.ready => Liveness.online,
      FlockState.noKeks || FlockState.external => Liveness.off,
      _ => Liveness.pending,
    };

    return Panel(
      accent: state == FlockState.ready,
      padding: EdgeInsets.zero,
      child: Stack(
        children: [
          Positioned.fill(
            child: NetBackdrop(
              intensity: state == FlockState.ready ? 1.1 : 0.5,
            ),
          ),
          Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    StateDot(live),
                    const SizedBox(width: 10),
                    Rubric(
                      text: Reliquary.instance.flockName(flock.id) == null
                          ? 'Flock'
                          : 'Flock ${flock.id}',
                    ),
                  ],
                ),
                const SizedBox(height: 14),
                Text(switch (state) {
                  FlockState.ready => 'Ready',
                  FlockState.noKeks => 'Set up needed',
                  FlockState.external => 'Managed externally',
                  FlockState.noAmbry => 'Secrets not sent',
                  FlockState.expired => 'Secrets expired',
                }, style: Styles.state),
                const SizedBox(height: 6),
                Text(
                  state == FlockState.noKeks
                      ? 'Set up the KEKs of this flock to add devices.'
                      : state == FlockState.external
                      ? '${devicesText(flock.approved)} · their KEKs are '
                            'kept somewhere else'
                      : flock.pending > 0
                      ? '${devicesText(flock.approved)} · '
                            '${flock.pending} waiting'
                      : devicesText(flock.approved),
                  style: Styles.detail,
                ),
                if (state != FlockState.external) ...[
                  const SizedBox(height: 20),
                  state == FlockState.noKeks
                      ? Btn(
                          label: 'Set up KEKs',
                          glyph: GlyphKind.keys,
                          expand: true,
                          onTap: onTap,
                        )
                      : Btn(
                          label: 'Add a device',
                          glyph: GlyphKind.qr,
                          expand: true,
                          onTap: onTap,
                        ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _DeviceCard extends StatelessWidget {
  const _DeviceCard({
    required this.flock,
    required this.device,
    this.manage = true,
  });

  final String flock;
  final Device device;
  final bool manage;

  @override
  Widget build(BuildContext context) {
    final created = device.created;
    final name = Reliquary.instance.deviceName(flock, device.id);

    return Panel(
      padding: const EdgeInsets.fromLTRB(16, 12, 10, 12),
      onTap: () => push(DevicePage(flock: flock, id: device.id)),
      child: Row(
        children: [
          SizedBox(
            width: 36,
            child: Align(
              alignment: Alignment.centerLeft,
              child: Glyph(
                GlyphKind.device,
                size: 20,
                color: device.approved ? Palette.amber : Palette.dim,
              ),
            ),
          ),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(name ?? 'Device ${device.id}', style: Styles.value),
                Text(
                  created == null ? '-' : 'Added ${date(created)}',
                  style: Styles.detail,
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

class _DangerRow extends StatelessWidget {
  const _DangerRow({required this.label, required this.detail, this.onTap});

  final String label;
  final String detail;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return Pressable(
      onTap: onTap,
      label: label,
      builder: (context, pressed) => Container(
        color: pressed ? Palette.bg3 : null,
        padding: const EdgeInsets.fromLTRB(16, 14, 10, 14),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    label,
                    style: Styles.body.copyWith(
                      color: onTap == null
                          ? Palette.dim
                          : pressed
                          ? Palette.amber2
                          : Palette.amber,
                    ),
                  ),
                  Text(detail, style: Styles.detail),
                ],
              ),
            ),
            Glyph(
              GlyphKind.chevron,
              size: 18,
              color: pressed ? Palette.amber : Palette.dim,
            ),
          ],
        ),
      ),
    );
  }
}
