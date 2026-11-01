import 'package:flutter/widgets.dart';

import '../api.dart';
import '../app.dart';
import '../core.dart';
import '../reliquary.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/fields.dart';
import '../widgets/marks.dart';
import '../widgets/ui.dart';

class DevicePage extends StatefulWidget {
  const DevicePage({super.key, required this.flock, required this.id});

  final String flock;
  final String id;

  @override
  State<DevicePage> createState() => _DevicePageState();
}

class _DevicePageState extends State<DevicePage> {
  bool _renew = true;

  Reliquary get _r => Reliquary.instance;

  Device? get _device {
    for (final d in _r.flock(widget.flock)?.devices ?? const <Device>[]) {
      if (d.id == widget.id) {
        return d;
      }
    }

    return null;
  }

  String get _name =>
      _r.deviceName(widget.flock, widget.id) ?? 'Device ${widget.id}';

  Future<void> _approve() async {
    try {
      await wait(
        'Approving the device',
        () => _r.approve(widget.flock, widget.id),
      );
      notify('$_name approved.', warn: false);
    } on ApiError catch (e) {
      notify(e.message);
    }
  }

  Future<void> _delete(Device device) async {
    final renew = _renew && device.approved && _r.hasKeks(widget.flock);

    final name = _name;
    final ok = await confirm(
      title: device.approved ? 'Remove $name' : 'Reject $name',
      text: renew
          ? 'The device is removed from the flock and its key is replaced, '
                'so it can never connect again, even in the wrong hands.'
          : device.approved
          ? 'The device is removed from the flock. It can still connect '
                'until you send new encrypted secrets.'
          : 'The device will not join this flock.',
      action: device.approved ? 'Remove' : 'Reject',
    );

    if (!ok) {
      return;
    }

    int? days;
    if (renew) {
      days = await chooseDays();
      if (days == null) {
        return;
      }
    }

    try {
      await wait(
        device.approved ? 'Removing the device' : 'Rejecting the device',
        () async {
          await _r.deleteDevice(widget.flock, device.id);

          if (renew) {
            await _r.renew(widget.flock, device.kek, days!);
          }
        },
      );

      navigatorKey.currentState?.maybePop();
      notify(
        renew ? '$name removed and its key replaced.' : '$name removed.',
        warn: false,
      );
    } on CoreError catch (e) {
      notify(
        e.cancelled
            ? '$name was removed but its key was not replaced.'
            : e.message,
      );
    } on ApiError catch (e) {
      notify(e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: _r,
      builder: (context, _) {
        final device = _device;

        if (device == null) {
          return PushedPage(
            rubric: 'Device',
            title: widget.id,
            children: const [
              Notice(text: 'This device is no longer in the flock.'),
            ],
          );
        }

        final created = device.created;
        final keks = _r.hasKeks(widget.flock);
        final external = _r.external(widget.flock);

        return PushedPage(
          rubric: 'Device',
          title: _name,
          bottom: external
              ? null
              : device.approved
              ? Btn(
                  label: 'Remove device',
                  glyph: GlyphKind.trash,
                  kind: BtnKind.secondary,
                  expand: true,
                  onTap: () => _delete(device),
                )
              : BtnPair(
                  first: Btn(
                    label: 'Reject',
                    kind: BtnKind.secondary,
                    expand: true,
                    onTap: () => _delete(device),
                  ),
                  second: Btn(label: 'Approve', expand: true, onTap: _approve),
                ),
          children: [
            Panel(
              accent: device.approved,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Tag(
                    device.approved ? 'In the flock' : 'Waiting for approval',
                    accent: device.approved,
                  ),
                  const SizedBox(height: 12),
                  Text(_name, style: Styles.state),
                  const SizedBox(height: 4),
                  Text(
                    'In flock ${_r.flockLabel(widget.flock)}',
                    style: Styles.detail,
                  ),
                ],
              ),
            ),
            KeyList(
              rows: [
                ('Device ID', device.id),
                ('Key number', device.approved ? device.kekHex : '-'),
                ('Added', created == null ? '-' : dateTime(created)),
              ],
            ),
            if (external)
              const Notice(
                text:
                    'This device is in a flock managed from somewhere else, '
                    'it cannot be changed here.',
              ),
            if (!device.approved && !external)
              const Notice(
                text:
                    'Only approve devices you added yourself. A device that '
                    'asked to join from a computer also needs its key file, '
                    'which this app never hands out.',
              ),
            if (device.approved && keks)
              SwitchRow(
                text:
                    'Replace its key when removing it. Do this if the '
                    'device was lost or stolen.',
                label: 'Replace the key',
                on: _renew,
                onChanged: (v) => setState(() => _renew = v),
              ),
          ],
        );
      },
    );
  }
}
