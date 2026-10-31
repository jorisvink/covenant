// Provisioning a device: register a fresh cosk with the reliquary,
// approve the device and have the C library turn it all into a vigil QR
// code. This is rlq flock join + device approve + kek install +
// tools/vigil-config.

import 'package:flutter/material.dart';

import '../api.dart';
import '../app.dart';
import '../core.dart';
import '../reliquary.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/fields.dart';
import '../widgets/marks.dart';
import '../widgets/ui.dart';
import 'qr.dart';

enum Mode { cathedral, liturgy, tier6, gospel }

enum _Step { cosk, register, approve, unlock }

String _stepText(_Step step, {required bool here}) => switch (step) {
  _Step.cosk => 'Create a key for the device',
  _Step.register => 'Register it with Reliquary',
  _Step.approve => 'Add it to the flock',
  _Step.unlock =>
    here
        ? 'Unlock your keys and hand it to Vigil'
        : 'Unlock your keys and make the QR code',
};

final _name = RegExp(r'[A-Za-z0-9 ._-]');
final _ip = RegExp(
  r'^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$',
);

bool _isIp(String s) => _ip.hasMatch(s);

bool _isNet(String s, {int min = 0}) {
  final parts = s.split('/');
  if (parts.length != 2 || !_isIp(parts[0])) {
    return false;
  }

  final mask = int.tryParse(parts[1]);
  return mask != null && mask >= min && mask <= 32;
}

List<String> _entries(TextEditingController text) =>
    text.text.split(RegExp(r'[\s,]+')).where((e) => e.isNotEmpty).toList();

class ProvisionPage extends StatefulWidget {
  const ProvisionPage({super.key, required this.flock});

  final String flock;

  @override
  State<ProvisionPage> createState() => _ProvisionPageState();
}

class _ProvisionPageState extends State<ProvisionPage> {
  final _instance = TextEditingController();
  final _tunnel = TextEditingController();
  final _peer = TextEditingController();
  final _routes = TextEditingController();
  final _dns = TextEditingController();
  final _prefix = TextEditingController(text: '172.31.0.0');
  final _group = TextEditingController();
  final _mtu = TextEditingController();

  Mode _mode = Mode.cathedral;
  bool _advanced = false;
  bool _shroud = true;
  bool _p2p = true;
  bool _remembrance = true;
  bool _discoverable = true;
  bool _peerNext = false;
  bool _blockIpv6 = true;
  String? _cathedral;

  // Where we are, so a failed step can be retried without starting over.
  bool _running = false;
  _Step? _at;
  String? _failed;
  Cosk? _cosk;
  Registration? _reg;
  int? _kek;

  bool _vigil = false;
  bool _here = false;

  Reliquary get _r => Reliquary.instance;

  bool get _started => _cosk != null;

  @override
  void initState() {
    super.initState();
    _cathedral = _r.session?.cathedral;

    Core.instance.handoffAvailable().then((v) {
      if (mounted) {
        setState(() => _vigil = v);
      }
    }, onError: (_) {});
  }

  @override
  void dispose() {
    for (final c in [
      _instance,
      _tunnel,
      _peer,
      _routes,
      _dns,
      _prefix,
      _group,
      _mtu,
    ]) {
      c.dispose();
    }

    final cosk = _cosk;
    if (cosk != null) {
      Core.instance.coskDrop(cosk.handle).ignore();
    }

    super.dispose();
  }

  String? _check() {
    final name = _instance.text.trim();

    if (name.isEmpty) {
      return 'Give the device a name.';
    }

    if (_mode == Mode.cathedral) {
      final peer = int.tryParse(_peer.text.trim(), radix: 16);
      if (_peer.text.trim().length != 2 || peer == null || peer == 0) {
        return 'Pick the device to connect to.';
      }

      if (!_isNet(_tunnel.text.trim(), min: 8)) {
        return 'Give the device an address, like 10.88.0.2/24.';
      }

      for (final r in _entries(_routes)) {
        if (!_isNet(r)) {
          return '$r is not a network, like 10.0.0.0/8.';
        }
      }
    }

    if (_mode == Mode.liturgy && !_isIp(_prefix.text.trim())) {
      return 'The network prefix looks like 172.31.0.0.';
    }

    if (_mode == Mode.tier6 &&
        _tunnel.text.trim().isNotEmpty &&
        !_isNet(_tunnel.text.trim(), min: 8)) {
      return 'The address looks like 10.88.0.2/24, or leave it empty.';
    }

    if ((_mode == Mode.liturgy || _mode == Mode.gospel) &&
        _group.text.trim().isNotEmpty &&
        !RegExp(r'^[0-9a-fA-F]{1,4}$').hasMatch(_group.text.trim())) {
      return 'A group number is up to 4 digits or letters a to f.';
    }

    if (_mode != Mode.gospel) {
      final dns = _entries(_dns);
      if (dns.length > 4) {
        return 'Up to four DNS servers.';
      }

      for (final d in dns) {
        if (!_isIp(d)) {
          return '$d is not a valid DNS server address.';
        }
      }
    }

    final mtu = _mtu.text.trim();
    if (mtu.isNotEmpty && mtu != 'auto') {
      final v = int.tryParse(mtu);
      if (v == null || v < 576 || v > 1500) {
        return 'The packet size is auto or between 576 and 1500.';
      }
    }

    final cathedral = _cathedral ?? '';
    if (!RegExp(r'^[^\s:]+:\d+$').hasMatch(cathedral)) {
      return 'Pick a cathedral under advanced settings.';
    }

    return null;
  }

  /// The public part of the configuration, as tools/vigil-config would
  /// write it up to the keys. The C library adds kek, cathedral_secret
  /// and cathedral_cosk.
  String _config(Registration reg, int kek) {
    final out = StringBuffer()
      ..writeln('vigil 1')
      ..writeln('instance ${_instance.text.trim()}');

    final group = _group.text.trim().toLowerCase();

    switch (_mode) {
      case Mode.cathedral:
        out.writeln('tunnel ${_tunnel.text.trim()}');
      case Mode.liturgy:
        out
          ..writeln('mode liturgy')
          ..writeln('liturgy_prefix ${_prefix.text.trim()}');
        if (group.isNotEmpty) {
          out.writeln('liturgy_group ${group.padLeft(4, '0')}');
        }
        if (!_discoverable) {
          out.writeln('liturgy_discoverable no');
        }
      case Mode.tier6:
        out
          ..writeln('mode liturgy')
          ..writeln('tier6 yes');
        if (_tunnel.text.trim().isNotEmpty) {
          out.writeln('tunnel ${_tunnel.text.trim()}');
        }
      case Mode.gospel:
        out.writeln('mode gospel');
        if (group.isNotEmpty) {
          out.writeln('liturgy_group ${group.padLeft(4, '0')}');
        }
    }

    final spi = _mode == Mode.cathedral
        ? '${hex(kek, prefix: false)}${_peer.text.trim().toLowerCase()}'
        : hex(kek, prefix: false);

    final cathedral = _cathedral!;
    final port = int.parse(cathedral.split(':').last);

    out
      ..writeln('spi $spi')
      ..writeln('cathedral $cathedral')
      ..writeln('cathedral_id ${reg.id}')
      ..writeln('cathedral_flock ${widget.flock}');

    final natport = _r.session?.natport;
    if (natport != null && natport != port + 1) {
      out.writeln('cathedral_nat_port $natport');
    }

    if (!_p2p) {
      out.writeln('p2p no');
    }

    if (!_remembrance && _mode != Mode.gospel) {
      out.writeln('cathedral_remembrance no');
    }

    if (_mtu.text.trim().isNotEmpty) {
      out.writeln('mtu ${_mtu.text.trim()}');
    }

    if (_mode == Mode.cathedral) {
      for (final r in _entries(_routes)) {
        out.writeln('route $r');
      }
    }

    if (_mode != Mode.gospel) {
      for (final d in _entries(_dns)) {
        out.writeln('dns $d');
      }
    }

    if (_shroud) {
      out.writeln('shroud yes');
    }

    if (!_blockIpv6 && _mode != Mode.gospel) {
      out.writeln('block_ipv6 no');
    }

    return out.toString();
  }

  Future<void> _go() async {
    final problem = _check();
    if (problem != null) {
      notify(problem);
      return;
    }

    setState(() {
      _running = true;
      _failed = null;
    });

    try {
      _at = _Step.cosk;
      setState(() {});
      _cosk ??= await Core.instance.cosk();

      _at = _Step.register;
      setState(() {});
      _reg ??= await _r.api.deviceCreate(widget.flock, _cosk!.pk);

      _at = _Step.approve;
      setState(() {});
      _kek ??= await _r.approve(widget.flock, _reg!.id);

      if (_mode == Mode.cathedral && _peerNext) {
        final next = _nextKek(_kek!);
        if (next == null) {
          throw ApiError('This flock is full, there is no room for a peer.');
        }

        _peer.text = hex(next, prefix: false);
      }

      if (_mode == Mode.cathedral &&
          int.parse(_peer.text.trim(), radix: 16) == _kek) {
        throw ApiError(
          'This device got the same key number as the device you picked to '
          'connect to. Pick another one.',
        );
      }

      _at = _Step.unlock;
      setState(() {});

      if (_here) {
        await Core.instance.handoff(
          flock: widget.flock,
          kek: _kek!,
          cosk: _cosk!,
          secret: _reg!.secret,
          config: _config(_reg!, _kek!),
        );

        _cosk = null;
        await _r.nameDevice(widget.flock, _reg!.id, _instance.text.trim());

        notify('Sent to Vigil, check it there and import it.', warn: false);
        navigatorKey.currentState?.pop();
        return;
      }

      final qr = await Core.instance.provision(
        flock: widget.flock,
        kek: _kek!,
        cosk: _cosk!,
        secret: _reg!.secret,
        config: _config(_reg!, _kek!),
      );

      // The C library consumed the cosk, there is nothing left to clean up.
      _cosk = null;

      await _r.nameDevice(widget.flock, _reg!.id, _instance.text.trim());

      replace(
        QrPage(
          code: qr,
          flock: widget.flock,
          device: _reg!.id,
          kek: _kek!,
          name: _instance.text.trim(),
        ),
      ).ignore();
    } on CoreError catch (e) {
      _fail(e.cancelled ? 'Your keys were not unlocked.' : e.message);
    } on ApiError catch (e) {
      _fail(e.message);
    }
  }

  void _fail(String message) {
    if (mounted) {
      setState(() {
        _running = false;
        _failed = message;
      });
    }
  }

  /// Throw away a half provisioned device.
  Future<void> _discard() async {
    final reg = _reg;

    if (reg != null) {
      try {
        await _r.deleteDevice(widget.flock, reg.id);
      } on ApiError catch (e) {
        notify('Could not remove the device: ${e.message}');
      }
    }

    // pop, not maybePop: the PopScope would only ask again.
    navigatorKey.currentState?.pop();
  }

  Future<void> _leave() async {
    if (_reg == null) {
      navigatorKey.currentState?.pop();
      return;
    }

    final ok = await confirm(
      title: 'Stop adding this device',
      text:
          'The device is already registered, leaving now removes it '
          'again.',
      action: 'Stop',
    );

    if (ok) {
      await _discard();
    }
  }

  List<Device> get _approved => [
    for (final d in _r.flock(widget.flock)?.devices ?? const <Device>[])
      if (d.approved) d,
  ];

  /// The key number Reliquary hands out after [self], it always picks the
  /// lowest one that is free.
  int? _nextKek(int self) {
    final used = {for (final d in _approved) d.kek, self};

    for (var kek = 1; kek < 256; kek++) {
      if (!used.contains(kek)) {
        return kek;
      }
    }

    return null;
  }

  /// The key number the device being added now will get.
  int? get _ownKek => _nextKek(0);

  Future<void> _pickPeer() async {
    final devices = _approved;
    final own = _ownKek;
    final next = own == null ? null : _nextKek(own);

    final kek = await choose<String>(
      title: 'Connect to',
      options: [
        if (next != null)
          (
            '',
            'The next device you add',
            'For the first device, add the other one right after this',
          ),
        for (final d in devices)
          (
            d.kekHex,
            _r.deviceName(widget.flock, d.id) ?? 'Device ${d.id}',
            'Key number ${d.kekHex}',
          ),
      ],
    );

    if (kek == null) {
      return;
    }

    setState(() {
      _peerNext = kek.isEmpty;
      _peer.text = kek.isEmpty ? hex(next!, prefix: false) : kek;
    });
  }

  Future<void> _pickCathedral() async {
    try {
      final list = await _r.loadCathedrals();
      final options = <(String, String, String?)>[];

      for (final line in list) {
        final at = line.split(' ').last;
        final descr = line.contains(' - ')
            ? line.substring(0, line.lastIndexOf(' - '))
            : null;
        options.add((at, at, descr));
      }

      final session = _r.session?.cathedral;
      if (session != null && !options.any((o) => o.$1 == session)) {
        options.insert(0, (session, session, 'The default'));
      }

      final picked = await choose<String>(title: 'Cathedral', options: options);

      if (picked != null) {
        setState(() => _cathedral = picked);
      }
    } on ApiError catch (e) {
      notify(e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    var index = 0;

    return PopScope(
      canPop: !_started && !_running,
      onPopInvokedWithResult: (popped, _) {
        if (!popped && !_running) {
          _leave();
        }
      },
      child: PushedPage(
        rubric: 'Add a device',
        title: 'New device',
        bottom: _bottom(),
        children: [
          if (_started || _running) ...[
            _Progress(at: _at, failed: _failed, here: _here),
            if (_reg != null) KeyList(rows: [('Device ID', _reg!.id)]),
            if (_failed != null) Notice(kind: NoticeKind.warn, text: _failed!),
          ] else ...[
            Text(
              _vigil
                  ? 'Give the device a name and choose how it connects.'
                  : 'Give the device a name and choose how it connects. You '
                        'then get a QR code to scan with the Vigil app on the '
                        'device.',
              style: Styles.body,
            ),
            if (_vigil) ...[
              GroupLabel('Which device', index: ++index),
              Choice<bool>(
                options: const [(false, 'Another phone'), (true, 'This phone')],
                value: _here,
                onChanged: (v) => setState(() => _here = v),
              ),
              Text(
                _here
                    ? 'Vigil on this phone gets the device straight from '
                          'Reliquary, no QR code needed.'
                    : 'You get a QR code to scan with the Vigil app on the '
                          'other device.',
                style: Styles.detail,
              ),
            ],
            GroupLabel('Name', index: ++index),
            Field(
              controller: _instance,
              hint: 'laptop',
              allow: _name,
              maxLength: 63,
            ),
            GroupLabel('How it connects', index: ++index),
            Choice<Mode>(
              options: [
                (Mode.cathedral, 'One device'),
                (Mode.liturgy, 'Group'),
                (Mode.gospel, 'Comms'),
                if (_advanced) (Mode.tier6, 'Tier6'),
              ],
              value: _mode,
              onChanged: (m) => setState(() => _mode = m),
            ),
            Text(_modeText(), style: Styles.detail),
            ..._modeFields(() => ++index),
            const SizedBox(height: 4),
            SwitchRow(
              text: 'Show advanced settings',
              on: _advanced,
              onChanged: (v) => setState(() {
                _advanced = v;
                if (!v && _mode == Mode.tier6) {
                  _mode = Mode.cathedral;
                }
              }),
            ),
            if (_advanced) ..._advancedFields(() => ++index),
          ],
        ],
      ),
    );
  }

  Widget _bottom() {
    if (_failed != null) {
      return BtnPair(
        first: Btn(
          label: 'Cancel',
          kind: BtnKind.secondary,
          expand: true,
          onTap: _discard,
        ),
        second: Btn(label: 'Try again', expand: true, onTap: _go),
      );
    }

    return Btn(
      label: _here ? 'Add to Vigil' : 'Make QR code',
      glyph: _here ? GlyphKind.device : GlyphKind.qr,
      expand: true,
      busy: _running,
      onTap: _go,
    );
  }

  String _modeText() => switch (_mode) {
    Mode.cathedral => 'A private connection to one other device in this flock.',
    Mode.liturgy => 'Connects by itself to every device in the same group.',
    Mode.tier6 => 'A group connection that carries a whole network, for tier6.',
    Mode.gospel =>
      'Only calls and chat in the Vigil app, the rest of the device is not '
          'connected.',
  };

  List<Widget> _modeFields(int Function() next) {
    switch (_mode) {
      case Mode.cathedral:
        return [
          GroupLabel('Connect to', index: next()),
          Row(
            children: [
              Expanded(
                child: Field(
                  controller: _peer,
                  hint: 'Pick a device',
                  allow: RegExp(r'[0-9a-fA-F]'),
                  maxLength: 2,
                  onChanged: (_) => setState(() => _peerNext = false),
                ),
              ),
              const SizedBox(width: 10),
              Btn(label: 'Pick', kind: BtnKind.secondary, onTap: _pickPeer),
            ],
          ),
          if (_peerName() != null) Text(_peerName()!, style: Styles.detail),
          GroupLabel('Your tunnel address', index: next()),
          Field(
            controller: _tunnel,
            hint: '10.88.0.2/24',
            allow: RegExp(r'[0-9./]'),
            keyboard: addressKeyboard,
          ),
          const Text(
            'The address of this device inside the tunnel, like '
            '10.88.0.2/24. Give every device in the flock a different one.',
            style: Styles.detail,
          ),
          GroupLabel('Send through it', index: next()),
          Field(controller: _routes, hint: '0.0.0.0/0 (optional)', lines: 2),
          const Text(
            'Other networks to reach through this connection, one per line. '
            '0.0.0.0/0 sends all internet traffic via the other device. Leave '
            'it empty to only reach the other device.',
            style: Styles.detail,
          ),
        ];
      case Mode.liturgy:
        return [
          GroupLabel('Group number', index: next()),
          Field(
            controller: _group,
            hint: '0001 (optional)',
            allow: RegExp(r'[0-9a-fA-F]'),
            maxLength: 4,
          ),
          const Text(
            'Devices with the same group number find each other. Leave it '
            'empty to use the default group.',
            style: Styles.detail,
          ),
          SwitchRow(
            text: 'Let others in the group find this device.',
            label: 'Discoverable',
            on: _discoverable,
            onChanged: (v) => setState(() => _discoverable = v),
          ),
        ];
      case Mode.tier6:
        return [
          GroupLabel('Your tunnel address', index: next()),
          Field(
            controller: _tunnel,
            hint: 'Empty to get one assigned',
            allow: RegExp(r'[0-9./]'),
            keyboard: addressKeyboard,
          ),
        ];
      case Mode.gospel:
        return [
          GroupLabel('Group number', index: next()),
          Field(
            controller: _group,
            hint: '0001 (optional)',
            allow: RegExp(r'[0-9a-fA-F]'),
            maxLength: 4,
          ),
          const Text(
            'Devices with the same group number can call each other. Leave '
            'it empty to use the default group.',
            style: Styles.detail,
          ),
        ];
    }
  }

  List<Widget> _advancedFields(int Function() next) {
    return [
      GroupLabel('Cathedral', index: next()),
      LinkList(
        rows: [
          LinkRow(
            _cathedral ?? 'Pick a cathedral',
            _pickCathedral,
            detail: 'The cathedral this device uses',
          ),
        ],
      ),
      const Text(
        'Cathedrals are the Reliquary servers that help your devices with '
        'discovery, connectability and key distribution. They cannot read '
        'anything your devices send.',
        style: Styles.detail,
      ),
      if (_mode == Mode.liturgy) ...[
        GroupLabel('Network prefix', index: next()),
        Field(
          controller: _prefix,
          hint: '172.31.0.0',
          allow: RegExp(r'[0-9.]'),
          keyboard: addressKeyboard,
        ),
      ],
      if (_mode != Mode.gospel) ...[
        GroupLabel('DNS servers', index: next()),
        Field(controller: _dns, hint: 'Optional, one per line', lines: 2),
      ],
      GroupLabel('Options', index: next()),
      SwitchRow(
        text: 'Disguise the connection so it is harder to spot (shroud).',
        label: 'Shroud',
        on: _shroud,
        onChanged: (v) => setState(() => _shroud = v),
      ),
      SwitchRow(
        text:
            'Connect devices directly when possible. If turned off, traffic '
            'is relayed end-to-end encrypted via the cathedrals.',
        label: 'Direct connections',
        on: _p2p,
        onChanged: (v) => setState(() => _p2p = v),
      ),
      if (_mode != Mode.gospel) ...[
        SwitchRow(
          text:
              'Learn about the other cathedrals, to switch over when one '
              'goes down.',
          label: 'Remembrance',
          on: _remembrance,
          onChanged: (v) => setState(() => _remembrance = v),
        ),
        SwitchRow(
          text: 'Block IPv6 when all traffic goes through the connection.',
          label: 'Block IPv6',
          on: _blockIpv6,
          onChanged: (v) => setState(() => _blockIpv6 = v),
        ),
      ],
      const Text('Packet size (MTU)', style: Styles.detail),
      Field(
        controller: _mtu,
        hint: 'Default (or auto)',
        allow: RegExp(r'[0-9auto]'),
        maxLength: 4,
      ),
    ];
  }

  /// The name of the device picked to connect to, if we know it.
  String? _peerName() {
    if (_peerNext) {
      return 'The next device you add, it gets key number ${_peer.text}. '
          'Add it right after this one and pick this device to connect to.';
    }

    final kek = int.tryParse(_peer.text.trim(), radix: 16);
    final device = kek == null ? null : _r.flock(widget.flock)?.byKek(kek);

    if (device == null) {
      return null;
    }

    return _r.deviceName(widget.flock, device.id) ?? 'Device ${device.id}';
  }
}

class _Progress extends StatelessWidget {
  const _Progress({required this.at, required this.failed, required this.here});

  final _Step? at;
  final String? failed;
  final bool here;

  @override
  Widget build(BuildContext context) {
    return Panel(
      padding: EdgeInsets.zero,
      child: Column(
        children: [
          for (final step in _Step.values) ...[
            if (step != _Step.values.first) const Line(),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              child: Row(
                children: [
                  StateDot(_state(step)),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      _stepText(step, here: here),
                      style: Styles.body.copyWith(
                        color: _state(step) == Liveness.off
                            ? Palette.dim
                            : Palette.fg,
                      ),
                    ),
                  ),
                  if (step == at && failed != null)
                    Text(
                      'FAILED',
                      style: Styles.rubric.copyWith(color: Palette.amber),
                    ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Liveness _state(_Step step) {
    final now = at;

    if (now == null || step.index > now.index) {
      return Liveness.off;
    }

    if (step.index < now.index) {
      return Liveness.online;
    }

    return Liveness.pending;
  }
}
