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
import 'remote.dart';

enum Mode { cathedral, liturgy, tier6, gospel }

String modeLabel(Mode mode) => switch (mode) {
  Mode.cathedral => 'One device',
  Mode.liturgy => 'Group',
  Mode.tier6 => 'Tier6',
  Mode.gospel => 'Comms',
};

Mode? modeNamed(String? name) {
  for (final m in Mode.values) {
    if (m.name == name) {
      return m;
    }
  }

  return null;
}

enum _Step { cosk, renew, register, approve, unlock }

enum Where { qr, here, remote, computer }

Future<void> addDevice(String flock, {Device? replace}) async {
  var here = false;

  try {
    here = await Core.instance.handoffAvailable();
  } on CoreError catch (_) {}

  final where = await choose<Where>(
    title: replace == null ? 'Add a device' : 'Reprovision a device',
    options: [
      (Where.qr, 'Phone next to you', 'Scan a QR code with Vigil'),
      if (replace == null) ...[
        (Where.remote, 'Phone far away', 'Type secret words into Vigil'),
        (Where.computer, 'Computer', 'Type secret words into the cephas tool'),
      ],
      if (here) (Where.here, 'This phone', 'Provision the Vigil app on this phone'),
    ],
  );

  if (where == null) {
    return;
  }

  await push<void>(ProvisionPage(flock: flock, where: where, replace: replace));
}

String _stepText(_Step step, {required bool here, required bool replace}) =>
    switch (step) {
      _Step.cosk => 'Create a cathedral key for the device',
      _Step.renew => 'Replace the KEK of the old device',
      _Step.register =>
        replace
            ? 'Hand the device over at Reliquary'
            : 'Register it with Reliquary',
      _Step.approve => 'Add it to the flock',
      _Step.unlock =>
        here
            ? 'Unlock your KEKs and hand it to Vigil'
            : 'Unlock your KEKs and make the QR code',
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
  const ProvisionPage({
    super.key,
    required this.flock,
    required this.where,
    this.replace,
  });

  final String flock;
  final Where where;
  final Device? replace;

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

  bool _running = false;
  _Step? _at;
  String? _failed;
  Cosk? _cosk;
  Registration? _reg;
  int? _kek;
  int? _days;
  bool _renewed = false;

  Where get _where => widget.where;

  bool get _here => _where == Where.here;

  bool get _remote => _where == Where.remote || _where == Where.computer;

  Reliquary get _r => Reliquary.instance;

  bool get _started => _cosk != null;

  String? get _keep {
    final old = widget.replace;
    return old == null ? null : _r.deviceName(widget.flock, old.id);
  }

  Mode? get _locked {
    final old = widget.replace;
    return old == null ? null : modeNamed(_r.deviceMode(widget.flock, old.id));
  }

  String get _intro {
    final ask = switch ((_keep != null, _locked != null)) {
      (false, false) => 'Give the device a name and choose how it connects.',
      (false, true) => 'Give the device a name, it keeps the its type.',
      (true, false) => 'The device keeps its name, choose how it connects.',
      (true, true) => 'The new device keeps the name and its type.',
    };

    return switch (_where) {
      Where.qr =>
        '$ask You then get a QR code to scan with the Vigil app on the '
            'device.',
      Where.here => ask,
      Where.remote =>
        '$ask You then get secret words to type into the Vigil app on the '
            'device.',
      Where.computer =>
        'Give the computer a name. You then get secret words to type into '
            'cephas on the computer, it only gets its KEK.',
    };
  }

  List<_Step> get _steps => widget.replace == null
      ? const [_Step.cosk, _Step.register, _Step.approve, _Step.unlock]
      : const [_Step.cosk, _Step.renew, _Step.register, _Step.unlock];

  @override
  void initState() {
    super.initState();
    _cathedral = _r.session?.cathedral;
    _instance.text = _keep ?? '';
    _mode = _locked ?? _mode;
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

    if (_where == Where.computer) {
      return _cathedralCheck();
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
          return '$r is not a network, write it like 10.0.0.0/8.';
        }
      }
    }

    if (_mode == Mode.liturgy && !_isIp(_prefix.text.trim())) {
      return 'Write the network prefix like 172.31.0.0.';
    }

    if (_mode == Mode.tier6 &&
        _tunnel.text.trim().isNotEmpty &&
        !_isNet(_tunnel.text.trim(), min: 8)) {
      return 'Write the address like 10.88.0.2/24, or leave it empty.';
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
        return 'The packet size must be auto or between 576 and 1500.';
      }
    }

    return _cathedralCheck();
  }

  String? _cathedralCheck() {
    final cathedral = _cathedral ?? '';
    if (!RegExp(r'^[^\s:]+:\d+$').hasMatch(cathedral)) {
      return 'Pick a cathedral under advanced settings.';
    }

    return null;
  }

  String _config(String device, int kek) {
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
      ..writeln('cathedral_id $device')
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

    if (_remote) {
      _far();
      return;
    }

    final old = widget.replace;

    if (old != null && !_renewed) {
      _days ??= await chooseDays();
      if (_days == null) {
        return;
      }
    }

    setState(() {
      _running = true;
      _failed = null;
    });

    try {
      _at = _Step.cosk;
      setState(() {});
      _cosk ??= await Core.instance.cosk();

      if (old != null) {
        if (!_renewed) {
          _at = _Step.renew;
          setState(() {});
          await _r.renew(widget.flock, old.kek, _days!);
          _renewed = true;
        }

        _at = _Step.register;
        setState(() {});
        _reg ??= await _r.replaceDevice(widget.flock, old, _cosk!.pk);
        _kek = old.kek;
      } else {
        _at = _Step.register;
        setState(() {});
        _reg ??= await _r.api.deviceCreate(widget.flock, _cosk!.pk);

        _at = _Step.approve;
        setState(() {});
        _kek ??= await _r.approve(widget.flock, _reg!.id);
      }

      if (_mode == Mode.cathedral && _peerNext) {
        final next = _nextKek(_kek!);
        if (next == null) {
          throw ApiError(
            'This flock is full, there is no room for the other device.',
          );
        }

        _peer.text = hex(next, prefix: false);
      }

      if (_mode == Mode.cathedral &&
          int.parse(_peer.text.trim(), radix: 16) == _kek) {
        throw ApiError(
          'This device got the same KEK ID as the device you picked to '
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
          config: _config(_reg!.id, _kek!),
        );

        _cosk = null;
        await _r.nameDevice(
          widget.flock,
          _reg!.id,
          _instance.text.trim(),
          mode: _mode.name,
        );

        notify(
          'Sent to Vigil, check it there and import it. It can take up to '
          'a minute before Reliquary accepts the new device.',
          warn: false,
        );
        navigatorKey.currentState?.pop();
        return;
      }

      final qr = await Core.instance.provision(
        flock: widget.flock,
        kek: _kek!,
        cosk: _cosk!,
        secret: _reg!.secret,
        config: _config(_reg!.id, _kek!),
      );

      _cosk = null;

      await _r.nameDevice(
        widget.flock,
        _reg!.id,
        _instance.text.trim(),
        mode: _mode.name,
      );

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
      _fail(e.cancelled ? 'Your KEKs were not unlocked.' : e.message);
    } on ApiError catch (e) {
      _fail(e.message);
    }
  }

  void _far() {
    final computer = _where == Where.computer;

    replace(
      RemotePage(
        flock: widget.flock,
        name: _instance.text.trim(),
        cathedral: _cathedral!,
        mode: computer ? null : _mode.name,
        config: computer
            ? null
            : (device, kek) {
                if (_mode == Mode.cathedral &&
                    int.parse(_peer.text.trim(), radix: 16) == kek) {
                  throw ApiError(
                    'This device got the same KEK ID as the device you '
                    'picked to connect to. Pick another one.',
                  );
                }

                return _config(device, kek);
              },
      ),
    ).ignore();
  }

  void _fail(String message) {
    if (mounted) {
      setState(() {
        _running = false;
        _failed = message;
      });
    }
  }

  Future<void> _discard() async {
    final reg = _reg;

    if (reg != null && widget.replace == null) {
      try {
        await _r.deleteDevice(widget.flock, reg.id);
      } on ApiError catch (e) {
        notify('Could not remove the device: ${e.message}');
      }
    }

    navigatorKey.currentState?.pop();
  }

  Future<void> _leave() async {
    if (widget.replace != null) {
      if (!_renewed) {
        navigatorKey.currentState?.pop();
        return;
      }

      final ok = await confirm(
        title: 'Stop replacing this device',
        text:
            'The KEK of the old device is already replaced, it can no '
            'longer connect. Replace the device again to set up the new one.',
        action: 'Stop',
      );

      if (ok) {
        navigatorKey.currentState?.pop();
      }
      return;
    }

    if (_reg == null) {
      navigatorKey.currentState?.pop();
      return;
    }

    final ok = await confirm(
      title: 'Cancel provisioning of this device',
      text: 'This will automatically remove the devices from the flock.',
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

  int? get _ownKek => widget.replace?.kek ?? _nextKek(0);

  Future<void> _pickPeer() async {
    final devices = _approved;
    final own = _ownKek;
    final next = own == null ? null : _nextKek(own);

    final kek = await choose<String>(
      title: 'Connect to',
      options: [
        if (next != null && !_remote)
          (
            '',
            'The next device you add',
            'For the first device, add the other one right after this',
          ),
        for (final d in devices)
          if (d.id != widget.replace?.id)
            (
              d.kekHex,
              _r.deviceName(widget.flock, d.id) ?? 'Device ${d.id}',
              'KEK ID ${d.kekHex}',
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
        rubric: widget.replace == null
            ? 'Add a device'
            : 'Reprovision a device',
        title: widget.replace == null
            ? 'New device'
            : _keep ?? 'Device ${widget.replace!.id}',
        bottom: _bottom(),
        children: [
          if (_started || _running) ...[
            _Progress(
              at: _at,
              failed: _failed,
              here: _here,
              steps: _steps,
              replace: widget.replace != null,
            ),
            if (_reg != null) KeyList(rows: [('Device ID', _reg!.id)]),
            if (_failed != null) Notice(kind: NoticeKind.warn, text: _failed!),
          ] else ...[
            if (widget.replace != null)
              const Notice(
                kind: NoticeKind.warn,
                text:
                    'The KEK of the old device is replaced, it can never '
                    'connect again. The new device takes over its identity',
              ),
            Text(_intro, style: Styles.body),
            GroupLabel('Name', index: ++index),
            if (_keep != null)
              Text(_keep!, style: Styles.body)
            else
              Field(
                controller: _instance,
                hint: 'laptop',
                allow: _name,
                maxLength: 63,
              ),
            if (_mode == Mode.gospel && _where != Where.computer)
              const Text(
                'The given name is signed by Covenant and authenticated '
                'by all other devices.',
                style: Styles.detail,
              ),
            if (_where != Where.computer) ...[
              GroupLabel('How it connects', index: ++index),
              Choice<Mode>(
                options: [
                  for (final m in [
                    Mode.cathedral,
                    Mode.liturgy,
                    Mode.gospel,
                    if (_advanced || _locked == Mode.tier6) Mode.tier6,
                  ])
                    if (_locked == null || m == _locked) (m, modeLabel(m)),
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
                  if (!v && _mode == Mode.tier6 && _locked == null) {
                    _mode = Mode.cathedral;
                  }
                }),
              ),
              if (_advanced) ..._advancedFields(() => ++index),
            ],
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
          onTap: widget.replace == null ? _discard : _leave,
        ),
        second: Btn(label: 'Try again', expand: true, onTap: _go),
      );
    }

    return Btn(
      label: 'Provision',
      glyph: _where == Where.qr ? GlyphKind.qr : GlyphKind.device,
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
            'Devices with the same group number can communicate with each '
            'other. Leave it empty to use the default group.',
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
        'Cathedrals help your devices find each other, connect and receive '
        'their encrypted secrets. They cannot read anything your devices '
        'send.',
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

  String? _peerName() {
    if (_peerNext) {
      return 'The next device you add, it gets KEK ID ${_peer.text}. '
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
  const _Progress({
    required this.at,
    required this.failed,
    required this.here,
    required this.steps,
    required this.replace,
  });

  final _Step? at;
  final String? failed;
  final bool here;
  final List<_Step> steps;
  final bool replace;

  @override
  Widget build(BuildContext context) {
    return Panel(
      padding: EdgeInsets.zero,
      child: Column(
        children: [
          for (final step in steps) ...[
            if (step != steps.first) const Line(),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              child: Row(
                children: [
                  StateDot(_state(step)),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      _stepText(step, here: here, replace: replace),
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
