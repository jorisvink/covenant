import 'dart:async';
import 'dart:io';

import 'package:flutter/widgets.dart';

import '../api.dart';
import '../app.dart';
import '../core.dart';
import '../reliquary.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/ui.dart';

enum _Step { join, words, approve, unlock, send }

String _stepText(_Step step) => switch (step) {
  _Step.join => 'Join the flock for the hand over',
  _Step.words => 'Wait for the device to join with the words',
  _Step.approve => 'Add it to the flock',
  _Step.unlock => 'Unlock your KEKs',
  _Step.send => 'Send the device its keys',
};

class _Cancelled implements Exception {}

class RemotePage extends StatefulWidget {
  const RemotePage({
    super.key,
    required this.flock,
    required this.name,
    required this.cathedral,
    this.mode,
    this.config,
  });

  final String flock;
  final String name;
  final String cathedral;
  final String? mode;
  final String Function(String device, int kek)? config;

  @override
  State<RemotePage> createState() => _RemotePageState();
}

class _RemotePageState extends State<RemotePage> {
  _Step _at = _Step.join;
  String? _failed;
  bool _running = false;
  bool _cancelled = false;
  bool _online = false;

  Cosk? _cosk;
  Registration? _self;
  int? _peer;
  List<String>? _words;
  Set<String> _before = const {};
  String? _device;

  Reliquary get _r => Reliquary.instance;

  bool get _computer => widget.config == null;

  @override
  void initState() {
    super.initState();
    _go();
  }

  @override
  void dispose() {
    _cancelled = true;
    _words = null;
    super.dispose();
  }

  Future<(int, int)> _cathedral() async {
    final at = widget.cathedral.lastIndexOf(':');
    if (at < 1) {
      throw ApiError('The cathedral ${widget.cathedral} has no port.');
    }

    final host = widget.cathedral.substring(0, at);
    final port = int.tryParse(widget.cathedral.substring(at + 1));

    if (port == null || port < 1 || port > 65535) {
      throw ApiError('The cathedral ${widget.cathedral} has no valid port.');
    }

    final List<InternetAddress> found;

    try {
      found = await InternetAddress.lookup(
        host,
        type: InternetAddressType.IPv4,
      );
    } on SocketException catch (_) {
      throw ApiError('Could not find the cathedral $host.');
    }

    if (found.isEmpty) {
      throw ApiError('The cathedral $host has no IPv4 address.');
    }

    var ip = 0;
    for (final b in found.first.rawAddress) {
      ip = (ip << 8) | b;
    }

    return (ip, port);
  }

  int? _next() {
    final used = {
      for (final d in _r.flock(widget.flock)?.devices ?? const <Device>[])
        if (d.approved) d.kek,
    };

    for (var kek = 1; kek < 256; kek++) {
      if (!used.contains(kek)) {
        return kek;
      }
    }

    return null;
  }

  void _step(_Step step) {
    if (_cancelled) {
      throw _Cancelled();
    }

    if (mounted) {
      setState(() => _at = step);
    }
  }

  Future<void> _go() async {
    _running = true;
    _failed = null;

    try {
      _step(_Step.join);

      final cathedral = await _cathedral();

      _cosk ??= await Core.instance.cosk();
      _self ??= await _r.api.deviceCreate(widget.flock, _cosk!.pk);

      final kek = await _r.approve(widget.flock, _self!.id);
      await _r.nameDevice(widget.flock, _self!.id, 'Covenant hand over');

      _step(_Step.words);

      _before = {
        for (final d in _r.flock(widget.flock)?.devices ?? const <Device>[])
          d.id,
      };

      _peer = _next();
      if (_peer == null) {
        throw ApiError('This flock is full, there is no room for the device.');
      }

      final words = await Core.instance.remoteWords(
        flock: widget.flock,
        identity: int.parse(_self!.id, radix: 16),
        cathedral: cathedral.$1,
        port: cathedral.$2,
        kek: kek,
        peer: _peer!,
      );

      if (mounted) {
        setState(() => _words = words.split(' '));
      }

      _device = await _joined();

      _step(_Step.approve);

      if (await _r.approve(widget.flock, _device!) != _peer) {
        throw ApiError('Reliquary gave the device another KEK ID, start over.');
      }

      _step(_Step.unlock);

      await Core.instance.remoteStart(
        flock: widget.flock,
        cosk: _cosk!,
        secret: _self!.secret,
        device: int.parse(_device!, radix: 16),
        config: widget.config?.call(_device!, _peer!),
      );

      _cosk = null;

      _step(_Step.send);

      await _send();
      await Core.instance.remoteStop();

      await _r.nameDevice(
        widget.flock,
        _device!,
        widget.name,
        mode: widget.mode,
      );

      await _leave();

      notify(
        _computer
            ? 'The computer has its KEK.'
            : 'The device has its keys, it can import them in Vigil.',
        warn: false,
      );

      _running = false;
      navigatorKey.currentState?.pop();
    } on _Cancelled {
      await _cleanup();
    } on CoreError catch (e) {
      await _fail(e.cancelled ? 'Your KEKs were not unlocked.' : e.message);
    } on ApiError catch (e) {
      await _fail(e.message);
    }
  }

  Future<String> _joined() async {
    while (true) {
      await Future<void>.delayed(const Duration(seconds: 3));

      if (_cancelled) {
        throw _Cancelled();
      }

      await _r.refreshFlock(widget.flock);

      final joined = [
        for (final d in _r.flock(widget.flock)?.devices ?? const <Device>[])
          if (!_before.contains(d.id)) d.id,
      ];

      if (joined.length > 1) {
        for (final id in joined) {
          await _r.deleteDevice(widget.flock, id);
        }

        throw ApiError(
          'More than one device joined the flock, they were removed again. '
          'Start over with new words.',
        );
      }

      if (joined.length == 1) {
        return joined.first;
      }
    }
  }

  Future<void> _send() async {
    final until = DateTime.now().add(const Duration(minutes: 10));

    while (true) {
      if (_cancelled) {
        throw _Cancelled();
      }

      final state = await Core.instance.remoteRun();
      if (state == 3) {
        return;
      }

      if (mounted && _online != (state == 2)) {
        setState(() => _online = state == 2);
      }

      if (DateTime.now().isAfter(until)) {
        throw ApiError(
          'The device did not connect in time. Check that it typed the '
          'words right and start over.',
        );
      }
    }
  }

  Future<void> _leave() async {
    final self = _self;
    if (self == null) {
      return;
    }

    _self = null;
    await _r.deleteDevice(widget.flock, self.id);
  }

  Future<void> _cleanup() async {
    _words = null;

    try {
      await Core.instance.remoteStop();

      final cosk = _cosk;
      if (cosk != null) {
        _cosk = null;
        await Core.instance.coskDrop(cosk.handle);
      }

      final device = _device;
      if (device != null) {
        _device = null;
        await _r.deleteDevice(widget.flock, device);
      }

      await _leave();
    } on ApiError catch (e) {
      notify('Could not clean up the flock: ${e.message}');
    } on CoreError catch (_) {}
  }

  Future<void> _fail(String message) async {
    await _cleanup();

    if (mounted) {
      setState(() {
        _running = false;
        _failed = message;
        _online = false;
      });
    }
  }

  Future<void> _stop() async {
    if (!_running) {
      navigatorKey.currentState?.pop();
      return;
    }

    final ok = await confirm(
      title: 'Cancel provisioning of this device',
      text: 'This will automatically remove the devices from the flock.',
      action: 'Stop',
    );

    if (ok) {
      _cancelled = true;
      _running = false;
      navigatorKey.currentState?.pop();
    }
  }

  Future<void> _again() async {
    setState(() {
      _at = _Step.join;
      _cancelled = false;
    });

    await _go();
  }

  @override
  Widget build(BuildContext context) {
    final words = _words;

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (popped, _) {
        if (!popped) {
          _stop();
        }
      },
      child: PushedPage(
        rubric: _computer ? 'Add a computer' : 'Add a device by words',
        title: widget.name,
        bottom: _failed != null
            ? BtnPair(
                first: Btn(
                  label: 'Cancel',
                  kind: BtnKind.secondary,
                  expand: true,
                  onTap: () => navigatorKey.currentState?.pop(),
                ),
                second: Btn(label: 'Try again', expand: true, onTap: _again),
              )
            : Btn(
                label: 'Stop',
                kind: BtnKind.secondary,
                expand: true,
                onTap: _stop,
              ),
        children: [
          _Progress(at: _at, failed: _failed, online: _online),
          if (_failed != null) Notice(kind: NoticeKind.warn, text: _failed!),
          if (words != null && _computer) ...[
            const Text(
              'Run these on the computer, cephas asks for the words below.',
              style: Styles.body,
            ),
            Pre.text(
              '\$ rlq flock join ${widget.flock}\n'
              '\$ rlq kek covenant ${widget.flock}',
            ),
          ],
          if (words != null && !_computer)
            const Text(
              'On the device open Vigil, choose to join with words and type '
              'in these words in this order.',
              style: Styles.body,
            ),
          if (words != null) ...[
            _Words(words: words),
            KeyList(
              rows: [
                ('Flock', widget.flock),
                ('KEK ID', hex(_peer ?? 0, prefix: false)),
              ],
            ),
          ],
          if (_at == _Step.send && _failed == null)
            const Notice(
              text:
                  'It can take up to a minute before Reliquary lets the '
                  'device and this phone reach each other.',
            ),
        ],
      ),
    );
  }
}

class _Words extends StatelessWidget {
  const _Words({required this.words});

  final List<String> words;

  @override
  Widget build(BuildContext context) {
    return Panel(
      accent: true,
      padding: const EdgeInsets.fromLTRB(16, 14, 16, 14),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final width = (constraints.maxWidth - 16) / 3;

          return Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              for (var i = 0; i < words.length; i++)
                SizedBox(
                  width: width,
                  child: Text.rich(
                    TextSpan(
                      children: [
                        TextSpan(
                          text: '${(i + 1).toString().padLeft(2)} ',
                          style: Styles.detail,
                        ),
                        TextSpan(text: words[i], style: Styles.value),
                      ],
                    ),
                  ),
                ),
            ],
          );
        },
      ),
    );
  }
}

class _Progress extends StatelessWidget {
  const _Progress({
    required this.at,
    required this.failed,
    required this.online,
  });

  final _Step at;
  final String? failed;
  final bool online;

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
                      step == _Step.send && step == at && online
                          ? 'Connected, sending the keys'
                          : _stepText(step),
                      style: Styles.body.copyWith(
                        color: step.index > at.index ? Palette.dim : Palette.fg,
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
    if (step.index > at.index) {
      return Liveness.off;
    }

    if (step.index < at.index) {
      return Liveness.online;
    }

    return Liveness.pending;
  }
}
