import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../api.dart';
import '../app.dart';
import '../reliquary.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/fields.dart';
import '../widgets/marks.dart';
import '../widgets/ui.dart';

enum _Way { register, login }

class AccountPage extends StatefulWidget {
  const AccountPage({super.key});

  @override
  State<AccountPage> createState() => _AccountPageState();
}

class _AccountPageState extends State<AccountPage> {
  final _api = TextEditingController(text: defaultApi);
  final _key = TextEditingController();

  _Way _way = _Way.register;
  bool _other = false;

  Reliquary get _r => Reliquary.instance;

  @override
  void dispose() {
    _api.dispose();
    _key.dispose();
    super.dispose();
  }

  String? _apiUrl() {
    final url = _api.text.trim();
    final uri = Uri.tryParse(url);

    // Plain http only for a reliquary running on this very machine.
    final local = uri?.scheme == 'http' && uri?.host == '127.0.0.1';

    if (uri == null || (uri.scheme != 'https' && !local) || uri.host.isEmpty) {
      notify('The server address starts with https://, like $defaultApi.');
      return null;
    }

    return url;
  }

  Future<void> _register() async {
    final url = _apiUrl();
    if (url == null) {
      return;
    }

    final ok = await confirm(
      title: 'Create an account',
      text:
          'A new account lasts 24 hours, you can extend it from the '
          'Account tab at any time.\n\n'
          'You get an account key, a long code that is the only way to log '
          'back in. Write it down, it cannot be recovered.\n\n'
          'Reliquary may not be used for anything illegal, you alone are '
          'responsible for what you send with it.',
      action: 'Create',
    );

    if (!ok) {
      return;
    }

    try {
      final account = await wait(
        'Creating the account',
        () => _r.register(url),
      );
      push(AccountKeyPage(accountKey: account.key)).ignore();
    } on ApiError catch (e) {
      notify(e.message);
    }
  }

  Future<void> _login() async {
    final url = _apiUrl();
    if (url == null) {
      return;
    }

    final key = _key.text.replaceAll(RegExp(r'\s'), '').toLowerCase();
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(key)) {
      notify('An account key is 64 letters and digits, check it again.');
      return;
    }

    try {
      await wait('Logging in', () => _r.login(url, key));
      _key.clear();
      goTab(NavTab.flocks);
      notify('Logged in.', warn: false);
    } on ApiError catch (e) {
      notify(e.message);
    }
  }

  Future<void> _logout() async {
    final ok = await confirm(
      title: 'Log out',
      text:
          'You are about to logout, your account key is not stored in the app. '
          'Your encrypted keys remain on this phone, locked. Log in again with '
          'your account key to continue managing your flocks.',
      action: 'Log out',
    );

    if (ok) {
      await _r.logout();
    }
  }

  Future<void> _extend() async {
    final ok = await confirm(
      title: 'Extend the account',
      text:
          'Your account will last until 31 days from now. Your flocks and '
          'devices stay as they are.',
      action: 'Extend',
    );

    if (!ok) {
      return;
    }

    try {
      await wait('Extending the account', _r.extend);
      notify('Account extended.', warn: false);
    } on ApiError catch (e) {
      notify(e.message);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: _r,
      builder: (context, _) {
        final s = _r.session;

        return TabPage(
          index: 3,
          rubric: 'Account',
          title: s == null ? 'Welcome' : 'Your account',
          glow: s != null,
          children: s == null ? _signIn() : _account(s),
        );
      },
    );
  }

  List<Widget> _signIn() {
    return [
      const Text(
        'Reliquary connects your devices to each other privately, wherever '
        'they are. Everything is encrypted end to end with keys that never '
        'leave your devices, Reliquary cannot read any of it.',
        style: Styles.body,
      ),
      Choice<_Way>(
        options: const [(_Way.register, 'New account'), (_Way.login, 'Log in')],
        value: _way,
        onChanged: (w) => setState(() => _way = w),
      ),
      if (_way == _Way.login) ...[
        const GroupLabel('Account key'),
        Field(
          controller: _key,
          hint: 'The 64 letters and digits you wrote down',
          allow: RegExp(r'[0-9a-fA-F ]'),
          maxLength: 71,
          lines: 2,
        ),
      ],
      SwitchRow(
        text: 'Use a different Reliquary server',
        on: _other,
        onChanged: (v) => setState(() {
          _other = v;
          if (!v) {
            _api.text = defaultApi;
          }
        }),
      ),
      if (_other) ...[
        const GroupLabel('Server address'),
        Field(controller: _api, hint: defaultApi, keyboard: TextInputType.url),
      ],
      if (_way == _Way.login)
        Btn(label: 'Log in', expand: true, onTap: _login)
      else
        Btn(label: 'Create account', expand: true, onTap: _register),
    ];
  }

  List<Widget> _account(Session s) {
    final a = _r.account;
    final soon = a != null && a.left < const Duration(days: 3);

    return [
      StatGrid(
        tiles: [
          StatTile(
            label: 'Time left',
            value: a == null ? '–' : timeLeft(a.left),
            detail: a == null
                ? 'Not known yet'
                : a.expired
                ? 'Expired'
                : 'Until ${dateTime(a.expiry)}',
          ),
          StatTile(
            label: 'Flocks',
            value: a == null
                ? '${_r.flocks.length}'
                : '${_r.flocks.length}/${a.flocksMax}',
            detail: 'On this account',
          ),
        ],
      ),
      if (a != null && a.expired)
        const Notice(
          kind: NoticeKind.warn,
          text:
              'Your account has expired. Your devices cannot get new keys '
              'and you cannot manage your flocks until you extend it.',
        )
      else if (soon)
        const Notice(
          kind: NoticeKind.warn,
          text: 'Your account expires soon, extend it to keep using it.',
        ),
      Btn(
        label: 'Extend account',
        glyph: GlyphKind.refresh,
        kind: soon ? BtnKind.primary : BtnKind.secondary,
        expand: true,
        onTap: _extend,
      ),
      KeyList(rows: [('Server', Uri.parse(s.api).host)]),
      Btn(
        label: 'Log out',
        kind: BtnKind.secondary,
        expand: true,
        onTap: _logout,
      ),
    ];
  }
}

String timeLeft(Duration d) {
  if (d.inDays > 0) {
    return '${d.inDays}d ${d.inHours % 24}h';
  }

  return '${d.inHours}h ${d.inMinutes % 60}m';
}

/// Shows the account key once, right after registering.
class AccountKeyPage extends StatefulWidget {
  const AccountKeyPage({super.key, required this.accountKey});

  final String accountKey;

  @override
  State<AccountKeyPage> createState() => _AccountKeyPageState();
}

class _AccountKeyPageState extends State<AccountKeyPage> {
  bool _done = false;
  Timer? _clear;

  void _copy() {
    Clipboard.setData(ClipboardData(text: widget.accountKey));
    notify('Copied, the clipboard is cleared in a minute.', warn: false);

    _clear?.cancel();
    _clear = Timer(const Duration(minutes: 1), () async {
      final now = await Clipboard.getData(Clipboard.kTextPlain);
      if (now?.text == widget.accountKey) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    });
  }

  Future<void> _finish() async {
    final ok = await confirm(
      title: 'Saved it?',
      text:
          'Nobody can give this key back to you if you lose it, not this '
          'app and not Reliquary.',
      action: 'I saved it',
    );

    if (ok) {
      setState(() => _done = true);
      goTab(NavTab.flocks);
    }
  }

  @override
  Widget build(BuildContext context) {
    final key = widget.accountKey;
    final groups = [
      for (var i = 0; i < key.length; i += 8) key.substring(i, i + 8),
    ];

    return PopScope(
      canPop: _done,
      onPopInvokedWithResult: (popped, _) {
        if (!popped) {
          _finish();
        }
      },
      child: PushedPage(
        rubric: 'Registered',
        title: 'Your account key',
        bottom: BtnPair(
          first: Btn(
            label: 'Copy',
            glyph: GlyphKind.copy,
            kind: BtnKind.secondary,
            expand: true,
            onTap: _copy,
          ),
          second: Btn(label: 'Done', expand: true, onTap: _finish),
        ),
        children: [
          const Text(
            'Write this down and keep it somewhere safe, like a password '
            'manager. You need it to log in again or on another phone.',
            style: Styles.body,
          ),
          Pre(
            child: SelectableText(
              [
                for (var i = 0; i < groups.length; i += 2)
                  '${groups[i]} ${groups[i + 1]}',
              ].join('\n'),
              style: Styles.pre.copyWith(fontSize: 16, color: Palette.amber),
            ),
          ),
          const Notice(
            kind: NoticeKind.warn,
            text:
                'Your account lasts 24 hours, extend it from the Account tab '
                'to keep it.',
          ),
        ],
      ),
    );
  }
}
