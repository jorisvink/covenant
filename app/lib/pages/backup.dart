import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/widgets.dart';

import '../app.dart';
import '../core.dart';
import '../reliquary.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/fields.dart';
import '../widgets/marks.dart';
import '../widgets/ui.dart';

Reliquary get _r => Reliquary.instance;

List<Widget> backupSection(Vault vault) {
  final backup = vault.backup;
  if (backup == null) {
    return const [];
  }

  final flocks = vault.flocks.values;
  final none = flocks.where((f) => f.backup == 'none').length;
  final pending = flocks.where((f) => f.backup == 'pending').length;
  final exported = flocks.where((f) => f.backup == 'exported').length;

  return [
    const GroupLabel('Backup', index: 2),
    if (!backup.key) ...[
      if (flocks.isNotEmpty)
        const Notice(
          kind: NoticeKind.warn,
          text:
              'Your KEKs are not backed up. If this phone breaks, every '
              'flock needs new KEKs and every device has to be set up again.',
        ),
      Btn(
        label: 'Make a recovery key',
        glyph: GlyphKind.shield,
        expand: true,
        onTap: () => _makeKey(replace: false),
      ),
    ] else ...[
      KeyList(
        rows: [
          ('Recovery key', 'On paper'),
          ('Folder', backup.folder ?? 'Not chosen'),
          ('Backed up', '$exported of ${flocks.length} flocks'),
        ],
      ),
      if (backup.folder == null)
        const Notice(
          kind: NoticeKind.warn,
          text:
              'Choose a folder for the backups. Until then they only exist '
              'on this phone, which does not help when it breaks.',
        )
      else if (pending > 0) ...[
        Notice(
          kind: NoticeKind.warn,
          text: pending == 1
              ? 'One backup is not in the backup folder yet.'
              : '$pending backups are not in the backup folder yet.',
        ),
        Btn(
          label: 'Write backups to the folder',
          glyph: GlyphKind.refresh,
          expand: true,
          onTap: _export,
        ),
      ],
      if (none > 0) ...[
        Notice(
          kind: NoticeKind.warn,
          text: none == 1
              ? 'One flock is not backed up.'
              : '$none flocks are not backed up.',
        ),
        Btn(
          label: 'Back up all flocks',
          glyph: GlyphKind.shield,
          expand: true,
          onTap: _backupAll,
        ),
      ],
      BtnPair(
        first: Btn(
          label: backup.folder == null ? 'Choose folder' : 'Change folder',
          kind: BtnKind.secondary,
          expand: true,
          onTap: _chooseFolder,
        ),
        second: Btn(
          label: 'Check key',
          kind: BtnKind.secondary,
          expand: true,
          onTap: () => push(const RecoveryCheckPage()),
        ),
      ),
      Btn(
        label: 'New recovery key',
        kind: BtnKind.ghost,
        expand: true,
        onTap: () => _makeKey(replace: true),
      ),
    ],
    Btn(
      label: 'Restore from a backup',
      glyph: GlyphKind.keys,
      kind: BtnKind.secondary,
      expand: true,
      onTap: () => push(const RestorePage()),
    ),
  ];
}

Future<void> _makeKey({required bool replace}) async {
  final ok = await confirm(
    title: replace ? 'New recovery key' : 'Make a recovery key',
    text: replace
        ? 'You get a new recovery key and every flock is backed up again '
              'for it, replacing the backups in the folder. The old recovery '
              'key still opens any old backup you copied elsewhere, destroy '
              'those and the old paper.'
        : 'You get a recovery key to write down. Your KEKs are backed up '
              'encrypted to it, this phone can make backups but never read '
              'them. With the recovery key and the backups you can bring '
              'your KEKs back on another phone.',
    action: replace ? 'Make new key' : 'Make key',
  );

  if (!ok) {
    return;
  }

  final Uint8List root;

  try {
    root = await wait('Making the recovery key', _r.backupKey);
  } on CoreError catch (e) {
    if (!e.cancelled) {
      notify(e.message);
    }
    return;
  }

  await push(RecoveryKeyPage(root: root));

  if (_r.vault?.backup?.folder == null) {
    await _chooseFolder();
  }
}

Future<void> _chooseFolder() async {
  try {
    final name = await _r.backupFolder();
    if (name != null) {
      notify('Backups go to $name.', warn: false);
    }
  } on CoreError catch (e) {
    notify(e.message);
  }
}

Future<void> _export() async {
  try {
    final count = await wait('Writing the backups', _r.backupExport);
    notify(
      count == 1 ? 'One backup written.' : '$count backups written.',
      warn: false,
    );
  } on CoreError catch (e) {
    notify(e.message);
  }
}

Future<void> _backupAll() async {
  try {
    await wait('Backing up your flocks', _r.backupAll);
    notify('All flocks are backed up.', warn: false);
  } on CoreError catch (e) {
    if (!e.cancelled) {
      notify(e.message);
    }
  }
}

String _groups(String hex) {
  final groups = [
    for (var i = 0; i < hex.length; i += 8) hex.substring(i, i + 8),
  ];

  return [
    for (var i = 0; i < groups.length; i += 2) '${groups[i]} ${groups[i + 1]}',
  ].join('\n');
}

class RecoveryKeyPage extends StatefulWidget {
  const RecoveryKeyPage({super.key, required this.root});

  final Uint8List root;

  @override
  State<RecoveryKeyPage> createState() => _RecoveryKeyPageState();
}

class _RecoveryKeyPageState extends State<RecoveryKeyPage> {
  bool _done = false;

  @override
  void dispose() {
    widget.root.fillRange(0, widget.root.length, 0);
    super.dispose();
  }

  Future<void> _finish() async {
    final ok = await confirm(
      title: 'Wrote it down?',
      text:
          'This is the only time you see it. Nobody can give it back to '
          'you, not this phone and not Reliquary. Without it the backups '
          'are useless.',
      action: 'I wrote it down',
    );

    if (ok) {
      setState(() => _done = true);
      navigatorKey.currentState?.pop();
    }
  }

  @override
  Widget build(BuildContext context) {
    final hex = [
      for (final b in widget.root) b.toRadixString(16).padLeft(2, '0'),
    ].join();

    return PopScope(
      canPop: _done,
      onPopInvokedWithResult: (popped, _) {
        if (!popped) {
          _finish();
        }
      },
      child: PushedPage(
        rubric: 'Backup',
        title: 'Your recovery key',
        bottom: Btn(label: 'Done', expand: true, onTap: _finish),
        children: [
          const Text(
            'Write this down on paper and keep it somewhere safe, away from '
            'the backup folder. Anyone with both can read your KEKs.',
            style: Styles.body,
          ),
          Pre(
            child: Text(
              _groups(hex),
              style: Styles.pre.copyWith(fontSize: 16, color: Palette.amber),
            ),
          ),
          const Notice(
            text:
                'Lost it? Make a new recovery key from the Keys tab, every '
                'backup is then made again for the new one.',
          ),
        ],
      ),
    );
  }
}

class RecoveryCheckPage extends StatefulWidget {
  const RecoveryCheckPage({super.key});

  @override
  State<RecoveryCheckPage> createState() => _RecoveryCheckPageState();
}

class _RecoveryCheckPageState extends State<RecoveryCheckPage> {
  final _key = TextEditingController();

  @override
  void dispose() {
    _key.dispose();
    super.dispose();
  }

  Future<void> _check() async {
    final root = recoveryKey(_key.text);
    if (root == null) {
      notify('A recovery key is 64 letters and digits, check it again.');
      return;
    }

    try {
      final ok = await _r.core.backupVerify(root);
      _key.clear();

      if (ok) {
        notify('That is your recovery key.', warn: false);
        navigatorKey.currentState?.pop();
      } else {
        notify('That is not the recovery key of this phone.');
      }
    } on CoreError catch (e) {
      notify(e.message);
    } finally {
      root.fillRange(0, root.length, 0);
    }
  }

  @override
  Widget build(BuildContext context) {
    return PushedPage(
      rubric: 'Backup',
      title: 'Check recovery key',
      bottom: Btn(label: 'Check', expand: true, onTap: _check),
      children: [
        const Text(
          'Type in the recovery key from your paper. This phone checks it '
          'without keeping it, so you know the paper is right before you '
          'need it.',
          style: Styles.body,
        ),
        Field(
          controller: _key,
          hint: 'The 64 letters and digits you wrote down',
          allow: RegExp(r'[0-9a-fA-F ]'),
          maxLength: 71,
          lines: 2,
        ),
      ],
    );
  }
}

class RestorePage extends StatefulWidget {
  const RestorePage({super.key});

  @override
  State<RestorePage> createState() => _RestorePageState();
}

class _RestorePageState extends State<RestorePage> {
  final _key = TextEditingController();

  List<BackupFile>? _found;
  String? _folder;

  @override
  void dispose() {
    _key.dispose();
    super.dispose();
  }

  Future<void> _pick() async {
    try {
      final name = await _r.backupFolder();
      if (name == null) {
        return;
      }

      final found = await wait('Looking for backups', _r.core.backupScan);
      setState(() {
        _folder = name;
        _found = found;
      });
    } on CoreError catch (e) {
      notify(e.message);
    }
  }

  Future<void> _restore() async {
    final root = recoveryKey(_key.text);
    if (root == null) {
      notify('A recovery key is 64 letters and digits, check it again.');
      return;
    }

    try {
      final r = await wait('Restoring your KEKs', () => _r.restore(root));
      _key.clear();

      final parts = [
        if (r.restored.isNotEmpty) '${_flocks(r.restored.length)} restored',
        if (r.skipped.isNotEmpty) '${_flocks(r.skipped.length)} already here',
        if (r.failed.isNotEmpty)
          '${_flocks(r.failed.length)} need another recovery key',
      ];

      notify('${parts.join(', ')}.', warn: r.failed.isNotEmpty);
      navigatorKey.currentState?.pop();
      unawaited(_r.refresh().catchError((_) {}));
    } on CoreError catch (e) {
      if (!e.cancelled) {
        notify(e.message);
      }
    } finally {
      root.fillRange(0, root.length, 0);
    }
  }

  String _flocks(int n) => n == 1 ? 'one flock' : '$n flocks';

  @override
  Widget build(BuildContext context) {
    final found = _found;
    final todo = found?.where((f) => !f.here).length ?? 0;

    return PushedPage(
      rubric: 'Backup',
      title: 'Restore KEKs',
      bottom: found == null
          ? Btn(label: 'Choose folder', expand: true, onTap: _pick)
          : Btn(
              label: 'Restore',
              expand: true,
              onTap: todo > 0 ? _restore : null,
            ),
      children: [
        const Text(
          'Bring back the KEKs of your flocks from their backups, with the '
          'recovery key you wrote down. Your devices keep working as they '
          'are, nothing needs to be set up again.',
          style: Styles.body,
        ),
        if (found == null)
          const Notice(
            text:
                'Choose the folder your backups were written to. It also '
                'becomes the backup folder of this phone.',
          )
        else ...[
          GroupLabel(
            'Backups in $_folder',
            trailing: Text('${found.length}', style: Styles.rubric),
          ),
          if (found.isEmpty)
            const Notice(
              kind: NoticeKind.warn,
              text: 'There are no backups in this folder.',
            )
          else
            KeyList(
              rows: [
                for (final f in found)
                  (f.flock, f.here ? 'Already here' : 'From ${date(f.made)}'),
              ],
            ),
          if (todo > 0) ...[
            const GroupLabel('Recovery key'),
            Field(
              controller: _key,
              hint: 'The 64 letters and digits you wrote down',
              allow: RegExp(r'[0-9a-fA-F ]'),
              maxLength: 71,
              lines: 2,
            ),
          ],
        ],
      ],
    );
  }
}
