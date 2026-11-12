import 'dart:io';

import 'package:flutter/widgets.dart';

import '../app.dart';
import '../core.dart';
import '../platform.dart';
import '../reliquary.dart';
import '../theme.dart';
import '../widgets/buttons.dart';
import '../widgets/marks.dart';
import '../widgets/ui.dart';
import 'backup.dart';
import 'flock.dart';

class KeysPage extends StatelessWidget {
  const KeysPage({super.key});

  Future<void> _wipe() async {
    final ok = await confirm(
      title: 'Wipe all KEKs',
      text:
          'Every KEK on this $here is destroyed. Your devices keep working '
          'until their encrypted secrets expire, after that each flock has '
          'to be set up again. This cannot be undone.',
      action: 'Wipe',
    );

    if (!ok) {
      return;
    }

    try {
      await Reliquary.instance.wipe();
      notify('All KEKs are wiped.', warn: false);
    } on CoreError catch (e) {
      notify(e.message);
    }
  }

  Future<void> _import(Future<String> Function() work) async {
    final r = Reliquary.instance;

    try {
      final flock = await wait('Importing the KEKs', work);
      notify('The KEKs of ${r.flockLabel(flock)} are imported.', warn: false);
    } on CoreError catch (e) {
      if (!e.cancelled) {
        notify(e.message);
      }
    }
  }

  Future<void> _passphrase() async {
    try {
      await wait('Changing the passphrase', Core.instance.passphraseChange);
      notify('Your passphrase is changed.', warn: false);
    } on CoreError catch (e) {
      if (!e.cancelled) {
        notify(e.message);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final r = Reliquary.instance;

    return ListenableBuilder(
      listenable: r,
      builder: (context, _) {
        final vault = r.vault;
        final flocks = vault?.flocks.values.toList() ?? const <KekSet>[];
        final hardware = vault?.hardware ?? Hardware.none;
        final strong =
            hardware == Hardware.strongbox ||
            hardware == Hardware.secureEnclave;

        return TabPage(
          index: 2,
          rubric: 'Keys',
          title: 'Your KEKs',
          glow: vault?.ready == true && strong,
          children: [
            Panel(
              accent: vault?.ready == true && hardware != Hardware.software,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      StateDot(
                        vault?.ready != true
                            ? Liveness.off
                            : hardware == Hardware.software ||
                                  vault!.invalidated
                            ? Liveness.pending
                            : Liveness.online,
                      ),
                      const SizedBox(width: 10),
                      Rubric(text: desktop ? 'Protection' : 'Vault'),
                    ],
                  ),
                  const SizedBox(height: 14),
                  Text(
                    vault == null
                        ? '…'
                        : vault.ready
                        ? vault.hardwareName
                        : 'Not created yet',
                    style: Styles.state,
                  ),
                  const SizedBox(height: 8),
                  Text(_explain(vault), style: Styles.body),
                ],
              ),
            ),
            if (vault?.invalidated ?? false)
              const Notice(
                kind: NoticeKind.warn,
                text:
                    'The screen lock of this phone was changed or removed, '
                    'so the KEKs on it can never be opened again. Wipe them '
                    'and set up the KEKs of your flocks again.',
              ),
            if (hardware == Hardware.software)
              const Notice(
                kind: NoticeKind.warn,
                text:
                    'This phone has no secure hardware to protect your KEKs. '
                    'They are still encrypted, but much easier to steal.',
              ),
            GroupLabel(
              'Flocks with KEKs here',
              index: 1,
              trailing: Text('${flocks.length}', style: Styles.rubric),
            ),
            if (flocks.isEmpty)
              Notice(text: 'No flocks with KEKs on this $here yet')
            else ...[
              if (r.session == null)
                const Notice(text: 'Log in to manage these flocks.'),
              LinkList(
                rows: [
                  for (final f in flocks)
                    LinkRow(
                      r.flockLabel(f.flock),
                      r.session == null
                          ? null
                          : () => push(FlockPage(id: f.flock)),
                      detail: vault?.backup?.key == true
                          ? 'Since ${date(f.created)} · ${_backup(f)}'
                          : 'Since ${date(f.created)}',
                    ),
                ],
              ),
            ],
            if (vault != null && !desktop) ...backupSection(vault),
            if (desktop) ...[
              const GroupLabel('Import KEKs', index: 2),
              LinkList(
                rows: [
                  LinkRow(
                    'From an ambry directory',
                    () => _import(r.importAmbry),
                    detail: 'The flock folder generated by ambry generate',
                  ),
                  LinkRow(
                    'From a phone backup',
                    () => _import(r.importBackup),
                    detail: 'A .rlqb backup and in combination with its '
                            'recovery key',
                  ),
                ],
              ),
              if (vault?.ready ?? false) ...[
                const GroupLabel('Passphrase', index: 3),
                LinkList(
                  rows: [
                    LinkRow(
                      'Change passphrase',
                      _passphrase,
                    ),
                  ],
                ),
              ],
            ],
            if (vault?.ready ?? false) ...[
              const SizedBox(height: 4),
              Btn(
                label: 'Wipe all KEKs',
                glyph: GlyphKind.trash,
                kind: BtnKind.secondary,
                expand: true,
                onTap: _wipe,
              ),
            ],
          ],
        );
      },
    );
  }

  String _backup(KekSet f) => switch (f.backup) {
    'exported' => 'backed up',
    'pending' => 'backup not in folder',
    _ => 'not backed up',
  };

  String _explain(Vault? vault) {
    if (vault == null) {
      return '';
    }

    if (desktop && !vault.ready) {
      return 'The Key-Encryption-Keys (KEKs) of your flocks are kept in '
          '~/.config/covenant, encrypted under a key that is locked with '
          'your passphrase. You choose the passphrase the first time you '
          'set up a flock, it cannot be recovered.';
    }

    if (desktop) {
      return 'The Key-Encryption-Keys (KEKs) of your flocks are kept in '
          '~/.config/covenant, encrypted under a key that is locked with '
          'your passphrase. Every use asks for it. To back up your KEKs, '
          'copy that folder somewhere safe.';
    }

    if (!vault.ready) {
      return 'The Key-Encryption-Keys (KEKs) of your flocks are locked in a '
          'vault on this phone. It is made the first time you set up a flock '
          'and never leaves the phone, only backups encrypted to your '
          'recovery key do.';
    }

    if (vault.hardware == Hardware.software) {
      return 'The Key-Encryption-Keys (KEKs) of your flocks are locked in a '
          'vault on this phone. Every use asks for your fingerprint, face or '
          'PIN. Backups are encrypted to your recovery key.';
    }

    return Platform.isIOS
        ? 'The Key-Encryption-Keys (KEKs) of your flocks are locked in a '
              'vault guarded by the Secure Enclave of this phone. Every use '
              'asks for Face ID, Touch ID or your passcode. Backups are '
              'encrypted to your recovery key.'
        : 'The Key-Encryption-Keys (KEKs) of your flocks are locked in a '
              'vault guarded by the secure hardware of this phone. Every use '
              'asks for your fingerprint, face or PIN. Backups are encrypted '
              'to your recovery key.';
  }
}
