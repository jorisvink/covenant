import 'dart:convert';

import 'package:flutter/services.dart';

import 'platform.dart';

class CoreError implements Exception {
  CoreError(this.code, this.message);

  final String code;
  final String message;

  bool get cancelled => code == 'cancelled';

  @override
  String toString() => message;
}

enum Hardware { strongbox, secureEnclave, tee, software, passphrase, none }

class Vault {
  Vault(this.json);

  final Map<String, dynamic> json;

  bool get ready => json['ready'] as bool? ?? false;

  bool get invalidated => json['invalidated'] as bool? ?? false;

  Hardware get hardware => switch (json['hardware'] as String? ?? 'none') {
    'strongbox' => Hardware.strongbox,
    'secure-enclave' => Hardware.secureEnclave,
    'tee' => Hardware.tee,
    'software' => Hardware.software,
    'passphrase' => Hardware.passphrase,
    _ => Hardware.none,
  };

  String get hardwareName => switch (hardware) {
    Hardware.strongbox => 'Security chip',
    Hardware.secureEnclave => 'Secure Enclave',
    Hardware.tee => 'Secure hardware',
    Hardware.software => 'No secure hardware',
    Hardware.passphrase => 'Passphrase',
    Hardware.none => 'Not set up yet',
  };

  String get auth => json['auth'] as String? ?? '';

  BackupState? get backup {
    final b = json['backup'];
    return b is Map<String, dynamic> ? BackupState(b) : null;
  }

  Map<String, KekSet> get flocks {
    final out = <String, KekSet>{};
    final list = json['flocks'] as List<dynamic>? ?? const [];

    for (final f in list.cast<Map<String, dynamic>>()) {
      final set = KekSet(f);
      out[set.flock] = set;
    }

    return out;
  }
}

class KekSet {
  KekSet(this.json);

  final Map<String, dynamic> json;

  String get flock => json['flock'] as String;

  DateTime get created =>
      DateTime.fromMillisecondsSinceEpoch((json['created'] as int) * 1000);

  String get backup => json['backup'] as String? ?? 'none';
}

class BackupState {
  BackupState(this.json);

  final Map<String, dynamic> json;

  bool get key => json['key'] as bool? ?? false;

  String? get folder => json['folder'] as String?;
}

class BackupFile {
  BackupFile(this.json);

  final Map<Object?, Object?> json;

  String get flock => json['flock'] as String;

  bool get here => json['here'] as bool? ?? false;

  DateTime get made =>
      DateTime.fromMillisecondsSinceEpoch((json['made'] as int) * 1000);

  DateTime get created =>
      DateTime.fromMillisecondsSinceEpoch((json['created'] as int) * 1000);
}

class Restored {
  Restored(this.json);

  final Map<Object?, Object?> json;

  List<String> _list(String key) =>
      (json[key] as List<Object?>? ?? const []).cast<String>();

  List<String> get restored => _list('restored');
  List<String> get skipped => _list('skipped');
  List<String> get failed => _list('failed');
}

Uint8List? recoveryKey(String text) {
  final hex = text.replaceAll(RegExp(r'\s'), '').toLowerCase();
  if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(hex)) {
    return null;
  }

  return Uint8List.fromList([
    for (var i = 0; i < hex.length; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16),
  ]);
}

class Bundle {
  Bundle(this.data, this.generation, this.expires);

  final Uint8List data;
  final int generation;

  final int expires;

  DateTime get expiry => ambryDay(expires);
}

const _ambryEpoch = 1697855580;

DateTime ambryDay(int day) =>
    DateTime.fromMillisecondsSinceEpoch((_ambryEpoch + day * 86400) * 1000);

class Cosk {
  Cosk(this.handle, this.pk);

  final int handle;
  final Uint8List pk;
}

class QrCode {
  QrCode(this.side, this.modules);

  final int side;
  final Uint8List modules;

  bool dark(int x, int y) => modules[y * side + x] != 0;

  void wipe() => modules.fillRange(0, modules.length, 0);
}

String _coreError(int code) => switch (code) {
  1 => 'The $here ran out of memory, try again.',
  2 => 'Something was not filled in correctly.',
  4 => 'Something went wrong, try again.',
  5 => 'The KEKs on this $here are damaged and cannot be opened.',
  6 => 'The KEKs on this $here were saved by a newer version of this app.',
  7 => 'The device settings are not valid.',
  8 => 'The device settings are not valid.',
  9 => 'The device settings are for another flock.',
  10 => 'The device settings do not match its KEK.',
  11 => 'Adding this device took too long, start over.',
  12 => 'Too many devices are being added at once.',
  13 => 'The device settings are too long for a QR code.',
  14 => 'This recovery key does not open these backups.',
  15 => 'The secret words for the device are gone, start over.',
  16 => 'The device did not answer the way it should, start over.',
  17 => 'That passphrase does not unlock your KEKs.',
  _ => 'Something went wrong ($code).',
};

class Core {
  Core._();

  static final Core instance = Core._();

  static const _channel = MethodChannel('se.sanctorum.reliquary/core');

  Future<T?> _call<T>(String method, [Object? arg]) async {
    try {
      return await _channel.invokeMethod<T>(method, arg);
    } on PlatformException catch (e) {
      if (e.code == 'core' && e.details is int) {
        throw CoreError(e.code, _coreError(e.details as int));
      }

      throw CoreError(e.code, e.message ?? e.code);
    }
  }

  Future<Vault> vault() async =>
      Vault(jsonDecode(await _call<String>('vault') ?? '{}'));

  Future<Bundle> _bundle(String method, Map<String, Object?> args) async {
    final r = await _call<Map<Object?, Object?>>(method, args);

    return Bundle(
      r!['bundle'] as Uint8List,
      r['generation'] as int,
      r['expires'] as int,
    );
  }

  Future<Bundle> generate(String flock, int days) =>
      _bundle('keksGenerate', {'flock': flock, 'days': days});

  Future<Bundle> renew(String flock, int kek, int days) =>
      _bundle('keksRenew', {'flock': flock, 'kek': kek, 'days': days});

  Future<Bundle> bundle(String flock, int days) =>
      _bundle('bundle', {'flock': flock, 'days': days});

  Future<void> forget(String flock) => _call<String>('keksDelete', flock);

  Future<void> wipe() => _call<String>('vaultWipe');

  Future<String> importAmbry() async =>
      await _call<String>('importAmbry') ?? '';

  Future<String> importBackup() async =>
      await _call<String>('importBackup') ?? '';

  Future<void> passphraseChange() => _call<String>('passphraseChange');

  Future<Cosk> cosk() async {
    final r = await _call<Map<Object?, Object?>>('coskNew');
    return Cosk(r!['handle'] as int, r['pk'] as Uint8List);
  }

  Future<void> coskDrop(int handle) => _call<String>('coskDrop', handle);

  /// Unlock the vault and turn the device into a QR code. The config
  /// is the public part, the C library adds the keys.
  Future<QrCode> provision({
    required String flock,
    required int kek,
    required Cosk cosk,
    required String secret,
    required String config,
  }) async {
    final r = await _call<Map<Object?, Object?>>('provision', {
      'flock': flock,
      'kek': kek,
      'handle': cosk.handle,
      'secret': secret,
      'config': config,
    });

    return QrCode(
      r!['side'] as int,
      Uint8List.fromList(r['modules'] as Uint8List),
    );
  }

  Future<bool> handoffAvailable() async =>
      await _call<bool>('handoffAvailable') ?? false;

  Future<void> handoff({
    required String flock,
    required int kek,
    required Cosk cosk,
    required String secret,
    required String config,
  }) => _call<String>('handoff', {
    'flock': flock,
    'kek': kek,
    'handle': cosk.handle,
    'secret': secret,
    'config': config,
  });

  Future<String> remoteWords({
    required String flock,
    required int identity,
    required int cathedral,
    required int port,
    required int kek,
    required int peer,
  }) async =>
      await _call<String>('remoteWords', {
        'flock': flock,
        'identity': identity,
        'cathedral': cathedral,
        'port': port,
        'kek': kek,
        'peer': peer,
      }) ??
      '';

  Future<void> remoteStart({
    required String flock,
    required Cosk cosk,
    required String secret,
    required int device,
    String? config,
  }) => _call<String>('remoteStart', {
    'flock': flock,
    'handle': cosk.handle,
    'secret': secret,
    'device': device,
    'config': config,
  });

  Future<int> remoteRun() async => await _call<int>('remoteRun') ?? -1;

  Future<void> remoteStop() => _call<String>('remoteStop');

  Future<Uint8List> backupKey() async =>
      Uint8List.fromList(await _call<Uint8List>('backupKey') ?? Uint8List(0));

  Future<void> backupAll() => _call<String>('backupAll');

  Future<String?> backupFolder() => _call<String>('backupFolder');

  Future<int> backupExport() async => await _call<int>('backupExport') ?? 0;

  Future<bool> backupVerify(Uint8List root) async =>
      await _call<bool>('backupVerify', root) ?? false;

  Future<List<BackupFile>> backupScan() async {
    final r = await _call<List<Object?>>('backupScan') ?? const [];
    return [for (final f in r) BackupFile(f as Map<Object?, Object?>)];
  }

  Future<Restored> backupRestore(Uint8List root) async =>
      Restored(await _call<Map<Object?, Object?>>('backupRestore', root) ?? {});

  Future<void> reminders(List<Map<String, Object>> reminders) async {
    if (desktop) {
      return;
    }

    await _call<String>('reminders', reminders);
  }

  Future<void> remindersAllow() async {
    if (desktop) {
      return;
    }

    await _call<String>('remindersAllow');
  }

  Future<String?> remindedFlock() async {
    if (desktop) {
      return null;
    }

    final flock = await _call<String>('remindedFlock');
    return flock == null || flock.isEmpty ? null : flock;
  }

  static const _sessionFiles = ['api', 'token', 'cathedral', 'natport'];

  Future<Map<String, dynamic>?> session() async {
    if (!desktop) {
      final raw = await _call<String>('session');
      return raw == null ? null : jsonDecode(raw) as Map<String, dynamic>;
    }

    final session = <String, dynamic>{};

    for (final name in _sessionFiles) {
      final value = await _call<String>('fileRead', name);
      if (value == null) {
        return null;
      }

      session[name] = value.trim();
    }

    return session;
  }

  Future<void> sessionSave(Map<String, dynamic> session) async {
    if (!desktop) {
      await _call<String>('sessionSave', jsonEncode(session));
      return;
    }

    for (final name in _sessionFiles) {
      await _call<String>('fileWrite', {
        'name': name,
        'data': '${session[name]}\n',
      });
    }
  }

  Future<void> sessionClear() async {
    if (!desktop) {
      await _call<String>('sessionClear');
      return;
    }

    for (final name in _sessionFiles) {
      await _call<String>('fileDelete', name);
    }
  }

  Future<Map<String, dynamic>> prefs() async {
    String? raw;

    if (desktop) {
      raw = await _call<String>('fileRead', 'prefs');
    } else {
      raw = await _call<String>('prefs');
    }

    return jsonDecode(raw ?? '{}') as Map<String, dynamic>;
  }

  Future<void> prefsSave(Map<String, dynamic> prefs) async {
    if (!desktop) {
      await _call<String>('prefsSave', jsonEncode(prefs));
      return;
    }

    await _call<String>('fileWrite', {
      'name': 'prefs',
      'data': jsonEncode(prefs),
    });
  }

  Future<String> version() async => await _call<String>('version') ?? '-';
}
