// The bridge to the native side. Kotlin and Swift keep the vault key
// behind the secure hardware of the phone and hand it to the C core for
// a single operation, we never get to see a KEK in here.

import 'dart:convert';

import 'package:flutter/services.dart';

class CoreError implements Exception {
  CoreError(this.code, this.message);

  final String code;
  final String message;

  /// The user backed out of unlocking the vault.
  bool get cancelled => code == 'cancelled';

  @override
  String toString() => message;
}

/// Where the vault key lives, from strongest to weakest.
enum Hardware { strongbox, secureEnclave, tee, software, none }

class Vault {
  Vault(this.json);

  final Map<String, dynamic> json;

  /// The vault key exists, flocks can have KEKs.
  bool get ready => json['ready'] as bool? ?? false;

  /// The vault key cannot be opened anymore, the lock screen went away.
  bool get invalidated => json['invalidated'] as bool? ?? false;

  Hardware get hardware => switch (json['hardware'] as String? ?? 'none') {
    'strongbox' => Hardware.strongbox,
    'secure-enclave' => Hardware.secureEnclave,
    'tee' => Hardware.tee,
    'software' => Hardware.software,
    _ => Hardware.none,
  };

  String get hardwareName => switch (hardware) {
    Hardware.strongbox => 'Security chip',
    Hardware.secureEnclave => 'Secure Enclave',
    Hardware.tee => 'Secure hardware',
    Hardware.software => 'No secure hardware',
    Hardware.none => 'Not set up yet',
  };

  /// What protects the vault key besides the hardware.
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

/// The sealed KEKs of a flock as stored on this phone.
class KekSet {
  KekSet(this.json);

  final Map<String, dynamic> json;

  String get flock => json['flock'] as String;

  DateTime get created =>
      DateTime.fromMillisecondsSinceEpoch((json['created'] as int) * 1000);

  /// none, pending or exported.
  String get backup => json['backup'] as String? ?? 'none';
}

class BackupState {
  BackupState(this.json);

  final Map<String, dynamic> json;

  bool get key => json['key'] as bool? ?? false;

  String? get folder => json['folder'] as String?;
}

/// A backup found in the backup folder.
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

/// The recovery key as the user typed it, null when it is not one.
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

/// A fresh ambry bundle, safe to hand to the reliquary.
class Bundle {
  Bundle(this.data, this.generation, this.expires);

  final Uint8List data;
  final int generation;

  /// Days since the ambry epoch, see SANCTUM_AMBRY_AGE_EPOCH.
  final int expires;

  DateTime get expiry => ambryDay(expires);
}

const _ambryEpoch = 1697855580;

DateTime ambryDay(int day) =>
    DateTime.fromMillisecondsSinceEpoch((_ambryEpoch + day * 86400) * 1000);

/// A cosk pair waiting in the C library for its device to be registered.
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

/// The COVENANT_ERROR_* codes from include/covenant.h.
String _coreError(int code) => switch (code) {
  1 => 'The phone ran out of memory, try again.',
  2 => 'Something was not filled in correctly.',
  4 => 'Something went wrong, try again.',
  5 => 'The keys on this phone are damaged and cannot be opened.',
  6 => 'The keys on this phone were saved by a newer version of this app.',
  7 => 'The device settings are not valid.',
  8 => 'The device settings are not valid.',
  9 => 'The device settings are for another flock.',
  10 => 'The device settings do not match its key.',
  11 => 'Adding this device took too long, start over.',
  12 => 'Too many devices are being added at once.',
  13 => 'The device settings are too long for a QR code.',
  14 => 'This recovery key does not open these backups.',
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

  /// New KEKs for the flock and the first ambry bundle made from them.
  Future<Bundle> generate(String flock, int days) =>
      _bundle('keksGenerate', {'flock': flock, 'days': days});

  /// Renew the KEK of one device and bundle the flock again.
  Future<Bundle> renew(String flock, int kek, int days) =>
      _bundle('keksRenew', {'flock': flock, 'kek': kek, 'days': days});

  /// A new ambry bundle from the KEKs we already have.
  Future<Bundle> bundle(String flock, int days) =>
      _bundle('bundle', {'flock': flock, 'days': days});

  Future<void> forget(String flock) => _call<String>('keksDelete', flock);

  Future<void> wipe() => _call<String>('vaultWipe');

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

    // What the channel hands us is read only, keep a copy we can wipe.
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

  /// A new recovery key, the caller wipes it.
  Future<Uint8List> backupKey() async =>
      Uint8List.fromList(await _call<Uint8List>('backupKey') ?? Uint8List(0));

  Future<void> backupAll() => _call<String>('backupAll');

  /// The name of the folder the user picked, null when they backed out.
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

  Future<void> reminders(List<Map<String, Object>> reminders) =>
      _call<String>('reminders', reminders);

  Future<void> remindersAllow() => _call<String>('remindersAllow');

  Future<String?> remindedFlock() async {
    final flock = await _call<String>('remindedFlock');
    return flock == null || flock.isEmpty ? null : flock;
  }

  Future<Map<String, dynamic>?> session() async {
    final raw = await _call<String>('session');
    return raw == null ? null : jsonDecode(raw) as Map<String, dynamic>;
  }

  Future<void> sessionSave(Map<String, dynamic> session) =>
      _call<String>('sessionSave', jsonEncode(session));

  Future<void> sessionClear() => _call<String>('sessionClear');

  /// Bookkeeping that is not secret, which bundle went up and when.
  Future<Map<String, dynamic>> prefs() async =>
      jsonDecode(await _call<String>('prefs') ?? '{}') as Map<String, dynamic>;

  Future<void> prefsSave(Map<String, dynamic> prefs) =>
      _call<String>('prefsSave', jsonEncode(prefs));

  Future<String> version() async => await _call<String>('version') ?? '-';
}
