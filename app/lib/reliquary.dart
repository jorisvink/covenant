import 'dart:async';

import 'package:flutter/foundation.dart';

import 'api.dart';
import 'core.dart';
import 'platform.dart';

class AmbryNote {
  AmbryNote(this.json);

  final Map<String, dynamic> json;

  int get generation => json['generation'] as int? ?? 0;
  int get expires => json['expires'] as int? ?? 0;
  bool get uploaded => json['uploaded'] as bool? ?? false;

  DateTime get expiry => ambryDay(expires);

  DateTime get made =>
      DateTime.fromMillisecondsSinceEpoch(json['made'] as int? ?? 0);

  int get daysLeft => expiry.difference(DateTime.now()).inDays;

  bool get expired => !expiry.isAfter(DateTime.now());

  String get generationHex =>
      '0x${generation.toRadixString(16).padLeft(8, '0')}';
}

class Work {
  Work(this.flock, this.step, [this.progress]);

  final String flock;
  final String step;
  final double? progress;
}

class Flock {
  Flock(this.id);

  final String id;

  List<Device>? devices;
  String? problem;

  int get approved => devices?.where((d) => d.approved).length ?? 0;
  int get pending => devices?.where((d) => !d.approved).length ?? 0;

  Device? byKek(int kek) {
    for (final d in devices ?? const <Device>[]) {
      if (d.approved && d.kek == kek) {
        return d;
      }
    }

    return null;
  }
}

class Reliquary extends ChangeNotifier {
  Reliquary._();

  static final Reliquary instance = Reliquary._();

  final Core core = Core.instance;

  Session? session;
  Vault? vault;
  Map<String, dynamic> _prefs = {};

  List<Flock> flocks = [];
  List<String>? cathedrals;
  AccountInfo? account;

  Work? work;
  double? loaded;

  bool started = false;
  bool loading = false;
  String? problem;

  Api get api {
    final s = session;
    if (s == null) {
      throw ApiError('You are not logged in.');
    }

    return Api(s);
  }

  Flock? flock(String id) {
    for (final f in flocks) {
      if (f.id == id) {
        return f;
      }
    }

    return null;
  }

  bool hasKeks(String flock) => vault?.flocks.containsKey(flock) ?? false;

  bool external(String id) => !hasKeks(id) && (flock(id)?.approved ?? 0) > 0;

  KekSet? keks(String flock) => vault?.flocks[flock];

  AmbryNote? ambry(String flock) {
    final notes = _prefs['ambry'] as Map<String, dynamic>? ?? const {};
    final note = notes[flock] as Map<String, dynamic>?;

    return note == null ? null : AmbryNote(note);
  }

  String? deviceName(String flock, String device) {
    final names = _prefs['names'] as Map<String, dynamic>? ?? const {};
    return names['$flock/$device'] as String?;
  }

  String? deviceMode(String flock, String device) {
    final modes = _prefs['modes'] as Map<String, dynamic>? ?? const {};
    return modes['$flock/$device'] as String?;
  }

  Future<void> nameDevice(
    String flock,
    String device,
    String name, {
    String? mode,
  }) async {
    await _names((names) => names['$flock/$device'] = name);

    if (mode != null) {
      await _map('modes', (modes) => modes['$flock/$device'] = mode);
    }
  }

  String? flockName(String flock) {
    final names = _prefs['names'] as Map<String, dynamic>? ?? const {};
    return names[flock] as String?;
  }

  String flockLabel(String flock) => flockName(flock) ?? flock;

  Future<void> nameFlock(String flock, String name) async {
    await _names((names) {
      if (name.isEmpty) {
        names.remove(flock);
      } else {
        names[flock] = name;
      }
    });

    await _remind();
  }

  Future<void> start() async {
    try {
      final saved = await core.session();
      session = saved == null ? null : Session.fromJson(saved);
      _prefs = await core.prefs();
      vault = await core.vault();

      if (session != null) {
        flocks = _cached();
      }
    } on CoreError catch (e) {
      problem = e.message;
    }

    started = true;
    notifyListeners();

    unawaited(_remind());

    if (session != null) {
      unawaited(refresh().catchError((_) {}));
    }
  }

  Future<void> reloadVault() async {
    vault = await core.vault();
    notifyListeners();
  }

  Future<void> refresh() async {
    if (session == null) {
      return;
    }

    loading = true;
    loaded = null;
    notifyListeners();

    try {
      try {
        account = await api.account();
      } on ApiError {
        account = null;
      }

      final ids = await api.flocks();
      final known = {for (final f in flocks) f.id: f};
      final next = [for (final id in ids) known[id] ?? Flock(id)];

      var done = 0;
      loaded = 0;
      notifyListeners();

      await Future.wait([
        for (final f in next)
          _devices(f).then((_) {
            loaded = ++done / next.length;
            notifyListeners();
          }),
      ]);

      flocks = next;
      problem = null;
      await _cache();
    } on ApiError catch (e) {
      problem = e.message;
      rethrow;
    } finally {
      loading = false;
      loaded = null;
      notifyListeners();
    }
  }

  Future<void> refreshFlock(String id) async {
    final f = flock(id);
    if (f == null) {
      return;
    }

    await _devices(f);
    await _cache();
    notifyListeners();
  }

  Future<void> _devices(Flock f) async {
    try {
      f.devices = await api.devices(f.id);
      f.problem = null;
    } on ApiError catch (e) {
      f.problem = e.message;
    }
  }

  Future<List<String>> loadCathedrals() async {
    cathedrals ??= await api.cathedrals();
    return cathedrals!;
  }

  Future<void> extend() async {
    await api.accountTime();
    account = await api.account();
    notifyListeners();

    if (problem != null) {
      await refresh();
    }
  }

  Future<Account> register(String apiUrl) async {
    final account = await Api.register(apiUrl);
    await _begin(account.session);
    return account;
  }

  Future<void> login(String apiUrl, String key) async {
    await _begin(await Api.login(apiUrl, key));
  }

  Future<void> _begin(Session s) async {
    await core.sessionSave(s.toJson());

    session = s;
    flocks = [];
    account = null;
    cathedrals = null;
    problem = null;
    notifyListeners();

    await refresh();
  }

  Future<void> logout() async {
    await core.sessionClear();

    session = null;
    flocks = [];
    account = null;
    cathedrals = null;
    problem = null;
    await _cache();
    notifyListeners();
  }

  Future<String> createFlock() async {
    final id = await api.flockCreate();

    flocks = [...flocks, Flock(id)..devices = []];
    await _cache();
    notifyListeners();

    return id;
  }

  Future<void> deleteFlock(String id) async {
    _manage(id);
    await api.flockDelete(id);

    if (hasKeks(id)) {
      await core.forget(id);
      await reloadVault();
    }

    flocks = [
      for (final f in flocks)
        if (f.id != id) f,
    ];

    await _note(id, null);
    await _names(
      (names) => names.removeWhere((k, _) => k == id || k.startsWith('$id/')),
    );
    await _map(
      'modes',
      (modes) => modes.removeWhere((k, _) => k.startsWith('$id/')),
    );
    await _cache();
  }

  Future<int> approve(String flock, String device) async {
    _manage(flock);
    final kek = await api.deviceApprove(flock, device);
    await refreshFlock(flock);
    return kek;
  }

  Future<Registration> replaceDevice(
    String flock,
    Device device,
    Uint8List pk,
  ) async {
    _manage(flock);
    final (reg, kek) = await api.deviceReplace(flock, device.id, pk);
    await refreshFlock(flock);

    if (kek != device.kek) {
      throw ApiError('Reliquary moved the device to another KEK ID.');
    }

    return reg;
  }

  Future<void> deleteDevice(String flock, String device) async {
    _manage(flock);
    await api.deviceDelete(flock, device);
    await _names((names) => names.remove('$flock/$device'));
    await _map('modes', (modes) => modes.remove('$flock/$device'));
    await refreshFlock(flock);
  }

  Future<AmbryNote> generate(String flock, int days) =>
      _work(flock, 'Making the KEKs', () async {
        final bundle = await core.generate(flock, days);
        await reloadVault();
        return bundle;
      });

  Future<AmbryNote> rebundle(String flock, int days) => _work(
    flock,
    'Making new encrypted secrets',
    () => core.bundle(flock, days),
  );

  Future<AmbryNote> renew(String flock, int kek, int days) =>
      _work(flock, 'Replacing the KEK of the device', () async {
        final bundle = await core.renew(flock, kek, days);
        await reloadVault();
        return bundle;
      });

  Future<Uint8List> backupKey() async {
    final root = await core.backupKey();
    await reloadVault();
    return root;
  }

  Future<void> backupAll() async {
    await core.backupAll();
    await reloadVault();
  }

  Future<String?> backupFolder() async {
    final name = await core.backupFolder();
    await reloadVault();
    return name;
  }

  Future<int> backupExport() async {
    final count = await core.backupExport();
    await reloadVault();
    return count;
  }

  Future<Restored> restore(Uint8List root) async {
    final r = await core.backupRestore(root);
    await reloadVault();
    return r;
  }

  Future<String> importAmbry() async {
    final flock = await core.importAmbry();
    await reloadVault();
    return flock;
  }

  Future<String> importBackup() async {
    final flock = await core.importBackup();
    await reloadVault();
    return flock;
  }

  Future<void> forget(String flock) async {
    await core.forget(flock);
    await _note(flock, null);
    await reloadVault();
  }

  Future<void> wipe() async {
    await core.wipe();
    _prefs.remove('ambry');
    await core.prefsSave(_prefs);
    await _remind();
    await reloadVault();
  }

  Future<bool> remindersFirst() async {
    if (desktop || _prefs['reminders'] == true) {
      return false;
    }

    _prefs['reminders'] = true;
    await core.prefsSave(_prefs);
    return true;
  }

  Future<AmbryNote> _work(
    String flock,
    String step,
    Future<Bundle> Function() make,
  ) async {
    _manage(flock);
    _working(Work(flock, step));

    try {
      return await _upload(flock, await make());
    } finally {
      work = null;
      notifyListeners();
    }
  }

  void _manage(String flock) {
    if (external(flock)) {
      throw ApiError(
        'This flock is managed externally, it cannot be changed here.',
      );
    }
  }

  void _working(Work next) {
    final now = work;

    if (now != null &&
        now.step == next.step &&
        ((now.progress ?? 0) * 100).floor() ==
            ((next.progress ?? 0) * 100).floor()) {
      return;
    }

    work = next;
    notifyListeners();
  }

  Future<AmbryNote> _upload(String flock, Bundle bundle) async {
    final note = {
      'generation': bundle.generation,
      'expires': bundle.expires,
      'made': DateTime.now().millisecondsSinceEpoch,
      'uploaded': false,
    };

    await _note(flock, note);

    const step = 'Sending the encrypted secrets to the cathedrals';
    _working(Work(flock, step, 0));

    await api.ambryUpload(
      flock,
      bundle.data,
      progress: (p) => _working(Work(flock, step, p)),
    );

    note['uploaded'] = true;
    await _note(flock, note);

    return AmbryNote(note);
  }

  /// The flocks and their devices as last seen, so a start shows them right
  /// away while refresh() brings them up to date.
  List<Flock> _cached() {
    final cached = _prefs['flocks'] as Map<String, dynamic>? ?? const {};

    return [
      for (final e in cached.entries)
        Flock(e.key)
          ..devices = e.value == null
              ? null
              : [
                  for (final d in e.value as List<dynamic>)
                    Device(d as Map<String, dynamic>),
                ],
    ];
  }

  Future<void> _cache() async {
    _prefs['flocks'] = {
      for (final f in flocks)
        f.id: f.devices == null ? null : [for (final d in f.devices!) d.json],
    };

    await core.prefsSave(_prefs);
  }

  Future<void> _names(void Function(Map<String, dynamic>) change) =>
      _map('names', change);

  Future<void> _map(
    String key,
    void Function(Map<String, dynamic>) change,
  ) async {
    final map = Map<String, dynamic>.from(
      _prefs[key] as Map<String, dynamic>? ?? const {},
    );

    change(map);

    _prefs[key] = map;
    await core.prefsSave(_prefs);
    notifyListeners();
  }

  Future<void> _note(String flock, Map<String, dynamic>? note) async {
    final notes = Map<String, dynamic>.from(
      _prefs['ambry'] as Map<String, dynamic>? ?? const {},
    );

    if (note == null) {
      notes.remove(flock);
    } else {
      notes[flock] = note;
    }

    _prefs['ambry'] = notes;
    await core.prefsSave(_prefs);
    await _remind();
    notifyListeners();
  }

  Future<void> _remind() async {
    final notes = _prefs['ambry'] as Map<String, dynamic>? ?? const {};
    final now = DateTime.now();
    final reminders = <Map<String, Object>>[];

    for (final MapEntry(key: flock, :value) in notes.entries) {
      final note = AmbryNote(value as Map<String, dynamic>);
      if (!note.uploaded) {
        continue;
      }

      for (final days in const [3, 1]) {
        final day = note.expiry.subtract(Duration(days: days));
        final at = DateTime(day.year, day.month, day.day, 10);

        if (at.isAfter(now)) {
          reminders.add({
            'flock': flock,
            'name': flockLabel(flock),
            'days': days,
            'at': at.millisecondsSinceEpoch,
          });
        }
      }
    }

    try {
      await core.reminders(reminders);
    } on CoreError {
      return;
    }
  }
}
