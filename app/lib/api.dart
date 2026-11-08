import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

const defaultApi = 'https://vessel.reliquary.se/v1';

class ApiError implements Exception {
  ApiError(this.message, {this.status});

  final String message;
  final int? status;

  @override
  String toString() => message;
}

class Session {
  Session({
    required this.api,
    required this.token,
    required this.cathedral,
    required this.natport,
  });

  final String api;
  final String token;
  final String cathedral;
  final int natport;

  factory Session.fromJson(Map<String, dynamic> json) => Session(
    api: json['api'] as String,
    token: json['token'] as String,
    cathedral: json['cathedral'] as String,
    natport: int.parse('${json['natport']}'),
  );

  Map<String, dynamic> toJson() => {
    'api': api,
    'token': token,
    'cathedral': cathedral,
    'natport': natport,
  };

  String get accountPage =>
      Uri.parse(api).replace(path: '/account/login').toString();
}

class AccountInfo {
  AccountInfo(this.expiry, this.flocksMax);

  final DateTime expiry;
  final int flocksMax;

  Duration get left {
    final d = expiry.difference(DateTime.now());
    return d.isNegative ? Duration.zero : d;
  }

  bool get expired => left == Duration.zero;
}

class Device {
  Device(this.json);

  final Map<String, dynamic> json;

  String get id => '${json['device_cathedral_id']}';

  int get kek => int.tryParse('${json['device_kek']}') ?? 0;

  String get kekHex => kek.toRadixString(16).padLeft(2, '0');

  bool get approved {
    final v = json['device_approved'];
    return v == true || v == 't' || v == 'true';
  }

  DateTime? get created {
    final v = int.tryParse('${json['device_created']}');
    return v == null ? null : DateTime.fromMillisecondsSinceEpoch(v * 1000);
  }
}

class Registration {
  Registration(this.id, this.secret, this.flock);

  final String id;
  final String secret;
  final String flock;
}

/// What register hands back, the account key is shown once and then
/// forgotten, exactly like rlq does.
class Account {
  Account(this.session, this.key);

  final Session session;
  final String key;
}

final _hex16 = RegExp(r'^[0-9a-f]{16}$');
final _hex8 = RegExp(r'^[0-9a-f]{8}$');

typedef Progress = void Function(double done);

bool isFlock(String id) => _hex16.hasMatch(id);
bool isDevice(String id) => _hex8.hasMatch(id);

class Api {
  Api(this.session);

  final Session session;

  static final HttpClient _http = HttpClient()
    ..connectionTimeout = const Duration(seconds: 15)
    ..idleTimeout = const Duration(seconds: 15)
    ..userAgent = 'reliquary-app/1';

  static Uri _uri(String api, String path) {
    final base = api.endsWith('/') ? api.substring(0, api.length - 1) : api;
    return Uri.parse('$base/$path');
  }

  // The reliquary allows about one request per second per client (see
  // ratelimit.py), so we line requests up and space them out.
  static Future<void> _queue = Future.value();
  static DateTime _last = DateTime.fromMillisecondsSinceEpoch(0);
  static const _spacing = Duration(milliseconds: 1050);

  static const _chunk = 64 * 1024;

  static Future<(int, Uint8List)> _request(
    String method,
    Uri uri, {
    String? token,
    List<int>? body,
    Progress? progress,
  }) {
    if (uri.scheme != 'https' && uri.host != '127.0.0.1') {
      throw ApiError('The server address must start with https://.');
    }

    final done = Completer<(int, Uint8List)>();

    _queue = _queue.then((_) async {
      for (var attempt = 0; ; attempt++) {
        final wait = _last.add(_spacing).difference(DateTime.now());
        if (!wait.isNegative) {
          await Future<void>.delayed(wait);
        }

        _last = DateTime.now();

        try {
          final r = await _send(
            method,
            uri,
            token: token,
            body: body,
            progress: progress,
          );
          if (r.$1 == 429 && attempt < 3) {
            await Future<void>.delayed(_spacing * (attempt + 1));
            continue;
          }
          done.complete(r);
        } catch (e, st) {
          done.completeError(e, st);
        }

        return;
      }
    });

    return done.future;
  }

  static Future<(int, Uint8List)> _send(
    String method,
    Uri uri, {
    String? token,
    List<int>? body,
    Progress? progress,
  }) async {
    try {
      final req = await _http.openUrl(method, uri);

      // Kore answers some errors before reading the body, a reused
      // connection then sees an answer it never asked for.
      req.persistentConnection = false;

      if (token != null) {
        req.headers.set('x-token', token);
      }

      if (body != null) {
        req.headers.contentType = ContentType.binary;
        req.contentLength = body.length;

        if (progress == null) {
          req.add(body);
        } else {
          for (var off = 0; off < body.length; off += _chunk) {
            final end = math.min(off + _chunk, body.length);
            req.add(body.sublist(off, end));
            await req.flush().timeout(const Duration(seconds: 60));
            progress(end / body.length);
          }
        }
      }

      final resp = await req.close().timeout(const Duration(seconds: 60));
      final data = await resp
          .fold<BytesBuilder>(BytesBuilder(), (b, d) => b..add(d))
          .timeout(const Duration(seconds: 60));

      return (resp.statusCode, data.takeBytes());
    } on SocketException {
      throw ApiError('Cannot reach ${uri.host}, check your internet.');
    } on HandshakeException {
      throw ApiError('Cannot set up a secure connection to ${uri.host}.');
    } on TimeoutException {
      throw ApiError('${uri.host} did not answer in time.');
    } on HttpException {
      throw ApiError('The connection to ${uri.host} failed, try again.');
    }
  }

  static String _text(Uint8List data) =>
      utf8.decode(data, allowMalformed: true).trim();

  static Never _fail(int status, Uint8List data) {
    final text = _text(data);

    switch (status) {
      case 403 when text == 'account expired':
        throw ApiError(
          'Your account has expired, extend it on the Account tab.',
          status: status,
        );
      case 403:
        throw ApiError(
          'Reliquary refused this, try logging in again.',
          status: status,
        );
      case 429:
        throw ApiError(
          'Too many requests, wait a little and try again.',
          status: status,
        );
    }

    throw ApiError(
      text.isEmpty ? 'Reliquary answered with an error ($status).' : text,
      status: status,
    );
  }

  Future<String> _post(
    String path, [
    List<int> body = const [],
    Progress? progress,
  ]) async {
    final (status, data) = await _request(
      'POST',
      _uri(session.api, path),
      token: session.token,
      body: body,
      progress: progress,
    );

    if (status != 200) {
      _fail(status, data);
    }

    return _text(data);
  }

  Future<String> _get(String path) async {
    final (status, data) = await _request(
      'GET',
      _uri(session.api, path),
      token: session.token,
    );

    if (status != 200) {
      _fail(status, data);
    }

    return _text(data);
  }

  static Map<String, dynamic> _json(String text) {
    try {
      return jsonDecode(text) as Map<String, dynamic>;
    } on FormatException {
      throw ApiError('Reliquary sent something unexpected.');
    }
  }

  static Future<Account> register(String api) async {
    final (status, data) = await _request(
      'POST',
      _uri(api, 'register'),
      body: const [],
    );

    if (status != 200) {
      _fail(status, data);
    }

    final json = _json(_text(data));

    return Account(
      Session(
        api: api,
        token: json['token'] as String,
        cathedral: json['cathedral'] as String,
        natport: int.parse('${json['natport']}'),
      ),
      json['account'] as String,
    );
  }

  static Future<Session> login(String api, String key) async {
    final (status, data) = await _request(
      'POST',
      _uri(api, 'init'),
      body: utf8.encode(key),
    );

    if (status == 403) {
      throw ApiError('That account key is not known.', status: status);
    }

    if (status != 200) {
      _fail(status, data);
    }

    final json = _json(_text(data));

    return Session(
      api: api,
      token: json['token'] as String,
      cathedral: json['cathedral'] as String,
      natport: int.parse('${json['natport']}'),
    );
  }

  Future<AccountInfo> account() async {
    final json = _json(await _get('account'));
    final expires = int.tryParse('${json['expires']}') ?? 0;

    return AccountInfo(
      DateTime.now().add(Duration(seconds: expires)),
      int.tryParse('${json['flocks_max']}') ?? 0,
    );
  }

  Future<void> accountTime() async {
    final text = await _post('account/time');

    if (text != 'time added') {
      throw ApiError(text);
    }
  }

  Future<List<String>> cathedrals() async {
    final text = await _get('cathedrals');
    return text.split('\n').where((l) => l.trim().isNotEmpty).toList();
  }

  Future<List<String>> flocks() async {
    final json = _json(await _get('flock/list'));
    final list = json['flocks'] as List<dynamic>? ?? const [];

    return [
      for (final f in list.cast<Map<String, dynamic>>()) f['id'] as String,
    ];
  }

  Future<String> flockCreate() async {
    final text = await _post('flock/create');

    if (!isFlock(text)) {
      throw ApiError(
        text == 'reached max flocks per account'
            ? 'Your account cannot hold any more flocks.'
            : text,
      );
    }

    return text;
  }

  Future<void> flockDelete(String flock) => _post('flock/$flock/delete');

  Future<List<Device>> devices(String flock) async {
    final json = _json(await _get('device/list/$flock'));
    final list = json['devices'] as List<dynamic>? ?? const [];

    return [for (final d in list.cast<Map<String, dynamic>>()) Device(d)];
  }

  Future<Registration> deviceCreate(String flock, Uint8List pk) async {
    final json = _json(await _post('device/$flock/create', pk));
    final id = json['cathedral_id'] as String? ?? '';
    final secret = json['cathedral_secret'] as String? ?? '';

    if (!isDevice(id) || !RegExp(r'^[0-9a-f]{64}$').hasMatch(secret)) {
      throw ApiError('Reliquary sent back an invalid device, try again.');
    }

    return Registration(id, secret, json['flock'] as String? ?? flock);
  }

  Future<int> deviceApprove(String flock, String device) async {
    final text = await _post('device/$flock/$device/approve');
    final match = RegExp(r'kek-0x([0-9a-f]{2})').firstMatch(text);

    if (match != null) {
      return int.parse(match.group(1)!, radix: 16);
    }

    for (final d in await devices(flock)) {
      if (d.id == device && d.approved) {
        return d.kek;
      }
    }

    throw ApiError(text);
  }

  Future<(Registration, int)> deviceReplace(
    String flock,
    String device,
    Uint8List pk,
  ) async {
    final json = _json(await _post('device/$flock/$device/replace', pk));
    final id = json['cathedral_id'] as String? ?? '';
    final secret = json['cathedral_secret'] as String? ?? '';
    final kek = json['kek'] as int? ?? 0;

    if (id != device ||
        kek < 1 ||
        kek > 255 ||
        !RegExp(r'^[0-9a-f]{64}$').hasMatch(secret)) {
      throw ApiError('Reliquary sent back an invalid device, try again.');
    }

    return (Registration(id, secret, json['flock'] as String? ?? flock), kek);
  }

  Future<String> deviceDelete(String flock, String device) =>
      _post('device/$flock/$device/delete');

  Future<void> ambryUpload(
    String flock,
    Uint8List bundle, {
    Progress? progress,
  }) async {
    final String text;

    try {
      text = await _post('ambry/$flock', bundle, progress);
    } on ApiError catch (e) {
      if (e.status == 403 && bundle.length != 3756730) {
        throw ApiError('Reliquary refused these encrypted secrets.');
      }
      rethrow;
    }

    if (text != 'ambry uploaded') {
      throw ApiError(text);
    }
  }
}
