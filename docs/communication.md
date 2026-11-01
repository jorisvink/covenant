# Communication

This document describes what the app sends and receives. It covers the
reliquary API, how a new device gets its keys and how the user
interface talks to the platform code.

## The reliquary API

The app talks to the reliquary API over HTTPS. The default address is
`https://vessel.reliquary.se/v1`. Any other address must also use
https, plain http is only accepted for `127.0.0.1`.

Every request after login carries the session token in an `x-token`
header. The app uses the normal TLS checks of Dart its HttpClient,
there is no certificate pinning.

The reliquary allows about one request per second per client. The app
queues all requests and spaces them 1050 ms apart. A request answered
with 429 is retried up to 3 times, each time waiting a little longer.

## What the app sends

These are the calls the app makes, and what goes in them.

| Call | Sends | Gets back |
|------|-------|-----------|
| `register` | nothing | account key, token, cathedral, nat port |
| `init` | the account key | token, cathedral, nat port |
| `account` | token | time left, flock limit |
| `account/time` | token | |
| `cathedrals` | token | the list of cathedrals |
| `flock/list` | token | the flock ids |
| `flock/create` | token | the new flock id |
| `flock/<id>/delete` | token | |
| `device/list/<flock>` | token | the devices of the flock |
| `device/<flock>/create` | the cosk public key | device id, cathedral secret |
| `device/<flock>/<id>/approve` | token | the KEK id of the device |
| `device/<flock>/<id>/delete` | token | |
| `ambry/<flock>` | the ambry bundle | |

The KEKs and the vault key are never sent. The ambry bundle holds the
shared secrets of the flock, encrypted under keys derived from the
KEKs. The reliquary cannot open it.

The cathedral secret of a new device comes from the reliquary. The
reliquary therefore knows it.

## Adding a device

Adding a device goes through these steps:

1. The C library makes a new ed25519 key pair, the cosk. It keeps the
   secret half in its context and hands back a handle and the public
   half.
2. The app registers the device with the public half. The reliquary
   answers with a device id and a cathedral secret.
3. The app approves the device. The reliquary answers with the KEK id
   it picked.
4. The app writes the public part of the vigil configuration. That is
   everything except the keys.
5. The user authenticates and the C library unseals the KEKs.
6. The C library checks the public part and adds the keys.
7. The result goes into a QR code, or straight to Vigil on the same
   phone.

The C library keeps at most 8 cosk pairs waiting at a time. A cosk pair
is wiped once its device is provisioned.

## The configuration check

The C library only adds keys to a configuration it accepts. It checks
that:

- it is at most 1024 bytes of printable ASCII,
- it starts with `vigil 1`,
- it has no `kek`, `secret`, `cathedral_secret`, `cathedral_cosk`,
  `name_pubkey` or `name_signature` line,
- it has exactly one `cathedral_flock` line, and it names the flock of
  the KEKs,
- it has exactly one `spi` line, and it starts with the KEK id,
- it has exactly one `instance` line, with a name vigil accepts: 1 to
  63 letters, digits, spaces, `.`, `-` or `_`.

It then appends these lines, all in hex:

- `kek`, the KEK of the device,
- `cathedral_secret`, from the reliquary,
- `cathedral_cosk`, the secret half of the cosk,
- `name_pubkey`, the public key the flock signs device names with,
- `name_signature`, the signature over the name of the device.

## Signed device names

Every flock has an ed25519 key to sign the names of its devices with.
Its seed is sealed together with the KEKs and is in the backups, so a
restore keeps it. The name of a device is its `instance`, the C library
signs:

```
m = "COVENANT.NAME" || flock || kek || len(name) || name
```

The flock is 64-bit big endian, the KEK id and the length are a single
byte.

Vigil sends its name and the signature to the devices it chats with.
The receiver does not take the flock or the KEK id from the sender. It
uses the flock of its own configuration and the KEK id of the tunnel
the name arrived on, and checks the signature with its own `name_pubkey`.
A device therefore cannot show itself under the name of another
device, and the cathedrals never see a name.

Renaming a device in vigil makes its signature stop matching, it then
falls back to its nickname. A new name needs the device to be
provisioned again.

For a QR code the configuration is built in memory from `covenant_alloc()`
and wiped once it is encoded. For a handover to Vigil the platform
hands the C library a buffer and wipes it after the handover.

## The QR code

For a QR code the C library encodes the configuration itself. It hands
back only the QR modules, one byte per module.

The modules go to the user interface to be drawn. They carry all of the
keys of the device. The QR page overwrites its copy with zeros when it
closes. The copy the platform channel hands over is read only and
cannot be wiped by the app.

On Android release builds screenshots of the QR code are blocked.

## Handing a device to Vigil

When Vigil is installed on the same phone, the configuration can go to
it directly instead of through a QR code.

On Android the app calls the content provider
`se.sanctorum.vigil.import` with the configuration. Vigil must answer
with `ok`. The app then wipes its copy and opens Vigil.

On iOS the app stores the configuration in a keychain item that both
apps share. That item is readable only while the phone is unlocked and
never synchronised. The app then opens `vigil://import`. If Vigil
cannot be opened, the item is removed again. The item is also removed
whenever the app starts.

## Between the interface and the platform

The Flutter side talks to Kotlin or Swift over one method channel,
`se.sanctorum.reliquary/core`. Calls that need the vault key ask the
user to authenticate on the platform side. The Flutter side never gets
the vault key or a KEK back.

The Flutter side does handle the recovery key. It gets it once when a
recovery key is made, and it sends it when the user types it in to
check or restore. See [backups.md](backups.md).

## Where this lives in the code

- `app/lib/api.dart` is the reliquary API client.
- `app/lib/pages/provision.dart` adds a device.
- `src/provision.c` checks the configuration and adds the keys.
- `src/qr.c` makes the QR code.
- `app/android/app/src/main/kotlin/se/sanctorum/reliquary/Handoff.kt`
  and `app/ios/Runner/ReliquaryPlugin.swift` hand devices to Vigil.
