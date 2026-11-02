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

## Adding a remote device

A device that cannot scan a QR code, or is not near the phone, gets
its keys over a sanctum tunnel instead, set up the way cephas sets it
up. The tunnel needs both ends in the flock, so the app joins the flock
for the length of the hand over:

1. The app makes a cosk, registers it and approves it. This takes a
   KEK ID that never leaves the phone, so it needs no renewal.
2. The app picks the KEK ID Reliquary hands out next, the lowest one
   that is free, and the C library makes the words for the device.
3. The device types in the words, joins the flock at Reliquary with a
   cosk of its own and gets its cathedral secret back from it.
4. The app waits for exactly one new device in the flock and approves
   it. If more than one shows up all of them are removed again. If the
   device gets another KEK ID than we picked we stop.
5. The user authenticates, the C library unseals the KEKs and puts
   together what the device gets.
6. Both ends set up the tunnel and the C library sends it. The device
   answers with the SHA3-256 digest of what it got, only a matching
   digest counts.
7. The app removes its own device from the flock again.

Vigil gets its configuration without the `cathedral_secret` and
`cathedral_cosk` lines, it adds its own. A computer gets only its KEK,
which cephas writes to a file.

### The words

There are 33 words from the cephas word list of 7776 words. The first
13 are the route, they tell the device where to find us:

```
flock (7) || our cs id (4) || our kek (1) || its kek (1) ||
cathedral (4) || port (2) || checksum (2)
```

All of it big endian, the flock without its domain. The route is a
number in base 7776, most significant word first. The checksum is the
first two bytes of:

```
SHA3-256("CEPHAS.ROUTE.CHECKSUM" || route[0..19) || passphrase)
```

so a word that is off anywhere is caught before the device tries to
reach us. The other 20 words are the passphrase, the shared secret of
the tunnel is derived from it exactly as cephas does in
cephas_secret_derive(). Its identities and KEK IDs are part of that
derivation, so a device that joined with other words never gets a
tunnel up.

The words are everything the device needs. Whoever has them and joins
before the device does gets its keys, the same as someone who sees the
QR code. In that case the real device joins second and the app stops,
so it does not go unnoticed. Only give the words to the person at the
device, best over a call.

## Where this lives in the code

- `app/lib/api.dart` is the reliquary API client.
- `app/lib/pages/provision.dart` adds a device.
- `src/provision.c` checks the configuration and adds the keys.
- `src/qr.c` makes the QR code.
- `src/remote.c` makes the words and runs the tunnel to a remote device,
  `app/lib/pages/remote.dart` drives it.
- `app/android/app/src/main/kotlin/se/sanctorum/reliquary/Handoff.kt`
  and `app/ios/Runner/ReliquaryPlugin.swift` hand devices to Vigil.
