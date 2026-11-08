# Flocks, devices and KEKs

This document describes what the app does. It covers the flocks on your
reliquary account, the KEKs of a flock and the ambry bundles made from
them.

## Accounts

You either register a new account or log in with an existing account
key. Registering hands back the account key once. The app shows it and
does not keep it. Logging in sends the account key to the reliquary and
gets a session token back.

The app stores only the session token, see [keys.md](keys.md) for
where.

## Flocks

A flock is a network on a cathedral. Its id is 64 bits, written as 16
hex characters. The app lists, creates and deletes flocks through the
reliquary API.

A flock has 255 KEK slots, `0x01` up to `0xff`. Every approved device
gets one of them.

A flock that has approved devices but no KEKs on this device is managed
elsewhere, for example with `ambry` on a computer. The app shows it but
refuses to change it. On Linux the KEKs of such a flock can be
imported, see below.

## Generating KEKs

The first time you set up a flock the C library generates all 255 KEKs.
It does this like `ambry generate`: every KEK is 32 bytes from the nyfe
random system, with a fresh random state per KEK.

The KEKs are sealed under the vault key right away, see
[keys.md](keys.md). The sealed KEKs are only stored once the first
ambry bundle for them was made. On a phone with a recovery key the KEKs
are also backed up, see [backups.md](backups.md).

## Importing KEKs on Linux

On Linux the Keys tab can import the KEKs of a flock from two sources.
Both refuse a flock that already has KEKs on the computer and leave the
source files untouched.

- A flock folder made by `ambry generate`. The folder must be named
  after the flock and hold `kek-data/kek-0x01` up to `kek-0xff`. The
  C library seals the KEKs with `covenant_keks_import()` and makes a
  new signing seed for them, as ambry has none.
- A backup made by a phone, together with its recovery key. The KEKs
  and the signing seed are restored as they were, see
  [backups.md](backups.md).

The folder or file is picked with a GTK file chooser and the recovery
key is typed into a GTK dialog, neither passes through the Flutter
side.

## Ambry bundles

An ambry bundle holds a shared secret for every pair of devices in the
flock. The cathedral hands the right entries to each device. Only the
device with the matching KEK can open them.

The C library makes a bundle the same way `ambry bundle` does when given
the same flock twice:

1. It masks the domain bits off the flock id.
2. It derives an internal KEK from each of the 255 KEKs with KMAC256,
   like `ambry generate` writes to `internal/kek-0xNN`.
3. It picks a random 32-bit generation and a random 64 byte seed.
4. For every pair of KEK ids it makes a fresh random 32 byte secret.
5. It wraps that secret twice with AES-256-GCM, once for each side of
   the pair. The key for each wrap is derived with KMAC256 from the
   sending device its internal KEK, the seed, the flock, the generation
   and the tunnel id.

A bundle is always 3756730 bytes. It is valid for 1 to 3650 days. The
app then uploads it to the reliquary.

The app remembers the generation and the expiry of the last bundle per
flock. On a phone it schedules a reminder notification at 10:00, 3 days
and 1 day before the bundle expires, once a bundle is uploaded. Linux
has no reminders.

## Removing a device

Removing an approved device deletes it at the reliquary. By default the
app then also replaces its KEK, like `ambry renew`:

1. The C library unseals the KEKs.
2. It replaces the KEK of that device with 32 new random bytes.
3. It seals the KEKs again and makes a new bundle.
4. The app uploads the bundle.

The removed device can then no longer open any new bundle. Without
renewal the device keeps a KEK that every new bundle is still made for.

## Replacing a device

A device that is lost, stolen or swapped for a new device is replaced
instead of removed. Replacing keeps its device ID, KEK ID and name:

1. The C library replaces the KEK of that KEK ID and the app uploads a
   new bundle, like removing it does. The old device can no longer open
   any new bundle.
2. The app makes a new cosk and hands it to the reliquary with
   `/v1/device/<flock>/<device>/replace`. The reliquary swaps the cosk
   public key and gives the device a new cathedral secret, so the old
   device can no longer talk to the cathedral either.
3. The app builds the configuration for the new device on the same KEK
   ID, with the name of the old one. The way it connects (one device,
   group, comms or tier6) stays the same, the app remembers it per
   device when it provisions one. For a device provisioned before it
   did so, any way can be picked.

Because the KEK ID never changes hands, the device name signed for it
only ever belongs to that device, see
[communication.md](communication.md).

## Adding a device

Adding a device registers it with the reliquary, approves it and turns
its keys into a vigil configuration. See
[communication.md](communication.md) for the steps.
