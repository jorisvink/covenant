# Flocks, devices and KEKs

This document describes what the app does. It covers the flocks on your
reliquary account, the KEKs of a flock and the ambry bundles made from
them.

## Accounts

You either register a new account or log in with an existing account
key. Registering hands back the account key once. The app shows it and
does not keep it. Logging in sends the account key to the reliquary and
gets a session token back.

The session token is what the app keeps. See
[communication.md](communication.md) for where it is stored.

## Flocks

A flock is a network on a cathedral. Its id is 64 bits, written as 16
hex characters. The app lists, creates and deletes flocks through the
reliquary API.

A flock has 255 KEK slots, `0x01` up to `0xff`. Every approved device
gets one of them.

A flock that has approved devices but no KEKs on this phone is managed
elsewhere, for example with `ambry` on a computer. The app shows it but
refuses to change it.

## Generating KEKs

The first time you set up a flock the C library generates all 255 KEKs.
It does this like `ambry generate`: every KEK is 32 bytes from the nyfe
random system, with a fresh random state per KEK.

The KEKs are sealed under the vault key right away, see
[keys.md](keys.md). The sealed KEKs are only stored once the first
ambry bundle for them was made. When there is a recovery key the KEKs
are also backed up, see [backups.md](backups.md).

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
flock. Once a bundle is uploaded it schedules a reminder notification at
10:00, 3 days and 1 day before the bundle expires.

## Removing a device

Removing an approved device deletes it at the reliquary. By default the
app then also replaces its KEK, like `ambry renew`:

1. The C library unseals the KEKs.
2. It replaces the KEK of that device with 32 new random bytes.
3. It seals the KEKs again and makes a new bundle.
4. The app uploads the bundle.

The removed device can then no longer open any new bundle. Without
renewal the device keeps a KEK that every new bundle is still made for.

## Adding a device

Adding a device registers it with the reliquary, approves it and turns
its keys into a vigil configuration. See
[communication.md](communication.md) for the steps.

## Where this lives in the code

- `src/keks.c` generates, renews and seals the KEKs.
- `src/ambry.c` makes the ambry bundles.
- `app/lib/reliquary.dart` drives the flows and keeps the bundle notes.
- `app/lib/api.dart` talks to the reliquary.
- `tests/core_test.c` checks the C library against `ambry` when it is in
  your PATH. It brings the KEKs of ambry in with `covenant_keks_import()`,
  which the app itself does not use.
