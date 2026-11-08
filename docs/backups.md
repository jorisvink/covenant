# Backups

This document describes how the KEKs are backed up and restored. A
backup protects against losing the phone or its hardware key. It is
encrypted to a recovery key that only the user has.

## The idea

The phone can make backups but can never read them back. It only stores
the public keys of the recovery key. Opening a backup needs the
recovery key itself, which the user writes down on paper.

Nothing about backups is stored on the reliquary.

Backups are made on phones only. On Linux the files in
`~/.config/covenant` are already encrypted and directly accessible, so
copying that directory is the backup there. A Linux computer can
import a backup made by a phone, see
[Importing on Linux](#importing-on-linux).

## The recovery key

The recovery key is 32 random bytes from the nyfe random system. It is
shown once, as 64 hex digits in groups of eight. The app does not keep
it and cannot show it again.

The C library derives everything else from the recovery key with
KMAC256:

```
seed    = KMAC256(root, "COVENANT.BACKUP.SEED"), 256-bit
mac_key = KMAC256(root, "COVENANT.BACKUP.MAC.KEY"), 256-bit
coins   = KMAC256(seed, "COVENANT.BACKUP.MLKEM"), 512-bit
sk_x    = KMAC256(seed, "COVENANT.BACKUP.X25519"), 256-bit
```

The coins give an ML-KEM-1024 key pair. `sk_x` is an x25519 private
key. The same recovery key always gives the same keys.

## The recipient

The phone stores a recipient instead of the recovery key. It holds:

- the ML-KEM-1024 public key,
- the x25519 public key,
- the MAC key, encrypted under the vault key.

The MAC key is sealed with AES-256-GCM. The key for that is derived
from the vault key and a random salt with KMAC256, using the label
`COVENANT.BACKUP.RECIPIENT`. The public keys are part of the AAD.

The recipient is 1704 bytes and is stored as `backup.recipient` in the
vault.

## Making a backup

Once there is a recovery key, a backup is made whenever the KEKs of a
flock change. That is when they are generated and when a KEK is
renewed. Making a new recovery key backs up every flock. The steps
are:

1. Open the recipient with the vault key to get the MAC key.
2. Unseal the KEKs with the vault key.
3. Encapsulate to the ML-KEM public key, giving `ct_m` and `ss_m`.
4. Make a random x25519 key `e`. `ct_x` is its public half, `ss_x`
   is `X25519(e, pk_x)`.
5. Derive the backup key:

   ```
   x = len(ct_x) || ct_x || len(pk_x) || pk_x || len(flock) || flock
   K = KMAC256(ss_m || ss_x, "COVENANT.BACKUP.KDF", x)
   ```

6. Encrypt the KEKs and the signing seed with AES-256-GCM under K,
   with the header as AAD.
7. MAC everything so far with KMAC256 under the MAC key, using the
   label `COVENANT.BACKUP.MAC`.

An attacker would have to break both ML-KEM-1024 and x25519 to learn
the backup key.

The MAC means that the public keys alone are not enough to make a
backup. Only a phone that holds the MAC key, or the recovery key itself,
can make one that restores.

## The backup file

A backup is 9888 bytes. All integers are big endian.

```
magic "COVB"	4
version		4	3
flock		8
created		8	when the KEKs were made
made		8	when the backup was made
nonce		12
reserved	4
ct_x		32
ct_m		1568
KEKs		255 * 32
seed		32	the signing seed of the flock
tag		16
mac		32
```

Restoring a backup brings the signing seed back too, so the device
names signed before still verify.

Only version 3 is accepted, older versions no longer open.

The flock and both times can be read without the recovery key. The app
uses that to list what is in the backup folder.

## The backup folder

The user picks a folder with the system folder picker. On Android that
is the storage access framework, on iOS a document picker with a
security scoped bookmark. On iOS the app also lists backups that iCloud
Drive has not downloaded yet.

Each flock gets one file, `reliquary-<flock>.rlqb`. A new backup
replaces the old file of that flock.

The phone first keeps the latest backup of each flock in its vault. It
marks it "pending" until it is written to the folder, then "exported".
Pending backups are written to the folder right after they are made,
and when a folder is picked. When the backup after generating or
renewing KEKs fails, it is logged and the flock is left without an up
to date backup. When backing up every flock fails, for a new recovery
key or on request, the user sees the error. A failed export to the
folder is always only logged. The Keys
tab shows per flock whether its backup is in the folder.

## Restoring

Restoring happens on a new phone, or after the vault was wiped:

1. The user picks the backup folder.
2. The user types in the recovery key.
3. The user authenticates. A new vault is made when there is none.
4. For every backup of a flock that this phone has no KEKs for, the
   core restores it.

Restoring one backup goes like this:

1. Derive the keys from the recovery key.
2. Check the MAC. A wrong MAC means a wrong recovery key.
3. Decapsulate `ct_m` with the ML-KEM private key, giving `ss_m`.
4. Compute `ss_x = X25519(sk_x, ct_x)`.
5. Derive K as above and decrypt the KEKs.
6. Seal the KEKs under the vault key of this phone.

The KEKs stay the same, so the devices of the flock keep working as
they are.

Flocks this phone already has KEKs for are skipped. A backup the
recovery key does not open is reported as failed. If none of them
opens, the restore fails as a whole.

When the phone has no recipient yet and at least one flock was
restored, the recipient of the recovery key that was used becomes the
recipient of the phone. When it already has a different one, the
restored flocks are backed up again to its own recipient.

## Checking the recovery key

The app can check a recovery key without restoring anything. The C
library derives the public keys from it and compares them to the
recipient. The recovery key is not kept.

## A lost recovery key

A lost recovery key cannot be recovered. You make a new one instead.
Every flock on the phone is then backed up again for the new key,
replacing the old backups in the folder.

## Importing on Linux

The Linux app imports one backup at a time from the Keys tab. The user
picks the `.rlqb` file and types the recovery key into a GTK dialog,
then the passphrase. The runner reads the flock from the backup header
and refuses it when the KEKs of that flock are already on the computer.
Otherwise the C library opens the backup as described above and seals
the KEKs under the vault key of the computer. The recovery key is wiped
right after.

The computer has no recipient and never makes backups of its own.

## Restoring with covenant-restore

`make tools` builds `tools/covenant-restore`. It reads a backup and asks for
the recovery key without echo on a terminal.

```
$ ./tools/covenant-restore reliquary-493abf95a07e0c00.rlqb
$ ./tools/covenant-restore reliquary-493abf95a07e0c00.rlqb /some/dir
```

Without an output directory it only checks that the recovery key opens
the backup. With one it writes the KEKs as `<flock>/kek-data/kek-0xNN`,
the layout of `ambry generate`. It refuses to run when the `<flock>`
directory already exists, so it never overwrites anything.

## What a backup does not cover

A backup only holds the KEKs and the signing seed. It does not hold
the session token, the account key, device names or bundle notes.

Without a backup, losing the phone or removing its screen lock loses
the KEKs. On Linux the same goes for losing the computer without a copy
of `~/.config/covenant`, or for forgetting the passphrase, as the copy
is locked with the same passphrase. The flock then needs new KEKs and all of its devices need
provisioning again.
