# How the keys are locked

This document describes how the KEKs are protected on a phone and on
a Linux computer. It follows the keys from the hardware of the phone,
or the passphrase on Linux, down to the files on disk and the memory
of the C library.

## The layers

There are three layers of keys.

1. The key that wraps the vault key. On a phone this is a hardware
   key in StrongBox or the TEE on Android, or in the Secure Enclave on
   iOS, and it never leaves the hardware. On Linux it is derived from a
   passphrase.
2. The vault key. It is 32 random bytes, wrapped by the key above. On
   a phone it is stored as `vault.key`, on Linux as `key`.
3. The sealed KEKs. The 255 KEKs of each flock are encrypted under a
   key derived from the vault key, one file per flock.

Opening a KEK needs the vault key, so it needs the user to
authenticate on a phone or to type the passphrase on Linux. There is
one vault key for all flocks on a device.

## The hardware key on Android

The hardware key is an AES-256-GCM key in the Android Keystore. The app
asks for it in StrongBox first and falls back to the TEE when the phone
has no StrongBox.

The key is created with these properties:

- It needs authentication for every single use. The timeout is 0.
- Biometrics (strong class) or the device credential both work.
- The device must be unlocked.
- Enrolling a new fingerprint does not invalidate it.
- Removing the screen lock invalidates it for good.

Because of the timeout of 0 the key cannot be used on its own. The app
sets up a Cipher first and hands it to the BiometricPrompt. Only after
the user authenticated may that one Cipher do its work.

The vault key is wrapped with that Cipher. The file holds the nonce,
the ciphertext and the tag. The AAD is `reliquary vault key 1`.

## The hardware key on iOS

The hardware key is a P-256 key in the Secure Enclave. On a device
without a Secure Enclave, such as the simulator, it is a keychain key
instead and the app reports it as "software".

The key is created with these properties:

- The access control needs user presence: Face ID, Touch ID or the
  passcode.
- It is only usable while a passcode is set, on this device only.
- Removing the passcode deletes it.

The vault key is encrypted to the public half with ECIES (cofactor
X9.63 SHA-256, AES-GCM). Opening it decrypts with the private half,
which prompts the user every time.

## The passphrase on Linux

A computer has no secure hardware the app can rely on, so the vault key
is wrapped under a passphrase instead. The user picks it the first time
KEKs are generated or imported, and types it again for every operation
that needs the vault key. A forgotten passphrase cannot be recovered.

The passphrase is typed into a GTK dialog in the native runner. It is
never handed to the Flutter side. The runner holds it in memory from
`covenant_alloc()` and wipes it as soon as the vault key is unwrapped.

The C library derives the wrapping key in two steps:

```
ikm = nyfe_passphrase_kdf(passphrase, salt, "COVENANT.WRAP.PASSPHRASE")
K   = KMAC256(ikm, "COVENANT.WRAP.KEY"), 256-bit
```

`nyfe_passphrase_kdf()` is the memory hard KDF from nyfe. It uses 32 MB
of memory and 65536 iterations with access patterns that depend on the
passphrase and the salt, and returns 64 bytes.

The vault key is encrypted with AES-256-GCM under K. The salt (32
bytes) and the nonce (12 bytes) are fresh on every wrap, and the header
is the AAD. The file is 104 bytes:

```
magic "COVW"	4
version		4
salt		32
nonce		12
reserved	4
vault key	32
tag		16
```

A wrong passphrase fails the tag check and is reported as such.

Changing the passphrase asks for the current one and then for the new
one twice. The vault key itself stays the same, it is only wrapped
again under the new passphrase, so the sealed KEKs are not touched.

## Sealing the KEKs

The C library seals the KEKs of a flock with AES-256-GCM. The key is
derived from the vault key with KMAC256:

```
x = len(salt) || salt || len(flock) || flock
K = KMAC256(vault key, "COVENANT.VAULT.KEKS", x)
```

The salt is 32 random bytes and the nonce is 12 random bytes. Both are
fresh on every seal.

The sealed file is 8280 bytes:

```
magic "COVK"	4
version		4
flock		8
created		8
salt		32
nonce		12
reserved	4
KEKs		255 * 32
seed		32
tag		16
```

The seed is made together with the KEKs and stays the same when a KEK
is renewed. It is the seed of the ed25519 key the flock signs device
names with, see [communication.md](communication.md).

The header is the AAD, so it cannot be changed without the tag failing.
The flock and the creation time can be read without the vault key. The
app uses that to list the flocks it has KEKs for.

## One operation at a time

Every operation that needs a KEK goes the same way:

1. The platform asks the user to authenticate, or on Linux for the
   passphrase.
2. It unwraps the vault key.
3. It hands the vault key and the sealed KEKs to the C library.
4. The C library unseals the KEKs, does its work and wipes them.
5. The platform overwrites its copy of the vault key with zeros.

The vault key is never stored in the clear. A new prompt is shown for
every operation.

On Linux the runner does the work of a call on a thread of its own, so
the window stays responsive during the passphrase KDF. The vault key
lives on the stack of that thread, registered with nyfe, and is wiped
with `nyfe_zeroize()` once the call is done.

## Memory in the C library

The C library keeps key material in memory from `covenant_alloc()`. That
memory:

- is mapped on its own pages with `mmap()`,
- is locked with `mlock()` when the system allows it,
- is kept out of core dumps where `MADV_DONTDUMP` exists,
- is registered with nyfe so it can be wiped in an emergency.

`covenant_free()` overwrites it with zeros before it is unmapped. Keys on
the stack are wiped with `nyfe_zeroize()` right after use.

On a fatal error the C library wipes all registered key material before
it aborts. On Android the JNI layer copies the vault key and the sealed
KEKs into memory from `covenant_alloc()` as well. On Linux the runner
uses the same memory for the passphrase and the recovery key.

All calls that touch key material hold one lock, so they never run
at the same time. Calls that only read a header, such as
`covenant_keks_info()` and `covenant_backup_info()`, do not hold the lock.

## Files on disk

On Android the vault lives in the `vault` directory under the app its
no-backup files directory. The manifest turns platform backups off and
excludes every domain from cloud backup and device transfer.

On iOS the vault lives in a `vault` directory under Application
Support. Files are written with complete file protection and are
excluded from backups.

On Linux everything lives in `$HOME/.config/covenant`, or in the
directory named by `$COVENANT` when that is set. The layout is:

```
key		the vault key, wrapped under the passphrase
<flock>/keks	the sealed KEKs of a flock
api		the address of the reliquary API
token		the session token
cathedral	the cathedral of the account
natport		the NAT port of the cathedral
prefs		the app settings, as json
lock		held while the app runs
```

The directories are created with mode 0700 and the files with mode
0600. Files are written to a temporary file, synced and then renamed
into place. Only one instance of the app runs at a time, it holds an
exclusive `flock()` on `lock` when it starts.

Files are wiped by overwriting them with zeros before they are deleted.
Flash storage may keep old copies. The real protection is that the
sealed KEKs cannot be opened without the hardware key or the
passphrase.

## Losing the hardware key or the passphrase

When the screen lock or passcode is removed the hardware key is gone.
The vault key can then never be unwrapped again. The app shows this
and offers to wipe the vault. On Linux a forgotten passphrase has the
same result. Wiping the KEKs on the Keys tab does not ask for the
passphrase, so a computer can always be reset.

Without a backup the KEKs are lost. The flock then needs new KEKs and
all of its devices need provisioning again. See
[backups.md](backups.md).

## Other protections

On Android release builds the app sets `FLAG_SECURE`. This blocks
screenshots and the thumbnail in the recent apps list.

On Android and iOS the app covers its screen when it is not in front.
On Linux it does not.

## What is not in the vault

The session token is stored separately. On Android it is encrypted
under its own Keystore key, which needs the device unlocked but no
prompt. On iOS it is in the keychain, readable when unlocked, this
device only. On Linux it is the plain `token` file, protected only by
its file mode.

Plain app settings hold the cached flock and device lists, the device
names you gave and the notes about the last bundle per flock. These
hold no keys.
