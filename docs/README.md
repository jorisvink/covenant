The app is built in three layers.

The library is written in C and lives in `src/` and `include/`. It is the
only code that ever sees a KEK in the clear. It generates KEKs, seals
them, makes ambry bundles, builds device configurations and makes and
opens backups. It uses the same nyfe code as ambry (vendored in
`nyfe/`), AES-256-GCM from mbedtls, ed25519 and x25519 from libsodium,
ML-KEM-1024 (vendored in `mlkem1024/`) and qrcodegen for QR codes.

The platform code is written in Kotlin on Android and Swift on iOS. It
owns the vault, thus the hardware key, the wrapped vault key and the files
with sealed KEKs. It asks the user to authenticate and hands the vault
key to the C library for a single operation.

The user interface is written in Flutter (Dart) and lives in `app/lib`.
It talks to the reliquary API and to the platform code. It never sees a
KEK or the vault key.

## Reading order

1. [flocks.md](flocks.md) describes what the app does with flocks,
   devices, KEKs and ambry bundles.
2. [keys.md](keys.md) describes how the KEKs are locked on the phone.
3. [communication.md](communication.md) describes what the app sends to
   the reliquary, and how a device gets its keys.
4. [backups.md](backups.md) describes how the KEKs are backed up to a
   recovery key and restored again.
