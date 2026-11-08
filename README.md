# Covenant

Covenant is a management tool for your flocks and devices on a Reliquary
instance. It runs under iOS, Android and Linux.

The app works against any Reliquary instance, to setup your own see
https://github.com/jorisvink/reliquary.

A free community-driven Reliquary instance is available at https://reliquary.se.

Covenant allows you to:

- Manage your account.
- Manage your flocks.
- Manage your devices in a flock.
- Manage KEKs and ambry distributions.
- Provision Vigil (on same phone, via QRcode or remotely).

A remote phone can be provisioned via an on-demand sanctum tunnel
between Vigil and Covenant. This means the provisioning config
is sent encrypted between the two applications with the caveat
that the shared secret is based on secret words (diceware-like random words).

A device running cephas can also be provisioned this way.
See docs/communication.md for more information on that.

# Disclaimer

Some parts of Covenant are written with the help of LLMs.

The security critical and cryptographic bits and pieces are
entirely written by me, while all other code has been reviewed
before being accepted.

# Building

## Android

```
$ make android
$ adb install -r app/build/app/outputs/flutter-apk/app-release.apk
```

## Linux

```
$ make linux
$ ./app/build/linux/x64/release/bundle/covenant
```

To install it for your user, with a launcher and icon in GNOME:

```
$ make linux
$ make linux-install
```

This puts the app under ~/.local/lib/covenant, a covenant symlink in
~/.local/bin and the desktop entry and icon under ~/.local/share. Set
PREFIX to install somewhere else, make linux-uninstall removes it again.

The linux version stores things under $HOME/.config/covenant.

## iOS

Requires macOS with Xcode installed. Before building make sure you
set your DEVELOPMENT_TEAM in app/ios/Team.xcconfig and override
the bundle identifier and handoff keychain group if needed, the
defaults live in app/ios/Covenant.xcconfig.

```
$ cat > app/ios/Team.xcconfig << EOF
DEVELOPMENT_TEAM = <team>
COVENANT_BUNDLE_ID = <bundle id>
COVENANT_HANDOFF_GROUP = <handoff group>
EOF
$ make ios
```

The COVENANT_HANDOFF_GROUP must match the VIGIL_HANDOFF_GROUP
from the Vigil project.
