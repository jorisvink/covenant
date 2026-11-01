# Covenant

An ISC licensed iOS and Android app to manage your Reliquary instance
and provision devices directly from your phone.

The app works against any Reliquary instance, to setup your own see
https://github.com/jorisvink/reliquary.

A free community-driven Reliquary instance is available at https://reliquary.se.

Covenant allows you to:

- Manage your account.
- Manage your flocks.
- Manage your devices in a flock.
- Manage KEKs and ambry distributions.
- Provision Vigil directly from your own phone.

What you cannot do:

- Provision things on your non-phone devices.

The way provisioning works is via a QRcode that can be scanned by Vigil
or imported directly on the same phone via Handover.

# Disclaimer

I wrote this project with the help of LLMs. The security critical
and cryptographic bits and pieces are entirely written by me, while
all other code has been reviewed before being accepted.

I rewrote a bunch of code the LLM suggested as well as it was not
up-to-par with what I consider good code.

I know nothing about app development, I am an old unix neckbeard who
hacks on COMSEC devices from a dark terminal, so this was somewhat of
a benchmark on how quicky and correctly I could get something like this
off the ground. The results are staggering and I think LLM-assisted
development is the way forward for projects like this.

I will continue to refuse LLM written code for security critical pieces
of software such as Sanctum and libkyrka. I strongly believe that those
should still be 100% human driven. Even so, LLMs should always be used
in the hunt for security bugs, as another tool in your toolbox next
to your fuzzers.

Building a strong foundation first, and designing things from scratch
by yourself will allow one to make good use of LLM driven development
once the basic building blocks are in place.

# Building

## Android

```
$ make android
$ adb install -r app/build/app/outputs/flutter-apk/app-release.apk
```

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
