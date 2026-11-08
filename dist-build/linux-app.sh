#!/bin/sh

set -e

. ./dist-build/flutter.sh

make PLATFORM=host

cd app
$FLUTTER build linux "$@"
