#!/bin/sh

set -e

BUNDLE=app/build/linux/x64/release/bundle
PREFIX=${PREFIX:-$HOME/.local}

APPDIR=$PREFIX/lib/covenant
BINDIR=$PREFIX/bin
DESKTOP=$PREFIX/share/applications
ICONS=$PREFIX/share/icons/hicolor

refresh() {
	if command -v gtk-update-icon-cache > /dev/null; then
		gtk-update-icon-cache -q -f -t $ICONS || true
	fi

	if command -v update-desktop-database > /dev/null; then
		update-desktop-database -q $DESKTOP || true
	fi
}

if [ "$1" = "uninstall" ]; then
	rm -rf $APPDIR
	rm -f $BINDIR/covenant
	rm -f $DESKTOP/covenant.desktop
	rm -f $ICONS/256x256/apps/covenant.png
	refresh
	echo "removed covenant from $PREFIX"
	exit 0
fi

if [ ! -x $BUNDLE/covenant ]; then
	echo "no linux build found, run make linux first"
	exit 1
fi

mkdir -p $PREFIX/lib $BINDIR $DESKTOP $ICONS/256x256/apps

rm -rf $APPDIR
cp -R $BUNDLE $APPDIR

ln -sf $APPDIR/covenant $BINDIR/covenant

cp app/linux/runner/covenant.png $ICONS/256x256/apps/covenant.png

sed "s|@APPDIR@|$APPDIR|" app/linux/covenant.desktop \
    > $DESKTOP/covenant.desktop

refresh

echo "installed covenant into $APPDIR"
echo "added $DESKTOP/covenant.desktop"
