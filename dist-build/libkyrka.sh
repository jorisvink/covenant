#!/bin/sh

set -e

if [ -z "$1" ]; then
	echo "usage: libkyrka.sh <target> [make variables]"
	exit 1
fi

TARGET=$1
shift

TOPDIR=`pwd`
LIBKYRKA=${LIBKYRKA:-$TOPDIR/build/src/libkyrka}
BUILD=$TOPDIR/build/$TARGET
SRC=$BUILD/libkyrka
AR=${AR:-ar}

if [ ! -f $LIBKYRKA/include/libkyrka/libkyrka.h ]; then
	echo "no libkyrka found at $LIBKYRKA, run dist-build/deps.sh"
	exit 1
fi

want=`cat $LIBKYRKA/.reliquary-fetched 2>/dev/null || echo local`

if [ -f $BUILD/lib/libkyrka.a ] &&
    [ "`cat $BUILD/lib/.libkyrka 2>/dev/null`" = "$want" ]; then
	exit 0
fi

mkdir -p $BUILD/include/libkyrka $BUILD/lib

rm -rf $SRC
cp -R $LIBKYRKA $SRC
rm -rf $SRC/.git

if [ -d $LIBKYRKA/.git ]; then
	REV=`git -C $LIBKYRKA rev-parse --short=8 HEAD`
	BRANCH=`git -C $LIBKYRKA rev-parse --abbrev-ref HEAD`
	echo "$BRANCH-$REV" > $SRC/RELEASE
elif [ ! -f $SRC/RELEASE ]; then
	echo "unknown" > $SRC/RELEASE
fi

make -C $SRC OBJDIR=obj AR=$AR "$@"

cp $SRC/libkyrka.a $BUILD/lib/
cp $SRC/include/libkyrka/libkyrka.h $BUILD/include/libkyrka/

# We carry our own nyfe and mlkem1024, drop the copies libkyrka has
# except for its passphrase kdf, which our nyfe does not have.
$AR d $BUILD/lib/libkyrka.a \
    sha3.o kmac256.o keccak1600.o agelas.o mem.o random.o file.o utils.o \
    cbd.o fips202.o indcpa.o kem.o ntt.o poly.o polyvec.o reduce.o \
    symmetric-shake.o verify.o

echo "$want" > $BUILD/lib/.libkyrka
rm -rf $SRC
