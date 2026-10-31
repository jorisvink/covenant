#!/bin/sh

set -e

if [ $# -ne 3 ]; then
	echo "usage: mbedcrypto.sh <target> <cc> <ar>"
	exit 1
fi

TOPDIR=`pwd`
BUILD=$TOPDIR/build/$1
CC=$2
AR=$3
SRC=$TOPDIR/build/src/mbedtls
JOBS=`getconf _NPROCESSORS_ONLN 2> /dev/null || echo 4`

if [ ! -f $SRC/include/mbedtls/gcm.h ]; then
	echo "no mbedtls found at $SRC, run dist-build/deps.sh"
	exit 1
fi

if [ -f $BUILD/mbedtls/lib/libmbedcrypto.a ]; then
	exit 0
fi

rm -rf $BUILD/mbedtls-build $BUILD/mbedtls
mkdir -p $BUILD/mbedtls-build $BUILD/mbedtls/lib

files=`sed -n '/^set(src_crypto/,/)/p' $SRC/library/CMakeLists.txt | \
    grep '\.c$'`

echo "building mbedcrypto for $1"
n=0
for f in $files; do
	obj=$BUILD/mbedtls-build/`basename $f .c`.o
	$CC -O2 -fPIC -I$SRC/include -I$SRC/library \
	    -c $SRC/library/$f -o $obj &
	n=`expr $n + 1`
	if [ $n -ge $JOBS ]; then
		wait
		n=0
	fi
done
wait

$AR rcs $BUILD/mbedtls/lib/libmbedcrypto.a $BUILD/mbedtls-build/*.o
cp -R $SRC/include $BUILD/mbedtls/include
rm -rf $BUILD/mbedtls-build
