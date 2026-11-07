#!/bin/sh

set -e

TOPDIR=`pwd`
OUT=$TOPDIR/build/ios

./dist-build/deps.sh

mkdir -p $OUT

for target in ios-arm64 ios-simulator-arm64; do
	case $target in
	ios-arm64)
		sdk=iphoneos
		cflags="-arch arm64 -mios-version-min=15.0"
		;;
	ios-simulator-arm64)
		sdk=iphonesimulator
		cflags="-arch arm64 -mios-simulator-version-min=15.0"
		;;
	esac

	cc="xcrun -sdk $sdk clang $cflags"
	BUILD=$TOPDIR/build/$target
	sodium=$BUILD/libsodium

	./dist-build/libsodium.sh $target \
	    --host=aarch64-apple-darwin CC="$cc"

	./dist-build/mbedcrypto.sh $target "$cc" ar

	./dist-build/libkyrka.sh $target \
	    OSNAME=ios CROSS_BUILD=1 CC="$cc" LIBSODIUM_PATH=$sodium

	make clean-objs
	make PLATFORM=ios CC="$cc" DEPS=$BUILD libcovenant.a
	mv libcovenant.a $BUILD/lib/
	make clean-objs

	libtool -static -o $BUILD/lib/libcovenant-all.a \
	    $BUILD/lib/libcovenant.a \
	    $BUILD/lib/libkyrka.a \
	    $BUILD/mbedtls/lib/libmbedcrypto.a \
	    $sodium/lib/libsodium.a
done

rm -rf $OUT/Covenant.xcframework

mkdir -p $OUT/headers
cp include/covenant.h $OUT/headers/
cat > $OUT/headers/module.modulemap << _EOF
module Covenant {
	header "covenant.h"
	export *
}
_EOF

xcodebuild -create-xcframework \
    -library build/ios-arm64/lib/libcovenant-all.a -headers $OUT/headers \
    -library build/ios-simulator-arm64/lib/libcovenant-all.a \
    -headers $OUT/headers \
    -output $OUT/Covenant.xcframework
