#!/bin/sh

set -e

TOPDIR=`pwd`
OUT=$TOPDIR/build/ios

./dist-build/deps.sh

mkdir -p $OUT

if [ ! -d $OUT/Clibsodium.xcframework ]; then
	rm -rf $TOPDIR/build/ios-libsodium-src
	cp -R $TOPDIR/build/src/libsodium $TOPDIR/build/ios-libsodium-src
	(cd $TOPDIR/build/ios-libsodium-src && \
	    env LIBSODIUM_FULL_BUILD=1 LIBSODIUM_SKIP_SIMULATORS= \
	    IOS_VERSION_MIN=15.0.0 IOS_SIMULATOR_VERSION_MIN=15.0.0 \
	    ./dist-build/apple-xcframework.sh)
	rm -rf $OUT/Clibsodium.xcframework
	cp -r $TOPDIR/build/ios-libsodium-src/libsodium-apple/Clibsodium.xcframework \
	    $OUT/
	rm -rf $TOPDIR/build/ios-libsodium-src
fi

for target in ios-arm64 ios-simulator-arm64; do
	case $target in
	ios-arm64)
		sdk=iphoneos
		slice=ios-arm64
		cflags="-arch arm64 -mios-version-min=15.0"
		;;
	ios-simulator-arm64)
		sdk=iphonesimulator
		slice=ios-arm64_x86_64-simulator
		cflags="-arch arm64 -mios-simulator-version-min=15.0"
		;;
	esac

	cc="xcrun -sdk $sdk clang $cflags"
	BUILD=$TOPDIR/build/$target
	sodium=$BUILD/libsodium

	mkdir -p $sodium/include $sodium/lib $BUILD/lib
	cp -r $OUT/Clibsodium.xcframework/$slice/Headers/* $sodium/include/
	cp $OUT/Clibsodium.xcframework/$slice/libsodium.a $sodium/lib/

	./dist-build/mbedcrypto.sh $target "$cc" ar

	make clean-objs
	make PLATFORM=ios CC="$cc" DEPS=$BUILD libcovenant.a
	mv libcovenant.a $BUILD/lib/
	make clean-objs

	libtool -static -o $BUILD/lib/libcovenant-all.a \
	    $BUILD/lib/libcovenant.a \
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
