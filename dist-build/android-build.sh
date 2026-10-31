#!/bin/sh

set -e

TOPDIR=`pwd`
API=30

./dist-build/deps.sh

. ./dist-build/android-sdk.sh

HOST=`uname -s | tr '[:upper:]' '[:lower:]'`-x86_64
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/$HOST/bin

if [ ! -d $TOOLCHAIN ]; then
	echo "no android ndk $NDK_VERSION found at $NDK"
	echo "point ANDROID_NDK_HOME at a standalone ndk"
	exit 1
fi

echo "using android sdk $SDK"
echo "using android ndk $NDK ($NDK_VERSION)"

for abi in arm64-v8a x86_64; do
	case $abi in
	arm64-v8a)
		script=android-armv8-a.sh
		sodium=libsodium-android-armv8-a+crypto
		cc=aarch64-linux-android$API-clang
		;;
	x86_64)
		script=android-x86_64.sh
		sodium=libsodium-android-westmere
		cc=x86_64-linux-android$API-clang
		;;
	esac

	BUILD=$TOPDIR/build/android-$abi

	if [ -f $BUILD/.ndk ] && [ "`cat $BUILD/.ndk`" != "$NDK" ]; then
		echo "ndk changed for $abi, rebuilding its dependencies"
		rm -rf $BUILD
	fi

	mkdir -p $BUILD
	echo "$NDK" > $BUILD/.ndk

	if [ ! -f $BUILD/libsodium/lib/libsodium.a ]; then
		rm -rf $BUILD/libsodium-src $BUILD/libsodium
		cp -R $TOPDIR/build/src/libsodium $BUILD/libsodium-src

		(cd $BUILD/libsodium-src && \
		    env ANDROID_NDK_HOME=$NDK NDK_PLATFORM=android-$API \
		    LIBSODIUM_FULL_BUILD=1 ./dist-build/$script)

		cp -R $BUILD/libsodium-src/$sodium $BUILD/libsodium
		rm -rf $BUILD/libsodium-src
	fi

	./dist-build/mbedcrypto.sh android-$abi \
	    $TOOLCHAIN/$cc $TOOLCHAIN/llvm-ar
done

make version

. ./dist-build/flutter.sh
(cd app && $FLUTTER pub get)
