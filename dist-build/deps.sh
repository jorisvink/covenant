#!/bin/sh

set -e

TOPDIR=`pwd`
SRC=$TOPDIR/build/src

. ./dist-build/fetch.sh

LIBSODIUM_VERSION=1.0.20
LIBSODIUM_URL=https://download.libsodium.org/libsodium/releases/libsodium-$LIBSODIUM_VERSION.tar.gz
LIBSODIUM_SHA256=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19

MBEDTLS_VERSION=3.6.7
MBEDTLS_URL=https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-$MBEDTLS_VERSION/mbedtls-$MBEDTLS_VERSION.tar.bz2
MBEDTLS_SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6

LIBKYRKA_VERSION=1.2.1
LIBKYRKA_URL=https://sanctorum.se/releases/libkyrka-$LIBKYRKA_VERSION.tgz
LIBKYRKA_SHA256=d9450f3b626d34e7f2ebcc7fae8eeb7b1633a67dcf6eb9ebbe0b8c0ce0529fd2

QRCODEGEN_VERSION=1.8.0
QRCODEGEN_URL=https://github.com/nayuki/QR-Code-generator/archive/refs/tags/v$QRCODEGEN_VERSION.tar.gz
QRCODEGEN_SHA256=2ec0a4d33d6f521c942eeaf473d42d5fe139abcfa57d2beffe10c5cf7d34ae60

fetch libsodium $LIBSODIUM_URL $LIBSODIUM_SHA256 \
    libsodium-$LIBSODIUM_VERSION.tar.gz $SRC
fetch mbedtls $MBEDTLS_URL $MBEDTLS_SHA256 \
    mbedtls-$MBEDTLS_VERSION.tar.bz2 $SRC
fetch libkyrka $LIBKYRKA_URL $LIBKYRKA_SHA256 \
    libkyrka-$LIBKYRKA_VERSION.tgz $SRC
fetch qrcodegen $QRCODEGEN_URL $QRCODEGEN_SHA256 \
    qrcodegen-$QRCODEGEN_VERSION.tar.gz $SRC
