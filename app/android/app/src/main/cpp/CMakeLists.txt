# The covenant core and its Android glue as libcovenant.so, linked
# against what dist-build/android-build.sh built.

cmake_minimum_required(VERSION 3.22)
project(covenant C)

if(NOT RELIQUARY_ROOT)
	message(FATAL_ERROR "RELIQUARY_ROOT is not set")
endif()

set(DEPS ${RELIQUARY_ROOT}/build/android-${ANDROID_ABI})
set(QRCODEGEN ${RELIQUARY_ROOT}/build/src/qrcodegen/c)

if(NOT EXISTS ${DEPS}/mbedtls/lib/libmbedcrypto.a)
	message(FATAL_ERROR "no mbedcrypto for ${ANDROID_ABI}, "
	    "run dist-build/android-build.sh in ${RELIQUARY_ROOT} first")
endif()

if(NOT EXISTS ${DEPS}/lib/libkyrka.a)
	message(FATAL_ERROR "no libkyrka for ${ANDROID_ABI}, "
	    "run dist-build/android-build.sh in ${RELIQUARY_ROOT} first")
endif()

if(NOT EXISTS ${RELIQUARY_ROOT}/obj/version.c)
	message(FATAL_ERROR "no version.c, "
	    "run dist-build/android-build.sh in ${RELIQUARY_ROOT} first")
endif()

set(STRICT -std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
	-Wmissing-prototypes -Wmissing-declarations -Wshadow
	-Wpointer-arith -Wcast-qual -Wsign-compare -O2
	-fstack-protector-all -Wtype-limits -fno-common)

add_library(nyfe STATIC
	${RELIQUARY_ROOT}/nyfe/src/agelas.c
	${RELIQUARY_ROOT}/nyfe/src/file.c
	${RELIQUARY_ROOT}/nyfe/src/keccak1600.c
	${RELIQUARY_ROOT}/nyfe/src/kmac256.c
	${RELIQUARY_ROOT}/nyfe/src/mem.c
	${RELIQUARY_ROOT}/nyfe/src/random.c
	${RELIQUARY_ROOT}/nyfe/src/selftest.c
	${RELIQUARY_ROOT}/nyfe/src/sha3.c
	${RELIQUARY_ROOT}/nyfe/src/utils.c)

target_include_directories(nyfe PRIVATE ${RELIQUARY_ROOT}/nyfe/include)
target_compile_definitions(nyfe PRIVATE NYFE_LIBRARY_ONLY=1 _GNU_SOURCE=1)
target_compile_options(nyfe PRIVATE ${STRICT} -fPIC -fno-builtin)

# mlkem1024 as sanctum builds it.
add_library(mlkem1024 STATIC
	${RELIQUARY_ROOT}/mlkem1024/src/cbd.c
	${RELIQUARY_ROOT}/mlkem1024/src/fips202.c
	${RELIQUARY_ROOT}/mlkem1024/src/indcpa.c
	${RELIQUARY_ROOT}/mlkem1024/src/kem.c
	${RELIQUARY_ROOT}/mlkem1024/src/ntt.c
	${RELIQUARY_ROOT}/mlkem1024/src/poly.c
	${RELIQUARY_ROOT}/mlkem1024/src/polyvec.c
	${RELIQUARY_ROOT}/mlkem1024/src/reduce.c
	${RELIQUARY_ROOT}/mlkem1024/src/symmetric-shake.c
	${RELIQUARY_ROOT}/mlkem1024/src/verify.c)

target_include_directories(mlkem1024 PRIVATE ${RELIQUARY_ROOT}/nyfe/include)
target_compile_definitions(mlkem1024 PRIVATE KYBER_K=4 _GNU_SOURCE=1)
target_compile_options(mlkem1024 PRIVATE ${STRICT} -fPIC -fno-builtin)

add_library(qrcodegen STATIC ${QRCODEGEN}/qrcodegen.c)
target_compile_options(qrcodegen PRIVATE -std=c99 -O2 -fPIC)

add_library(covenant SHARED
	${RELIQUARY_ROOT}/src/covenant.c
	${RELIQUARY_ROOT}/src/ambry.c
	${RELIQUARY_ROOT}/src/backup.c
	${RELIQUARY_ROOT}/src/buf.c
	${RELIQUARY_ROOT}/src/cipher.c
	${RELIQUARY_ROOT}/src/keks.c
	${RELIQUARY_ROOT}/src/provision.c
	${RELIQUARY_ROOT}/src/qr.c
	${RELIQUARY_ROOT}/src/remote.c
	${RELIQUARY_ROOT}/src/wrap.c
	${RELIQUARY_ROOT}/src/platform_android.c
	${RELIQUARY_ROOT}/obj/version.c)

target_include_directories(covenant PRIVATE
	${RELIQUARY_ROOT}/include
	${RELIQUARY_ROOT}/nyfe/include
	${QRCODEGEN}
	${DEPS}/include
	${DEPS}/mbedtls/include
	${DEPS}/libsodium/include)

target_compile_definitions(covenant PRIVATE PLATFORM_ANDROID _GNU_SOURCE=1)
target_compile_options(covenant PRIVATE ${STRICT})

target_link_libraries(covenant
	${DEPS}/lib/libkyrka.a
	nyfe
	mlkem1024
	qrcodegen
	${DEPS}/mbedtls/lib/libmbedcrypto.a
	${DEPS}/libsodium/lib/libsodium.a
	log)

target_link_options(covenant PRIVATE "-Wl,-z,max-page-size=16384")
