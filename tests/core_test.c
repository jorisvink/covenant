/*
 * Copyright (c) 2026 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "covenant-int.h"
#include "wordlist.h"

/*
 * Tests for the C library. When ambry is in our PATH (or $AMBRY
 * points to it) we also check ourselves against it, both the KEK
 * derivation and that bundles from either of us unwrap the way chapel
 * unwraps them.
 */

#define TEST_FLOCK	0x493abf95a07e0c00ULL

#define CHECK(x)							\
	do {								\
		if (!(x)) {						\
			fprintf(stderr, "%s:%d: check failed: %s (%u)\n",\
			    __FILE__, __LINE__, #x,			\
			    covenant_last_error(ctx));			\
			exit(1);					\
		}							\
	} while (0)

static int	test_ambry_find(const char *);
static void	test_file_read(const char *, u_int8_t *, size_t);
static void	test_ambry_reference(const char *, u_int8_t *, size_t);
static int	test_ambry_unwrap(const u_int8_t *, size_t,
		    u_int64_t, const u_int8_t *, size_t);

static void	test_version(void);
static void	test_key_wrap(void);
static void	test_qr_limit(void);
static void	test_cosk_limit(void);
static void	test_kek_derive(void);
static void	test_remote_words(void);
static void	test_cipher_vector(void);
static void	test_emergency_erase(void);
static void	test_fatal_report(const char *, va_list);
static void	test_hex(const char *, u_int8_t *, size_t);
static void	test_fatal(const u_int8_t *, const u_int8_t *, int);
static void	test_backup_remac(const u_int8_t *, u_int8_t *, size_t);

static void	test_wrong_vault(const u_int8_t *, const u_int8_t *);
static void	test_backup_forged(const u_int8_t *, const u_int8_t *);

static void	test_keks_seal(const u_int8_t *, const u_int8_t *);
static void	test_keks_renew(const u_int8_t *, const u_int8_t *);
static void	test_config_build(const u_int8_t *, const u_int8_t *);
static void	test_config_name(const struct covenant_keks *, const char *,
		    u_int8_t, const char *);
static void	test_provision_qr(const u_int8_t *, const u_int8_t *);
static void	test_config_remote(const u_int8_t *, const u_int8_t *);
static void	test_remote_start(const u_int8_t *, const u_int8_t *);
static void	test_backup_restore(const u_int8_t *, const u_int8_t *);
static void	test_provision_config(const u_int8_t *, const u_int8_t *);
static void	test_route_decode(const char *, struct covenant_route *,
		    char *, size_t);
static void	test_ambry_bundle(const u_int8_t *, const u_int8_t *,
		    const u_int8_t *);

/* The path to ambry, when we have one. */
static char	ambry[1024];

/* Where a forked child reports what it saw in the fatal callback. */
static int		fatal_fd = -1;
static u_int8_t		*fatal_key = NULL;

#if defined(COVENANT_COVERAGE)
/* Flushes coverage data, a child that aborts would lose it otherwise. */
extern void	__gcov_dump(void);
#endif

/* The context all tests run under. */
static COVENANT	*ctx = NULL;

int
main(void)
{
	int		have;
	u_int8_t	data[COVENANT_KEKS_DATA_LEN];
	u_int8_t	secret[COVENANT_VAULT_KEY_LEN];
	u_int8_t	sealed[COVENANT_KEKS_SEALED_LEN];
	char		dir[] = "/tmp/covenant-test.XXXXXXXX";

	CHECK((ctx = covenant_ctx_alloc()) != NULL);
	CHECK(covenant_last_error(NULL) == COVENANT_ERROR_NO_CONTEXT);
	CHECK(covenant_random_bytes(ctx, secret, sizeof(secret)) == 0);
	CHECK(covenant_random_bytes(NULL, secret, sizeof(secret)) == -1);
	CHECK(covenant_random_bytes(ctx, NULL, sizeof(secret)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	CHECK(covenant_random_bytes(ctx, secret, 0) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	CHECK(covenant_random_bytes(ctx, NULL, 0) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);


	have = test_ambry_find(getenv("AMBRY"));

	if (have) {
		CHECK(mkdtemp(dir) != NULL);
		CHECK(chdir(dir) == 0);
		test_ambry_reference(dir, data, sizeof(data));
		covenant_keks_import(ctx, secret, sizeof(secret),
		    TEST_FLOCK, data, sizeof(data), sealed,
		    sizeof(sealed));
	} else {
		printf("no ambry found, not testing against it\n");
		covenant_keks_generate(ctx, secret, sizeof(secret),
		    TEST_FLOCK, sealed, sizeof(sealed));
	}

	test_keks_seal(secret, sealed);
	test_ambry_bundle(secret, sealed, have ? data : NULL);
	test_config_build(secret, sealed);
	test_provision_qr(secret, sealed);
	test_provision_config(secret, sealed);
	test_keks_renew(secret, sealed);
	test_backup_restore(secret, sealed);
	test_key_wrap();
	test_remote_words();
	test_config_remote(secret, sealed);
	test_remote_start(secret, sealed);
	test_version();
	test_qr_limit();
	test_cosk_limit();
	test_kek_derive();
	test_cipher_vector();
	test_wrong_vault(secret, sealed);
	test_backup_forged(secret, sealed);
	test_emergency_erase();
	test_fatal(secret, sealed, 1);
	test_fatal(secret, sealed, 0);

	if (have) {
		CHECK(system("rm -rf 493abf95a07e0c00 ref.bundle") == 0);
		CHECK(chdir("/") == 0);
		CHECK(rmdir(dir) == 0);
	}

	covenant_ctx_free(ctx);
	printf("ok\n");

	return (0);
}

/*
 * Wrap a vault key under a passphrase and make sure only that passphrase
 * opens it again.
 */
static void
test_key_wrap(void)
{
	size_t		idx;
	u_int8_t	key[COVENANT_VAULT_KEY_LEN];
	u_int8_t	out[COVENANT_VAULT_KEY_LEN];
	u_int8_t	copy[COVENANT_WRAPPED_KEY_LEN];
	u_int8_t	other[COVENANT_WRAPPED_KEY_LEN];
	u_int8_t	wrapped[COVENANT_WRAPPED_KEY_LEN];

	CHECK(covenant_random_bytes(ctx, key, sizeof(key)) == 0);

	covenant_key_wrap(ctx, "hunter2", 7, key, sizeof(key),
	    wrapped, sizeof(wrapped));
	CHECK(covenant_key_unwrap(ctx, "hunter2", 7, wrapped,
	    sizeof(wrapped), out, sizeof(out)) == 0);
	CHECK(memcmp(key, out, sizeof(key)) == 0);

	CHECK(covenant_key_unwrap(ctx, "hunter3", 7, wrapped,
	    sizeof(wrapped), out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PASSPHRASE);

	/* Flipping a bit anywhere, header included, must be caught. */
	for (idx = 8; idx < sizeof(wrapped); idx += 19) {
		memcpy(copy, wrapped, sizeof(copy));
		copy[idx] ^= 0x80;
		CHECK(covenant_key_unwrap(ctx, "hunter2", 7, copy,
		    sizeof(copy), out, sizeof(out)) == -1);
		CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PASSPHRASE);
	}

	memcpy(copy, wrapped, sizeof(copy));
	copy[7] ^= 0x01;
	CHECK(covenant_key_unwrap(ctx, "hunter2", 7, copy,
	    sizeof(copy), out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);

	/* Not a wrapped key at all. */
	memcpy(copy, wrapped, sizeof(copy));
	memcpy(copy, "COVK", 4);
	CHECK(covenant_key_unwrap(ctx, "hunter2", 7, copy,
	    sizeof(copy), out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);

	/* Two wraps of the same key must never look the same. */
	covenant_key_wrap(ctx, "hunter2", 7, key, sizeof(key),
	    other, sizeof(other));
	CHECK(memcmp(wrapped + 8, other + 8, sizeof(other) - 8) != 0);
}

/*
 * Seal and open KEKs and make sure we catch anything that is off.
 */
static void
test_keks_seal(const u_int8_t *secret, const u_int8_t *sealed)
{
	size_t			idx;
	struct covenant_info	info;
	struct covenant_keks	*keks;
	u_int8_t		bad[COVENANT_VAULT_KEY_LEN];
	u_int8_t		copy[COVENANT_KEKS_SEALED_LEN];
	u_int8_t		other[COVENANT_KEKS_SEALED_LEN];

	CHECK(covenant_keks_info(ctx, sealed,
	    COVENANT_KEKS_SEALED_LEN, &info) == 0);
	CHECK(info.flock == TEST_FLOCK);
	CHECK(info.created + 60 >= (u_int64_t)time(NULL));

	CHECK(covenant_keks_check(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN) == 0);

	memcpy(bad, secret, sizeof(bad));
	bad[0] ^= 0x01;
	CHECK(covenant_keks_check(ctx, bad, sizeof(bad),
	    sealed, COVENANT_KEKS_SEALED_LEN) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);

	/* Flipping a bit anywhere, header included, must be caught. */
	for (idx = 0; idx < COVENANT_KEKS_SEALED_LEN; idx += 97) {
		memcpy(copy, sealed, sizeof(copy));
		copy[idx] ^= 0x80;
		CHECK(covenant_keks_check(ctx, secret, COVENANT_VAULT_KEY_LEN,
		    copy, sizeof(copy)) == -1);
	}

	/* An unknown version must be told apart from a broken seal. */
	memcpy(copy, sealed, sizeof(copy));
	copy[7] ^= 0x01;
	CHECK(covenant_keks_check(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    copy, sizeof(copy)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);

	/* Version 1, from before the signing seed, is no longer taken. */
	memcpy(copy, sealed, sizeof(copy));
	copy[7] = 0x01;
	CHECK(covenant_keks_info(ctx, copy, sizeof(copy), &info) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);
	CHECK(covenant_keks_info(ctx, copy,
	    sizeof(copy) - COVENANT_SIGN_SEED_LEN, &info) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);

	/* Two seals of the same flock must never look the same. */
	covenant_keks_generate(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    TEST_FLOCK, copy, sizeof(copy));
	covenant_keks_generate(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    TEST_FLOCK, other, sizeof(other));
	CHECK(memcmp(copy + 24, other + 24, sizeof(copy) - 24) != 0);

	/* And the generated KEKs must not all be the same either. */
	covenant_lock();
	CHECK((keks = covenant_keks_open(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    copy, sizeof(copy))) != NULL);
	CHECK(memcmp(keks->kek[0], keks->kek[1], COVENANT_KEK_LEN) != 0);
	CHECK(memcmp(keks->kek[0], keks->kek[254], COVENANT_KEK_LEN) != 0);
	covenant_keks_close(keks);
	covenant_unlock();
}

/*
 * Check that our bundles unwrap the way chapel unwraps them, and that the
 * bundles ambry makes unwrap with that same code.
 */
static void
test_ambry_bundle(const u_int8_t *secret, const u_int8_t *sealed,
    const u_int8_t *data)
{
	u_int32_t			gen;
	u_int8_t			*ours;
	struct covenant_keks		*keks;
	u_int16_t			expires;
	u_int8_t			*bundle;
	struct sanctum_ambry_head	hdr, ref;

	CHECK((bundle = calloc(1, COVENANT_AMBRY_LEN)) != NULL);

	CHECK(covenant_ambry_bundle(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN, 30, bundle, COVENANT_AMBRY_LEN,
	    &gen, &expires) == 0);

	memcpy(&hdr, bundle, sizeof(hdr));
	CHECK(be32toh(hdr.generation) == gen);
	CHECK(be16toh(hdr.expires) == expires);

	CHECK(covenant_ambry_bundle(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN, COVENANT_AMBRY_DAYS_MAX, bundle,
	    COVENANT_AMBRY_LEN, &gen, &expires) == 0);

	CHECK(covenant_ambry_bundle(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN, 30, bundle, COVENANT_AMBRY_LEN,
	    &gen, &expires) == 0);
	memcpy(&hdr, bundle, sizeof(hdr));

	CHECK((ours = malloc(COVENANT_KEKS_DATA_LEN)) != NULL);

	covenant_lock();
	CHECK((keks = covenant_keks_open(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN)) != NULL);
	memcpy(ours, keks->kek, COVENANT_KEKS_DATA_LEN);
	covenant_keks_close(keks);
	covenant_unlock();

	CHECK(test_ambry_unwrap(bundle, COVENANT_AMBRY_LEN,
	    TEST_FLOCK, ours, COVENANT_KEKS_DATA_LEN) == 0);

	if (data != NULL) {
		CHECK(memcmp(ours, data, COVENANT_KEKS_DATA_LEN) == 0);

		/* The reference bundle must unwrap with the same code. */
		CHECK(system("$AMBRY_BIN bundle 493abf95a07e0c00 "
		    "493abf95a07e0c00 30 ref.bundle > /dev/null 2>&1") == 0);
		test_file_read("ref.bundle", bundle, COVENANT_AMBRY_LEN);
		CHECK(test_ambry_unwrap(bundle, COVENANT_AMBRY_LEN,
		    TEST_FLOCK, data, COVENANT_KEKS_DATA_LEN) == 0);

		memcpy(&ref, bundle, sizeof(ref));
		CHECK(ref.expires == hdr.expires);
	}

	nyfe_mem_zero(ours, COVENANT_KEKS_DATA_LEN);

	free(ours);
	free(bundle);
}

/*
 * Check the configuration we put together, and everything we refuse
 * to put together.
 */
static void
test_config_build(const u_int8_t *secret, const u_int8_t *sealed)
{
	int			len;
	struct covenant_keks	*keks;
	char			sk_hex[129];
	u_int8_t		cs[32], sk[64];
	u_int8_t		pk[32], seed_sk[64];
	char			out[2048], want[2048];
	char			kek[65], cs_hex[65], pk_hex[65];
	const char		*public =
	    "vigil 1\n"
	    "instance laptop\n"
	    "tunnel 10.88.0.2/24\n"
	    "spi 0c0d\n"
	    "cathedral cathedral.reliquary.se:4469\n"
	    "cathedral_id 5eb2411f\n"
	    "cathedral_flock 493abf95a07e0c00\n";
	const char		*gospel =
	    "vigil 1\n"
	    "instance laptop\n"
	    "mode gospel\n"
	    "spi 0c\n"
	    "cathedral cathedral.reliquary.se:4469\n"
	    "cathedral_id 5eb2411f\n"
	    "cathedral_flock 493abf95a07e0c00\n";

	memset(cs, 0xc5, sizeof(cs));
	memset(sk, 0x5c, sizeof(sk));
	(void)sodium_bin2hex(cs_hex, sizeof(cs_hex), cs, sizeof(cs));
	(void)sodium_bin2hex(sk_hex, sizeof(sk_hex), sk, sizeof(sk));

	covenant_lock();
	CHECK((keks = covenant_keks_open(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN)) != NULL);

	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), public, out, sizeof(out)) == 0);

	(void)sodium_bin2hex(kek, sizeof(kek),
	    keks->kek[0x0c - 1], COVENANT_KEK_LEN);

	/* Only comms gets a signed name. */
	len = snprintf(want, sizeof(want), "%skek %s\ncathedral_secret %s\n"
	    "cathedral_cosk %s\n", public, kek, cs_hex, sk_hex);
	CHECK(len >= 0 && (size_t)len < sizeof(want));
	CHECK(strcmp(out, want) == 0);

	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), gospel, out, sizeof(out)) == 0);

	CHECK(crypto_sign_seed_keypair(pk, seed_sk, keks->seed) == 0);
	(void)sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
	nyfe_mem_zero(seed_sk, sizeof(seed_sk));

	len = snprintf(want, sizeof(want), "%skek %s\ncathedral_secret %s\n"
	    "cathedral_cosk %s\nname_pubkey %s\nname_signature ",
	    gospel, kek, cs_hex, sk_hex, pk_hex);
	CHECK(len >= 0 && (size_t)len < sizeof(want));
	CHECK(strncmp(out, want, len) == 0);
	CHECK(strlen(out) == (size_t)len + (COVENANT_SIGNATURE_LEN * 2) + 1);

	test_config_name(keks, out, 0x0c, "laptop");

	/* Every device needs a name to sign. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);

	/* The flock key or a signature smuggled in. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\nname_pubkey 00\n",
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_KEYS);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\nname_signature 00\n",
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_KEYS);

	/* An instance vigil would refuse, or two of them. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance bad/name\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance a\ninstance b\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance "
	    "0123456789012345678901234567890123456789012345678901234567890123"
	    "\nspi 0c\ncathedral_flock 493abf95a07e0c00\n",
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);

	/* Wrong KEK for the spi. */
	CHECK(covenant_config_build(ctx, keks, 0x0d, cs, sizeof(cs),
	    sk, sizeof(sk), public, out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_SPI);

	/* Another flock. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0d00\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_FLOCK);

	/* A tier6 configuration picks its own flock domain, nothing else. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nmode liturgy\n"
	    "tier6 yes\nspi 0c\ncathedral_flock 493abf95a07e0c66\n",
	    out, sizeof(out)) == 0);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c66\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_FLOCK);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\ntier6 yes\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0d66\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_FLOCK);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\ntier6 yes\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c6\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_FLOCK);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\ntier6 yes\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0cG6\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_FLOCK);

	/* Keys smuggled in. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\nkek 00\n",
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_KEYS);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\ncathedral_cosk 00\n",
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_KEYS);

	/* Not a vigil config, or odd characters. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "spi 0c\ncathedral_flock 493abf95a07e0c00\n",
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\t\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);

	/* Options vigil would find behind whitespace we do not skip. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\n"
	    " cathedral_flock 493abf95a07e0d00\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\n  spi 0d\n",
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi  0d\n"
	    "cathedral_flock 493abf95a07e0c00\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop \nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance laptop\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\n \n", out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);

	/* Too small to hold it all. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), public, out, 300) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG);

	/* Liturgy style, spi is just our KEK and no trailing newline. */
	CHECK(covenant_config_build(ctx, keks, 0x0c, cs, sizeof(cs),
	    sk, sizeof(sk), "vigil 1\ninstance mesh\nmode liturgy\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00", out, sizeof(out)) == 0);
	CHECK(strstr(out, "493abf95a07e0c00\nkek ") != NULL);

	covenant_keks_close(keks);
	covenant_unlock();
}

/*
 * Check the name_signature in config the way vigil does, rebuilding
 * what was signed from the flock, the KEK id and the name.
 */
static void
test_config_name(const struct covenant_keks *keks, const char *config,
    u_int8_t kek, const char *name)
{
	u_int64_t	flock;
	size_t		len, off;
	const char	*sig_hex, *pk_hex;
	u_int8_t	pk[32], sig[64], msg[128];

	CHECK((pk_hex = strstr(config, "\nname_pubkey ")) != NULL);
	CHECK((sig_hex = strstr(config, "\nname_signature ")) != NULL);

	pk_hex += strlen("\nname_pubkey ");
	sig_hex += strlen("\nname_signature ");

	CHECK(sodium_hex2bin(pk, sizeof(pk), pk_hex, sizeof(pk) * 2,
	    NULL, &len, NULL) == 0 && len == sizeof(pk));
	CHECK(sodium_hex2bin(sig, sizeof(sig), sig_hex, sizeof(sig) * 2,
	    NULL, &len, NULL) == 0 && len == sizeof(sig));

	off = strlen(COVENANT_NAME_LABEL);
	memcpy(msg, COVENANT_NAME_LABEL, off);

	flock = htobe64(keks->flock);
	memcpy(&msg[off], &flock, sizeof(flock));
	off += sizeof(flock);

	len = strlen(name);
	msg[off++] = kek;
	msg[off++] = (u_int8_t)len;
	memcpy(&msg[off], name, len);
	off += len;

	CHECK(crypto_sign_verify_detached(sig, msg, off, pk) == 0);

	/* Another KEK id or another name must not verify. */
	msg[strlen(COVENANT_NAME_LABEL) + sizeof(flock)] = kek + 1;
	CHECK(crypto_sign_verify_detached(sig, msg, off, pk) != 0);
	msg[strlen(COVENANT_NAME_LABEL) + sizeof(flock)] = kek;

	msg[off - 1] ^= 0x01;
	CHECK(crypto_sign_verify_detached(sig, msg, off, pk) != 0);
}

/*
 * Take a device from its cosk all the way to a QR code, the cosk must
 * be consumed by it.
 */
static void
test_provision_qr(const u_int8_t *secret, const u_int8_t *sealed)
{
	struct covenant_device	dev;
	int			side;
	u_int32_t		handle;
	u_int8_t		qr[COVENANT_QR_MAX_LEN];
	u_int8_t		pk[COVENANT_COSK_PUBLIC_LEN];

	CHECK(covenant_cosk_new(ctx, &handle, pk, sizeof(pk) - 1) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	CHECK(covenant_cosk_new(ctx, &handle, pk, sizeof(pk)) == 0);
	CHECK(handle != 0);

	memset(&dev, 0, sizeof(dev));
	dev.secret = secret;
	dev.secret_len = COVENANT_VAULT_KEY_LEN;
	dev.keks = sealed;
	dev.keks_len = COVENANT_KEKS_SEALED_LEN;
	dev.cosk = handle;
	dev.kek = 0x0c;
	dev.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";
	dev.config =
	    "vigil 1\n"
	    "instance mesh\n"
	    "mode liturgy\n"
	    "liturgy_prefix 172.31.0.0\n"
	    "liturgy_group 0001\n"
	    "spi 0c\n"
	    "cathedral cathedral.reliquary.se:4469\n"
	    "cathedral_id 5eb2411f\n"
	    "cathedral_flock 493abf95a07e0c00\n";

	/* A failure leaves the cosk in place so it can be tried again. */
	dev.kek = 0x0d;
	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_SPI);
	dev.kek = 0x0c;

	dev.cathedral_secret = "c5";
	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	dev.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";

	CHECK(covenant_provision(ctx, &dev, qr, 10, &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_QR_SIZE);

	dev.keks_len = COVENANT_KEKS_SEALED_LEN - 1;
	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	dev.keks_len = COVENANT_KEKS_SEALED_LEN;

	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == 0);
	CHECK(side >= 21 && side <= COVENANT_QR_SIDE_MAX);

	/* Finder pattern in the top left corner. */
	CHECK(qr[0] == 1 && qr[6] == 1 && qr[(6 * side)] == 1);
	CHECK(qr[(1 * side) + 1] == 0 && qr[(2 * side) + 2] == 1);

	/* The cosk was consumed by the device. */
	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_COSK);

	CHECK(covenant_cosk_new(ctx, &handle, pk, sizeof(pk)) == 0);
	CHECK(covenant_cosk_drop(ctx, handle) == 0);
	CHECK(covenant_cosk_drop(ctx, handle) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_COSK);

	dev.cosk = handle;
	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_COSK);

	CHECK(covenant_qr_encode(ctx, "vigil 1\n", qr, sizeof(qr), &side) == 0);
	CHECK(side == 21);
}

/*
 * Provision a device into its configuration for vigil on the same
 * device, it must carry the keys and consume the cosk.
 */
static void
test_provision_config(const u_int8_t *secret, const u_int8_t *sealed)
{
	u_int32_t		handle;
	struct covenant_device	dev;
	char			config[COVENANT_CONFIG_MAX_LEN];
	u_int8_t		pk[COVENANT_COSK_PUBLIC_LEN];

	CHECK(covenant_cosk_new(ctx, &handle, pk, sizeof(pk)) == 0);

	memset(&dev, 0, sizeof(dev));
	dev.secret = secret;
	dev.secret_len = COVENANT_VAULT_KEY_LEN;
	dev.keks = sealed;
	dev.keks_len = COVENANT_KEKS_SEALED_LEN;
	dev.cosk = handle;
	dev.kek = 0x0c;
	dev.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";
	dev.config =
	    "vigil 1\n"
	    "instance phone\n"
	    "mode gospel\n"
	    "spi 0c\n"
	    "cathedral cathedral.reliquary.se:4469\n"
	    "cathedral_id 5eb2411f\n"
	    "cathedral_flock 493abf95a07e0c00\n";

	CHECK(covenant_provision_config(NULL, &dev, config,
	    sizeof(config)) == -1);
	CHECK(covenant_provision_config(ctx, NULL, config,
	    sizeof(config)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	CHECK(covenant_provision_config(ctx, &dev, NULL, sizeof(config)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	CHECK(covenant_provision_config(ctx, &dev, config,
	    sizeof(config) - 1) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);

	CHECK(covenant_provision_config(ctx, &dev, config,
	    sizeof(config)) == 0);
	CHECK(!strncmp(config, dev.config, strlen(dev.config)));
	CHECK(strstr(config, "\nkek ") != NULL);
	CHECK(strstr(config, "\ncathedral_secret c5c5") != NULL);
	CHECK(strstr(config, "\ncathedral_cosk ") != NULL);

	/* The cosk was consumed by the device. */
	CHECK(covenant_provision_config(ctx, &dev, config,
	    sizeof(config)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_COSK);
}

/*
 * Make the words for a remote device and read the route back from them
 * the way the device does.
 */
static void
test_remote_words(void)
{
	struct covenant_route	route, got;
	char			pass[COVENANT_PASSPHRASE_LEN];
	char			again[COVENANT_REMOTE_WORDS_LEN];
	char			words[COVENANT_REMOTE_WORDS_LEN];

	memset(&route, 0, sizeof(route));
	route.flock = TEST_FLOCK;
	route.identity = 0xdeadbeef;
	route.cathedral = 0xc0a80101;
	route.port = 4469;
	route.kek = 0x01;
	route.peer = 0xfe;

	CHECK(covenant_remote_words(NULL, &route, words, sizeof(words)) == -1);
	CHECK(covenant_remote_words(ctx, NULL, words, sizeof(words)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	CHECK(covenant_remote_words(ctx, &route, words,
	    sizeof(words) - 1) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);

	/* A flock with its domain, or the same KEK on both ends. */
	route.flock = TEST_FLOCK | 0x01;
	CHECK(covenant_remote_words(ctx, &route, words, sizeof(words)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	route.flock = TEST_FLOCK;

	route.peer = route.kek;
	CHECK(covenant_remote_words(ctx, &route, words, sizeof(words)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	route.peer = 0xfe;

	CHECK(covenant_remote_words(ctx, &route, words, sizeof(words)) == 0);
	test_route_decode(words, &got, pass, sizeof(pass));

	CHECK(got.flock == route.flock);
	CHECK(got.identity == route.identity);
	CHECK(got.cathedral == route.cathedral);
	CHECK(got.port == route.port);
	CHECK(got.kek == route.kek);
	CHECK(got.peer == route.peer);

	/* A fresh passphrase every time. */
	CHECK(covenant_remote_words(ctx, &route, again, sizeof(again)) == 0);
	CHECK(strcmp(words, again) != 0);

	covenant_remote_stop(ctx);
	covenant_remote_stop(ctx);
}

/*
 * Read the route and the passphrase back from the words, checking that
 * the checksum is right and that it catches a word that is off.
 */
static void
test_route_decode(const char *words, struct covenant_route *route,
    char *pass, size_t pass_len)
{
	struct nyfe_sha3	sha;
	int			count;
	u_int32_t		val, id;
	size_t			idx, len, off;
	u_int16_t		port, which[COVENANT_ROUTE_WORDS];
	u_int8_t		data[COVENANT_ROUTE_LEN], digest[32];
	char			copy[COVENANT_REMOTE_WORDS_LEN], *word, *next;

	CHECK(strlen(words) < sizeof(copy));
	memcpy(copy, words, strlen(words) + 1);

	count = 0;
	pass[0] = '\0';

	for (word = copy; word != NULL; word = next) {
		if ((next = strchr(word, ' ')) != NULL)
			*(next)++ = '\0';

		for (idx = 0; idx < COVENANT_WORD_COUNT; idx++) {
			if (!strcmp(covenant_words[idx], word))
				break;
		}

		CHECK(idx < COVENANT_WORD_COUNT);

		if (count < COVENANT_ROUTE_WORDS) {
			which[count] = idx;
		} else {
			len = strlen(pass);
			CHECK(snprintf(pass + len, pass_len - len,
			    "%s ", word) < (int)(pass_len - len));
		}

		count++;
	}

	CHECK(count == COVENANT_ROUTE_WORDS + COVENANT_PASSPHRASE_WORDS);

	memset(data, 0, sizeof(data));

	for (idx = 0; idx < COVENANT_ROUTE_WORDS; idx++) {
		val = which[idx];
		for (off = sizeof(data); off > 0; off--) {
			val += data[off - 1] * COVENANT_WORD_COUNT;
			data[off - 1] = val & 0xff;
			val >>= 8;
		}
		CHECK(val == 0);
	}

	nyfe_sha3_init256(&sha);
	nyfe_sha3_update(&sha, COVENANT_ROUTE_LABEL,
	    strlen(COVENANT_ROUTE_LABEL));
	nyfe_sha3_update(&sha, data, 19);
	nyfe_sha3_update(&sha, pass, strlen(pass));
	nyfe_sha3_final(&sha, digest, sizeof(digest));

	CHECK(data[19] == digest[0] && data[20] == digest[1]);

	memset(route, 0, sizeof(*route));

	memcpy(&route->flock, &data[0], 7);
	route->flock = be64toh(route->flock);

	memcpy(&id, &data[7], sizeof(id));
	route->identity = be32toh(id);

	route->kek = data[11];
	route->peer = data[12];

	memcpy(&id, &data[13], sizeof(id));
	route->cathedral = be32toh(id);

	memcpy(&port, &data[17], sizeof(port));
	route->port = be16toh(port);

	/* Another passphrase must not match the checksum. */
	if (pass[0] == 'a')
		pass[0] = 'b';
	else
		pass[0] = 'a';

	nyfe_sha3_init256(&sha);
	nyfe_sha3_update(&sha, COVENANT_ROUTE_LABEL,
	    strlen(COVENANT_ROUTE_LABEL));
	nyfe_sha3_update(&sha, data, 19);
	nyfe_sha3_update(&sha, pass, strlen(pass));
	nyfe_sha3_final(&sha, digest, sizeof(digest));

	CHECK(data[19] != digest[0] || data[20] != digest[1]);
}

/*
 * The configuration for a remote device carries the KEK and the signed
 * name but none of the keys the device has itself.
 */
static void
test_config_remote(const u_int8_t *secret, const u_int8_t *sealed)
{
	int			len;
	struct covenant_keks	*keks;
	u_int8_t		pk[32], seed_sk[64];
	char			out[COVENANT_REMOTE_CONFIG_LEN];
	char			kek[65], pk_hex[65], want[2048];
	const char		*public =
	    "vigil 1\n"
	    "instance far away\n"
	    "mode gospel\n"
	    "spi 0c\n"
	    "cathedral 192.168.1.1:4469\n"
	    "cathedral_id 5eb2411f\n"
	    "cathedral_flock 493abf95a07e0c00\n";

	covenant_lock();
	CHECK((keks = covenant_keks_open(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN)) != NULL);

	CHECK(covenant_config_remote(ctx, keks, 0x0c, public,
	    out, sizeof(out)) == 0);

	(void)sodium_bin2hex(kek, sizeof(kek),
	    keks->kek[0x0c - 1], COVENANT_KEK_LEN);

	CHECK(crypto_sign_seed_keypair(pk, seed_sk, keks->seed) == 0);
	(void)sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
	nyfe_mem_zero(seed_sk, sizeof(seed_sk));

	len = snprintf(want, sizeof(want),
	    "%skek %s\nname_pubkey %s\nname_signature ", public, kek, pk_hex);
	CHECK(len >= 0 && (size_t)len < sizeof(want));
	CHECK(strncmp(out, want, len) == 0);
	CHECK(strlen(out) == (size_t)len + (COVENANT_SIGNATURE_LEN * 2) + 1);

	test_config_name(keks, out, 0x0c, "far away");

	/* Only comms gets a signed name. */
	CHECK(covenant_config_remote(ctx, keks, 0x0c, "vigil 1\n"
	    "instance far away\nmode liturgy\ntier6 yes\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c66\n", out, sizeof(out)) == 0);
	CHECK(strstr(out, "name_pubkey") == NULL);
	CHECK(strstr(out, "name_signature") == NULL);

	/* The same checks apply as for any other device. */
	CHECK(covenant_config_remote(ctx, keks, 0x0d, public,
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_SPI);
	CHECK(covenant_config_remote(ctx, keks, 0x0c, "vigil 1\nspi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\ncathedral_secret 00\n",
	    out, sizeof(out)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_KEYS);

	covenant_keks_close(keks);
	covenant_unlock();
}

/*
 * Start the tunnel to a remote device, everything we refuse to start
 * it with and that the cosk is only consumed once it is up.
 */
static void
test_remote_start(const u_int8_t *secret, const u_int8_t *sealed)
{
	struct covenant_remote	rem;
	struct covenant_route	route;
	u_int32_t		handle;
	u_int8_t		other[COVENANT_VAULT_KEY_LEN];
	u_int8_t		pk[COVENANT_COSK_PUBLIC_LEN];
	char			words[COVENANT_REMOTE_WORDS_LEN];
	u_int8_t		elsewhere[COVENANT_KEKS_SEALED_LEN];

	CHECK(covenant_cosk_new(ctx, &handle, pk, sizeof(pk)) == 0);

	memset(&rem, 0, sizeof(rem));
	rem.secret = secret;
	rem.secret_len = COVENANT_VAULT_KEY_LEN;
	rem.keks = sealed;
	rem.keks_len = COVENANT_KEKS_SEALED_LEN;
	rem.cosk = handle;
	rem.device = 0x5eb2411f;
	rem.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";
	rem.config =
	    "vigil 1\n"
	    "instance far away\n"
	    "mode gospel\n"
	    "spi 0c\n"
	    "cathedral 127.0.0.1:4469\n"
	    "cathedral_id 5eb2411f\n"
	    "cathedral_flock 493abf95a07e0c00\n";

	/* No words made yet. */
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_REMOTE);
	CHECK(covenant_remote_run(ctx) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_REMOTE);

	memset(&route, 0, sizeof(route));
	route.flock = TEST_FLOCK;
	route.identity = 0xdeadbeef;
	route.cathedral = 0x7f000001;
	route.port = 4469;
	route.kek = 0x01;
	route.peer = 0x0c;

	CHECK(covenant_remote_words(ctx, &route, words, sizeof(words)) == 0);

	CHECK(covenant_remote_start(NULL, &rem) == -1);
	CHECK(covenant_remote_start(ctx, NULL) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);

	rem.secret_len--;
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	rem.secret_len++;

	rem.device = route.identity;
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	rem.device = 0x5eb2411f;

	rem.cosk = handle + 1;
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_COSK);
	rem.cosk = handle;

	rem.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5zz";
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	rem.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";

	/* KEKs we cannot open, or the KEKs of another flock. */
	memcpy(other, secret, sizeof(other));
	other[0] ^= 0x01;
	rem.secret = other;
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);
	rem.secret = secret;

	covenant_keks_generate(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    TEST_FLOCK + 0x100, elsewhere, sizeof(elsewhere));
	rem.keks = elsewhere;
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_FLOCK);
	rem.keks = sealed;

	/* A configuration for another KEK leaves everything in place. */
	rem.config =
	    "vigil 1\n"
	    "instance far away\n"
	    "spi 0d\n"
	    "cathedral_flock 493abf95a07e0c00\n";
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_CONFIG_SPI);

	rem.config = NULL;
	CHECK(covenant_remote_start(ctx, &rem) == 0);
	CHECK(covenant_remote_run(ctx) == COVENANT_REMOTE_WAITING);

	/* Started once, the cosk is gone and it cannot start again. */
	CHECK(covenant_remote_start(ctx, &rem) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_REMOTE);
	CHECK(covenant_cosk_drop(ctx, handle) == -1);

	covenant_remote_stop(ctx);
	CHECK(covenant_remote_run(ctx) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_REMOTE);
}

/*
 * Renewing a single KEK must leave all the others alone.
 */
static void
test_keks_renew(const u_int8_t *secret, const u_int8_t *sealed)
{
	int			idx;
	struct covenant_keks	*a, *b;
	u_int8_t		renewed[COVENANT_KEKS_SEALED_LEN];

	CHECK(covenant_keks_renew(ctx, secret, COVENANT_VAULT_KEY_LEN, sealed,
	    COVENANT_KEKS_SEALED_LEN, 0x42, renewed, sizeof(renewed)) == 0);

	covenant_lock();
	CHECK((a = covenant_keks_open(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN)) != NULL);
	CHECK((b = covenant_keks_open(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    renewed, sizeof(renewed))) != NULL);

	CHECK(a->flock == b->flock);
	CHECK(a->created == b->created);
	CHECK(memcmp(a->seed, b->seed, sizeof(a->seed)) == 0);

	for (idx = 1; idx <= COVENANT_KEK_COUNT; idx++) {
		if (idx == 0x42) {
			CHECK(memcmp(a->kek[idx - 1], b->kek[idx - 1],
			    COVENANT_KEK_LEN) != 0);
		} else {
			CHECK(memcmp(a->kek[idx - 1], b->kek[idx - 1],
			    COVENANT_KEK_LEN) == 0);
		}
	}

	covenant_keks_close(a);
	covenant_keks_close(b);
	covenant_unlock();
}

/*
 * Back up the KEKs and restore them under another vault key.
 */
static void
test_backup_restore(const u_int8_t *secret, const u_int8_t *sealed)
{
	struct covenant_info		ki;
	struct covenant_backup_info	bi;
	struct covenant_keks		*a, *b;
	u_int8_t			backup[COVENANT_BACKUP_LEN];
	u_int8_t			data[COVENANT_KEKS_DATA_LEN];
	u_int8_t			root[COVENANT_BACKUP_ROOT_LEN];
	u_int8_t			secret2[COVENANT_VAULT_KEY_LEN];
	u_int8_t			restored[COVENANT_KEKS_SEALED_LEN];
	u_int8_t			rcpt[COVENANT_BACKUP_RECIPIENT_LEN];
	u_int8_t			again[COVENANT_BACKUP_RECIPIENT_LEN];

	CHECK(covenant_random_bytes(ctx, secret2, sizeof(secret2)) == 0);

	covenant_backup_keygen(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    root, sizeof(root), rcpt, sizeof(rcpt));

	/*
	 * The same recovery key gives a recipient with a fresh salt but
	 * the same public keys, which works just like the first one.
	 */
	covenant_backup_recipient(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    root, sizeof(root), again, sizeof(again));
	CHECK(memcmp(rcpt, again, sizeof(rcpt)) != 0);
	CHECK(covenant_backup_verify(ctx, root, sizeof(root),
	    again, sizeof(again)) == 0);
	CHECK(covenant_backup_seal(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    again, sizeof(again), sealed, COVENANT_KEKS_SEALED_LEN,
	    backup, sizeof(backup)) == 0);

	CHECK(covenant_backup_verify(ctx, root, sizeof(root),
	    rcpt, sizeof(rcpt)) == 0);
	root[7] ^= 0x01;
	CHECK(covenant_backup_verify(ctx, root, sizeof(root),
	    rcpt, sizeof(rcpt)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_RECOVERY_KEY);
	root[7] ^= 0x01;

	CHECK(covenant_backup_seal(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    rcpt, sizeof(rcpt), sealed, COVENANT_KEKS_SEALED_LEN,
	    backup, sizeof(backup)) == 0);

	/* A recipient made under another vault key. */
	CHECK(covenant_backup_seal(ctx, secret2, sizeof(secret2),
	    rcpt, sizeof(rcpt), sealed, COVENANT_KEKS_SEALED_LEN,
	    backup, sizeof(backup)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);

	rcpt[100] ^= 0x01;
	CHECK(covenant_backup_seal(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    rcpt, sizeof(rcpt), sealed, COVENANT_KEKS_SEALED_LEN,
	    backup, sizeof(backup)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);
	rcpt[100] ^= 0x01;

	CHECK(covenant_backup_seal(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    rcpt, sizeof(rcpt), sealed, COVENANT_KEKS_SEALED_LEN,
	    backup, sizeof(backup)) == 0);

	CHECK(covenant_keks_info(ctx, sealed,
	    COVENANT_KEKS_SEALED_LEN, &ki) == 0);
	CHECK(covenant_backup_info(ctx, backup, sizeof(backup), &bi) == 0);
	CHECK(bi.flock == ki.flock);
	CHECK(bi.created == ki.created);
	CHECK(bi.made >= bi.created);

	CHECK(covenant_backup_restore(ctx, secret2, sizeof(secret2),
	    root, sizeof(root), backup, sizeof(backup),
	    restored, sizeof(restored)) == 0);

	covenant_lock();
	CHECK((a = covenant_keks_open(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    sealed, COVENANT_KEKS_SEALED_LEN)) != NULL);
	CHECK((b = covenant_keks_open(ctx, secret2, sizeof(secret2),
	    restored, sizeof(restored))) != NULL);

	CHECK(a->flock == b->flock);
	CHECK(a->created == b->created);
	CHECK(memcmp(a->kek, b->kek, sizeof(a->kek)) == 0);
	CHECK(memcmp(a->seed, b->seed, sizeof(a->seed)) == 0);

	covenant_keks_close(b);
	covenant_unlock();

	CHECK(covenant_backup_open(ctx, root, sizeof(root),
	    backup, sizeof(backup), data, sizeof(data), &bi) == 0);
	CHECK(bi.flock == ki.flock);
	CHECK(memcmp(a->kek, data, sizeof(data)) == 0);

	covenant_lock();
	covenant_keks_close(a);
	covenant_unlock();

	root[0] ^= 0x80;
	CHECK(covenant_backup_restore(ctx, secret2, sizeof(secret2),
	    root, sizeof(root), backup, sizeof(backup),
	    restored, sizeof(restored)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_RECOVERY_KEY);
	root[0] ^= 0x80;

	/* The flock in the header, the KEM ciphertext, the KEKs and the mac. */
	backup[8] ^= 0x01;
	CHECK(covenant_backup_restore(ctx, secret2, sizeof(secret2),
	    root, sizeof(root), backup, sizeof(backup),
	    restored, sizeof(restored)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_RECOVERY_KEY);
	backup[8] ^= 0x01;

	backup[200] ^= 0x01;
	CHECK(covenant_backup_restore(ctx, secret2, sizeof(secret2),
	    root, sizeof(root), backup, sizeof(backup),
	    restored, sizeof(restored)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_RECOVERY_KEY);
	backup[200] ^= 0x01;

	backup[sizeof(backup) - 100] ^= 0x01;
	CHECK(covenant_backup_restore(ctx, secret2, sizeof(secret2),
	    root, sizeof(root), backup, sizeof(backup),
	    restored, sizeof(restored)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_RECOVERY_KEY);
	backup[sizeof(backup) - 100] ^= 0x01;

	backup[sizeof(backup) - 1] ^= 0x01;
	CHECK(covenant_backup_restore(ctx, secret2, sizeof(secret2),
	    root, sizeof(root), backup, sizeof(backup),
	    restored, sizeof(restored)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_RECOVERY_KEY);
	backup[sizeof(backup) - 1] ^= 0x01;

	backup[7] = 0x02;
	CHECK(covenant_backup_info(ctx, backup, sizeof(backup), &bi) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);
	CHECK(covenant_backup_restore(ctx, secret2, sizeof(secret2),
	    root, sizeof(root), backup, sizeof(backup),
	    restored, sizeof(restored)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);
	CHECK(covenant_backup_info(ctx, backup,
	    sizeof(backup) - COVENANT_SIGN_SEED_LEN, &bi) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	backup[7] = 0x03;

	backup[0] = 'X';
	CHECK(covenant_backup_info(ctx, backup, sizeof(backup), &bi) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);
}

/*
 * Unwrap every entry of a bundle like chapel_ambry_unwrap() does with
 * the device KEKs, and check both directions carry the same secret.
 * Each entry must only unwrap with the KEK of its sending side.
 */
static int
test_ambry_unwrap(const u_int8_t *bundle, size_t len, u_int64_t flock,
    const u_int8_t *keks, size_t keks_len)
{
	struct nyfe_kmac256		kdf;
	struct sanctum_ambry_head	hdr;
	struct sanctum_ambry_aad	aad;
	struct sanctum_ambry_entry	entry;
	u_int8_t			n, id;
	struct covenant_cipher		cipher;
	u_int64_t			flock_be;
	size_t				off, count;
	u_int16_t			tunnel, other;
	u_int8_t			ss[32], prev[32];
	u_int8_t			kek[COVENANT_KEK_LEN], key[32];
	u_int8_t			nonce[SANCTUM_NONCE_LENGTH];

	if (len != COVENANT_AMBRY_LEN || keks_len != COVENANT_KEKS_DATA_LEN)
		return (-1);

	memcpy(&hdr, bundle, sizeof(hdr));
	flock = flock & ~((u_int64_t)SANCTUM_FLOCK_DOMAIN_MASK);
	flock_be = htobe64(flock);

	memset(nonce, 0, sizeof(nonce));
	nonce[SANCTUM_NONCE_LENGTH - 1] = 0x01;

	count = 0;

	for (off = sizeof(hdr); off < len; off += sizeof(entry)) {
		memcpy(&entry, bundle + off, sizeof(entry));

		if (entry.flock != flock_be)
			return (-1);

		tunnel = be16toh(entry.tunnel);
		if ((tunnel >> 8) == 0 || (tunnel & 0xff) == 0 ||
		    (tunnel >> 8) == (tunnel & 0xff))
			return (-1);

		/*
		 * Each pair is (src, dst) followed by (dst, src). Try the
		 * KEK of the sending side, which must work, and the KEK of
		 * the other side, which must not.
		 */
		for (other = 0; other <= 1; other++) {
			id = other ? (tunnel & 0xff) : (tunnel >> 8);

			covenant_kek_derive(&keks[(id - 1) * COVENANT_KEK_LEN],
			    COVENANT_KEK_LEN, flock, flock, kek, sizeof(kek));

			nyfe_kmac256_init(&kdf, kek, sizeof(kek),
			    SANCTUM_AMBRY_KDF, strlen(SANCTUM_AMBRY_KDF));

			n = sizeof(hdr.seed);
			nyfe_kmac256_update(&kdf, &n, sizeof(n));
			nyfe_kmac256_update(&kdf, hdr.seed, sizeof(hdr.seed));

			n = sizeof(flock_be);
			nyfe_kmac256_update(&kdf, &n, sizeof(n));
			nyfe_kmac256_update(&kdf, &flock_be, sizeof(flock_be));
			nyfe_kmac256_update(&kdf, &n, sizeof(n));
			nyfe_kmac256_update(&kdf, &flock_be, sizeof(flock_be));

			n = sizeof(hdr.generation);
			nyfe_kmac256_update(&kdf, &n, sizeof(n));
			nyfe_kmac256_update(&kdf, &hdr.generation,
			    sizeof(hdr.generation));

			n = sizeof(entry.tunnel);
			nyfe_kmac256_update(&kdf, &n, sizeof(n));
			nyfe_kmac256_update(&kdf, &entry.tunnel,
			    sizeof(entry.tunnel));

			nyfe_kmac256_final(&kdf, key, sizeof(key));

			aad.tunnel = entry.tunnel;
			aad.flock_src = flock_be;
			aad.flock_dst = flock_be;
			aad.expires = hdr.expires;
			aad.generation = hdr.generation;
			memcpy(aad.seed, hdr.seed, sizeof(hdr.seed));

			cipher.ctx = covenant_cipher_setup(key, sizeof(key));

			cipher.aad = &aad;
			cipher.aad_len = sizeof(aad);

			cipher.nonce = nonce;
			cipher.nonce_len = sizeof(nonce);

			cipher.pt = ss;
			cipher.ct = entry.key;
			cipher.tag = entry.tag;
			cipher.data_len = sizeof(entry.key);

			covenant_lock();

			if (covenant_cipher_decrypt(&cipher) == -1) {
				covenant_cipher_cleanup(cipher.ctx);
				covenant_unlock();

				if (other)
					continue;

				fprintf(stderr, "%04x does not unwrap\n",
				    tunnel);
				return (-1);
			}

			covenant_cipher_cleanup(cipher.ctx);
			covenant_unlock();

			if (other) {
				fprintf(stderr, "%04x unwraps with the "
				    "wrong KEK\n", tunnel);
				return (-1);
			}
		}

		if ((count % 2) == 0) {
			memcpy(prev, ss, sizeof(ss));
		} else if (memcmp(prev, ss, sizeof(ss))) {
			fprintf(stderr, "%04x has another secret\n", tunnel);
			return (-1);
		}

		count++;
	}

	if (count != 255 * 254)
		return (-1);

	return (0);
}

/*
 * Check if we have ambry and remember where it lives.
 */
static int
test_ambry_find(const char *path)
{
	int		len;
	char		cmd[1100];

	if (path == NULL)
		path = "ambry";

	len = snprintf(cmd, sizeof(cmd), "command -v %s > /dev/null", path);
	if (len < 0 || (size_t)len >= sizeof(cmd))
		return (0);

	if (system(cmd) != 0)
		return (0);

	len = snprintf(ambry, sizeof(ambry), "%s", path);
	if (len < 0 || (size_t)len >= sizeof(ambry))
		return (0);

	if (setenv("AMBRY_BIN", ambry, 1) == -1)
		return (0);

	return (1);
}

/*
 * Have ambry generate the KEKs for our test flock and read them in,
 * checking our derivation against its internal KEKs along the way.
 */
static void
test_ambry_reference(const char *dir, u_int8_t *data, size_t data_len)
{
	int		idx, len;
	char		path[1024];
	u_int8_t	internal[COVENANT_KEK_LEN], derived[COVENANT_KEK_LEN];

	CHECK(data_len == COVENANT_KEKS_DATA_LEN);
	CHECK(system("$AMBRY_BIN generate 493abf95a07e0c00 > /dev/null") == 0);

	for (idx = 1; idx <= COVENANT_KEK_COUNT; idx++) {
		len = snprintf(path, sizeof(path),
		    "%s/493abf95a07e0c00/kek-data/kek-0x%02x", dir, idx);
		CHECK(len >= 0 && (size_t)len < sizeof(path));
		test_file_read(path,
		    &data[(idx - 1) * COVENANT_KEK_LEN], COVENANT_KEK_LEN);

		len = snprintf(path, sizeof(path),
		    "%s/493abf95a07e0c00/internal/kek-0x%02x", dir, idx);
		CHECK(len >= 0 && (size_t)len < sizeof(path));
		test_file_read(path, internal, sizeof(internal));

		covenant_kek_derive(&data[(idx - 1) * COVENANT_KEK_LEN],
		    COVENANT_KEK_LEN, TEST_FLOCK, TEST_FLOCK,
		    derived, sizeof(derived));
		CHECK(memcmp(internal, derived, sizeof(derived)) == 0);
	}
}

/*
 * Read exactly len bytes from the given file, no more and no less.
 */
static void
test_file_read(const char *path, u_int8_t *buf, size_t len)
{
	FILE		*fp;
	u_int8_t	extra;

	CHECK((fp = fopen(path, "rb")) != NULL);
	CHECK(fread(buf, 1, len, fp) == len);
	CHECK(fread(&extra, 1, 1, fp) == 0);

	(void)fclose(fp);
}

/*
 * The version names the build revision and the date it was built on,
 * as "revision (YYYY-MM-DD)".
 */
static void
test_version(void)
{
	size_t		len;
	const char	*version;

	CHECK((version = covenant_version()) != NULL);

	len = strlen(version);
	CHECK(len > 13);

	CHECK(version[len - 13] == ' ' && version[len - 12] == '(');
	CHECK(version[len - 7] == '-' && version[len - 4] == '-');
	CHECK(version[len - 1] == ')');
}

/*
 * More than a QR code can hold is refused, not cut short.
 */
static void
test_qr_limit(void)
{
	int		side;
	char		*text;
	u_int8_t	qr[COVENANT_QR_MAX_LEN];

	CHECK((text = malloc(3001)) != NULL);
	memset(text, 'a', 3000);
	text[3000] = '\0';

	CHECK(covenant_qr_encode(ctx, text, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_QR_SIZE);

	CHECK(covenant_qr_encode(NULL, "vigil 1\n", qr, sizeof(qr),
	    &side) == -1);
	CHECK(covenant_qr_encode(ctx, NULL, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	CHECK(covenant_qr_encode(ctx, "vigil 1\n", NULL, sizeof(qr),
	    &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);

	free(text);
}

/*
 * At most 8 cosk pairs wait for their device at a time, each with a
 * handle of its own. Dropping one makes room for the next.
 */
static void
test_cosk_limit(void)
{
	int		idx, other;
	u_int32_t	handle[COVENANT_COSK_MAX], extra;
	u_int8_t	pk[COVENANT_COSK_MAX][COVENANT_COSK_PUBLIC_LEN];

	for (idx = 0; idx < COVENANT_COSK_MAX; idx++) {
		CHECK(covenant_cosk_new(ctx, &handle[idx], pk[idx],
		    sizeof(pk[idx])) == 0);
		CHECK(handle[idx] != 0);

		for (other = 0; other < idx; other++) {
			CHECK(handle[other] != handle[idx]);
			CHECK(memcmp(pk[other], pk[idx], sizeof(pk[idx])) != 0);
		}
	}

	CHECK(covenant_cosk_new(ctx, &extra, pk[0], sizeof(pk[0])) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_COSK_FULL);

	CHECK(covenant_cosk_drop(ctx, handle[3]) == 0);
	CHECK(covenant_cosk_new(ctx, &handle[3], pk[3], sizeof(pk[3])) == 0);

	for (idx = 0; idx < COVENANT_COSK_MAX; idx++)
		CHECK(covenant_cosk_drop(ctx, handle[idx]) == 0);

	CHECK(covenant_cosk_drop(ctx, 0) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_COSK);
	CHECK(covenant_cosk_drop(NULL, handle[0]) == -1);
	CHECK(covenant_cosk_new(NULL, &extra, pk[0], sizeof(pk[0])) == -1);
	CHECK(covenant_cosk_new(ctx, NULL, pk[0], sizeof(pk[0])) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
}

/*
 * The internal KEK of a device is the same for a pair of flocks no
 * matter which side derives it, and differs for another pair.
 */
static void
test_kek_derive(void)
{
	u_int8_t	aa[COVENANT_KEK_LEN];
	u_int8_t	kek[COVENANT_KEK_LEN];
	u_int8_t	ab[COVENANT_KEK_LEN], ba[COVENANT_KEK_LEN];

	CHECK(covenant_random_bytes(ctx, kek, sizeof(kek)) == 0);

	covenant_kek_derive(kek, sizeof(kek), TEST_FLOCK, TEST_FLOCK + 0x100,
	    ab, sizeof(ab));
	covenant_kek_derive(kek, sizeof(kek), TEST_FLOCK + 0x100, TEST_FLOCK,
	    ba, sizeof(ba));
	covenant_kek_derive(kek, sizeof(kek), TEST_FLOCK, TEST_FLOCK,
	    aa, sizeof(aa));

	CHECK(memcmp(ab, ba, sizeof(ab)) == 0);
	CHECK(memcmp(ab, aa, sizeof(ab)) != 0);
	CHECK(memcmp(ab, kek, sizeof(ab)) != 0);
}

/*
 * AES-256-GCM against test case 16 of the GCM specification, and a
 * tag that is off by a bit must not decrypt.
 */
static void
test_cipher_vector(void)
{
	struct covenant_cipher	cipher;
	u_int8_t		key[32];
	u_int8_t		aad[20];
	u_int8_t		nonce[12];
	u_int8_t		tag[16], want_tag[16];
	u_int8_t		pt[60], ct[60], want_ct[60], out[60];

	test_hex("feffe9928665731c6d6a8f9467308308"
	    "feffe9928665731c6d6a8f9467308308", key, sizeof(key));
	test_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, sizeof(aad));
	test_hex("cafebabefacedbaddecaf888", nonce, sizeof(nonce));
	test_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a"
	    "318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
	    pt, sizeof(pt));
	test_hex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd25"
	    "55d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
	    want_ct, sizeof(want_ct));
	test_hex("76fc6ece0f4e1768cddf8853bb2d551b",
	    want_tag, sizeof(want_tag));

	covenant_lock();

	memset(&cipher, 0, sizeof(cipher));
	cipher.ctx = covenant_cipher_setup(key, sizeof(key));
	cipher.aad = aad;
	cipher.aad_len = sizeof(aad);
	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);
	cipher.pt = pt;
	cipher.ct = ct;
	cipher.tag = tag;
	cipher.data_len = sizeof(pt);

	covenant_cipher_encrypt(&cipher);
	CHECK(memcmp(ct, want_ct, sizeof(ct)) == 0);
	CHECK(memcmp(tag, want_tag, sizeof(tag)) == 0);

	cipher.pt = out;
	CHECK(covenant_cipher_decrypt(&cipher) == 0);
	CHECK(memcmp(out, pt, sizeof(out)) == 0);

	tag[15] ^= 0x01;
	CHECK(covenant_cipher_decrypt(&cipher) == -1);

	covenant_cipher_cleanup(cipher.ctx);
	covenant_unlock();
}

/*
 * Everything that opens the KEKs refuses another vault key, and a
 * device that failed to provision keeps its cosk for another try.
 */
static void
test_wrong_vault(const u_int8_t *secret, const u_int8_t *sealed)
{
	struct covenant_device	dev;
	int			side;
	u_int16_t		expires;
	u_int8_t		*bundle;
	u_int32_t		handle, gen;
	u_int8_t		qr[COVENANT_QR_MAX_LEN];
	u_int8_t		pk[COVENANT_COSK_PUBLIC_LEN];
	u_int8_t		other[COVENANT_VAULT_KEY_LEN];
	char			config[COVENANT_CONFIG_MAX_LEN];
	u_int8_t		renewed[COVENANT_KEKS_SEALED_LEN];

	memcpy(other, secret, sizeof(other));
	other[31] ^= 0x01;

	CHECK((bundle = malloc(COVENANT_AMBRY_LEN)) != NULL);
	CHECK(covenant_ambry_bundle(ctx, other, sizeof(other), sealed,
	    COVENANT_KEKS_SEALED_LEN, 30, bundle, COVENANT_AMBRY_LEN,
	    &gen, &expires) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);
	free(bundle);

	CHECK(covenant_keks_renew(ctx, other, sizeof(other), sealed,
	    COVENANT_KEKS_SEALED_LEN, 0x42, renewed, sizeof(renewed)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);

	CHECK(covenant_cosk_new(ctx, &handle, pk, sizeof(pk)) == 0);

	memset(&dev, 0, sizeof(dev));
	dev.secret = other;
	dev.secret_len = sizeof(other);
	dev.keks = sealed;
	dev.keks_len = COVENANT_KEKS_SEALED_LEN;
	dev.cosk = handle;
	dev.kek = 0x0c;
	dev.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";
	dev.config =
	    "vigil 1\n"
	    "instance laptop\n"
	    "spi 0c\n"
	    "cathedral_flock 493abf95a07e0c00\n";

	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);
	CHECK(covenant_provision_config(ctx, &dev, config,
	    sizeof(config)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);

	dev.secret = secret;

	/* Something that is not hex for the cathedral secret. */
	dev.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5zz";
	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	dev.cathedral_secret =
	    "c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5";

	CHECK(covenant_provision(ctx, &dev, NULL, sizeof(qr), &side) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_PARAMETER);
	CHECK(covenant_provision(NULL, &dev, qr, sizeof(qr), &side) == -1);

	/* After all of that the cosk is still there for the device. */
	CHECK(covenant_provision(ctx, &dev, qr, sizeof(qr), &side) == 0);

	nyfe_mem_zero(other, sizeof(other));
}

/*
 * Backups that someone made with the MAC key but not with the KEKs of
 * the flock, and recipients that are not ours.
 */
static void
test_backup_forged(const u_int8_t *secret, const u_int8_t *sealed)
{
	struct covenant_backup_info	bi;
	u_int8_t			*backup, *copy;
	u_int8_t			data[COVENANT_KEKS_DATA_LEN];
	u_int8_t			other[COVENANT_VAULT_KEY_LEN];
	u_int8_t			root[COVENANT_BACKUP_ROOT_LEN];
	u_int8_t			restored[COVENANT_KEKS_SEALED_LEN];
	u_int8_t			bad[COVENANT_BACKUP_RECIPIENT_LEN];
	u_int8_t			elsewhere[COVENANT_KEKS_SEALED_LEN];
	u_int8_t			rcpt[COVENANT_BACKUP_RECIPIENT_LEN];

	CHECK((backup = malloc(COVENANT_BACKUP_LEN)) != NULL);
	CHECK((copy = malloc(COVENANT_BACKUP_LEN)) != NULL);

	covenant_backup_keygen(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    root, sizeof(root), rcpt, sizeof(rcpt));
	CHECK(covenant_backup_seal(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    rcpt, sizeof(rcpt), sealed, COVENANT_KEKS_SEALED_LEN,
	    backup, COVENANT_BACKUP_LEN) == 0);

	/* A recipient with another magic or version is not one of ours. */
	memcpy(bad, rcpt, sizeof(bad));
	bad[0] = 'X';
	CHECK(covenant_backup_verify(ctx, root, sizeof(root),
	    bad, sizeof(bad)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);
	CHECK(covenant_backup_seal(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    bad, sizeof(bad), sealed, COVENANT_KEKS_SEALED_LEN,
	    copy, COVENANT_BACKUP_LEN) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);

	memcpy(bad, rcpt, sizeof(bad));
	bad[7] ^= 0x01;
	CHECK(covenant_backup_verify(ctx, root, sizeof(root),
	    bad, sizeof(bad)) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);

	/* KEKs sealed under another vault key than the recipient. */
	CHECK(covenant_random_bytes(ctx, other, sizeof(other)) == 0);
	covenant_keks_generate(ctx, other, sizeof(other), TEST_FLOCK,
	    elsewhere, sizeof(elsewhere));
	CHECK(covenant_backup_seal(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    rcpt, sizeof(rcpt), elsewhere, sizeof(elsewhere),
	    copy, COVENANT_BACKUP_LEN) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_INTEGRITY);

	/* Opening it on a computer needs the right recovery key too. */
	root[3] ^= 0x01;
	CHECK(covenant_backup_open(ctx, root, sizeof(root), backup,
	    COVENANT_BACKUP_LEN, data, sizeof(data), &bi) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_RECOVERY_KEY);
	root[3] ^= 0x01;

	memcpy(copy, backup, COVENANT_BACKUP_LEN);
	copy[7] ^= 0x01;
	CHECK(covenant_backup_open(ctx, root, sizeof(root), copy,
	    COVENANT_BACKUP_LEN, data, sizeof(data), &bi) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_VERSION);

	/*
	 * The MAC only proves who made the backup. With a valid MAC the
	 * KEKs must still decrypt under the key both KEMs agree on, so
	 * changed KEKs, a changed ML-KEM ciphertext or an x25519 key that
	 * gives no shared secret are all refused.
	 */
	memcpy(copy, backup, COVENANT_BACKUP_LEN);
	copy[1648 + 100] ^= 0x01;
	test_backup_remac(root, copy, COVENANT_BACKUP_LEN);
	CHECK(covenant_backup_restore(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    root, sizeof(root), copy, COVENANT_BACKUP_LEN,
	    restored, sizeof(restored)) == -1);
	CHECK(covenant_backup_open(ctx, root, sizeof(root), copy,
	    COVENANT_BACKUP_LEN, data, sizeof(data), &bi) == -1);

	memcpy(copy, backup, COVENANT_BACKUP_LEN);
	copy[80 + 100] ^= 0x01;
	test_backup_remac(root, copy, COVENANT_BACKUP_LEN);
	CHECK(covenant_backup_restore(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    root, sizeof(root), copy, COVENANT_BACKUP_LEN,
	    restored, sizeof(restored)) == -1);

	memcpy(copy, backup, COVENANT_BACKUP_LEN);
	memset(&copy[48], 0, COVENANT_X25519_LEN);
	test_backup_remac(root, copy, COVENANT_BACKUP_LEN);
	CHECK(covenant_backup_restore(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    root, sizeof(root), copy, COVENANT_BACKUP_LEN,
	    restored, sizeof(restored)) == -1);

	/* And the untouched backup with its own MAC redone still opens. */
	memcpy(copy, backup, COVENANT_BACKUP_LEN);
	test_backup_remac(root, copy, COVENANT_BACKUP_LEN);
	CHECK(memcmp(copy, backup, COVENANT_BACKUP_LEN) == 0);
	CHECK(covenant_backup_restore(ctx, secret, COVENANT_VAULT_KEY_LEN,
	    root, sizeof(root), copy, COVENANT_BACKUP_LEN,
	    restored, sizeof(restored)) == 0);

	nyfe_mem_zero(root, sizeof(root));
	nyfe_mem_zero(data, sizeof(data));
	nyfe_mem_zero(other, sizeof(other));

	free(backup);
	free(copy);
}

/*
 * Redo the MAC over a backup as docs/backups.md describes it:
 *
 *	mac_key = KMAC256(root, "COVENANT.BACKUP.MAC.KEY"), 256-bit
 *	mac = KMAC256(mac_key, "COVENANT.BACKUP.MAC", backup), 256-bit
 */
static void
test_backup_remac(const u_int8_t *root, u_int8_t *backup, size_t len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		key[32];

	nyfe_kmac256_init(&kdf, root, COVENANT_BACKUP_ROOT_LEN,
	    "COVENANT.BACKUP.MAC.KEY", strlen("COVENANT.BACKUP.MAC.KEY"));
	nyfe_kmac256_final(&kdf, key, sizeof(key));

	nyfe_kmac256_init(&kdf, key, sizeof(key),
	    "COVENANT.BACKUP.MAC", strlen("COVENANT.BACKUP.MAC"));
	nyfe_kmac256_update(&kdf, backup, len - 32);
	nyfe_kmac256_final(&kdf, &backup[len - 32], 32);

	nyfe_mem_zero(key, sizeof(key));
}

/*
 * An emergency erase wipes all key material the library knows about.
 * Nothing can be used afterwards, so it runs in a child.
 */
static void
test_emergency_erase(void)
{
	pid_t		pid;
	size_t		idx;
	u_int8_t	*key;
	int		status;

	CHECK(fflush(stdout) == 0);
	CHECK((pid = fork()) != -1);

	if (pid == 0) {
		key = covenant_alloc(64);
		memset(key, 0xaa, 64);

		covenant_emergency_erase();

		for (idx = 0; idx < 64; idx++) {
			if (key[idx] != 0)
				exit(1);
		}

		exit(0);
	}

	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/*
 * Using the library wrong, here renewing KEK 0 which no flock has, is
 * fatal: it wipes all key material, tells the platform why through
 * the fatal callback (or on stderr without one) and aborts.
 */
static void
test_fatal(const u_int8_t *secret, const u_int8_t *sealed, int callback)
{
	pid_t		pid;
	ssize_t		ret;
	size_t		len;
	char		report[256];
	int		fds[2], status;
	u_int8_t	out[COVENANT_KEKS_SEALED_LEN];

	CHECK(pipe(fds) == 0);
	CHECK(fflush(stdout) == 0);
	CHECK((pid = fork()) != -1);

	if (pid == 0) {
		(void)close(fds[0]);

		if (callback) {
			fatal_fd = fds[1];
			fatal_key = covenant_alloc(32);
			memset(fatal_key, 0xaa, 32);
			covenant_fatal_callback(test_fatal_report);
		} else {
			if (dup2(fds[1], STDERR_FILENO) == -1)
				_exit(1);
		}

		if (covenant_keks_renew(ctx, secret, COVENANT_VAULT_KEY_LEN,
		    sealed, COVENANT_KEKS_SEALED_LEN, 0, out, sizeof(out)) == 0)
			_exit(2);
		_exit(1);
	}

	(void)close(fds[1]);

	len = 0;

	for (;;) {
		ret = read(fds[0], &report[len], sizeof(report) - len - 1);
		CHECK(ret != -1);
		if (ret == 0)
			break;
		len += (size_t)ret;
		CHECK(len < sizeof(report) - 1);
	}

	report[len] = '\0';
	(void)close(fds[0]);

	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);

	if (callback) {
		CHECK(report[0] == 'w');
		CHECK(len > 1);
	} else {
		CHECK(len > 0);
	}
}

/*
 * The fatal callback in the child, report if the key material was
 * already wiped and the reason we were given.
 */
static void
test_fatal_report(const char *fmt, va_list args)
{
	size_t		idx;
	int		wiped;
	char		msg[200];

	wiped = 1;

	for (idx = 0; idx < 32; idx++) {
		if (fatal_key[idx] != 0)
			wiped = 0;
	}

	if (vsnprintf(msg, sizeof(msg), fmt, args) < 0)
		msg[0] = '\0';

	if (wiped) {
		if (write(fatal_fd, "w", 1) == -1)
			_exit(1);
	} else {
		if (write(fatal_fd, "-", 1) == -1)
			_exit(1);
	}
	if (write(fatal_fd, msg, strlen(msg)) == -1)
		_exit(1);

#if defined(COVENANT_COVERAGE)
	__gcov_dump();
#endif
}

/*
 * Decode the given hex string, which must be exactly len bytes.
 */
static void
test_hex(const char *hex, u_int8_t *out, size_t len)
{
	size_t		got;

	CHECK(sodium_hex2bin(out, len, hex, strlen(hex), NULL, &got,
	    NULL) == 0);
	CHECK(got == len);
}
