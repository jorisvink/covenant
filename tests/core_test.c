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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "covenant-int.h"

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

static void	test_keks_seal(const u_int8_t *, const u_int8_t *);
static void	test_keks_renew(const u_int8_t *, const u_int8_t *);
static void	test_config_build(const u_int8_t *, const u_int8_t *);
static void	test_config_name(const struct covenant_keks *, const char *,
		    u_int8_t, const char *);
static void	test_provision_qr(const u_int8_t *, const u_int8_t *);
static void	test_backup_restore(const u_int8_t *, const u_int8_t *);
static void	test_provision_config(const u_int8_t *, const u_int8_t *);
static void	test_ambry_bundle(const u_int8_t *, const u_int8_t *,
		    const u_int8_t *);

/* The path to ambry, when we have one. */
static char	ambry[1024];

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

	CHECK(crypto_sign_seed_keypair(pk, seed_sk, keks->seed) == 0);
	(void)sodium_bin2hex(pk_hex, sizeof(pk_hex), pk, sizeof(pk));
	nyfe_mem_zero(seed_sk, sizeof(seed_sk));

	len = snprintf(want, sizeof(want), "%skek %s\ncathedral_secret %s\n"
	    "cathedral_cosk %s\nname_pubkey %s\nname_signature ",
	    public, kek, cs_hex, sk_hex, pk_hex);
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
