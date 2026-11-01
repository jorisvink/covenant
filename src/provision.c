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

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "covenant-int.h"

/* The maximum length of the public part we accept from the platform. */
#define CONFIG_PUBLIC_MAX	1024

/* The largest key we hex encode into the configuration, with its NUL. */
#define CONFIG_HEX_MAX		((SANCTUM_ED25519_SIGN_SECRET_LENGTH * 2) + 1)

static int	provision_name_valid(const char *);
static int	provision_hex_decode(const char *, u_int8_t *, size_t);
static void	provision_hex_encode(const u_int8_t *, size_t, char *, size_t);
static int	provision_device_check(struct covenant *,
		    const struct covenant_device *);
static int	provision_config_check(struct covenant *, const char *,
		    u_int64_t, u_int8_t, char *, size_t);
static void	provision_name_sign(const struct covenant_keks *, u_int8_t,
		    const char *, u_int8_t *, size_t, u_int8_t *, size_t);
static int	provision_device_config(struct covenant *,
		    const struct covenant_device *, char *, size_t,
		    struct covenant_cosk **);

static struct covenant_cosk	*provision_cosk_lookup(struct covenant *,
				    u_int32_t);

/* The options that carry keys or signatures, only we get to add those. */
static const char *config_keys[] = {
	"kek",
	"secret",
	"name_pubkey",
	"cathedral_secret",
	"cathedral_cosk",
	"name_signature",
	NULL
};

/*
 * Generate a new cosk pair, keep the secret half in the context and
 * hand back a handle for it together with the public half.
 */
int
covenant_cosk_new(struct covenant *ctx, u_int32_t *handle, void *pk,
    size_t pk_len)
{
	int			idx;
	struct covenant_cosk	*cosk;

	if (ctx == NULL)
		return (-1);

	if (handle == NULL || pk == NULL ||
	    pk_len != COVENANT_COSK_PUBLIC_LEN) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	covenant_lock();

	for (idx = 0; idx < COVENANT_COSK_MAX; idx++) {
		if (ctx->cosk[idx].handle == 0)
			break;
	}

	if (idx == COVENANT_COSK_MAX) {
		covenant_unlock();
		ctx->last_error = COVENANT_ERROR_COSK_FULL;
		return (-1);
	}

	cosk = &ctx->cosk[idx];

	for (;;) {
		nyfe_random_bytes(&cosk->handle, sizeof(cosk->handle));

		if (cosk->handle == 0)
			continue;

		if (provision_cosk_lookup(ctx, cosk->handle) != cosk)
			continue;

		break;
	}

	if (crypto_sign_keypair(pk, cosk->sk) != 0) {
		nyfe_mem_zero(cosk, sizeof(*cosk));
		covenant_unlock();
		ctx->last_error = COVENANT_ERROR_INTERNAL;
		return (-1);
	}

	*handle = cosk->handle;
	covenant_unlock();

	return (0);
}

/*
 * Forget about a pending cosk pair.
 */
int
covenant_cosk_drop(struct covenant *ctx, u_int32_t handle)
{
	struct covenant_cosk		*cosk;

	if (ctx == NULL)
		return (-1);

	covenant_lock();

	if ((cosk = provision_cosk_lookup(ctx, handle)) == NULL) {
		covenant_unlock();
		ctx->last_error = COVENANT_ERROR_NO_COSK;
		return (-1);
	}

	nyfe_mem_zero(cosk, sizeof(*cosk));
	covenant_unlock();

	return (0);
}

/*
 * Build the vigil configuration for the device and encode it as a QR
 * code into qr (one byte per module, 1 is dark), its side goes in side.
 * On success the cosk pair of the device is consumed.
 */
int
covenant_provision(struct covenant *ctx, const struct covenant_device *dev,
    void *qr, size_t qr_len, int *side)
{
	int			ret;
	char			*config;
	struct covenant_cosk	*cosk;

	if (ctx == NULL)
		return (-1);

	if (provision_device_check(ctx, dev) == -1)
		return (-1);

	if (qr == NULL || qr_len == 0 || side == NULL) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	covenant_lock();

	config = covenant_alloc(COVENANT_CONFIG_MAX_LEN);
	ret = provision_device_config(ctx, dev, config,
	    COVENANT_CONFIG_MAX_LEN, &cosk);

	if (ret == 0)
		ret = covenant_qr_render(ctx, config, qr, qr_len, side);

	if (ret == 0)
		nyfe_mem_zero(cosk, sizeof(*cosk));

	covenant_free(config, COVENANT_CONFIG_MAX_LEN);
	covenant_unlock();

	return (ret);
}

/*
 * Build the vigil configuration for the device into out (NUL terminated),
 * for a platform that hands it to vigil on the same device instead of
 * showing a QR code. On success the cosk pair of the device is consumed.
 *
 * The configuration carries all of the keys of the device, the platform
 * should give us memory it wipes and only keep it for the handover.
 */
int
covenant_provision_config(struct covenant *ctx,
    const struct covenant_device *dev, char *out, size_t out_len)
{
	int			ret;
	struct covenant_cosk	*cosk;

	if (ctx == NULL)
		return (-1);

	if (provision_device_check(ctx, dev) == -1)
		return (-1);

	if (out == NULL || out_len != COVENANT_CONFIG_MAX_LEN) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	covenant_lock();
	ret = provision_device_config(ctx, dev, out, out_len, &cosk);

	if (ret == 0)
		nyfe_mem_zero(cosk, sizeof(*cosk));

	covenant_unlock();

	return (ret);
}

/*
 * Encode any text as a QR code, see covenant_provision() for the layout.
 */
int
covenant_qr_encode(struct covenant *ctx, const char *text, void *qr,
    size_t qr_len, int *side)
{
	int		ret;

	if (ctx == NULL)
		return (-1);

	if (text == NULL || qr == NULL || qr_len == 0 || side == NULL) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	covenant_lock();
	ret = covenant_qr_render(ctx, text, qr, qr_len, side);
	covenant_unlock();

	return (ret);
}

/*
 * Put the public part and the keys together into out, the caller
 * holds the lock and out should come from covenant_alloc().
 */
int
covenant_config_build(struct covenant *ctx, const struct covenant_keks *keks,
    u_int8_t kek, const u_int8_t *cs, size_t cs_len, const u_int8_t *sk,
    size_t sk_len, const char *public, char *out, size_t out_len)
{
	struct covenant_buf	buf;
	char			hex[CONFIG_HEX_MAX];
	char			name[COVENANT_NAME_MAX + 1];
	u_int8_t		sig[COVENANT_SIGNATURE_LEN];
	u_int8_t		pk[SANCTUM_ED25519_SIGN_PUBLIC_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(keks != NULL);
	PRECOND(kek != 0);
	PRECOND(cs != NULL);
	PRECOND(cs_len == COVENANT_CATHEDRAL_SECRET_LEN);
	PRECOND(sk != NULL);
	PRECOND(sk_len == SANCTUM_ED25519_SIGN_SECRET_LENGTH);
	PRECOND(public != NULL);
	PRECOND(out != NULL);
	PRECOND(out_len > 0);

	if (provision_config_check(ctx, public, keks->flock, kek,
	    name, sizeof(name)) == -1)
		return (-1);

	nyfe_zeroize_register(hex, sizeof(hex));

	covenant_buf_init(&buf, out, out_len);
	covenant_buf_appendf(&buf, "%s", public);

	if (public[strlen(public) - 1] != '\n')
		covenant_buf_appendf(&buf, "\n");

	provision_hex_encode(keks->kek[kek - 1],
	    sizeof(keks->kek[kek - 1]), hex, sizeof(hex));
	covenant_buf_appendf(&buf, "kek %s\n", hex);

	provision_hex_encode(cs, cs_len, hex, sizeof(hex));
	covenant_buf_appendf(&buf, "cathedral_secret %s\n", hex);

	provision_hex_encode(sk, sk_len, hex, sizeof(hex));
	covenant_buf_appendf(&buf, "cathedral_cosk %s\n", hex);

	provision_name_sign(keks, kek, name, pk, sizeof(pk), sig, sizeof(sig));

	provision_hex_encode(pk, sizeof(pk), hex, sizeof(hex));
	covenant_buf_appendf(&buf, "name_pubkey %s\n", hex);

	provision_hex_encode(sig, sizeof(sig), hex, sizeof(hex));
	covenant_buf_appendf(&buf, "name_signature %s\n", hex);

	nyfe_zeroize(hex, sizeof(hex));

	if (buf.flags & COVENANT_BUF_FULL) {
		nyfe_mem_zero(out, out_len);
		ctx->last_error = COVENANT_ERROR_CONFIG;
		return (-1);
	}

	return (0);
}

/*
 * Check that the platform gave us everything a device needs.
 */
static int
provision_device_check(struct covenant *ctx, const struct covenant_device *dev)
{
	PRECOND(ctx != NULL);

	if (dev == NULL || dev->secret == NULL ||
	    dev->secret_len != COVENANT_VAULT_KEY_LEN || dev->keks == NULL ||
	    dev->keks_len != COVENANT_KEKS_SEALED_LEN || dev->config == NULL ||
	    dev->cathedral_secret == NULL || dev->kek == 0) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	return (0);
}

/*
 * Put the configuration of the device together into out. The caller
 * holds the lock and consumes the cosk we hand back once it is done
 * with the configuration.
 */
static int
provision_device_config(struct covenant *ctx, const struct covenant_device *dev,
    char *out, size_t out_len, struct covenant_cosk **cosk)
{
	int			ret;
	struct covenant_keks	*keks;
	u_int8_t		cs[COVENANT_CATHEDRAL_SECRET_LEN];

	PRECOND(ctx != NULL);
	PRECOND(dev != NULL);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_CONFIG_MAX_LEN);
	PRECOND(cosk != NULL);

	nyfe_zeroize_register(cs, sizeof(cs));

	if (provision_hex_decode(dev->cathedral_secret, cs, sizeof(cs)) == -1) {
		nyfe_zeroize(cs, sizeof(cs));
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	if ((*cosk = provision_cosk_lookup(ctx, dev->cosk)) == NULL) {
		nyfe_zeroize(cs, sizeof(cs));
		ctx->last_error = COVENANT_ERROR_NO_COSK;
		return (-1);
	}

	if ((keks = covenant_keks_open(ctx, dev->secret, dev->secret_len,
	    dev->keks, dev->keks_len)) == NULL) {
		nyfe_zeroize(cs, sizeof(cs));
		return (-1);
	}

	ret = covenant_config_build(ctx, keks, dev->kek, cs, sizeof(cs),
	    (*cosk)->sk, sizeof((*cosk)->sk), dev->config, out, out_len);

	nyfe_zeroize(cs, sizeof(cs));
	covenant_keks_close(keks);

	return (ret);
}

/*
 * Make sure the public part is a vigil configuration without keys for
 * the flock the KEKs belong to, with an spi that starts with the KEK and
 * with exactly one instance, which is copied into name.
 */
static int
provision_config_check(struct covenant *ctx, const char *public,
    u_int64_t flock, u_int8_t kek, char *name, size_t name_len)
{
	size_t		len, idx;
	char		*line, *next, *opt;
	int		ret, flocks, spis, names;
	char		spi[8], want[32], buf[CONFIG_PUBLIC_MAX + 1];

	PRECOND(ctx != NULL);
	PRECOND(public != NULL);
	PRECOND(kek != 0);
	PRECOND(name != NULL);
	PRECOND(name_len == COVENANT_NAME_MAX + 1);

	len = strlen(public);

	if (len == 0 || len > CONFIG_PUBLIC_MAX) {
		ctx->last_error = COVENANT_ERROR_CONFIG;
		return (-1);
	}

	for (idx = 0; idx < len; idx++) {
		if (public[idx] == '\n')
			continue;

		if (public[idx] < 0x20 || public[idx] > 0x7e) {
			ctx->last_error = COVENANT_ERROR_CONFIG;
			return (-1);
		}
	}

	if (strncmp(public, "vigil 1\n", 8)) {
		ctx->last_error = COVENANT_ERROR_CONFIG;
		return (-1);
	}

	memcpy(buf, public, len + 1);

	ret = snprintf(spi, sizeof(spi), "%02x", kek);
	if (ret < 0 || (size_t)ret >= sizeof(spi))
		covenant_fatal("snprintf on spi");

	ret = snprintf(want, sizeof(want), "%016" PRIx64, flock);
	if (ret < 0 || (size_t)ret >= sizeof(want))
		covenant_fatal("snprintf on flock");

	spis = 0;
	names = 0;
	flocks = 0;

	for (line = buf; line != NULL; line = next) {
		next = strchr(line, '\n');
		if (next != NULL)
			*(next)++ = '\0';

		if (line[0] == '\0')
			continue;

		if ((opt = strchr(line, ' ')) == NULL) {
			ctx->last_error = COVENANT_ERROR_CONFIG;
			return (-1);
		}

		*(opt)++ = '\0';

		for (idx = 0; config_keys[idx] != NULL; idx++) {
			if (!strcmp(line, config_keys[idx])) {
				ctx->last_error = COVENANT_ERROR_CONFIG_KEYS;
				return (-1);
			}
		}

		if (!strcmp(line, "cathedral_flock")) {
			if (strcmp(opt, want)) {
				ctx->last_error = COVENANT_ERROR_CONFIG_FLOCK;
				return (-1);
			}
			flocks++;
		}

		if (!strcmp(line, "spi")) {
			if (strncmp(opt, spi, 2)) {
				ctx->last_error = COVENANT_ERROR_CONFIG_SPI;
				return (-1);
			}
			spis++;
		}

		if (!strcmp(line, "instance")) {
			if (provision_name_valid(opt) == -1) {
				ctx->last_error = COVENANT_ERROR_CONFIG;
				return (-1);
			}

			ret = snprintf(name, name_len, "%s", opt);
			if (ret < 0 || (size_t)ret >= name_len)
				covenant_fatal("snprintf on instance");

			names++;
		}
	}

	if (flocks != 1 || spis != 1 || names != 1) {
		ctx->last_error = COVENANT_ERROR_CONFIG;
		return (-1);
	}

	return (0);
}

/*
 * Check that name is an instance name vigil accepts, using the same
 * rules as its config_parse_instance().
 */
static int
provision_name_valid(const char *name)
{
	size_t		idx, len;

	PRECOND(name != NULL);

	len = strlen(name);
	if (len == 0 || len > COVENANT_NAME_MAX)
		return (-1);

	for (idx = 0; idx < len; idx++) {
		if (!isalnum((unsigned char)name[idx]) && name[idx] != '-' &&
		    name[idx] != '_' && name[idx] != '.' && name[idx] != ' ')
			return (-1);
	}

	return (0);
}

/*
 * Derive the signing key of the flock from its seed, return its public
 * half in pk and sign the name of the device into sig. See
 * COVENANT_NAME_LABEL for what is signed.
 */
static void
provision_name_sign(const struct covenant_keks *keks, u_int8_t kek,
    const char *name, u_int8_t *pk, size_t pk_len, u_int8_t *sig,
    size_t sig_len)
{
	u_int64_t	flock;
	size_t		len, off;
	u_int8_t	msg[COVENANT_NAME_MSG_MAX];
	u_int8_t	sk[SANCTUM_ED25519_SIGN_SECRET_LENGTH];

	PRECOND(keks != NULL);
	PRECOND(kek != 0);
	PRECOND(name != NULL);
	PRECOND(pk != NULL);
	PRECOND(pk_len == SANCTUM_ED25519_SIGN_PUBLIC_LENGTH);
	PRECOND(sig != NULL);
	PRECOND(sig_len == COVENANT_SIGNATURE_LEN);

	nyfe_zeroize_register(sk, sizeof(sk));

	if (crypto_sign_seed_keypair(pk, sk, keks->seed) != 0)
		covenant_fatal("failed to derive the flock signing key");

	len = strlen(name);
	VERIFY(len > 0 && len <= COVENANT_NAME_MAX);

	off = sizeof(COVENANT_NAME_LABEL) - 1;
	memcpy(msg, COVENANT_NAME_LABEL, off);

	flock = htobe64(keks->flock);
	memcpy(&msg[off], &flock, sizeof(flock));
	off += sizeof(flock);

	msg[off++] = kek;
	msg[off++] = (u_int8_t)len;

	memcpy(&msg[off], name, len);
	off += len;

	if (crypto_sign_detached(sig, NULL, msg, off, sk) != 0)
		covenant_fatal("failed to sign the device name");

	nyfe_zeroize(sk, sizeof(sk));
}

/*
 * Find the pending cosk pair for the given handle, the caller holds
 * the lock.
 */
static struct covenant_cosk *
provision_cosk_lookup(struct covenant *ctx, u_int32_t handle)
{
	int		idx;

	PRECOND(ctx != NULL);

	if (handle == 0)
		return (NULL);

	for (idx = 0; idx < COVENANT_COSK_MAX; idx++) {
		if (ctx->cosk[idx].handle == handle)
			return (&ctx->cosk[idx]);
	}

	return (NULL);
}

/*
 * Encode len bytes as lowercase hex into out, which must have room
 * for the terminating NUL as well.
 */
static void
provision_hex_encode(const u_int8_t *in, size_t len, char *out, size_t out_len)
{
	PRECOND(in != NULL);
	PRECOND(len > 0);
	PRECOND(out != NULL);
	PRECOND(out_len >= (len * 2) + 1);

	(void)sodium_bin2hex(out, out_len, in, len);
}

/*
 * Decode exactly len bytes worth of hex from the given string.
 */
static int
provision_hex_decode(const char *hex, u_int8_t *out, size_t len)
{
	size_t		got;
	const char	*end;

	PRECOND(hex != NULL);
	PRECOND(out != NULL);
	PRECOND(len > 0);

	if (strlen(hex) != len * 2)
		return (-1);

	if (sodium_hex2bin(out, len, hex, len * 2, NULL, &got, &end) != 0 ||
	    got != len || end != hex + (len * 2)) {
		nyfe_mem_zero(out, len);
		return (-1);
	}

	return (0);
}
