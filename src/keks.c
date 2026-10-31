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

#include <string.h>
#include <time.h>

#include "covenant-int.h"

static void	keks_seal_key_derive(const u_int8_t *, size_t,
		    const struct covenant_keks_head *, u_int8_t *, size_t);
static int	keks_header_verify(struct covenant *, const void *, size_t);

/*
 * Generate all KEKs for the given flock and seal them into out.
 */
void
covenant_keks_generate(struct covenant *ctx, const void *secret, size_t len,
    u_int64_t flock, void *out, size_t out_len)
{
	int			idx;
	struct covenant_keks	*keks;

	PRECOND(ctx != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_KEKS_SEALED_LEN);

	covenant_lock();

	keks = covenant_alloc(sizeof(*keks));
	keks->flock = flock;
	keks->created = (u_int64_t)time(NULL);

	for (idx = 0; idx < COVENANT_KEK_COUNT; idx++) {
		nyfe_random_init();
		nyfe_random_bytes(keks->kek[idx], sizeof(keks->kek[idx]));
	}

	nyfe_random_init();

	covenant_keks_seal(secret, len, keks, out, out_len);
	covenant_keks_close(keks);

	covenant_unlock();
}

/*
 * Import existing KEKs and seal them into out.
 */
void
covenant_keks_import(struct covenant *ctx, const void *secret, size_t len,
    u_int64_t flock, const void *data, size_t data_len, void *out,
    size_t out_len)
{
	struct covenant_keks		*keks;

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(data != NULL);
	PRECOND(data_len == COVENANT_KEKS_DATA_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_KEKS_SEALED_LEN);

	covenant_lock();

	keks = covenant_alloc(sizeof(*keks));
	keks->flock = flock;
	keks->created = (u_int64_t)time(NULL);

	nyfe_memcpy(keks->kek, data, data_len);

	covenant_keks_seal(secret, len, keks, out, out_len);
	covenant_keks_close(keks);

	covenant_unlock();
}

/*
 * Replace a single KEK with a new one.
 */
int
covenant_keks_renew(struct covenant *ctx, const void *secret, size_t len,
    const void *in, size_t in_len, u_int8_t id, void *out, size_t out_len)
{
	struct covenant_keks		*keks;

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_KEKS_SEALED_LEN);
	PRECOND(id > 0);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_KEKS_SEALED_LEN);

	covenant_lock();

	if ((keks = covenant_keks_open(ctx, secret, len, in, in_len)) == NULL) {
		covenant_unlock();
		return (-1);
	}

	nyfe_random_init();
	nyfe_random_bytes(keks->kek[id - 1], sizeof(keks->kek[id - 1]));
	nyfe_random_init();

	covenant_keks_seal(secret, len, keks, out, out_len);
	covenant_keks_close(keks);

	covenant_unlock();

	return (0);
}

/*
 * Return encrypted KEK bundle its meta-data.
 */
int
covenant_keks_info(struct covenant *ctx, const void *in, size_t in_len,
    struct covenant_info *info)
{
	const struct covenant_keks_head	*hdr;

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_KEKS_SEALED_LEN);
	PRECOND(info != NULL);

	if (keks_header_verify(ctx, in, in_len) == -1)
		return (-1);

	hdr = in;

	info->flock = be64toh(hdr->flock);
	info->created = be64toh(hdr->created);

	return (0);
}

/*
 * Attempt to open the encrypted KEK bundle with the given secret.
 */
int
covenant_keks_check(struct covenant *ctx, const void *secret, size_t len,
    const void *in, size_t in_len)
{
	struct covenant_keks		*keks;

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_KEKS_SEALED_LEN);

	covenant_lock();

	if ((keks = covenant_keks_open(ctx, secret, len, in, in_len)) == NULL) {
		covenant_unlock();
		return (-1);
	}

	covenant_keks_close(keks);
	covenant_unlock();

	return (0);
}

/*
 * Open an encrypted KEK bundle.
 */
struct covenant_keks *
covenant_keks_open(struct covenant *ctx, const u_int8_t *secret, size_t len,
    const void *in, size_t in_len)
{
	struct covenant_keks_head	hdr;
	const u_int8_t			*ptr;
	struct covenant_keks		*keks;
	struct covenant_cipher		cipher;
	u_int8_t			tag[SANCTUM_TAG_LENGTH];
	u_int8_t			key[SANCTUM_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_KEKS_SEALED_LEN);

	if (keks_header_verify(ctx, in, in_len) == -1)
		return (NULL);

	ptr = in;
	memcpy(&hdr, ptr, sizeof(hdr));

	keks = covenant_alloc(sizeof(*keks));
	keks->flock = be64toh(hdr.flock);
	keks->created = be64toh(hdr.created);

	VERIFY(in_len == sizeof(hdr) + sizeof(keks->kek) + sizeof(tag));

	nyfe_memcpy(keks->kek, ptr + sizeof(hdr), sizeof(keks->kek));
	nyfe_memcpy(tag, ptr + sizeof(hdr) + sizeof(keks->kek), sizeof(tag));

	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	keks_seal_key_derive(secret, len, &hdr, key, sizeof(key));
	cipher.ctx = covenant_cipher_setup(key, sizeof(key));
	nyfe_zeroize(key, sizeof(key));

	cipher.aad = &hdr;
	cipher.aad_len = sizeof(hdr);

	cipher.nonce = hdr.nonce;
	cipher.nonce_len = sizeof(hdr.nonce);

	cipher.tag = tag;
	cipher.pt = keks->kek;
	cipher.ct = keks->kek;
	cipher.data_len = sizeof(keks->kek);

	if (covenant_cipher_decrypt(&cipher) == -1) {
		covenant_cipher_cleanup(cipher.ctx);
		nyfe_zeroize(&cipher, sizeof(cipher));
		covenant_keks_close(keks);
		ctx->last_error = COVENANT_ERROR_INTEGRITY;
		return (NULL);
	}

	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	return (keks);
}

/*
 * Wipe all KEK data.
 */
void
covenant_keks_close(struct covenant_keks *keks)
{
	PRECOND(keks != NULL);

	covenant_free(keks, sizeof(*keks));
}

/*
 * Encrypt the KEKs under a fresh salt and nonce.
 */
void
covenant_keks_seal(const u_int8_t *secret, size_t len,
    const struct covenant_keks *keks, u_int8_t *out, size_t out_len)
{
	struct covenant_keks_head	hdr;
	struct covenant_cipher		cipher;
	u_int8_t			key[SANCTUM_KEY_LENGTH];

	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(keks != NULL);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_KEKS_SEALED_LEN);

	VERIFY(out_len == sizeof(hdr) + sizeof(keks->kek) + SANCTUM_TAG_LENGTH);

	memset(&hdr, 0, sizeof(hdr));
	memcpy(hdr.magic, COVENANT_KEKS_MAGIC, sizeof(hdr.magic));

	hdr.flock = htobe64(keks->flock);
	hdr.created = htobe64(keks->created);
	hdr.version = htobe32(COVENANT_KEKS_VERSION);

	nyfe_random_bytes(hdr.salt, sizeof(hdr.salt));
	nyfe_random_bytes(hdr.nonce, sizeof(hdr.nonce));

	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	keks_seal_key_derive(secret, len, &hdr, key, sizeof(key));
	cipher.ctx = covenant_cipher_setup(key, sizeof(key));
	nyfe_zeroize(key, sizeof(key));

	memcpy(out, &hdr, sizeof(hdr));
	nyfe_memcpy(out + sizeof(hdr), keks->kek, sizeof(keks->kek));

	cipher.aad = &hdr;
	cipher.aad_len = sizeof(hdr);

	cipher.nonce = hdr.nonce;
	cipher.nonce_len = sizeof(hdr.nonce);

	cipher.pt = out + sizeof(hdr);
	cipher.ct = out + sizeof(hdr);
	cipher.tag = out + sizeof(hdr) + sizeof(keks->kek);
	cipher.data_len = sizeof(keks->kek);

	covenant_cipher_encrypt(&cipher);
	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));
}

/*
 * Derive actual KEK for the given flock from our device KEK.
 *
 *	if src <= dst:
 *		flock_a = src
 *		flock_b = dst
 *	else:
 *		flock_a = dst
 *		flock_b = src
 *
 *	x = len(flock_a) || flock_a || len(flock_b) || flock_b
 *	K = KMAC256(kek, SANCTUM_KEY_KEK_UNWRAP_KDF_LABEL, x), 256-bit
 */
void
covenant_kek_derive(const u_int8_t *kek, size_t kek_len, u_int64_t src,
    u_int64_t dst, u_int8_t *out, size_t out_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		len;
	u_int64_t		flock_a, flock_b;

	PRECOND(kek != NULL);
	PRECOND(kek_len == COVENANT_KEK_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_KEK_LEN);

	nyfe_zeroize_register(&kdf, sizeof(kdf));

	if (src <= dst) {
		flock_a = htobe64(src);
		flock_b = htobe64(dst);
	} else {
		flock_a = htobe64(dst);
		flock_b = htobe64(src);
	}

	nyfe_kmac256_init(&kdf, kek, kek_len,
	    SANCTUM_KEY_KEK_UNWRAP_KDF_LABEL,
	    sizeof(SANCTUM_KEY_KEK_UNWRAP_KDF_LABEL) - 1);

	len = sizeof(flock_a);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &flock_a, sizeof(flock_a));
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &flock_b, sizeof(flock_b));

	nyfe_kmac256_final(&kdf, out, out_len);
	nyfe_zeroize(&kdf, sizeof(kdf));
}

/*
 * Derive the key the KEKs are sealed under.
 *
 *	x = len(salt) || salt || len(flock) || flock
 *	K = KMAC256(vault key, COVENANT_KEKS_KDF_LABEL, x), 256-bit
 */
static void
keks_seal_key_derive(const u_int8_t *secret, size_t klen,
    const struct covenant_keks_head *hdr, u_int8_t *out, size_t out_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		len;

	PRECOND(secret != NULL);
	PRECOND(klen == COVENANT_VAULT_KEY_LEN);
	PRECOND(hdr != NULL);
	PRECOND(out != NULL);
	PRECOND(out_len == SANCTUM_KEY_LENGTH);

	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_kmac256_init(&kdf, secret, klen,
	    COVENANT_KEKS_KDF_LABEL, sizeof(COVENANT_KEKS_KDF_LABEL) - 1);

	len = sizeof(hdr->salt);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, hdr->salt, sizeof(hdr->salt));

	len = sizeof(hdr->flock);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &hdr->flock, sizeof(hdr->flock));

	nyfe_kmac256_final(&kdf, out, out_len);
	nyfe_zeroize(&kdf, sizeof(kdf));
}

/*
 * Check the meta-data fields in a header.
 */
static int
keks_header_verify(struct covenant *ctx, const void *in, size_t in_len)
{
	const struct covenant_keks_head		*hdr;

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_KEKS_SEALED_LEN);

	hdr = in;

	if (memcmp(hdr->magic, COVENANT_KEKS_MAGIC, sizeof(hdr->magic))) {
		ctx->last_error = COVENANT_ERROR_VERSION;
		return (-1);
	}

	if (be32toh(hdr->version) != COVENANT_KEKS_VERSION) {
		ctx->last_error = COVENANT_ERROR_VERSION;
		return (-1);
	}

	return (0);
}
