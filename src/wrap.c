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

#include <stdint.h>
#include <string.h>

#include "covenant-int.h"

static void	wrap_key_derive(const void *, size_t,
		    const struct covenant_wrap_head *, u_int8_t *, size_t);

/*
 * Wrap the vault key under the given passphrase into out.
 */
void
covenant_key_wrap(struct covenant *ctx, const void *pass, size_t pass_len,
    const void *key, size_t key_len, void *out, size_t out_len)
{
	struct covenant_wrap_head	hdr;
	u_int8_t			*ptr;
	struct covenant_cipher		cipher;
	u_int8_t			wk[SANCTUM_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(pass != NULL);
	PRECOND(pass_len > 0);
	PRECOND(key != NULL);
	PRECOND(key_len == COVENANT_VAULT_KEY_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_WRAPPED_KEY_LEN);

	VERIFY(out_len == sizeof(hdr) + key_len + SANCTUM_TAG_LENGTH);

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = htobe32(COVENANT_WRAP_VERSION);
	memcpy(hdr.magic, COVENANT_WRAP_MAGIC, sizeof(hdr.magic));

	covenant_lock();

	nyfe_random_bytes(hdr.salt, sizeof(hdr.salt));
	nyfe_random_bytes(hdr.nonce, sizeof(hdr.nonce));

	nyfe_zeroize_register(wk, sizeof(wk));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	wrap_key_derive(pass, pass_len, &hdr, wk, sizeof(wk));
	cipher.ctx = covenant_cipher_setup(wk, sizeof(wk));
	nyfe_zeroize(wk, sizeof(wk));

	ptr = out;
	memcpy(ptr, &hdr, sizeof(hdr));
	nyfe_memcpy(&ptr[sizeof(hdr)], key, key_len);

	cipher.aad = &hdr;
	cipher.aad_len = sizeof(hdr);

	cipher.nonce = hdr.nonce;
	cipher.nonce_len = sizeof(hdr.nonce);

	cipher.pt = &ptr[sizeof(hdr)];
	cipher.ct = &ptr[sizeof(hdr)];
	cipher.data_len = key_len;
	cipher.tag = &ptr[sizeof(hdr) + key_len];

	covenant_cipher_encrypt(&cipher);
	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	covenant_unlock();
}

/*
 * Unwrap the vault key with the given passphrase into key. Returns -1
 * with COVENANT_ERROR_PASSPHRASE if the passphrase does not open it.
 */
int
covenant_key_unwrap(struct covenant *ctx, const void *pass, size_t pass_len,
    const void *in, size_t in_len, void *key, size_t key_len)
{
	struct covenant_wrap_head	hdr;
	const u_int8_t			*ptr;
	struct covenant_cipher		cipher;
	u_int8_t			wk[SANCTUM_KEY_LENGTH];
	u_int8_t			tag[SANCTUM_TAG_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(pass != NULL);
	PRECOND(pass_len > 0);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_WRAPPED_KEY_LEN);
	PRECOND(key != NULL);
	PRECOND(key_len == COVENANT_VAULT_KEY_LEN);

	VERIFY(in_len == sizeof(hdr) + key_len + sizeof(tag));

	ptr = in;
	memcpy(&hdr, ptr, sizeof(hdr));

	if (memcmp(hdr.magic, COVENANT_WRAP_MAGIC, sizeof(hdr.magic))) {
		ctx->last_error = COVENANT_ERROR_VERSION;
		return (-1);
	}

	if (be32toh(hdr.version) != COVENANT_WRAP_VERSION) {
		ctx->last_error = COVENANT_ERROR_VERSION;
		return (-1);
	}

	covenant_lock();

	nyfe_memcpy(key, &ptr[sizeof(hdr)], key_len);
	nyfe_memcpy(tag, &ptr[sizeof(hdr) + key_len], sizeof(tag));

	nyfe_zeroize_register(wk, sizeof(wk));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	wrap_key_derive(pass, pass_len, &hdr, wk, sizeof(wk));
	cipher.ctx = covenant_cipher_setup(wk, sizeof(wk));
	nyfe_zeroize(wk, sizeof(wk));

	cipher.aad = &hdr;
	cipher.aad_len = sizeof(hdr);

	cipher.nonce = hdr.nonce;
	cipher.nonce_len = sizeof(hdr.nonce);

	cipher.pt = key;
	cipher.ct = key;
	cipher.tag = tag;
	cipher.data_len = key_len;

	if (covenant_cipher_decrypt(&cipher) == -1) {
		covenant_cipher_cleanup(cipher.ctx);
		nyfe_mem_zero(key, key_len);
		nyfe_zeroize(&cipher, sizeof(cipher));
		covenant_unlock();
		ctx->last_error = COVENANT_ERROR_PASSPHRASE;
		return (-1);
	}

	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	covenant_unlock();

	return (0);
}

/*
 * Derive the key the vault key is wrapped under.
 *
 * We first run the passphrase through nyfe_passphrase_kdf() which
 * produces 64-bytes of IKM, this is then run through KMAC256():
 *
 *	K = KMAC256(ikm, COVENANT_WRAP_KDF_LABEL, ""), 256-bit
 */
static void
wrap_key_derive(const void *pass, size_t pass_len,
    const struct covenant_wrap_head *hdr, u_int8_t *out, size_t out_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		okm[NYFE_KEY_LEN];

	PRECOND(pass != NULL);
	PRECOND(pass_len > 0);
	PRECOND(pass_len <= UINT32_MAX);
	PRECOND(hdr != NULL);
	PRECOND(out != NULL);
	PRECOND(out_len == SANCTUM_KEY_LENGTH);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_passphrase_kdf(pass, pass_len, hdr->salt,
	    sizeof(hdr->salt), okm, sizeof(okm), COVENANT_WRAP_PASS_LABEL,
	    sizeof(COVENANT_WRAP_PASS_LABEL) - 1);

	nyfe_kmac256_init(&kdf, okm, sizeof(okm),
	    COVENANT_WRAP_KDF_LABEL, sizeof(COVENANT_WRAP_KDF_LABEL) - 1);
	nyfe_zeroize(okm, sizeof(okm));

	nyfe_kmac256_final(&kdf, out, out_len);
	nyfe_zeroize(&kdf, sizeof(kdf));
}
