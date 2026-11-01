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

#include <limits.h>
#include <string.h>
#include <time.h>

#include "covenant-int.h"

/*
 * Everything we need while making a bundle.
 */
struct ambry_work {
	u_int8_t	seen[USHRT_MAX + 1];
	u_int8_t	key[SANCTUM_KEY_LENGTH];
	u_int8_t	derived[COVENANT_KEK_COUNT][COVENANT_KEK_LEN];
};

static void	ambry_key_wrap(const struct sanctum_ambry_head *,
		    u_int8_t *, size_t, const u_int8_t *, size_t,
		    const u_int8_t *, size_t, u_int64_t, u_int16_t);

/*
 * Generate an ambry bundle valid for the given number of days into out.
 * The generation and the expiry day (since SANCTUM_AMBRY_AGE_EPOCH) are
 * handed back for bookkeeping.
 */
int
covenant_ambry_bundle(struct covenant *ctx, const void *secret, size_t len,
    const void *in, size_t in_len, u_int16_t days, void *out, size_t out_len,
    u_int32_t *generation, u_int16_t *expires)
{
	time_t				now;
	u_int32_t			gen;
	struct sanctum_ambry_head	hdr;
	u_int64_t			flock;
	struct covenant_keks		*keks;
	struct ambry_work		*work;
	u_int8_t			*entry;
	int				src, dst, idx;
	u_int16_t			tunnel, reverse, expiry;

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_KEKS_SEALED_LEN);
	PRECOND(days > 0 && days <= COVENANT_AMBRY_DAYS_MAX);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_AMBRY_LEN);
	PRECOND(generation != NULL);
	PRECOND(expires != NULL);

	covenant_lock();

	if ((keks = covenant_keks_open(ctx, secret, len, in, in_len)) == NULL) {
		covenant_unlock();
		return (-1);
	}

	flock = keks->flock & ~((u_int64_t)SANCTUM_FLOCK_DOMAIN_MASK);
	work = covenant_alloc(sizeof(*work));

	for (idx = 0; idx < COVENANT_KEK_COUNT; idx++) {
		covenant_kek_derive(keks->kek[idx], sizeof(keks->kek[idx]),
		    flock, flock, work->derived[idx],
		    sizeof(work->derived[idx]));
	}

	covenant_keks_close(keks);
	memset(&hdr, 0, sizeof(hdr));

	nyfe_random_init();
	nyfe_random_bytes(&gen, sizeof(gen));
	nyfe_random_bytes(hdr.seed, sizeof(hdr.seed));

	time(&now);
	now += (SANCTUM_AMBRY_AGE_SECONDS_PER_DAY * days);
	now -= SANCTUM_AMBRY_AGE_EPOCH;
	expiry = now / SANCTUM_AMBRY_AGE_SECONDS_PER_DAY;

	hdr.generation = htobe32(gen);
	hdr.expires = htobe16(expiry);

	memcpy(out, &hdr, sizeof(hdr));
	entry = (u_int8_t *)out + sizeof(hdr);

	for (src = 1; src <= 0xff; src++) {
		for (dst = 1; dst <= 0xff; dst++) {
			if (src == dst)
				continue;

			tunnel = src << 8 | dst;
			reverse = dst << 8 | src;

			if (work->seen[tunnel] || work->seen[reverse])
				continue;

			nyfe_random_init();
			nyfe_random_bytes(work->key, sizeof(work->key));
			nyfe_random_init();

			ambry_key_wrap(&hdr, entry,
			    sizeof(struct sanctum_ambry_entry),
			    work->key, sizeof(work->key),
			    work->derived[src - 1],
			    sizeof(work->derived[src - 1]), flock, tunnel);
			entry += sizeof(struct sanctum_ambry_entry);

			ambry_key_wrap(&hdr, entry,
			    sizeof(struct sanctum_ambry_entry),
			    work->key, sizeof(work->key),
			    work->derived[dst - 1],
			    sizeof(work->derived[dst - 1]), flock, reverse);
			entry += sizeof(struct sanctum_ambry_entry);

			work->seen[tunnel] = 1;
			work->seen[reverse] = 1;
		}
	}

	VERIFY(entry == (u_int8_t *)out + out_len);

	covenant_free(work, sizeof(*work));
	covenant_unlock();

	*generation = gen;
	*expires = expiry;

	return (0);
}

/*
 * Wrap the shared secret for one direction of a tunnel under the KEK
 * of the sending device, see ambry_key_wrap() in ambry and its mirror
 * chapel_ambry_unwrap() in sanctum.
 */
static void
ambry_key_wrap(const struct sanctum_ambry_head *hdr, u_int8_t *out,
    size_t out_len, const u_int8_t *key, size_t key_len, const u_int8_t *kek,
    size_t kek_len, u_int64_t flock, u_int16_t tunnel)
{
	struct nyfe_kmac256		kdf;
	struct sanctum_ambry_aad	aad;
	struct sanctum_ambry_entry	entry;
	u_int8_t			in_len;
	struct covenant_cipher		cipher;
	u_int64_t			flock_src, flock_dst;
	u_int8_t			okm[SANCTUM_KEY_LENGTH];
	u_int8_t			nonce[SANCTUM_NONCE_LENGTH];

	PRECOND(hdr != NULL);
	PRECOND(out != NULL);
	PRECOND(out_len == sizeof(entry));
	PRECOND(key != NULL);
	PRECOND(key_len == sizeof(entry.key));
	PRECOND(kek != NULL);
	PRECOND(kek_len == COVENANT_KEK_LEN);

	flock_src = htobe64(flock);
	flock_dst = htobe64(flock);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(&entry, sizeof(entry));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	entry.flock = flock_src;
	entry.tunnel = htobe16(tunnel);
	nyfe_memcpy(entry.key, key, key_len);

	nyfe_kmac256_init(&kdf, kek, kek_len,
	    SANCTUM_AMBRY_KDF, strlen(SANCTUM_AMBRY_KDF));

	in_len = sizeof(hdr->seed);
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, hdr->seed, sizeof(hdr->seed));

	in_len = sizeof(flock_src);
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, &flock_src, sizeof(flock_src));
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, &flock_dst, sizeof(flock_dst));

	in_len = sizeof(hdr->generation);
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, &hdr->generation, sizeof(hdr->generation));

	in_len = sizeof(tunnel);
	nyfe_kmac256_update(&kdf, &in_len, sizeof(in_len));
	nyfe_kmac256_update(&kdf, &entry.tunnel, sizeof(entry.tunnel));

	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));

	cipher.ctx = covenant_cipher_setup(okm, sizeof(okm));
	nyfe_zeroize(okm, sizeof(okm));

	aad.tunnel = entry.tunnel;
	aad.flock_src = flock_src;
	aad.flock_dst = flock_dst;
	aad.expires = hdr->expires;
	aad.generation = hdr->generation;
	nyfe_memcpy(aad.seed, hdr->seed, sizeof(hdr->seed));

	nyfe_mem_zero(nonce, sizeof(nonce));
	nonce[SANCTUM_NONCE_LENGTH - 1] = 0x01;

	cipher.aad = &aad;
	cipher.aad_len = sizeof(aad);

	cipher.nonce = nonce;
	cipher.nonce_len = sizeof(nonce);

	cipher.pt = entry.key;
	cipher.ct = entry.key;
	cipher.tag = &entry.tag[0];
	cipher.data_len = sizeof(entry.key);

	covenant_cipher_encrypt(&cipher);
	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	memcpy(out, &entry, sizeof(entry));
	nyfe_zeroize(&entry, sizeof(entry));
}
