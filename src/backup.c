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

#include <sodium.h>

#include "covenant-int.h"

/*
 * The keys derived from a recovery key.
 */
struct backup_keys {
	u_int8_t	mac_key[SANCTUM_KEY_LENGTH];
	u_int8_t	x25519_sk[COVENANT_X25519_LEN];
	u_int8_t	x25519_pk[COVENANT_X25519_LEN];
	u_int8_t	mlkem_sk[COVENANT_MLKEM_SECRET_LEN];
	u_int8_t	mlkem_pk[COVENANT_MLKEM_PUBLIC_LEN];
};

/*
 * The ML-KEM and x25519 shared secrets, the key for backup_seal_key_derive().
 */
struct backup_okm {
	u_int8_t	mlkem[COVENANT_MLKEM_SHARED_LEN];
	u_int8_t	x25519[COVENANT_X25519_LEN];
} __attribute__((packed));

static void	backup_keys_derive(const u_int8_t *, size_t,
		    struct backup_keys *);
static int	backup_header_verify(struct covenant *, const u_int8_t *,
		    size_t, struct covenant_backup_head *);
static void	backup_mac_calculate(const u_int8_t *, size_t,
		    const u_int8_t *, size_t, u_int8_t *, size_t);
static void	backup_recipient_make(const u_int8_t *, size_t,
		    const u_int8_t *, size_t, u_int8_t *, size_t);
static void	backup_recipient_key_derive(const u_int8_t *, size_t,
		    const struct covenant_recipient *, u_int8_t *, size_t);
static int	backup_keks_seal(struct covenant *,
		    const struct covenant_recipient *, const u_int8_t *,
		    size_t, const struct covenant_keks *, u_int8_t *, size_t);
static void	backup_seal_key_derive(const struct backup_okm *,
		    const struct covenant_backup_head *,
		    const u_int8_t *, size_t, u_int8_t *, size_t);
static int	backup_recipient_open(struct covenant *,
		    const u_int8_t *, size_t, const u_int8_t *, size_t,
		    struct covenant_recipient *, u_int8_t *, size_t);

static struct covenant_keks	*backup_keks_open(struct covenant *,
				    const u_int8_t *, size_t,
				    const u_int8_t *, size_t);

/*
 * Generate a new recovery key into root and its recipient into out.
 */
void
covenant_backup_keygen(struct covenant *ctx, const void *secret, size_t len,
    void *root, size_t root_len, void *out, size_t out_len)
{
	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(root != NULL);
	PRECOND(root_len == COVENANT_BACKUP_ROOT_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_BACKUP_RECIPIENT_LEN);

	covenant_lock();

	nyfe_random_init();
	nyfe_random_bytes(root, root_len);
	nyfe_random_init();

	backup_recipient_make(secret, len, root, root_len, out, out_len);

	covenant_unlock();
}

/*
 * Make the recipient for the given recovery key into out.
 */
void
covenant_backup_recipient(struct covenant *ctx, const void *secret, size_t len,
    const void *root, size_t root_len, void *out, size_t out_len)
{
	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(root != NULL);
	PRECOND(root_len == COVENANT_BACKUP_ROOT_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_BACKUP_RECIPIENT_LEN);

	covenant_lock();
	backup_recipient_make(secret, len, root, root_len, out, out_len);
	covenant_unlock();
}

/*
 * Check that the recipient belongs to the given recovery key.
 */
int
covenant_backup_verify(struct covenant *ctx, const void *root, size_t root_len,
    const void *in, size_t in_len)
{
	struct covenant_recipient	rcpt;
	struct backup_keys		*keys;
	int				mismatch;

	PRECOND(ctx != NULL);
	PRECOND(root != NULL);
	PRECOND(root_len == COVENANT_BACKUP_ROOT_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_BACKUP_RECIPIENT_LEN);

	VERIFY(in_len == sizeof(rcpt));
	memcpy(&rcpt, in, sizeof(rcpt));

	if (memcmp(rcpt.magic, COVENANT_RECIPIENT_MAGIC, sizeof(rcpt.magic)) ||
	    be32toh(rcpt.version) != COVENANT_RECIPIENT_VERSION) {
		ctx->last_error = COVENANT_ERROR_VERSION;
		return (-1);
	}

	covenant_lock();

	keys = covenant_alloc(sizeof(*keys));
	backup_keys_derive(root, root_len, keys);

	mismatch = nyfe_mem_cmp(rcpt.x25519,
	    keys->x25519_pk, sizeof(rcpt.x25519));
	mismatch |= nyfe_mem_cmp(rcpt.mlkem,
	    keys->mlkem_pk, sizeof(rcpt.mlkem));

	covenant_free(keys, sizeof(*keys));
	covenant_unlock();

	if (mismatch) {
		ctx->last_error = COVENANT_ERROR_RECOVERY_KEY;
		return (-1);
	}

	return (0);
}

/*
 * Back up the sealed KEKs in `in` to the recipient into out.
 */
int
covenant_backup_seal(struct covenant *ctx, const void *secret, size_t len,
    const void *recipient, size_t recipient_len, const void *in,
    size_t in_len, void *out, size_t out_len)
{
	int				ret;
	struct covenant_recipient	rcpt;
	struct covenant_keks		*keks;
	u_int8_t			mac_key[SANCTUM_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(recipient != NULL);
	PRECOND(recipient_len == COVENANT_BACKUP_RECIPIENT_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_KEKS_SEALED_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_BACKUP_LEN);

	covenant_lock();
	nyfe_zeroize_register(mac_key, sizeof(mac_key));

	if (backup_recipient_open(ctx, secret, len, recipient, recipient_len,
	    &rcpt, mac_key, sizeof(mac_key)) == -1) {
		nyfe_zeroize(mac_key, sizeof(mac_key));
		covenant_unlock();
		return (-1);
	}

	if ((keks = covenant_keks_open(ctx, secret, len, in, in_len)) == NULL) {
		nyfe_zeroize(mac_key, sizeof(mac_key));
		covenant_unlock();
		return (-1);
	}

	ret = backup_keks_seal(ctx, &rcpt, mac_key, sizeof(mac_key),
	    keks, out, out_len);
	nyfe_zeroize(mac_key, sizeof(mac_key));

	covenant_keks_close(keks);
	covenant_unlock();

	return (ret);
}

/*
 * Open a backup with the recovery key and seal its KEKs under the
 * vault key into out. A backup of version 2 has no signing seed, the
 * KEKs then get a new one.
 */
int
covenant_backup_restore(struct covenant *ctx, const void *secret, size_t len,
    const void *root, size_t root_len, const void *in, size_t in_len,
    void *out, size_t out_len)
{
	struct covenant_keks		*keks;

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(root != NULL);
	PRECOND(root_len == COVENANT_BACKUP_ROOT_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_BACKUP_LEN ||
	    in_len == COVENANT_BACKUP_V2_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_KEKS_SEALED_LEN);

	covenant_lock();

	if ((keks = backup_keks_open(ctx, root, root_len,
	    in, in_len)) == NULL) {
		covenant_unlock();
		return (-1);
	}

	covenant_keks_seal(secret, len, keks, out, out_len);
	covenant_keks_close(keks);

	covenant_unlock();

	return (0);
}

/*
 * The public part of a backup, so the platform can tell what it has
 * without asking for the recovery key.
 */
int
covenant_backup_info(struct covenant *ctx, const void *in, size_t in_len,
    struct covenant_backup_info *info)
{
	struct covenant_backup_head	head;

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(info != NULL);

	if (in_len != COVENANT_BACKUP_LEN && in_len != COVENANT_BACKUP_V2_LEN) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	if (backup_header_verify(ctx, in, in_len, &head) == -1)
		return (-1);

	info->flock = be64toh(head.flock);
	info->made = be64toh(head.made);
	info->created = be64toh(head.created);

	return (0);
}

#if defined(PLATFORM_HOST)
/*
 * Open a backup with the recovery key and return the KEK contents.
 * Only exists here for covenant-restore.
 */
int
covenant_backup_open(struct covenant *ctx, const void *root, size_t root_len,
    const void *in, size_t in_len, void *data, size_t data_len,
    struct covenant_backup_info *info)
{
	struct covenant_keks		*keks;

	PRECOND(ctx != NULL);
	PRECOND(root != NULL);
	PRECOND(root_len == COVENANT_BACKUP_ROOT_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_BACKUP_LEN ||
	    in_len == COVENANT_BACKUP_V2_LEN);
	PRECOND(data != NULL);
	PRECOND(data_len == COVENANT_KEKS_DATA_LEN);
	PRECOND(info != NULL);

	if (covenant_backup_info(ctx, in, in_len, info) == -1)
		return (-1);

	covenant_lock();

	keks = backup_keks_open(ctx, root, root_len, in, in_len);
	if (keks == NULL) {
		covenant_unlock();
		return (-1);
	}

	nyfe_memcpy(data, keks->kek, data_len);

	covenant_keks_close(keks);
	covenant_unlock();

	return (0);
}
#endif

/*
 * Encrypt the KEKs and the signing seed to the recipient and mac the
 * result under mac_key into out. The caller holds the lock.
 */
static int
backup_keks_seal(struct covenant *ctx, const struct covenant_recipient *rcpt,
    const u_int8_t *mac_key, size_t mac_key_len,
    const struct covenant_keks *keks, u_int8_t *out, size_t out_len)
{
	struct backup_okm		okm;
	struct covenant_backup_head	head;
	struct covenant_cipher		cipher;
	u_int8_t			eph[COVENANT_X25519_LEN];
	u_int8_t			key[SANCTUM_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(rcpt != NULL);
	PRECOND(mac_key != NULL);
	PRECOND(mac_key_len == SANCTUM_KEY_LENGTH);
	PRECOND(keks != NULL);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_BACKUP_LEN);

	VERIFY(out_len == sizeof(head) + COVENANT_KEKS_SECRET_LEN +
	    SANCTUM_TAG_LENGTH + SANCTUM_KEY_LENGTH);

	memset(&head, 0, sizeof(head));
	memcpy(head.magic, COVENANT_BACKUP_MAGIC, sizeof(head.magic));

	head.version = htobe32(COVENANT_BACKUP_VERSION);
	head.flock = htobe64(keks->flock);
	head.created = htobe64(keks->created);
	head.made = htobe64((u_int64_t)time(NULL));

	nyfe_random_bytes(head.nonce, sizeof(head.nonce));

	nyfe_zeroize_register(eph, sizeof(eph));
	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(&okm, sizeof(okm));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	(void)pqcrystals_kyber1024_ref_enc(head.mlkem, okm.mlkem, rcpt->mlkem);

	nyfe_random_bytes(eph, sizeof(eph));

	if (crypto_scalarmult_curve25519_base(head.x25519, eph) == -1 ||
	    crypto_scalarmult_curve25519(okm.x25519, eph, rcpt->x25519) == -1) {
		nyfe_zeroize(eph, sizeof(eph));
		nyfe_zeroize(key, sizeof(key));
		nyfe_zeroize(&okm, sizeof(okm));
		nyfe_zeroize(&cipher, sizeof(cipher));
		ctx->last_error = COVENANT_ERROR_INTERNAL;
		return (-1);
	}

	nyfe_zeroize(eph, sizeof(eph));

	backup_seal_key_derive(&okm, &head, rcpt->x25519, sizeof(rcpt->x25519),
	    key, sizeof(key));
	nyfe_zeroize(&okm, sizeof(okm));

	cipher.ctx = covenant_cipher_setup(key, sizeof(key));
	nyfe_zeroize(key, sizeof(key));

	memcpy(out, &head, sizeof(head));
	covenant_keks_pack(keks, &out[sizeof(head)], COVENANT_KEKS_SECRET_LEN);

	cipher.aad = &head;
	cipher.aad_len = sizeof(head);

	cipher.nonce = head.nonce;
	cipher.nonce_len = sizeof(head.nonce);

	cipher.pt = &out[sizeof(head)];
	cipher.ct = &out[sizeof(head)];
	cipher.tag = &out[sizeof(head) + COVENANT_KEKS_SECRET_LEN];
	cipher.data_len = COVENANT_KEKS_SECRET_LEN;

	covenant_cipher_encrypt(&cipher);
	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	backup_mac_calculate(mac_key, mac_key_len,
	    out, out_len - SANCTUM_KEY_LENGTH,
	    out + out_len - SANCTUM_KEY_LENGTH, SANCTUM_KEY_LENGTH);

	return (0);
}

/*
 * Open a backup with the recovery key into memory from covenant_alloc().
 * The caller holds the lock and must covenant_keks_close() the result.
 */
static struct covenant_keks *
backup_keks_open(struct covenant *ctx, const u_int8_t *root, size_t root_len,
    const u_int8_t *in, size_t in_len)
{
	struct backup_okm		okm;
	struct covenant_backup_head	head;
	u_int8_t			*data;
	struct covenant_keks		*keks;
	struct backup_keys		*keys;
	struct covenant_cipher		cipher;
	size_t				data_len;
	u_int8_t			tag[SANCTUM_TAG_LENGTH];
	u_int8_t			key[SANCTUM_KEY_LENGTH];
	u_int8_t			mac[SANCTUM_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(root != NULL);
	PRECOND(root_len == COVENANT_BACKUP_ROOT_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_BACKUP_LEN ||
	    in_len == COVENANT_BACKUP_V2_LEN);

	if (in_len == COVENANT_BACKUP_LEN)
		data_len = COVENANT_KEKS_SECRET_LEN;
	else
		data_len = COVENANT_KEKS_DATA_LEN;

	VERIFY(in_len == sizeof(head) + data_len + sizeof(tag) + sizeof(mac));

	if (backup_header_verify(ctx, in, in_len, &head) == -1)
		return (NULL);

	keys = covenant_alloc(sizeof(*keys));
	backup_keys_derive(root, root_len, keys);

	backup_mac_calculate(keys->mac_key, sizeof(keys->mac_key),
	    in, in_len - sizeof(mac), mac, sizeof(mac));

	if (nyfe_mem_cmp(mac, in + in_len - sizeof(mac), sizeof(mac))) {
		covenant_free(keys, sizeof(*keys));
		ctx->last_error = COVENANT_ERROR_RECOVERY_KEY;
		return (NULL);
	}

	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(&okm, sizeof(okm));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	(void)pqcrystals_kyber1024_ref_dec(okm.mlkem,
	    head.mlkem, keys->mlkem_sk);

	if (crypto_scalarmult_curve25519(okm.x25519,
	    keys->x25519_sk, head.x25519) == -1) {
		covenant_free(keys, sizeof(*keys));
		nyfe_zeroize(key, sizeof(key));
		nyfe_zeroize(&okm, sizeof(okm));
		nyfe_zeroize(&cipher, sizeof(cipher));
		ctx->last_error = COVENANT_ERROR_INTEGRITY;
		return (NULL);
	}

	backup_seal_key_derive(&okm, &head,
	    keys->x25519_pk, sizeof(keys->x25519_pk), key, sizeof(key));

	nyfe_zeroize(&okm, sizeof(okm));
	covenant_free(keys, sizeof(*keys));

	data = covenant_alloc(data_len);
	nyfe_memcpy(data, &in[sizeof(head)], data_len);
	nyfe_memcpy(tag, &in[sizeof(head) + data_len], sizeof(tag));

	cipher.ctx = covenant_cipher_setup(key, sizeof(key));
	nyfe_zeroize(key, sizeof(key));

	cipher.aad = &head;
	cipher.aad_len = sizeof(head);

	cipher.nonce = head.nonce;
	cipher.nonce_len = sizeof(head.nonce);

	cipher.tag = tag;
	cipher.pt = data;
	cipher.ct = data;
	cipher.data_len = data_len;

	if (covenant_cipher_decrypt(&cipher) == -1) {
		covenant_cipher_cleanup(cipher.ctx);
		nyfe_zeroize(&cipher, sizeof(cipher));
		covenant_free(data, data_len);
		ctx->last_error = COVENANT_ERROR_RECOVERY_KEY;
		return (NULL);
	}

	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	keks = covenant_alloc(sizeof(*keks));
	keks->flock = be64toh(head.flock);
	keks->created = be64toh(head.created);

	if (data_len == COVENANT_KEKS_SECRET_LEN) {
		covenant_keks_unpack(keks, data, data_len);
	} else {
		nyfe_memcpy(keks->kek, data, sizeof(keks->kek));
		nyfe_random_init();
		nyfe_random_bytes(keks->seed, sizeof(keks->seed));
		nyfe_random_init();
	}

	covenant_free(data, data_len);

	return (keks);
}

/*
 * Derive the key a backup is encrypted under.
 *
 *	x = len(eph) || eph || len(pk) || pk || len(flock) || flock
 *	K = KMAC256(mlkem ss || x25519 ss, COVENANT_BACKUP_KDF_LABEL, x),
 *	    256-bit
 */
static void
backup_seal_key_derive(const struct backup_okm *okm,
    const struct covenant_backup_head *head, const u_int8_t *pk, size_t pk_len,
    u_int8_t *out, size_t out_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		len;

	PRECOND(okm != NULL);
	PRECOND(head != NULL);
	PRECOND(pk != NULL);
	PRECOND(pk_len == COVENANT_X25519_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == SANCTUM_KEY_LENGTH);

	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_kmac256_init(&kdf, okm, sizeof(*okm),
	    COVENANT_BACKUP_KDF_LABEL, sizeof(COVENANT_BACKUP_KDF_LABEL) - 1);

	len = sizeof(head->x25519);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, head->x25519, sizeof(head->x25519));

	len = pk_len;
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, pk, pk_len);

	len = sizeof(head->flock);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, &head->flock, sizeof(head->flock));

	nyfe_kmac256_final(&kdf, out, out_len);
	nyfe_zeroize(&kdf, sizeof(kdf));
}

/*
 * Calculate the mac of a backup under the mac key, it covers everything
 * that comes before it.
 *
 *	M = KMAC256(mac key, COVENANT_BACKUP_MAC_LABEL, backup), 256-bit
 */
static void
backup_mac_calculate(const u_int8_t *key, size_t key_len, const u_int8_t *in,
    size_t in_len, u_int8_t *out, size_t out_len)
{
	struct nyfe_kmac256	kdf;

	PRECOND(key != NULL);
	PRECOND(key_len == SANCTUM_KEY_LENGTH);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_BACKUP_LEN - SANCTUM_KEY_LENGTH ||
	    in_len == COVENANT_BACKUP_V2_LEN - SANCTUM_KEY_LENGTH);
	PRECOND(out != NULL);
	PRECOND(out_len == SANCTUM_KEY_LENGTH);

	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_kmac256_init(&kdf, key, key_len,
	    COVENANT_BACKUP_MAC_LABEL, sizeof(COVENANT_BACKUP_MAC_LABEL) - 1);
	nyfe_kmac256_update(&kdf, in, in_len);

	nyfe_kmac256_final(&kdf, out, out_len);
	nyfe_zeroize(&kdf, sizeof(kdf));
}

/*
 * Derive the mac key and both key pairs from the recovery key.
 *
 *	seed = KMAC256(root, COVENANT_BACKUP_SEED_LABEL), 256-bit
 *	mac key = KMAC256(root, COVENANT_BACKUP_MAC_KEY_LABEL), 256-bit
 *	coins = KMAC256(seed, COVENANT_BACKUP_MLKEM_LABEL), 512-bit
 *	x25519 = KMAC256(seed, COVENANT_BACKUP_X25519_LABEL), 256-bit
 */
static void
backup_keys_derive(const u_int8_t *root, size_t root_len,
    struct backup_keys *keys)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		seed[SANCTUM_KEY_LENGTH];
	u_int8_t		coins[COVENANT_MLKEM_COINS_LEN];

	PRECOND(root != NULL);
	PRECOND(root_len == COVENANT_BACKUP_ROOT_LEN);
	PRECOND(keys != NULL);

	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(seed, sizeof(seed));
	nyfe_zeroize_register(coins, sizeof(coins));

	nyfe_kmac256_init(&kdf, root, root_len,
	    COVENANT_BACKUP_SEED_LABEL, sizeof(COVENANT_BACKUP_SEED_LABEL) - 1);
	nyfe_kmac256_final(&kdf, seed, sizeof(seed));

	nyfe_kmac256_init(&kdf, root, root_len,
	    COVENANT_BACKUP_MAC_KEY_LABEL,
	    sizeof(COVENANT_BACKUP_MAC_KEY_LABEL) - 1);
	nyfe_kmac256_final(&kdf, keys->mac_key, sizeof(keys->mac_key));

	nyfe_kmac256_init(&kdf, seed, sizeof(seed),
	    COVENANT_BACKUP_MLKEM_LABEL,
	    sizeof(COVENANT_BACKUP_MLKEM_LABEL) - 1);
	nyfe_kmac256_final(&kdf, coins, sizeof(coins));

	(void)pqcrystals_kyber1024_ref_keypair_derand(keys->mlkem_pk,
	    keys->mlkem_sk, coins);
	nyfe_zeroize(coins, sizeof(coins));

	nyfe_kmac256_init(&kdf, seed, sizeof(seed),
	    COVENANT_BACKUP_X25519_LABEL,
	    sizeof(COVENANT_BACKUP_X25519_LABEL) - 1);
	nyfe_kmac256_final(&kdf, keys->x25519_sk, sizeof(keys->x25519_sk));

	nyfe_zeroize(&kdf, sizeof(kdf));
	nyfe_zeroize(seed, sizeof(seed));

	if (crypto_scalarmult_curve25519_base(keys->x25519_pk,
	    keys->x25519_sk) == -1)
		covenant_fatal("failed to derive the backup x25519 key");
}

/*
 * Make the recipient for the recovery key into out, with the mac key
 * sealed under the vault key. The caller holds the lock.
 */
static void
backup_recipient_make(const u_int8_t *secret, size_t len,
    const u_int8_t *root, size_t root_len, u_int8_t *out, size_t out_len)
{
	struct covenant_recipient	rcpt;
	struct backup_keys		*keys;
	struct covenant_cipher		cipher;
	u_int8_t			key[SANCTUM_KEY_LENGTH];

	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(root != NULL);
	PRECOND(root_len == COVENANT_BACKUP_ROOT_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == COVENANT_BACKUP_RECIPIENT_LEN);

	VERIFY(out_len == sizeof(rcpt));

	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	memset(&rcpt, 0, sizeof(rcpt));
	memcpy(rcpt.magic, COVENANT_RECIPIENT_MAGIC, sizeof(rcpt.magic));
	rcpt.version = htobe32(COVENANT_RECIPIENT_VERSION);

	nyfe_random_bytes(rcpt.salt, sizeof(rcpt.salt));
	nyfe_random_bytes(rcpt.nonce, sizeof(rcpt.nonce));

	keys = covenant_alloc(sizeof(*keys));
	backup_keys_derive(root, root_len, keys);

	memcpy(rcpt.x25519, keys->x25519_pk, sizeof(rcpt.x25519));
	memcpy(rcpt.mlkem, keys->mlkem_pk, sizeof(rcpt.mlkem));

	backup_recipient_key_derive(secret, len, &rcpt, key, sizeof(key));
	cipher.ctx = covenant_cipher_setup(key, sizeof(key));
	nyfe_zeroize(key, sizeof(key));

	cipher.aad = &rcpt;
	cipher.aad_len = sizeof(rcpt) - sizeof(rcpt.mac_key) -
	    sizeof(rcpt.tag);

	cipher.nonce = rcpt.nonce;
	cipher.nonce_len = sizeof(rcpt.nonce);

	cipher.tag = rcpt.tag;
	cipher.pt = keys->mac_key;
	cipher.ct = rcpt.mac_key;
	cipher.data_len = sizeof(rcpt.mac_key);

	covenant_cipher_encrypt(&cipher);
	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	covenant_free(keys, sizeof(*keys));
	memcpy(out, &rcpt, sizeof(rcpt));
}

/*
 * Copy the recipient into rcpt and decrypt its mac key into mac_key.
 * The caller holds the lock.
 */
static int
backup_recipient_open(struct covenant *ctx, const u_int8_t *secret, size_t len,
    const u_int8_t *in, size_t in_len, struct covenant_recipient *rcpt,
    u_int8_t *mac_key, size_t mac_key_len)
{
	struct covenant_cipher	cipher;
	u_int8_t		key[SANCTUM_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_BACKUP_RECIPIENT_LEN);
	PRECOND(rcpt != NULL);
	PRECOND(mac_key != NULL);
	PRECOND(mac_key_len == sizeof(rcpt->mac_key));

	VERIFY(in_len == sizeof(*rcpt));
	memcpy(rcpt, in, sizeof(*rcpt));

	if (memcmp(rcpt->magic, COVENANT_RECIPIENT_MAGIC,
	    sizeof(rcpt->magic)) ||
	    be32toh(rcpt->version) != COVENANT_RECIPIENT_VERSION) {
		ctx->last_error = COVENANT_ERROR_VERSION;
		return (-1);
	}

	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	backup_recipient_key_derive(secret, len, rcpt, key, sizeof(key));
	cipher.ctx = covenant_cipher_setup(key, sizeof(key));
	nyfe_zeroize(key, sizeof(key));

	cipher.aad = rcpt;
	cipher.aad_len = sizeof(*rcpt) - sizeof(rcpt->mac_key) -
	    sizeof(rcpt->tag);

	cipher.nonce = rcpt->nonce;
	cipher.nonce_len = sizeof(rcpt->nonce);

	cipher.tag = rcpt->tag;
	cipher.pt = mac_key;
	cipher.ct = rcpt->mac_key;
	cipher.data_len = mac_key_len;

	if (covenant_cipher_decrypt(&cipher) == -1) {
		covenant_cipher_cleanup(cipher.ctx);
		nyfe_zeroize(&cipher, sizeof(cipher));
		nyfe_mem_zero(mac_key, mac_key_len);
		ctx->last_error = COVENANT_ERROR_INTEGRITY;
		return (-1);
	}

	covenant_cipher_cleanup(cipher.ctx);
	nyfe_zeroize(&cipher, sizeof(cipher));

	return (0);
}

/*
 * Derive the key the mac key in a recipient is sealed under.
 *
 *	x = len(salt) || salt
 *	K = KMAC256(vault key, COVENANT_RECIPIENT_KDF_LABEL, x), 256-bit
 */
static void
backup_recipient_key_derive(const u_int8_t *secret, size_t len,
    const struct covenant_recipient *rcpt, u_int8_t *out, size_t out_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		salt_len;

	PRECOND(secret != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);
	PRECOND(rcpt != NULL);
	PRECOND(out != NULL);
	PRECOND(out_len == SANCTUM_KEY_LENGTH);

	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_kmac256_init(&kdf, secret, len,
	    COVENANT_RECIPIENT_KDF_LABEL,
	    sizeof(COVENANT_RECIPIENT_KDF_LABEL) - 1);

	salt_len = sizeof(rcpt->salt);
	nyfe_kmac256_update(&kdf, &salt_len, sizeof(salt_len));
	nyfe_kmac256_update(&kdf, rcpt->salt, sizeof(rcpt->salt));

	nyfe_kmac256_final(&kdf, out, out_len);
	nyfe_zeroize(&kdf, sizeof(kdf));
}

/*
 * Copy the header of a backup into head and check its magic and version.
 */
static int
backup_header_verify(struct covenant *ctx, const u_int8_t *in, size_t in_len,
    struct covenant_backup_head *head)
{
	u_int32_t	want;

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(in_len == COVENANT_BACKUP_LEN ||
	    in_len == COVENANT_BACKUP_V2_LEN);
	PRECOND(head != NULL);

	memcpy(head, in, sizeof(*head));

	if (in_len == COVENANT_BACKUP_LEN)
		want = COVENANT_BACKUP_VERSION;
	else
		want = COVENANT_BACKUP_V2;

	if (memcmp(head->magic, COVENANT_BACKUP_MAGIC, sizeof(head->magic)) ||
	    be32toh(head->version) != want) {
		ctx->last_error = COVENANT_ERROR_VERSION;
		return (-1);
	}

	return (0);
}
