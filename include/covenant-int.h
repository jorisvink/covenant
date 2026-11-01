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

#ifndef __H_COVENANT_INT_H
#define __H_COVENANT_INT_H

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "covenant.h"
#include "libnyfe.h"

/* Portability for apple platforms. */
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe16(x)		OSSwapHostToBigInt16(x)
#define htobe32(x)		OSSwapHostToBigInt32(x)
#define htobe64(x)		OSSwapHostToBigInt64(x)
#define be16toh(x)		OSSwapBigToHostInt16(x)
#define be32toh(x)		OSSwapBigToHostInt32(x)
#define be64toh(x)		OSSwapBigToHostInt64(x)
#else
#include <endian.h>
#endif

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			covenant_fatal("precondition failed in "	\
			    "covenant: %s:%s:%d", __FILE__, __func__,	\
			    __LINE__);					\
		}							\
	} while (0)

#define VERIFY(x)							\
	do {								\
		if (!(x)) {						\
			covenant_fatal("verification failed in "	\
			    "%s:%s:%d", __FILE__, __func__, __LINE__);	\
		}							\
	} while (0)

/*
 * The parts of sanctum we must agree with byte for byte, see
 * sanctum/include/sanctum_ambry.h, sanctum_cipher.h and sanctum_kdf.h.
 */
#define SANCTUM_KEY_LENGTH			32
#define SANCTUM_TAG_LENGTH			16
#define SANCTUM_NONCE_LENGTH			12
#define SANCTUM_ED25519_SIGN_SECRET_LENGTH	64
#define SANCTUM_ED25519_SIGN_PUBLIC_LENGTH	32
#define SANCTUM_AMBRY_SEED_LEN			64
#define SANCTUM_AMBRY_AGE_SECONDS_PER_DAY	86400
#define SANCTUM_AMBRY_AGE_EPOCH			1697855580
#define SANCTUM_AMBRY_KDF			"SANCTUM.AMBRY.KDF"
#define SANCTUM_KEY_KEK_UNWRAP_KDF_LABEL	"SANCTUM.KEY.KEK.UNWRAP.KDF"

/* The flock domain bits, ambry works on the flock without them. */
#define SANCTUM_FLOCK_DOMAIN_MASK		0xff

/*
 * The ambry AAD data per entry.
 */
struct sanctum_ambry_aad {
	u_int16_t	tunnel;
	u_int16_t	expires;
	u_int64_t	flock_src;
	u_int64_t	flock_dst;
	u_int32_t	generation;
	u_int8_t	seed[SANCTUM_AMBRY_SEED_LEN];
} __attribute__((packed));

/*
 * The ambry header.
 */
struct sanctum_ambry_head {
	u_int16_t	expires;
	u_int32_t	generation;
	u_int8_t	seed[SANCTUM_AMBRY_SEED_LEN];
} __attribute__((packed));

/*
 * An ambry entry, the wrapped key for one direction of a tunnel.
 */
struct sanctum_ambry_entry {
	u_int64_t	flock;
	u_int16_t	tunnel;
	u_int8_t	key[SANCTUM_KEY_LENGTH];
	u_int8_t	tag[SANCTUM_TAG_LENGTH];
} __attribute__((packed));

/*
 * A set of flock KEKs as stored by the platform. The header is the
 * AAD, the KEKs are encrypted with AES-256-GCM under a key derived
 * from the vault key and the salt (fresh on every seal).
 */
#define COVENANT_KEKS_MAGIC	"COVK"
#define COVENANT_KEKS_VERSION	2
#define COVENANT_KEKS_KDF_LABEL	"COVENANT.VAULT.KEKS"

struct covenant_keks_head {
	u_int8_t	magic[4];
	u_int32_t	version;
	u_int64_t	flock;
	u_int64_t	created;
	u_int8_t	salt[32];
	u_int8_t	nonce[SANCTUM_NONCE_LENGTH];
	u_int8_t	reserved[4];
} __attribute__((packed));

/*
 * ML-KEM-1024 and x25519 sizes.
 */
#define COVENANT_X25519_LEN		32
#define COVENANT_MLKEM_COINS_LEN	64
#define COVENANT_MLKEM_SECRET_LEN	3168
#define COVENANT_MLKEM_PUBLIC_LEN	1568
#define COVENANT_MLKEM_CIPHERTEXT_LEN	1568
#define COVENANT_MLKEM_SHARED_LEN	32

/*
 * The header of a backup.
 */
#define COVENANT_BACKUP_MAGIC		"COVB"
#define COVENANT_BACKUP_VERSION		3
#define COVENANT_BACKUP_KDF_LABEL	"COVENANT.BACKUP.KDF"
#define COVENANT_BACKUP_MAC_LABEL	"COVENANT.BACKUP.MAC"
#define COVENANT_BACKUP_SEED_LABEL	"COVENANT.BACKUP.SEED"
#define COVENANT_BACKUP_MLKEM_LABEL	"COVENANT.BACKUP.MLKEM"
#define COVENANT_BACKUP_X25519_LABEL	"COVENANT.BACKUP.X25519"
#define COVENANT_BACKUP_MAC_KEY_LABEL	"COVENANT.BACKUP.MAC.KEY"

struct covenant_backup_head {
	u_int8_t	magic[4];
	u_int32_t	version;
	u_int64_t	flock;
	u_int64_t	created;
	u_int64_t	made;
	u_int8_t	nonce[SANCTUM_NONCE_LENGTH];
	u_int8_t	reserved[4];
	u_int8_t	x25519[COVENANT_X25519_LEN];
	u_int8_t	mlkem[COVENANT_MLKEM_CIPHERTEXT_LEN];
} __attribute__((packed));

/*
 * A backup recipient, the public keys of a recovery key together with
 * its mac key sealed under the vault key. Everything up to the sealed
 * mac key is the AAD.
 */
#define COVENANT_RECIPIENT_MAGIC	"COVR"
#define COVENANT_RECIPIENT_VERSION	2
#define COVENANT_RECIPIENT_KDF_LABEL	"COVENANT.BACKUP.RECIPIENT"

struct covenant_recipient {
	u_int8_t	magic[4];
	u_int32_t	version;
	u_int8_t	salt[32];
	u_int8_t	nonce[SANCTUM_NONCE_LENGTH];
	u_int8_t	reserved[4];
	u_int8_t	x25519[COVENANT_X25519_LEN];
	u_int8_t	mlkem[COVENANT_MLKEM_PUBLIC_LEN];
	u_int8_t	mac_key[SANCTUM_KEY_LENGTH];
	u_int8_t	tag[SANCTUM_TAG_LENGTH];
} __attribute__((packed));

/*
 * The KEKs of a flock in the clear, only ever in memory from
 * covenant_alloc() and only while the lock is held.
 */
struct covenant_keks {
	u_int64_t	flock;
	u_int64_t	created;
	u_int8_t	kek[COVENANT_KEK_COUNT][COVENANT_KEK_LEN];
	u_int8_t	seed[COVENANT_SIGN_SEED_LEN];
};

/* The encrypted part of sealed KEKs and of a backup, kek || seed. */
#define COVENANT_KEKS_SECRET_LEN	\
    (COVENANT_KEKS_DATA_LEN + COVENANT_SIGN_SEED_LEN)

/*
 * The name of a device is signed with the ed25519 key of its flock:
 *
 *	m = COVENANT_NAME_LABEL || flock || kek || len(name) || name
 *
 * The flock is 64-bit big endian, kek and len(name) are one byte each.
 * The name is the instance of the device. It is at most COVENANT_NAME_MAX
 * bytes long and uses only the characters vigil accepts.
 */
#define COVENANT_NAME_LABEL		"COVENANT.NAME"
#define COVENANT_NAME_MAX		63
#define COVENANT_SIGNATURE_LEN		64

/* The longest m we sign, label || flock || kek || len(name) || name. */
#define COVENANT_NAME_MSG_MAX		\
    (sizeof(COVENANT_NAME_LABEL) - 1 + 8 + 1 + 1 + COVENANT_NAME_MAX)

/*
 * Used to interface with the cipher.
 */
struct covenant_cipher {
	void			*pt;
	void			*ct;
	void			*aad;
	void			*ctx;
	void			*tag;
	void			*nonce;
	size_t			aad_len;
	size_t			data_len;
	size_t			nonce_len;
};

/* The number of devices that can be in the middle of provisioning. */
#define COVENANT_COSK_MAX		8

/*
 * A cosk pair waiting for its device to be registered and approved.
 */
struct covenant_cosk {
	u_int32_t	handle;
	u_int8_t	sk[SANCTUM_ED25519_SIGN_SECRET_LENGTH];
};

/*
 * A covenant context.
 */
struct covenant {
	u_int32_t		last_error;
	struct covenant_cosk	cosk[COVENANT_COSK_MAX];
};

/*
 * A buffer to append formatted output into, see vigil_buf in parish.
 */
#define COVENANT_BUF_FULL		(1 << 0)

struct covenant_buf {
	char		*data;
	int		flags;
	size_t		length;
	size_t		offset;
};

/* from $(OBJDIR)/version.c */
extern const char	*covenant_build_rev;
extern const char	*covenant_build_date;

/* src/covenant.c */
void	covenant_lock(void);
void	covenant_unlock(void);
void	*covenant_alloc(size_t);
void	covenant_free(void *, size_t);
void	covenant_fatal(const char *, ...)
	    __attribute__((format (printf, 1, 2))) __attribute__((noreturn));

/* For nyfe, see nyfe/include/nyfe.h. */
void	fatal(const char *, ...)
	    __attribute__((format (printf, 1, 2))) __attribute__((noreturn));

/* src/buf.c */
void	covenant_buf_init(struct covenant_buf *, char *, size_t);
void	covenant_buf_appendf(struct covenant_buf *, const char *, ...)
	    __attribute__((format (printf, 2, 3)));

/* The ML-KEM-1024 reference implementation. */
int	pqcrystals_kyber1024_ref_enc(u_int8_t *, u_int8_t *, const u_int8_t *);
int	pqcrystals_kyber1024_ref_dec(u_int8_t *, const u_int8_t *,
	    const u_int8_t *);
int	pqcrystals_kyber1024_ref_keypair_derand(u_int8_t *, u_int8_t *,
	    const u_int8_t *);

/* src/cipher.c */
int	covenant_cipher_init(void);
void	covenant_cipher_cleanup(void *);
void	covenant_cipher_encrypt(struct covenant_cipher *);
int	covenant_cipher_decrypt(struct covenant_cipher *);
void	*covenant_cipher_setup(const u_int8_t *, size_t);

/* src/keks.c */
void			covenant_keks_close(struct covenant_keks *);
void			covenant_keks_seal(const u_int8_t *, size_t,
			    const struct covenant_keks *, u_int8_t *, size_t);
void			covenant_keks_unpack(struct covenant_keks *,
			    const u_int8_t *, size_t);
void			covenant_keks_pack(const struct covenant_keks *,
			    u_int8_t *, size_t);
void			covenant_kek_derive(const u_int8_t *, size_t, u_int64_t,
			    u_int64_t, u_int8_t *, size_t);
struct covenant_keks	*covenant_keks_open(struct covenant *,
			    const u_int8_t *, size_t, const void *, size_t);

/* src/provision.c */
int	covenant_config_build(struct covenant *,
	    const struct covenant_keks *, u_int8_t, const u_int8_t *, size_t,
	    const u_int8_t *, size_t, const char *, char *, size_t);

/* src/qr.c */
int	covenant_qr_render(struct covenant *, const char *, u_int8_t *,
	    size_t, int *);

#endif
