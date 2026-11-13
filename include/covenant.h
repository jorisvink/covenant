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

#ifndef __H_COVENANT_H
#define __H_COVENANT_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <sys/types.h>

#include <stdarg.h>

/* The length of the vault key the platform keeps for us. */
#define COVENANT_VAULT_KEY_LEN		32

/* The length of a KEK, same as SANCTUM_AMBRY_KEK_LEN. */
#define COVENANT_KEK_LEN		32

/* The number of KEKs in a flock, 0x01 - 0xff. */
#define COVENANT_KEK_COUNT		255

/* The length of the seed for the ed25519 key that signs device names. */
#define COVENANT_SIGN_SEED_LEN		32

/* The length of the sealed KEKs and signing seed of a flock. */
#define COVENANT_KEKS_SEALED_LEN	\
    (72 + (COVENANT_KEK_COUNT * COVENANT_KEK_LEN) + \
    COVENANT_SIGN_SEED_LEN + 16)

/* The length of all KEKs of a flock, kek-0x01 up to kek-0xff. */
#define COVENANT_KEKS_DATA_LEN		(COVENANT_KEK_COUNT * COVENANT_KEK_LEN)

/* The length of an ambry bundle for a single flock. */
#define COVENANT_AMBRY_LEN		3756730

/* Days an ambry bundle can be valid for at most. */
#define COVENANT_AMBRY_DAYS_MAX		3650

/* The length of a cathedral offer signing (cosk) public key. */
#define COVENANT_COSK_PUBLIC_LEN	32

/* The length of a cathedral offer signing (cosk) secret key. */
#define COVENANT_COSK_SECRET_LEN	64

/* The length of a cathedral secret, it is given to us as hex. */
#define COVENANT_CATHEDRAL_SECRET_LEN	32

/* The largest QR code we produce (version 40) in modules per side. */
#define COVENANT_QR_SIDE_MAX		177

/* The length of a buffer that fits the largest QR code. */
#define COVENANT_QR_MAX_LEN		\
    (COVENANT_QR_SIDE_MAX * COVENANT_QR_SIDE_MAX)

/* The length of a buffer that fits the largest vigil configuration. */
#define COVENANT_CONFIG_MAX_LEN		2048

/* The length of a backup recovery key. */
#define COVENANT_BACKUP_ROOT_LEN	32

/* The length of a backup recipient. */
#define COVENANT_BACKUP_RECIPIENT_LEN	1704

/* The length of a backup of the KEKs and signing seed of a flock. */
#define COVENANT_BACKUP_LEN		\
    (1648 + (COVENANT_KEK_COUNT * COVENANT_KEK_LEN) + \
    COVENANT_SIGN_SEED_LEN + 16 + 32)

/* The length of the vault key wrapped under a passphrase. */
#define COVENANT_WRAPPED_KEY_LEN	(56 + COVENANT_VAULT_KEY_LEN + 16)

/* The number of words that tell a remote device where to find us. */
#define COVENANT_ROUTE_WORDS		13

/* The number of words in the passphrase for its tunnel, as in cephas. */
#define COVENANT_PASSPHRASE_WORDS	20

/* The length of a buffer that fits all words for a remote device. */
#define COVENANT_REMOTE_WORDS_LEN	512

/*
 * The states of the tunnel to a remote device.
 */
#define COVENANT_REMOTE_WAITING		1
#define COVENANT_REMOTE_ONLINE		2
#define COVENANT_REMOTE_DONE		3

/*
 * Library error codes.
 */
#define COVENANT_ERROR_NONE		0
#define COVENANT_ERROR_SYSTEM		1
#define COVENANT_ERROR_PARAMETER	2
#define COVENANT_ERROR_NO_CONTEXT	3
#define COVENANT_ERROR_INTERNAL		4
#define COVENANT_ERROR_INTEGRITY	5
#define COVENANT_ERROR_VERSION		6
#define COVENANT_ERROR_CONFIG		7
#define COVENANT_ERROR_CONFIG_KEYS	8
#define COVENANT_ERROR_CONFIG_FLOCK	9
#define COVENANT_ERROR_CONFIG_SPI	10
#define COVENANT_ERROR_NO_COSK		11
#define COVENANT_ERROR_COSK_FULL	12
#define COVENANT_ERROR_QR_SIZE		13
#define COVENANT_ERROR_RECOVERY_KEY	14
#define COVENANT_ERROR_NO_REMOTE	15
#define COVENANT_ERROR_REMOTE		16
#define COVENANT_ERROR_PASSPHRASE	17

/*
 * What we know about sealed KEKs without unsealing them.
 */
struct covenant_info {
	u_int64_t	flock;
	u_int64_t	created;
};

/*
 * The public part of a backup.
 */
struct covenant_backup_info {
	u_int64_t	flock;
	u_int64_t	made;
	u_int64_t	created;
};

/*
 * Everything needed to provision a device, into a QR code, into its
 * configuration for vigil on the same device or into its keys alone.
 *
 * The config is the vigil configuration without its keys, we add the
 * KEK, the cathedral secret (hex, as the reliquary hands it out), the
 * cosk that was made with covenant_cosk_new(), the public key of the
 * flock and the signature over the instance of the device. The keys
 * alone need no config.
 */
struct covenant_device {
	const void	*secret;
	size_t		secret_len;

	const void	*keks;
	size_t		keks_len;

	const char	*config;
	const char	*cathedral_secret;

	u_int8_t	kek;
	u_int32_t	cosk;
};

/*
 * The keys of a device, for a computer that keeps them in files the
 * way rlq does instead of in a vigil configuration.
 */
struct covenant_device_keys {
	u_int8_t	kek[COVENANT_KEK_LEN];
	u_int8_t	cosk[COVENANT_COSK_SECRET_LEN];
	u_int8_t	cosk_pub[COVENANT_COSK_PUBLIC_LEN];
	u_int8_t	secret[COVENANT_CATHEDRAL_SECRET_LEN];
};

/*
 * Where a remote device finds us, it gets this as the first words.
 *
 * The identity and kek are the ones we joined the flock under, peer is
 * the KEK the remote device will get. The cathedral is an IPv4 address
 * in host byte order.
 */
struct covenant_route {
	u_int64_t	flock;
	u_int32_t	identity;
	u_int32_t	cathedral;
	u_int16_t	port;
	u_int8_t	kek;
	u_int8_t	peer;
};

/*
 * Everything needed to provision a remote device over a cephas tunnel.
 *
 * The cathedral secret (hex) and the cosk are ours, the device is the
 * cathedral id the remote device joined under. The config is the vigil
 * configuration without its keys, we add the KEK, the public key of
 * the flock and the signature over the instance of the device. The
 * remote device adds its own cathedral secret and cosk.
 *
 * Without a config we only send the KEK, for cephas on a computer.
 */
struct covenant_remote {
	const void	*secret;
	size_t		secret_len;

	const void	*keks;
	size_t		keks_len;

	const char	*config;
	const char	*cathedral_secret;

	u_int32_t	cosk;
	u_int32_t	device;
};

/* A covenant context as an opaque. */
typedef struct covenant		COVENANT;

/*
 * The public API.
 */

const char	*covenant_version(void);
u_int32_t	covenant_last_error(COVENANT *);

COVENANT	*covenant_ctx_alloc(void);
void		covenant_ctx_free(COVENANT *);
void		covenant_emergency_erase(void);
void		covenant_fatal_callback(void (*)(const char *, va_list));

int	covenant_random_bytes(COVENANT *, void *, size_t);

int	covenant_keks_info(COVENANT *, const void *, size_t,
	    struct covenant_info *);
int	covenant_keks_check(COVENANT *, const void *, size_t,
	    const void *, size_t);
void	covenant_keks_generate(COVENANT *, const void *, size_t,
	    u_int64_t, void *, size_t);
int	covenant_keks_renew(COVENANT *, const void *, size_t,
	    const void *, size_t, u_int8_t, void *, size_t);
void	covenant_keks_import(COVENANT *, const void *, size_t,
	    u_int64_t, const void *, size_t, void *, size_t);

int	covenant_ambry_bundle(COVENANT *, const void *, size_t,
	    const void *, size_t, u_int16_t, void *, size_t,
	    u_int32_t *, u_int16_t *);

void	covenant_backup_keygen(COVENANT *, const void *, size_t,
	    void *, size_t, void *, size_t);
void	covenant_backup_recipient(COVENANT *, const void *, size_t,
	    const void *, size_t, void *, size_t);

int	covenant_backup_info(COVENANT *, const void *, size_t,
	    struct covenant_backup_info *);
int	covenant_backup_verify(COVENANT *, const void *, size_t,
	    const void *, size_t);
int	covenant_backup_seal(COVENANT *, const void *, size_t,
	    const void *, size_t, const void *, size_t, void *, size_t);
int	covenant_backup_restore(COVENANT *, const void *, size_t,
	    const void *, size_t, const void *, size_t, void *, size_t);

#if defined(PLATFORM_HOST)
int	covenant_backup_open(COVENANT *, const void *, size_t,
	    const void *, size_t, void *, size_t,
	    struct covenant_backup_info *);
#endif

int	covenant_key_unwrap(COVENANT *, const void *, size_t,
	    const void *, size_t, void *, size_t);
void	covenant_key_wrap(COVENANT *, const void *, size_t,
	    const void *, size_t, void *, size_t);

int	covenant_cosk_drop(COVENANT *, u_int32_t);
int	covenant_cosk_new(COVENANT *, u_int32_t *, void *, size_t);

int	covenant_qr_encode(COVENANT *, const char *, void *, size_t, int *);
int	covenant_provision(COVENANT *, const struct covenant_device *,
	    void *, size_t, int *);
int	covenant_provision_keys(COVENANT *, const struct covenant_device *,
	    struct covenant_device_keys *);
int	covenant_provision_config(COVENANT *, const struct covenant_device *,
	    char *, size_t);

int	covenant_remote_run(COVENANT *);
void	covenant_remote_stop(COVENANT *);
int	covenant_remote_start(COVENANT *, const struct covenant_remote *);
int	covenant_remote_words(COVENANT *, const struct covenant_route *,
	    char *, size_t);

#if defined(__cplusplus)
}
#endif

#endif
