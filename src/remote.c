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
#include <sys/socket.h>

#include <netinet/in.h>

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "covenant-int.h"
#include "wordlist.h"

/*
 * Provisioning a device that cannot scan a QR code, over a sanctum
 * tunnel set up the way cephas sets it up.
 *
 * We join the flock ourselves and hand the user the words for the
 * device. The first COVENANT_ROUTE_WORDS words are the route, they
 * tell the device where to find us:
 *
 *	flock (7) || identity (4) || kek (1) || peer (1) ||
 *	cathedral (4) || port (2) || checksum (2)
 *
 * Everything is big endian and the flock goes without its domain. The
 * route is written as a number in base COVENANT_WORD_COUNT, the most
 * significant word first. The 21 bytes of the route always fit in the
 * 13 words, 7776^13 is just over 2^168. The checksum is the first two
 * bytes of:
 *
 *	SHA3-256(COVENANT_ROUTE_LABEL || route[0..19) || passphrase)
 *
 * so a wrong word anywhere is caught before the device ever tries to
 * reach us.
 *
 * The other COVENANT_PASSPHRASE_WORDS words are the passphrase the
 * shared secret of the tunnel is derived from, exactly as cephas does.
 */

/* The MTU we give libkyrka, the configuration must fit in one packet. */
#define REMOTE_MTU		1400

static const char	*remote_word_select(void);

static void	remote_passphrase(struct covenant_tunnel *);
static void	remote_socket_read(struct covenant_tunnel *);
static void	remote_tunnel_close(struct covenant_tunnel *);
static void	remote_payload_send(struct covenant_tunnel *);
static void	remote_route_words(struct covenant_tunnel *,
		    const struct covenant_route *, struct covenant_buf *);
static void	remote_secret_derive(struct covenant_tunnel *,
		    u_int8_t *, size_t);
static void	remote_sendto(struct covenant_tunnel *, struct kyrka_packet *,
		    const struct sockaddr_in *);
static int	remote_payload(struct covenant *, struct covenant_tunnel *,
		    const struct covenant_remote *);
static int	remote_tunnel_setup(struct covenant *,
		    struct covenant_tunnel *, const u_int8_t *, size_t,
		    const u_int8_t *, size_t);

static void	remote_tunnel_event(KYRKA *, union kyrka_event *, void *);
static void	remote_heaven_ifc(struct kyrka_packet *, u_int64_t, void *);
static void	remote_purgatory_ifc(struct kyrka_packet *, u_int64_t, void *);
static void	remote_cathedral_ifc(struct kyrka_packet *, u_int64_t, void *);

/*
 * Make the words for a remote device, the route followed by a fresh
 * passphrase. We keep the passphrase until covenant_remote_start() is
 * called or until the words are made again.
 *
 * The words carry the passphrase, the platform should give us memory
 * it wipes and only keep it while the words are shown.
 */
int
covenant_remote_words(struct covenant *ctx, const struct covenant_route *route,
    char *out, size_t out_len)
{
	size_t			len;
	struct covenant_buf	buf;
	struct covenant_tunnel	*tun;

	if (ctx == NULL)
		return (-1);

	if (route == NULL || out == NULL ||
	    out_len != COVENANT_REMOTE_WORDS_LEN) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	if (route->flock == 0 ||
	    (route->flock & SANCTUM_FLOCK_DOMAIN_MASK) != 0 ||
	    route->identity == 0 || route->cathedral == 0 || route->port == 0 ||
	    route->kek == 0 || route->peer == 0 || route->kek == route->peer) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	covenant_lock();

	covenant_tunnel_free(ctx);

	tun = covenant_alloc(sizeof(*tun));

	tun->fd = -1;
	tun->cfg.identity = route->identity;
	tun->cfg.flock_src = route->flock;
	tun->cfg.tunnel = (route->kek << 8) | route->peer;

	tun->cathedral.sin_family = AF_INET;
	tun->cathedral.sin_port = htons(route->port);
	tun->cathedral.sin_addr.s_addr = htonl(route->cathedral);

	remote_passphrase(tun);

	covenant_buf_init(&buf, out, out_len);
	remote_route_words(tun, route, &buf);

	len = strlen(tun->pass);
	VERIFY(len > 0 && tun->pass[len - 1] == ' ');

	covenant_buf_appendf(&buf, "%.*s", (int)(len - 1), tun->pass);
	VERIFY(!(buf.flags & COVENANT_BUF_FULL));

	ctx->tunnel = tun;
	covenant_unlock();

	return (0);
}

/*
 * Set up the tunnel to the remote device that joined the flock under
 * the given cathedral id. We unseal the KEKs, put together what we
 * send to the device and derive the shared secret from the passphrase.
 *
 * On success the cosk pair is consumed, the caller then keeps calling
 * covenant_remote_run() until the device has it all.
 */
int
covenant_remote_start(struct covenant *ctx, const struct covenant_remote *rem)
{
	int			ret;
	struct covenant_tunnel	*tun;
	struct covenant_cosk	*cosk;
	u_int8_t		cs[COVENANT_CATHEDRAL_SECRET_LEN];

	if (ctx == NULL)
		return (-1);

	if (rem == NULL || rem->secret == NULL ||
	    rem->keks_len != COVENANT_KEKS_SEALED_LEN || rem->device == 0 ||
	    rem->secret_len != COVENANT_VAULT_KEY_LEN || rem->keks == NULL ||
	    rem->cathedral_secret == NULL) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	covenant_lock();

	tun = ctx->tunnel;

	if (tun == NULL) {
		ctx->last_error = COVENANT_ERROR_NO_REMOTE;
		covenant_unlock();
		return (-1);
	}

	if (tun->kyrka != NULL) {
		ctx->last_error = COVENANT_ERROR_NO_REMOTE;
		covenant_unlock();
		return (-1);
	}

	if (rem->device == tun->cfg.identity) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		covenant_unlock();
		return (-1);
	}

	if ((cosk = covenant_cosk_lookup(ctx, rem->cosk)) == NULL) {
		ctx->last_error = COVENANT_ERROR_NO_COSK;
		covenant_unlock();
		return (-1);
	}

	nyfe_zeroize_register(cs, sizeof(cs));

	if (covenant_hex_decode(rem->cathedral_secret, cs, sizeof(cs)) == -1) {
		nyfe_zeroize(cs, sizeof(cs));
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		covenant_unlock();
		return (-1);
	}

	tun->device = rem->device;

	if ((ret = remote_payload(ctx, tun, rem)) == 0) {
		ret = remote_tunnel_setup(ctx, tun, cs, sizeof(cs),
		    cosk->sk, sizeof(cosk->sk));
	}

	if (ret == 0) {
		nyfe_mem_zero(cosk, sizeof(*cosk));
		nyfe_mem_zero(tun->pass, sizeof(tun->pass));
	} else {
		tun->device = 0;
		tun->length = 0;
		nyfe_mem_zero(tun->payload, sizeof(tun->payload));
	}

	nyfe_zeroize(cs, sizeof(cs));
	covenant_unlock();

	return (ret);
}

/*
 * Wait up to a second for packets from the cathedral or the device and
 * do the book keeping for the tunnel once every second, sending the
 * device what it needs while the tunnel is up.
 *
 * Returns the state of the tunnel or -1 if something went wrong or if
 * the tunnel was stopped while we waited.
 */
int
covenant_remote_run(struct covenant *ctx)
{
	struct timespec		ts;
	struct pollfd		pfd;
	struct covenant_tunnel	*tun;
	int			nfd, ret;

	if (ctx == NULL)
		return (-1);

	covenant_lock();

	tun = ctx->tunnel;

	if (tun == NULL) {
		ctx->last_error = COVENANT_ERROR_NO_REMOTE;
		covenant_unlock();
		return (-1);
	}

	if (tun->kyrka == NULL) {
		ctx->last_error = COVENANT_ERROR_NO_REMOTE;
		covenant_unlock();
		return (-1);
	}

	pfd.fd = tun->fd;
	pfd.events = POLLIN;

	ret = tun->state;
	covenant_unlock();

	if ((nfd = poll(&pfd, 1, 1000)) == -1) {
		if (errno == EINTR)
			return (ret);
		ctx->last_error = COVENANT_ERROR_SYSTEM;
		return (-1);
	}

	covenant_lock();

	tun = ctx->tunnel;

	if (tun == NULL) {
		ctx->last_error = COVENANT_ERROR_NO_REMOTE;
		covenant_unlock();
		return (-1);
	}

	if (tun->kyrka == NULL) {
		ctx->last_error = COVENANT_ERROR_NO_REMOTE;
		covenant_unlock();
		return (-1);
	}

	if (nfd > 0) {
		if (pfd.revents & POLLIN)
			remote_socket_read(tun);
	}

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	if ((ts.tv_sec - tun->last) >= 1) {
		tun->last = ts.tv_sec;

		if (kyrka_cathedral_notify(tun->kyrka) == -1)
			tun->error = COVENANT_ERROR_INTERNAL;

		if (kyrka_key_manage(tun->kyrka) == -1)
			tun->error = COVENANT_ERROR_INTERNAL;

		if (tun->state == COVENANT_REMOTE_ONLINE)
			remote_payload_send(tun);
	}

	if (tun->error != 0) {
		ret = -1;
		ctx->last_error = tun->error;
	} else {
		ret = tun->state;
	}

	covenant_unlock();

	return (ret);
}

/*
 * Tear down the tunnel to the remote device and forget the passphrase
 * and anything we were going to send.
 */
void
covenant_remote_stop(struct covenant *ctx)
{
	if (ctx == NULL)
		return;

	covenant_lock();
	covenant_tunnel_free(ctx);
	covenant_unlock();
}

/*
 * Free the tunnel to the remote device if there is one, the caller
 * holds the lock.
 */
void
covenant_tunnel_free(struct covenant *ctx)
{
	PRECOND(ctx != NULL);

	if (ctx->tunnel == NULL)
		return;

	remote_tunnel_close(ctx->tunnel);
	covenant_free(ctx->tunnel, sizeof(*ctx->tunnel));

	ctx->tunnel = NULL;
}

/*
 * Select a random word from the word list.
 */
static const char *
remote_word_select(void)
{
	u_int32_t		idx, min;
	const u_int32_t		upper = COVENANT_WORD_COUNT;

	min = -upper % upper;

	for (;;) {
		nyfe_random_bytes(&idx, sizeof(idx));
		if (idx >= min)
			break;
	}

	idx = idx % upper;

	return (covenant_words[idx]);
}

/*
 * Make a fresh passphrase, every word is followed by a space just like
 * cephas puts them together.
 */
static void
remote_passphrase(struct covenant_tunnel *tun)
{
	int			idx;
	struct covenant_buf	buf;

	PRECOND(tun != NULL);

	covenant_buf_init(&buf, tun->pass, sizeof(tun->pass));

	for (idx = 0; idx < COVENANT_PASSPHRASE_WORDS; idx++)
		covenant_buf_appendf(&buf, "%s ", remote_word_select());

	VERIFY(!(buf.flags & COVENANT_BUF_FULL));
}

/*
 * Write the route as words into buf, see the top of this file.
 */
static void
remote_route_words(struct covenant_tunnel *tun,
    const struct covenant_route *route, struct covenant_buf *buf)
{
	size_t			idx;
	struct nyfe_sha3	sha;
	int			word;
	u_int16_t		port;
	u_int64_t		flock;
	u_int32_t		val, rem, id, ip;
	u_int16_t		words[COVENANT_ROUTE_WORDS];
	u_int8_t		data[COVENANT_ROUTE_LEN], digest[32];

	PRECOND(tun != NULL);
	PRECOND(route != NULL);
	PRECOND(buf != NULL);

	flock = htobe64(route->flock);
	memcpy(&data[0], &flock, 7);

	id = htobe32(route->identity);
	memcpy(&data[7], &id, sizeof(id));

	data[11] = route->kek;
	data[12] = route->peer;

	ip = htobe32(route->cathedral);
	memcpy(&data[13], &ip, sizeof(ip));

	port = htobe16(route->port);
	memcpy(&data[17], &port, sizeof(port));

	nyfe_zeroize_register(&sha, sizeof(sha));

	nyfe_sha3_init256(&sha);
	nyfe_sha3_update(&sha, COVENANT_ROUTE_LABEL,
	    sizeof(COVENANT_ROUTE_LABEL) - 1);
	nyfe_sha3_update(&sha, data, 19);
	nyfe_sha3_update(&sha, tun->pass, strlen(tun->pass));
	nyfe_sha3_final(&sha, digest, sizeof(digest));

	nyfe_zeroize(&sha, sizeof(sha));

	data[19] = digest[0];
	data[20] = digest[1];

	for (word = COVENANT_ROUTE_WORDS - 1; word >= 0; word--) {
		rem = 0;
		for (idx = 0; idx < sizeof(data); idx++) {
			val = (rem << 8) | data[idx];
			data[idx] = val / COVENANT_WORD_COUNT;
			rem = val % COVENANT_WORD_COUNT;
		}
		words[word] = rem;
	}

	for (word = 0; word < COVENANT_ROUTE_WORDS; word++)
		covenant_buf_appendf(buf, "%s ", covenant_words[words[word]]);
}

/*
 * Put together what we send to the remote device, its configuration
 * or only its KEK, and the digest it must ack.
 */
static int
remote_payload(struct covenant *ctx, struct covenant_tunnel *tun,
    const struct covenant_remote *rem)
{
	int			ret;
	u_int8_t		kek;
	struct nyfe_sha3	sha;
	struct covenant_keks	*keks;

	PRECOND(ctx != NULL);
	PRECOND(tun != NULL);
	PRECOND(rem != NULL);

	if ((keks = covenant_keks_open(ctx, rem->secret, rem->secret_len,
	    rem->keks, rem->keks_len)) == NULL)
		return (-1);

	if (keks->flock != tun->cfg.flock_src) {
		covenant_keks_close(keks);
		ctx->last_error = COVENANT_ERROR_CONFIG_FLOCK;
		return (-1);
	}

	ret = 0;
	kek = tun->cfg.tunnel & 0xff;

	if (rem->config != NULL) {
		ret = covenant_config_remote(ctx, keks, kek, rem->config,
		    (char *)tun->payload, sizeof(tun->payload));
		tun->type = COVENANT_REMOTE_MSG_CONFIG;
		tun->length = strlen((const char *)tun->payload);
	} else {
		nyfe_memcpy(tun->payload, keks->kek[kek - 1], COVENANT_KEK_LEN);
		tun->type = COVENANT_REMOTE_MSG_KEK;
		tun->length = COVENANT_KEK_LEN;
	}

	covenant_keks_close(keks);

	if (ret == -1)
		return (-1);

	nyfe_zeroize_register(&sha, sizeof(sha));

	nyfe_sha3_init256(&sha);
	nyfe_sha3_update(&sha, tun->payload, tun->length);
	nyfe_sha3_final(&sha, tun->digest, sizeof(tun->digest));

	nyfe_zeroize(&sha, sizeof(sha));

	return (0);
}

/*
 * Get our libkyrka context configured for the tunnel to the device and
 * open the socket we talk to the cathedral and the device over.
 */
static int
remote_tunnel_setup(struct covenant *ctx, struct covenant_tunnel *tun,
    const u_int8_t *cs, size_t cs_len, const u_int8_t *sk, size_t sk_len)
{
	u_int8_t	secret[SANCTUM_KEY_LENGTH];

	PRECOND(ctx != NULL);
	PRECOND(tun != NULL);
	PRECOND(cs != NULL);
	PRECOND(cs_len == COVENANT_CATHEDRAL_SECRET_LEN);
	PRECOND(sk != NULL);
	PRECOND(sk_len == SANCTUM_ED25519_SIGN_SECRET_LENGTH);

	if ((tun->kyrka = kyrka_ctx_alloc(remote_tunnel_event, tun)) == NULL) {
		ctx->last_error = COVENANT_ERROR_INTERNAL;
		return (-1);
	}

	tun->cfg.udata = tun;
	tun->cfg.send = remote_cathedral_ifc;

	nyfe_zeroize_register(secret, sizeof(secret));
	remote_secret_derive(tun, secret, sizeof(secret));

	if (kyrka_shroud_enable(tun->kyrka) == -1)
		goto cleanup;

	if (kyrka_mtu_size(tun->kyrka, REMOTE_MTU) == -1)
		goto cleanup;

	if (kyrka_heaven_ifc(tun->kyrka, remote_heaven_ifc, tun) == -1)
		goto cleanup;

	if (kyrka_purgatory_ifc(tun->kyrka, remote_purgatory_ifc, tun) == -1)
		goto cleanup;

	if (kyrka_secret_load(tun->kyrka, secret, sizeof(secret)) == -1)
		goto cleanup;

	if (kyrka_cathedral_config(tun->kyrka, &tun->cfg) == -1)
		goto cleanup;

	if (kyrka_cathedral_secret_load(tun->kyrka, cs, cs_len) == -1)
		goto cleanup;

	if (kyrka_cathedral_cosk_load(tun->kyrka, sk, sk_len) == -1)
		goto cleanup;

	nyfe_zeroize(secret, sizeof(secret));

	if ((tun->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		remote_tunnel_close(tun);
		ctx->last_error = COVENANT_ERROR_SYSTEM;
		return (-1);
	}

	tun->last = 0;
	tun->error = 0;
	memcpy(&tun->peer, &tun->cathedral, sizeof(tun->peer));
	tun->state = COVENANT_REMOTE_WAITING;

	return (0);

cleanup:
	nyfe_zeroize(secret, sizeof(secret));

	remote_tunnel_close(tun);
	ctx->last_error = COVENANT_ERROR_INTERNAL;

	return (-1);
}

/*
 * Close the socket and free the libkyrka context of the tunnel.
 */
static void
remote_tunnel_close(struct covenant_tunnel *tun)
{
	PRECOND(tun != NULL);

	if (tun->fd != -1) {
		(void)close(tun->fd);
		tun->fd = -1;
	}

	if (tun->kyrka != NULL) {
		kyrka_ctx_free(tun->kyrka);
		tun->kyrka = NULL;
	}
}

/*
 * Derive the shared secret for the tunnel from the passphrase, the
 * same way cephas does in cephas_secret_derive().
 *
 * We first run the passphrase through nyfe_passphrase_kdf() which
 * produces 64-bytes of IKM, this is then run through KMAC256():
 *
 *    X = len(flock_a) || flock_a || len(flock_b) || flock_b ||
 *        len(identity_a) || identity_a || len(identity_b) || identity_b ||
 *        len(peer_a) || peer_a || len(peer_b) || peer_b
 *
 *    secret = KMAC256(ikm, "CEPHAS.KDF.SHARED.SECRET", X)
 */
static void
remote_secret_derive(struct covenant_tunnel *tun, u_int8_t *secret, size_t len)
{
	struct nyfe_kmac256	kdf;
	u_int64_t		flock_a, flock_b;
	u_int32_t		identity_a, identity_b;
	u_int8_t		ilen, peer_a, peer_b, tmp;
	u_int8_t		okm[NYFE_KEY_LEN], salt[NYFE_KEY_FILE_SALT_LEN];

	PRECOND(tun != NULL);
	PRECOND(secret != NULL);
	PRECOND(len == SANCTUM_KEY_LENGTH);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_mem_zero(salt, sizeof(salt));

	nyfe_passphrase_kdf(tun->pass, strlen(tun->pass), salt, sizeof(salt),
	    okm, sizeof(okm), COVENANT_REMOTE_PASS_LABEL,
	    sizeof(COVENANT_REMOTE_PASS_LABEL) - 1);

	if (tun->cfg.identity < tun->device) {
		identity_a = htobe32(tun->cfg.identity);
		identity_b = htobe32(tun->device);
	} else {
		identity_a = htobe32(tun->device);
		identity_b = htobe32(tun->cfg.identity);
	}

	peer_a = (tun->cfg.tunnel >> 8) & 0xff;
	peer_b = tun->cfg.tunnel & 0xff;

	if (peer_a > peer_b) {
		tmp = peer_a;
		peer_a = peer_b;
		peer_b = tmp;
	}

	if (tun->cfg.flock_src < tun->cfg.flock_dst) {
		flock_a = htobe64(tun->cfg.flock_src);
		flock_b = htobe64(tun->cfg.flock_dst);
	} else {
		flock_a = htobe64(tun->cfg.flock_dst);
		flock_b = htobe64(tun->cfg.flock_src);
	}

	nyfe_kmac256_init(&kdf, okm, sizeof(okm),
	    COVENANT_REMOTE_KDF_LABEL, sizeof(COVENANT_REMOTE_KDF_LABEL) - 1);
	nyfe_zeroize(okm, sizeof(okm));

	ilen = sizeof(flock_a);
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &flock_a, sizeof(flock_a));

	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &flock_b, sizeof(flock_b));

	ilen = sizeof(identity_a);
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &identity_a, sizeof(identity_a));

	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &identity_b, sizeof(identity_b));

	ilen = sizeof(peer_a);
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &peer_a, sizeof(peer_a));

	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &peer_b, sizeof(peer_b));

	nyfe_kmac256_final(&kdf, secret, len);
	nyfe_zeroize(&kdf, sizeof(kdf));
}

/*
 * Read everything that is waiting on our socket and hand it to libkyrka.
 *
 * Packets that arrive before we have keys for them and ambries that we
 * have no KEK for are expected, anything else breaks the tunnel.
 */
static void
remote_socket_read(struct covenant_tunnel *tun)
{
	ssize_t			ret;
	size_t			len;
	struct kyrka_packet	pkt;
	void			*ptr;

	PRECOND(tun != NULL);

	for (;;) {
		if ((ptr = kyrka_packet_recvbuf(tun->kyrka,
		    &pkt, &len)) == NULL) {
			tun->error = COVENANT_ERROR_INTERNAL;
			return;
		}

		ret = recv(tun->fd, ptr, len, MSG_DONTWAIT);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			if (errno != EWOULDBLOCK && errno != EAGAIN)
				tun->error = COVENANT_ERROR_SYSTEM;
			return;
		}

		if (ret == 0)
			continue;

		pkt.length = ret;
		pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;

		if (kyrka_purgatory_input(tun->kyrka, &pkt) == -1) {
			switch (kyrka_last_error(tun->kyrka)) {
			case KYRKA_ERROR_NO_RX_KEY:
			case KYRKA_ERROR_SHROUD_NO_KEYS:
			case KYRKA_ERROR_CATHEDRAL_CONFIG:
				break;
			default:
				tun->error = COVENANT_ERROR_REMOTE;
				return;
			}
		}
	}
}

/*
 * Send the remote device its configuration or its KEK.
 */
static void
remote_payload_send(struct covenant_tunnel *tun)
{
	size_t				len;
	struct kyrka_packet		pkt;
	struct covenant_remote_msg	*msg;
	struct covenant_remote_config	*cfg;
	void				*data;

	PRECOND(tun != NULL);
	PRECOND(tun->state == COVENANT_REMOTE_ONLINE);

	nyfe_zeroize_register(&pkt, sizeof(pkt));

	if ((data = kyrka_packet_databuf(tun->kyrka, &pkt, &len)) == NULL) {
		nyfe_zeroize(&pkt, sizeof(pkt));
		tun->error = COVENANT_ERROR_INTERNAL;
		return;
	}

	VERIFY(len >= sizeof(*cfg));

	if (tun->type == COVENANT_REMOTE_MSG_CONFIG) {
		cfg = data;
		VERIFY(tun->length <= sizeof(cfg->data));
		nyfe_mem_zero(cfg, sizeof(*cfg));

		cfg->type = COVENANT_REMOTE_MSG_CONFIG;
		cfg->length = htobe16(tun->length);
		nyfe_memcpy(cfg->data, tun->payload, tun->length);

		pkt.length = sizeof(*cfg);
	} else {
		msg = data;
		nyfe_mem_zero(msg, sizeof(*msg));

		msg->type = COVENANT_REMOTE_MSG_KEK;
		nyfe_memcpy(msg->data, tun->payload, sizeof(msg->data));

		pkt.length = sizeof(*msg);
	}

	pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;

	if (kyrka_heaven_input(tun->kyrka, &pkt) == -1)
		tun->error = COVENANT_ERROR_REMOTE;

	nyfe_zeroize(&pkt, sizeof(pkt));
}

/*
 * Callback from libkyrka when a tunnel event occurred.
 */
static void
remote_tunnel_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	struct covenant_tunnel		*tun;

	PRECOND(ctx != NULL);
	PRECOND(evt != NULL);
	PRECOND(udata != NULL);

	tun = udata;

	switch (evt->type) {
	case KYRKA_EVENT_KEYS_INFO:
		if (tun->state != COVENANT_REMOTE_WAITING)
			break;
		if (evt->keys.tx_spi != 0 && evt->keys.rx_spi != 0)
			tun->state = COVENANT_REMOTE_ONLINE;
		break;
	case KYRKA_EVENT_PEER_DISCOVERY:
		tun->peer.sin_port = evt->peer.port;
		tun->peer.sin_addr.s_addr = evt->peer.ip;
		break;
	default:
		break;
	}
}

/*
 * Callback from libkyrka when there is plaintext from the device, it
 * either sends us heartbeats or acks what it got from us.
 */
static void
remote_heaven_ifc(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	struct covenant_tunnel			*tun;
	const struct covenant_remote_msg	*msg;

	PRECOND(pkt != NULL);
	PRECOND(udata != NULL);

	(void)magic;

	tun = udata;

	if (tun->state != COVENANT_REMOTE_ONLINE)
		return;

	if (pkt->length != sizeof(*msg)) {
		tun->error = COVENANT_ERROR_REMOTE;
		return;
	}

	msg = kyrka_packet_data(pkt);

	switch (msg->type) {
	case COVENANT_REMOTE_MSG_HEARTBEAT:
		break;
	case COVENANT_REMOTE_MSG_ACK:
		if (nyfe_mem_cmp(msg->data,
		    tun->digest, sizeof(tun->digest)) != 0) {
			tun->error = COVENANT_ERROR_REMOTE;
			break;
		}

		tun->length = 0;
		nyfe_mem_zero(tun->payload, sizeof(tun->payload));

		tun->state = COVENANT_REMOTE_DONE;
		break;
	default:
		tun->error = COVENANT_ERROR_REMOTE;
		break;
	}
}

/*
 * Callback from libkyrka when there is ciphertext for the device.
 */
static void
remote_purgatory_ifc(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	struct covenant_tunnel		*tun;

	PRECOND(pkt != NULL);
	PRECOND(udata != NULL);

	(void)magic;

	tun = udata;
	remote_sendto(tun, pkt, &tun->peer);
}

/*
 * Callback from libkyrka when there is ciphertext for the cathedral.
 */
static void
remote_cathedral_ifc(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	struct covenant_tunnel		*tun;

	PRECOND(pkt != NULL);
	PRECOND(udata != NULL);

	(void)magic;

	tun = udata;
	remote_sendto(tun, pkt, &tun->cathedral);
}

/*
 * Send the ciphertext in pkt to the given address. The network being
 * gone for a moment is no error, the tunnel copes with lost packets.
 */
static void
remote_sendto(struct covenant_tunnel *tun, struct kyrka_packet *pkt,
    const struct sockaddr_in *sin)
{
	size_t		len;
	void		*data;

	PRECOND(tun != NULL);
	PRECOND(pkt != NULL);
	PRECOND(sin != NULL);

	if ((data = kyrka_packet_sendbuf(tun->kyrka, pkt, &len)) == NULL) {
		tun->error = COVENANT_ERROR_INTERNAL;
		return;
	}

	if (sendto(tun->fd, data, len, 0,
	    (const struct sockaddr *)sin, sizeof(*sin)) == -1) {
		switch (errno) {
		case EINTR:
		case EAGAIN:
		case ENOBUFS:
		case ENETDOWN:
		case ENETUNREACH:
		case EHOSTUNREACH:
		case EADDRNOTAVAIL:
			break;
		default:
			tun->error = COVENANT_ERROR_SYSTEM;
			break;
		}
	}
}
