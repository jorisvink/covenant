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
#include <arpa/inet.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "covenant-int.h"

/*
 * Tests for handing a remote device its keys over a tunnel. We play the
 * device ourselves with a libkyrka context of its own, set up the way
 * cephas sets itself up from the words, and talk to covenant over
 * 127.0.0.1. Our socket stands in for the cathedral, which is where
 * covenant sends everything for the device. A cathedral relays traffic
 * between the two, shrouding it for each side with the key it shares
 * with that side, so the device shrouds what it sends with the key of
 * the cathedral secret covenant was given. Like the cathedral we tell
 * what covenant shrouded for its cathedral apart from what it shrouded
 * for its peer by the shroud identity in front of the packet.
 *
 * What we hold the tunnel to is described in docs/communication.md:
 * vigil gets its configuration without the cathedral_secret and
 * cathedral_cosk lines, a computer only its KEK, the device answers
 * with the SHA3-256 digest of what it got and only a matching digest
 * counts.
 */

#define TEST_FLOCK	0x493abf95a07e0c00ULL
#define TEST_DEVICE	0x5eb2411f
#define TEST_KEK	0x0c

/* Our identity and KEK, either both above or both below the device. */
#define TEST_IDENTITY	0xdeadbeef
#define TEST_OURS	0x01
#define TEST_IDENTITY_LOW	0x01020304
#define TEST_OURS_HIGH		0xfe

/* How long a single step of the hand over may take, in seconds. */
#define TEST_SECONDS	30

/* The labels a cathedral recognizes a shroud identity with. */
#define SHROUD_BASE_LABEL	"SANCTUM.SHROUD.BASE.IDENTITY"
#define SHROUD_ID_LABEL		"SANCTUM.SHROUD.IDENTITY"
#define SHROUD_ID_LEN		16

/* The labels cephas derives the shared secret of the tunnel with. */
#define CEPHAS_KDF_LABEL	"CEPHAS.KDF.SHARED.SECRET"
#define CEPHAS_PASS_LABEL	"CEPHAS.PBKDF.PASSPHRASE"

#define CHECK(x)							\
	do {								\
		if (!(x)) {						\
			fprintf(stderr, "%s:%d: check failed: %s (%u)\n",\
			    __FILE__, __LINE__, #x,			\
			    covenant_last_error(ctx));			\
			exit(1);					\
		}							\
	} while (0)

/*
 * The remote device, the side cephas or vigil plays.
 */
struct device {
	int			fd;
	int			got;
	u_int8_t		type;
	u_int8_t		ours;
	time_t			last;
	struct sockaddr_in	peer;
	struct sockaddr_in	self;
	int			online;
	KYRKA			*kyrka;
	size_t			length;
	u_int32_t		identity;
	u_int8_t		base[SHROUD_ID_LEN];
	u_int8_t		data[COVENANT_REMOTE_CONFIG_LEN];
};

static void	device_run(struct device *);
static void	device_stop(struct device *);
static void	device_shroud_base(struct device *);
static void	device_send_raw(struct device *, const void *, size_t);
static void	device_send(struct device *, u_int8_t, const u_int8_t *);
static void	device_start(struct device *, const char *,
		    const u_int8_t *, int);
static void	device_input(struct device *, const u_int8_t *, size_t,
		    u_int8_t);
static void	device_secret(struct device *, const char *, u_int8_t *,
		    size_t);
static int	device_cathedral_shroud(struct device *, const u_int8_t *,
		    size_t);

static void	device_event(KYRKA *, union kyrka_event *, void *);
static void	device_heaven(struct kyrka_packet *, u_int64_t, void *);
static void	device_cathedral(struct kyrka_packet *, u_int64_t, void *);
static void	device_purgatory(struct kyrka_packet *, u_int64_t, void *);

static int	test_drive_got(struct device *, int);
static int	test_drive(struct device *, int, int);
static void	test_digest(const u_int8_t *, size_t, u_int8_t *);
static void	test_start(struct device *, const char *, int, int);

static void	test_garbage(void);
static void	test_bad_ack(void);
static void	test_reversed(void);
static void	test_kek_only(void);
static void	test_wrong_words(void);
static void	test_configuration(void);

/* The vault key and the sealed KEKs every hand over is made from. */
static u_int8_t		secret[COVENANT_VAULT_KEY_LEN];
static u_int8_t		sealed[COVENANT_KEKS_SEALED_LEN];

/* The KEK the device must end up with. */
static u_int8_t		kek[COVENANT_KEK_LEN];

/* The context all tests run under. */
static COVENANT		*ctx = NULL;

/* The configuration vigil puts together for a comms device. */
static const char	*public =
    "vigil 1\n"
    "instance far away\n"
    "mode gospel\n"
    "spi 0c\n"
    "cathedral 127.0.0.1:4469\n"
    "cathedral_id 5eb2411f\n"
    "cathedral_flock 493abf95a07e0c00\n";

int
main(void)
{
	struct covenant_keks	*keks;

	CHECK((ctx = covenant_ctx_alloc()) != NULL);
	CHECK(covenant_random_bytes(ctx, secret, sizeof(secret)) == 0);

	covenant_keks_generate(ctx, secret, sizeof(secret), TEST_FLOCK,
	    sealed, sizeof(sealed));

	covenant_lock();
	CHECK((keks = covenant_keks_open(ctx, secret, sizeof(secret),
	    sealed, sizeof(sealed))) != NULL);
	memcpy(kek, keks->kek[TEST_KEK - 1], sizeof(kek));
	covenant_keks_close(keks);
	covenant_unlock();

	test_configuration();
	test_kek_only();
	test_bad_ack();
	test_garbage();
	test_reversed();
	test_wrong_words();

	nyfe_mem_zero(kek, sizeof(kek));
	covenant_ctx_free(ctx);

	printf("ok\n");

	return (0);
}

/*
 * A vigil device gets its configuration with its KEK and signed name
 * but without the keys it has itself, and is done once it acks it.
 */
static void
test_configuration(void)
{
	struct device	dev;
	u_int8_t	digest[32];
	char		hex[(COVENANT_KEK_LEN * 2) + 1];
	char		config[COVENANT_REMOTE_CONFIG_LEN + 1];

	test_start(&dev, public, 0, 0);

	CHECK(test_drive_got(&dev, TEST_SECONDS) == COVENANT_REMOTE_ONLINE);
	CHECK(dev.type == COVENANT_REMOTE_MSG_CONFIG);
	CHECK(dev.length > strlen(public) && dev.length < sizeof(config));

	memcpy(config, dev.data, dev.length);
	config[dev.length] = '\0';

	(void)sodium_bin2hex(hex, sizeof(hex), kek, sizeof(kek));

	CHECK(strncmp(config, public, strlen(public)) == 0);
	CHECK(strstr(config, hex) != NULL);
	CHECK(strstr(config, "\nname_pubkey ") != NULL);
	CHECK(strstr(config, "\nname_signature ") != NULL);
	CHECK(strstr(config, "cathedral_secret") == NULL);
	CHECK(strstr(config, "cathedral_cosk") == NULL);

	test_digest(dev.data, dev.length, digest);
	device_send(&dev, COVENANT_REMOTE_MSG_ACK, digest);

	CHECK(test_drive(&dev, COVENANT_REMOTE_DONE, TEST_SECONDS) ==
	    COVENANT_REMOTE_DONE);

	device_stop(&dev);
	covenant_remote_stop(ctx);
}

/*
 * A computer only gets its KEK. Heartbeats from it do not end the hand
 * over, only an ack of the KEK does.
 */
static void
test_kek_only(void)
{
	struct device	dev;
	int		idx;
	u_int8_t	digest[32], none[32];

	test_start(&dev, NULL, 0, 0);

	CHECK(test_drive_got(&dev, TEST_SECONDS) == COVENANT_REMOTE_ONLINE);
	CHECK(dev.type == COVENANT_REMOTE_MSG_KEK);
	CHECK(dev.length == sizeof(kek));
	CHECK(memcmp(dev.data, kek, sizeof(kek)) == 0);

	memset(none, 0, sizeof(none));

	for (idx = 0; idx < 3; idx++) {
		device_send(&dev, COVENANT_REMOTE_MSG_HEARTBEAT, none);
		CHECK(test_drive(&dev, COVENANT_REMOTE_DONE, 1) ==
		    COVENANT_REMOTE_ONLINE);
	}

	test_digest(dev.data, dev.length, digest);
	device_send(&dev, COVENANT_REMOTE_MSG_ACK, digest);

	CHECK(test_drive(&dev, COVENANT_REMOTE_DONE, TEST_SECONDS) ==
	    COVENANT_REMOTE_DONE);

	/* Once done it stays done, whatever the device sends after. */
	CHECK(covenant_remote_run(ctx) == COVENANT_REMOTE_DONE);

	digest[0] ^= 0x01;
	device_send(&dev, COVENANT_REMOTE_MSG_ACK, digest);
	device_send(&dev, 0x7f, digest);
	CHECK(test_drive(&dev, -1, 2) == COVENANT_REMOTE_DONE);

	device_stop(&dev);
	covenant_remote_stop(ctx);

	CHECK(covenant_remote_run(ctx) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_NO_REMOTE);
}

/*
 * An ack for anything other than what we sent must fail the hand over,
 * the device did not get its keys intact.
 */
static void
test_bad_ack(void)
{
	struct device	dev;
	u_int8_t	digest[32];

	test_start(&dev, public, 0, 0);

	CHECK(test_drive_got(&dev, TEST_SECONDS) == COVENANT_REMOTE_ONLINE);

	test_digest(dev.data, dev.length, digest);
	digest[0] ^= 0x01;
	device_send(&dev, COVENANT_REMOTE_MSG_ACK, digest);

	CHECK(test_drive(&dev, COVENANT_REMOTE_DONE, TEST_SECONDS) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_REMOTE);

	device_stop(&dev);
	covenant_remote_stop(ctx);
}

/*
 * A message we do not know from the device fails the hand over too.
 */
static void
test_garbage(void)
{
	struct device	dev;
	u_int8_t	data[32];

	test_start(&dev, NULL, 0, 0);

	CHECK(test_drive_got(&dev, TEST_SECONDS) == COVENANT_REMOTE_ONLINE);

	memset(data, 0xaa, sizeof(data));
	device_send(&dev, 0x7f, data);

	CHECK(test_drive(&dev, COVENANT_REMOTE_DONE, TEST_SECONDS) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_REMOTE);

	device_stop(&dev);
	covenant_remote_stop(ctx);
}

/*
 * The tunnel comes up no matter which end has the lower identity and
 * KEK id. A message of the wrong size from the device fails it.
 */
static void
test_reversed(void)
{
	struct device	dev;
	u_int8_t	data[8];

	test_start(&dev, NULL, 0, 1);

	CHECK(test_drive_got(&dev, TEST_SECONDS) == COVENANT_REMOTE_ONLINE);
	CHECK(dev.type == COVENANT_REMOTE_MSG_KEK);
	CHECK(memcmp(dev.data, kek, sizeof(kek)) == 0);

	memset(data, 0, sizeof(data));
	data[0] = COVENANT_REMOTE_MSG_HEARTBEAT;
	device_send_raw(&dev, data, sizeof(data));

	CHECK(test_drive(&dev, COVENANT_REMOTE_DONE, TEST_SECONDS) == -1);
	CHECK(covenant_last_error(ctx) == COVENANT_ERROR_REMOTE);

	device_stop(&dev);
	covenant_remote_stop(ctx);
}

/*
 * A device that joined with other words never gets the tunnel up and
 * never sees anything we meant for the real device.
 */
static void
test_wrong_words(void)
{
	struct device	dev;

	test_start(&dev, public, 1, 0);

	CHECK(test_drive(&dev, COVENANT_REMOTE_ONLINE, 8) ==
	    COVENANT_REMOTE_WAITING);
	CHECK(dev.online == 0);
	CHECK(dev.got == 0);

	device_stop(&dev);
	covenant_remote_stop(ctx);
}

/*
 * Make the words for the device and start the tunnel on our end, then
 * set up the device from those words. With wrong set the device gets
 * one of the passphrase words wrong, with reversed set our identity and
 * KEK id are the other way around compared to the device.
 */
static void
test_start(struct device *dev, const char *config, int wrong, int reversed)
{
	struct covenant_remote	rem;
	socklen_t		len;
	struct covenant_route	route;
	u_int32_t		handle;
	u_int8_t		cs[COVENANT_CATHEDRAL_SECRET_LEN];
	char			hex[(COVENANT_CATHEDRAL_SECRET_LEN * 2) + 1];
	u_int8_t		pk[COVENANT_COSK_PUBLIC_LEN];
	char			words[COVENANT_REMOTE_WORDS_LEN];

	memset(dev, 0, sizeof(*dev));

	if (reversed) {
		dev->ours = TEST_OURS_HIGH;
		dev->identity = TEST_IDENTITY_LOW;
	} else {
		dev->ours = TEST_OURS;
		dev->identity = TEST_IDENTITY;
	}

	dev->self.sin_family = AF_INET;
	dev->self.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	CHECK((dev->fd = socket(AF_INET, SOCK_DGRAM, 0)) != -1);
	CHECK(bind(dev->fd, (struct sockaddr *)&dev->self,
	    sizeof(dev->self)) == 0);

	len = sizeof(dev->self);
	CHECK(getsockname(dev->fd, (struct sockaddr *)&dev->self, &len) == 0);

	memset(&route, 0, sizeof(route));
	route.flock = TEST_FLOCK;
	route.identity = dev->identity;
	route.cathedral = INADDR_LOOPBACK;
	route.port = ntohs(dev->self.sin_port);
	route.kek = dev->ours;
	route.peer = TEST_KEK;

	CHECK(covenant_remote_words(ctx, &route, words, sizeof(words)) == 0);
	CHECK(covenant_cosk_new(ctx, &handle, pk, sizeof(pk)) == 0);
	CHECK(covenant_random_bytes(ctx, cs, sizeof(cs)) == 0);
	(void)sodium_bin2hex(hex, sizeof(hex), cs, sizeof(cs));

	memset(&rem, 0, sizeof(rem));
	rem.secret = secret;
	rem.secret_len = sizeof(secret);
	rem.keks = sealed;
	rem.keks_len = sizeof(sealed);
	rem.cosk = handle;
	rem.device = TEST_DEVICE;
	rem.config = config;
	rem.cathedral_secret = hex;

	CHECK(covenant_remote_start(ctx, &rem) == 0);

	device_start(dev, words, cs, wrong);
	nyfe_mem_zero(cs, sizeof(cs));
}

/*
 * Run both ends until covenant reports the state we want, an error or
 * until seconds have passed. Returns the last state covenant reported.
 */
static int
test_drive(struct device *dev, int want, int seconds)
{
	struct timespec		ts;
	time_t			start;
	int			state;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	start = ts.tv_sec;

	for (;;) {
		state = covenant_remote_run(ctx);
		device_run(dev);

		if (state == -1 || state == want)
			return (state);

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);

		if ((ts.tv_sec - start) >= seconds)
			return (state);
	}
}

/*
 * Run both ends until the device got what we send it, returns the
 * state covenant reported last.
 */
static int
test_drive_got(struct device *dev, int seconds)
{
	struct timespec		ts;
	time_t			start;
	int			state;

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	start = ts.tv_sec;

	for (;;) {
		state = covenant_remote_run(ctx);
		device_run(dev);

		if (state == -1 || dev->got)
			return (state);

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);

		if ((ts.tv_sec - start) >= seconds)
			return (state);
	}
}

/*
 * The SHA3-256 digest the device acks with.
 */
static void
test_digest(const u_int8_t *data, size_t len, u_int8_t *digest)
{
	struct nyfe_sha3	sha;

	nyfe_sha3_init256(&sha);
	nyfe_sha3_update(&sha, data, len);
	nyfe_sha3_final(&sha, digest, 32);
}

/*
 * Set up the device side from the words, the way cephas does it: the
 * route tells it the flock, both KEK ids and our identity, the rest of
 * the words are the passphrase the shared secret is derived from. The
 * device shares the cathedral secret with covenant, see the top of
 * this file, its cosk is made up here.
 */
static void
device_start(struct device *dev, const char *words, const u_int8_t *cs,
    int wrong)
{
	struct kyrka_cathedral_cfg	cfg;
	size_t				len;
	int				idx;
	const char			*ptr;
	u_int8_t			sk[64];
	u_int8_t			shared[SANCTUM_KEY_LENGTH];
	char				pass[COVENANT_REMOTE_WORDS_LEN];

	ptr = words;

	for (idx = 0; idx < COVENANT_ROUTE_WORDS; idx++) {
		CHECK((ptr = strchr(ptr, ' ')) != NULL);
		ptr++;
	}

	len = strlen(ptr);
	CHECK(len + 2 < sizeof(pass));

	memcpy(pass, ptr, len);
	pass[len++] = ' ';
	pass[len] = '\0';

	if (wrong) {
		if (pass[0] == 'a')
			pass[0] = 'b';
		else
			pass[0] = 'a';
	}

	device_secret(dev, pass, shared, sizeof(shared));
	nyfe_mem_zero(pass, sizeof(pass));

	device_shroud_base(dev);

	CHECK(covenant_random_bytes(ctx, sk, sizeof(sk)) == 0);

	CHECK((dev->kyrka = kyrka_ctx_alloc(device_event, dev)) != NULL);
	CHECK(kyrka_shroud_enable(dev->kyrka) == 0);
	CHECK(kyrka_p2p_active(dev->kyrka, 0) == 0);
	CHECK(kyrka_mtu_size(dev->kyrka, 1400) == 0);
	CHECK(kyrka_heaven_ifc(dev->kyrka, device_heaven, dev) == 0);
	CHECK(kyrka_purgatory_ifc(dev->kyrka, device_purgatory, dev) == 0);
	CHECK(kyrka_secret_load(dev->kyrka, shared, sizeof(shared)) == 0);

	memset(&cfg, 0, sizeof(cfg));
	cfg.udata = dev;
	cfg.identity = TEST_DEVICE;
	cfg.flock_src = TEST_FLOCK;
	cfg.tunnel = (TEST_KEK << 8) | dev->ours;
	cfg.send = device_cathedral;

	CHECK(kyrka_cathedral_config(dev->kyrka, &cfg) == 0);
	CHECK(kyrka_cathedral_secret_load(dev->kyrka, cs,
	    COVENANT_CATHEDRAL_SECRET_LEN) == 0);
	CHECK(kyrka_cathedral_cosk_load(dev->kyrka, sk, sizeof(sk)) == 0);

	nyfe_mem_zero(sk, sizeof(sk));
	nyfe_mem_zero(shared, sizeof(shared));
}

/*
 * The shroud base identity of covenant towards its cathedral, from the
 * flock (both ways, without its domain) and its identity.
 */
static void
device_shroud_base(struct device *dev)
{
	struct nyfe_kmac256	kdf;
	u_int64_t		flock;
	u_int32_t		identity;
	u_int8_t		ilen, zero[32];

	memset(zero, 0, sizeof(zero));

	flock = htobe64(TEST_FLOCK & ~((u_int64_t)SANCTUM_FLOCK_DOMAIN_MASK));
	identity = htobe32(dev->identity);

	nyfe_kmac256_init(&kdf, zero, sizeof(zero),
	    SHROUD_BASE_LABEL, sizeof(SHROUD_BASE_LABEL) - 1);

	ilen = sizeof(flock);
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &flock, sizeof(flock));
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &flock, sizeof(flock));

	ilen = sizeof(identity);
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &identity, sizeof(identity));

	nyfe_kmac256_final(&kdf, dev->base, sizeof(dev->base));
}

/*
 * Derive the shared secret of the tunnel from the passphrase exactly
 * as cephas_secret_derive() does. The device knows the flock but not a
 * second one, so the other flock is 0 like it is for cephas. Both
 * identities and both KEK ids go in from low to high.
 */
static void
device_secret(struct device *dev, const char *pass, u_int8_t *out,
    size_t out_len)
{
	struct nyfe_kmac256	kdf;
	u_int64_t		flock_a, flock_b;
	u_int8_t		okm[64], salt[32];
	u_int8_t		ilen, peer_a, peer_b;
	u_int32_t		identity_a, identity_b;

	memset(salt, 0, sizeof(salt));

	nyfe_passphrase_kdf(pass, strlen(pass), salt, sizeof(salt),
	    okm, sizeof(okm), CEPHAS_PASS_LABEL, sizeof(CEPHAS_PASS_LABEL) - 1);

	if (dev->identity < TEST_DEVICE) {
		identity_a = htobe32(dev->identity);
		identity_b = htobe32(TEST_DEVICE);
	} else {
		identity_a = htobe32(TEST_DEVICE);
		identity_b = htobe32(dev->identity);
	}

	if (dev->ours < TEST_KEK) {
		peer_a = dev->ours;
		peer_b = TEST_KEK;
	} else {
		peer_a = TEST_KEK;
		peer_b = dev->ours;
	}

	flock_a = htobe64(0);
	flock_b = htobe64(TEST_FLOCK);

	nyfe_kmac256_init(&kdf, okm, sizeof(okm),
	    CEPHAS_KDF_LABEL, sizeof(CEPHAS_KDF_LABEL) - 1);
	nyfe_mem_zero(okm, sizeof(okm));

	ilen = 8;
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &flock_a, sizeof(flock_a));
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &flock_b, sizeof(flock_b));

	ilen = 4;
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &identity_a, sizeof(identity_a));
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &identity_b, sizeof(identity_b));

	ilen = 1;
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &peer_a, sizeof(peer_a));
	nyfe_kmac256_update(&kdf, &ilen, sizeof(ilen));
	nyfe_kmac256_update(&kdf, &peer_b, sizeof(peer_b));

	nyfe_kmac256_final(&kdf, out, out_len);
	nyfe_mem_zero(&kdf, sizeof(kdf));
}

/*
 * Read what covenant sent us and do the key management of the device
 * once a second, like cephas does. Whoever sends to us is covenant,
 * that is our peer.
 *
 * Covenant shrouds its key offers with the peer key and its data with
 * the key of its cathedral, the shroud identity tells us which.
 */
static void
device_run(struct device *dev)
{
	struct timespec		ts;
	ssize_t			ret;
	socklen_t		slen;
	u_int8_t		buf[2048];

	for (;;) {
		slen = sizeof(dev->peer);
		ret = recvfrom(dev->fd, buf, sizeof(buf), MSG_DONTWAIT,
		    (struct sockaddr *)&dev->peer, &slen);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
			break;
		}

		if (device_cathedral_shroud(dev, buf, ret)) {
			device_input(dev, buf, ret,
			    KYRKA_PACKET_SHROUD_CATHEDRAL);
		} else {
			device_input(dev, buf, ret, KYRKA_PACKET_SHROUD_PEER);
		}
	}

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	if ((ts.tv_sec - dev->last) >= 1) {
		dev->last = ts.tv_sec;
		CHECK(kyrka_cathedral_notify(dev->kyrka) == 0);
		CHECK(kyrka_key_manage(dev->kyrka) == 0);
	}
}

/*
 * Check if covenant shrouded the packet for its cathedral, the way a
 * cathedral finds the shroud of a client: the packet starts with a
 * shroud identity and the seed it was derived from.
 *
 *	base = KMAC256(0, SHROUD_BASE_LABEL, flocks || identity)
 *	id = KMAC256(base, SHROUD_ID_LABEL, seed)
 */
static int
device_cathedral_shroud(struct device *dev, const u_int8_t *data,
    size_t len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		id[SHROUD_ID_LEN];

	if (len < sizeof(id) * 2)
		return (0);

	nyfe_kmac256_init(&kdf, dev->base, sizeof(dev->base),
	    SHROUD_ID_LABEL, sizeof(SHROUD_ID_LABEL) - 1);
	nyfe_kmac256_update(&kdf, &data[sizeof(id)], sizeof(id));
	nyfe_kmac256_final(&kdf, id, sizeof(id));

	if (memcmp(id, data, sizeof(id)))
		return (0);

	return (1);
}

/*
 * Hand a packet from covenant to the device, unshrouded with the given
 * key. What the device cannot open, like what covenant sends to its
 * cathedral, is dropped like any device drops it.
 */
static void
device_input(struct device *dev, const u_int8_t *data, size_t len,
    u_int8_t shroud)
{
	struct kyrka_packet	pkt;
	size_t			room;
	void			*ptr;

	CHECK((ptr = kyrka_packet_recvbuf(dev->kyrka, &pkt, &room)) != NULL);
	CHECK(len <= room);

	memcpy(ptr, data, len);
	pkt.length = len;
	pkt.shroud = shroud;

	if (kyrka_purgatory_input(dev->kyrka, &pkt) == -1) {
		CHECK(kyrka_last_error(dev->kyrka) == KYRKA_ERROR_NO_RX_KEY);
	}
}

/*
 * Send covenant a message from the device.
 */
static void
device_send(struct device *dev, u_int8_t type, const u_int8_t *data)
{
	struct covenant_remote_msg	msg;

	msg.type = type;
	memcpy(msg.data, data, sizeof(msg.data));

	device_send_raw(dev, &msg, sizeof(msg));
}

/*
 * Send covenant whatever is in data, the way cephas sends a message.
 */
static void
device_send_raw(struct device *dev, const void *data, size_t len)
{
	struct kyrka_packet	pkt;
	size_t			room;
	void			*ptr;

	CHECK(dev->online);
	CHECK((ptr = kyrka_packet_databuf(dev->kyrka, &pkt, &room)) != NULL);
	CHECK(len <= room);

	memcpy(ptr, data, len);

	pkt.length = len;
	pkt.shroud = KYRKA_PACKET_SHROUD_CATHEDRAL;

	CHECK(kyrka_heaven_input(dev->kyrka, &pkt) == 0);
}

/*
 * Tear down the device side.
 */
static void
device_stop(struct device *dev)
{
	kyrka_ctx_free(dev->kyrka);
	(void)close(dev->fd);

	nyfe_mem_zero(dev, sizeof(*dev));
}

/*
 * The device has keys both ways, the tunnel is up.
 */
static void
device_event(KYRKA *kyrka, union kyrka_event *evt, void *udata)
{
	struct device	*dev;

	dev = udata;

	if (evt->type == KYRKA_EVENT_KEYS_INFO) {
		if (evt->keys.tx_spi != 0 && evt->keys.rx_spi != 0)
			dev->online = 1;
	}
}

/*
 * Covenant sent the device its configuration or its KEK, remember the
 * first one we got.
 */
static void
device_heaven(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	struct device				*dev;
	const struct covenant_remote_msg	*msg;
	const struct covenant_remote_config	*cfg;
	const u_int8_t				*data;

	dev = udata;
	data = kyrka_packet_data(pkt);

	if (dev->got)
		return;

	CHECK(pkt->length > 0);

	switch (data[0]) {
	case COVENANT_REMOTE_MSG_CONFIG:
		CHECK(pkt->length == sizeof(*cfg));
		cfg = (const struct covenant_remote_config *)data;
		dev->length = be16toh(cfg->length);
		CHECK(dev->length <= sizeof(dev->data));
		memcpy(dev->data, cfg->data, dev->length);
		break;
	case COVENANT_REMOTE_MSG_KEK:
		CHECK(pkt->length == sizeof(*msg));
		msg = (const struct covenant_remote_msg *)data;
		dev->length = sizeof(msg->data);
		memcpy(dev->data, msg->data, dev->length);
		break;
	default:
		CHECK(0);
		break;
	}

	dev->type = data[0];
	dev->got = 1;
}

/*
 * Ciphertext for covenant, once we know where it is.
 */
static void
device_purgatory(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
	size_t		len;
	struct device	*dev;
	void		*data;

	dev = udata;

	if (dev->peer.sin_port == 0)
		return;

	CHECK((data = kyrka_packet_sendbuf(dev->kyrka, pkt, &len)) != NULL);

	CHECK(sendto(dev->fd, data, len, 0,
	    (const struct sockaddr *)&dev->peer, sizeof(dev->peer)) != -1);
}

/*
 * There is no cathedral for the device, what it would send it is
 * dropped.
 */
static void
device_cathedral(struct kyrka_packet *pkt, u_int64_t magic, void *udata)
{
}
