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
#include <sys/mman.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "covenant-int.h"

static void	covenant_fatalv(const char *, va_list);

/* Set to 1 once libsodium, the cipher and nyfe are set up. */
static int		initialized = 0;

/* Every call into the C library holds this, nyfe has global state. */
static pthread_mutex_t	lock = PTHREAD_MUTEX_INITIALIZER;

/* The fatal callback. */
static void		(*fatal_callback)(const char *, va_list) = NULL;

/*
 * Returns the covenant core its version string.
 */
const char *
covenant_version(void)
{
	int			len;
	static __thread char	version[128];

	len = snprintf(version, sizeof(version), "%s (%s)",
	    covenant_build_rev, covenant_build_date);
	if (len < 0 || (size_t)len >= sizeof(version))
		covenant_fatal("snprintf on version string");

	return (version);
}

/*
 * Sets the fatal callback, called before we abort on a very serious
 * error so the platform can log the reason.
 */
void
covenant_fatal_callback(void (*cb)(const char *, va_list))
{
	fatal_callback = cb;
	nyfe_fatal_callback(covenant_fatalv);
}

/*
 * Allocate a new covenant context, the first one also sets up
 * libsodium, the cipher and the nyfe random system.
 */
struct covenant *
covenant_ctx_alloc(void)
{
	struct covenant	*ctx;

	covenant_lock();

	if (initialized == 0) {
		if (sodium_init() == -1 || covenant_cipher_init() == -1) {
			covenant_unlock();
			return (NULL);
		}

		nyfe_zeroize_init();
		nyfe_fatal_callback(covenant_fatalv);
		nyfe_selftest_kmac256();
		nyfe_random_init();

		initialized = 1;
	}

	ctx = covenant_alloc(sizeof(*ctx));
	covenant_unlock();

	return (ctx);
}

/*
 * Zeroize and free the given covenant context, this forgets about
 * all cosk pairs that were still pending.
 */
void
covenant_ctx_free(struct covenant *ctx)
{
	if (ctx != NULL) {
		covenant_lock();
		covenant_free(ctx, sizeof(*ctx));
		covenant_unlock();
	}
}

/*
 * Obtain the last error that occurred in the covenant context.
 */
u_int32_t
covenant_last_error(struct covenant *ctx)
{
	if (ctx == NULL)
		return (COVENANT_ERROR_NO_CONTEXT);

	return (ctx->last_error);
}

/*
 * Perform an "emergency" erase of all key material we know about.
 *
 * You cannot safely use *ANY* covenant context after calling this,
 * call it from an error handler when you are going to abort anyway.
 */
void
covenant_emergency_erase(void)
{
	nyfe_zeroize_all();
}

/*
 * Fill the given buffer with random bytes from the nyfe random system.
 */
int
covenant_random_bytes(struct covenant *ctx, void *buf, size_t len)
{
	if (ctx == NULL)
		return (-1);

	if (buf == NULL || len == 0) {
		ctx->last_error = COVENANT_ERROR_PARAMETER;
		return (-1);
	}

	covenant_lock();
	nyfe_random_bytes(buf, len);
	covenant_unlock();

	return (0);
}

/*
 * Take the lock that every call into the C library holds.
 */
void
covenant_lock(void)
{
	if (pthread_mutex_lock(&lock) != 0)
		abort();
}

/*
 * Release the lock that every call into the C library holds.
 */
void
covenant_unlock(void)
{
	if (pthread_mutex_unlock(&lock) != 0)
		abort();
}

/*
 * Allocate memory for key material on its own pages, locked in memory
 * when we are allowed to and kept out of core dumps. The memory is on
 * the zeroize list until it is given back with covenant_free().
 */
void *
covenant_alloc(size_t len)
{
	void		*ptr;

	PRECOND(len > 0);

	ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (ptr == MAP_FAILED)
		covenant_fatal("mmap: failed to allocate %zu bytes", len);

	(void)mlock(ptr, len);

#if defined(MADV_DONTDUMP)
	(void)madvise(ptr, len, MADV_DONTDUMP);
#endif

	nyfe_zeroize_register(ptr, len);

	return (ptr);
}

/*
 * Zeroize and release memory from covenant_alloc().
 */
void
covenant_free(void *ptr, size_t len)
{
	PRECOND(ptr != NULL);
	PRECOND(len > 0);

	nyfe_zeroize(ptr, len);
	(void)munlock(ptr, len);

	if (munmap(ptr, len) == -1)
		covenant_fatal("munmap: failed to release %zu bytes", len);
}

/*
 * Something happened we cannot recover from, erase what we can and die.
 */
void
covenant_fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	covenant_fatalv(fmt, args);
	va_end(args);

	abort();
}

/*
 * What nyfe calls when one of its own PRECOND or VERIFY trips.
 */
void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	covenant_fatalv(fmt, args);
	va_end(args);

	abort();
}

/*
 * Erase all key material and let the platform log the reason.
 */
static void
covenant_fatalv(const char *fmt, va_list args)
{
	nyfe_zeroize_all();

	if (fatal_callback != NULL) {
		fatal_callback(fmt, args);
	} else {
		fprintf(stderr, "covenant: ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
	}
}
