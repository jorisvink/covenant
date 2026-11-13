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

#ifndef __H_RUNNER_H
#define __H_RUNNER_H

#include <sys/types.h>

#include <flutter_linux/flutter_linux.h>

/* covenant.c */
int	runner_single(void);
void	*runner_alloc(size_t);
void	runner_free(void *, size_t);
int	runner_channel_init(FlView *, GtkWindow *);

/* dialog.c */
int	runner_recovery(GtkWindow *, const char *, u_int8_t *, size_t);
int	runner_pick(GtkWindow *, const char *, int, const char *, char **);
int	runner_passphrase(GtkWindow *, const char *, int, char **, size_t *);

#endif
