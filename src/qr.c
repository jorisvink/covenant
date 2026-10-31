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

#include <stdbool.h>

#include "qrcodegen.h"

#include "covenant-int.h"

/*
 * The buffers qrcodegen works in.
 */
struct qr_work {
	u_int8_t	temp[qrcodegen_BUFFER_LEN_MAX];
	u_int8_t	code[qrcodegen_BUFFER_LEN_MAX];
};

/*
 * Encode text into qr with one byte per module (1 is dark), the side
 * of the code goes in side. The caller holds the lock.
 */
int
covenant_qr_render(struct covenant *ctx, const char *text, u_int8_t *qr,
    size_t qr_len, int *sz)
{
	struct qr_work		*work;
	int			x, y, size;

	PRECOND(ctx != NULL);
	PRECOND(text != NULL);
	PRECOND(qr != NULL);
	PRECOND(qr_len > 0);
	PRECOND(sz != NULL);

	work = covenant_alloc(sizeof(*work));

	if (!qrcodegen_encodeText(text, work->temp, work->code,
	    qrcodegen_Ecc_MEDIUM, qrcodegen_VERSION_MIN,
	    qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true)) {
		covenant_free(work, sizeof(*work));
		ctx->last_error = COVENANT_ERROR_QR_SIZE;
		return (-1);
	}

	size = qrcodegen_getSize(work->code);
	VERIFY(size > 0 && size <= COVENANT_QR_SIDE_MAX);

	if ((size_t)size * (size_t)size > qr_len) {
		covenant_free(work, sizeof(*work));
		ctx->last_error = COVENANT_ERROR_QR_SIZE;
		return (-1);
	}

	for (y = 0; y < size; y++) {
		for (x = 0; x < size; x++) {
			qr[(y * size) + x] =
			    qrcodegen_getModule(work->code, x, y) ? 1 : 0;
		}
	}

	covenant_free(work, sizeof(*work));
	*sz = size;

	return (0);
}
