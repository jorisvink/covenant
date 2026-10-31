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
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "covenant-int.h"

static void	usage(void) __attribute__((noreturn));

static void	restore_root_read(u_int8_t *, size_t);
static void	restore_backup_read(const char *, u_int8_t *, size_t);
static void	restore_kek_write(const char *, int, const u_int8_t *, size_t);

/* How we use thing? */
static void
usage(void)
{
	fprintf(stderr, "usage: covenant-restore <backup> [outdir]\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	time_t				made;
	COVENANT			*ctx;
	struct covenant_backup_info	info;
	int				idx, len;
	u_int8_t			*data, *backup;
	char				path[1024], when[32];
	u_int8_t			root[COVENANT_BACKUP_ROOT_LEN];

	nyfe_zeroize_init();

	if (argc != 2 && argc != 3)
		usage();

	if ((ctx = covenant_ctx_alloc()) == NULL)
		fatal("failed to start the covenant core");

	if ((data = calloc(1, COVENANT_KEKS_DATA_LEN)) == NULL)
		fatal("calloc");

	if ((backup = calloc(1, COVENANT_BACKUP_LEN)) == NULL)
		fatal("calloc");

	restore_backup_read(argv[1], backup, COVENANT_BACKUP_LEN);

	if (covenant_backup_info(ctx, backup, COVENANT_BACKUP_LEN, &info) == -1)
		fatal("%s is not a covenant backup we know", argv[1]);

	nyfe_zeroize_register(root, sizeof(root));
	nyfe_zeroize_register(data, COVENANT_KEKS_DATA_LEN);

	restore_root_read(root, sizeof(root));

	if (covenant_backup_open(ctx, root, sizeof(root), backup,
	    COVENANT_BACKUP_LEN, data, COVENANT_KEKS_DATA_LEN, &info) == -1)
		fatal("the recovery key does not open %s", argv[1]);

	nyfe_zeroize(root, sizeof(root));

	made = (time_t)info.made;
	(void)strftime(when, sizeof(when), "%Y-%m-%d %H:%M", localtime(&made));
	printf("flock %016" PRIx64 ", backup made %s\n", info.flock, when);

	if (argc == 3) {
		len = snprintf(path, sizeof(path),
		    "%s/%016" PRIx64, argv[2], info.flock);
		if (len < 0 || (size_t)len >= sizeof(path))
			errx(1, "path to flock %016" PRIx64 " is too long",
			    info.flock);

		if (mkdir(path, 0700) == -1)
			err(1, "mkdir(%s)", path);

		len = snprintf(path, sizeof(path),
		    "%s/%016" PRIx64 "/kek-data", argv[2], info.flock);
		if (len < 0 || (size_t)len >= sizeof(path))
			errx(1, "path to kek-data is too long");

		if (mkdir(path, 0700) == -1)
			err(1, "mkdir(%s)", path);

		for (idx = 1; idx <= COVENANT_KEK_COUNT; idx++) {
			restore_kek_write(path, idx,
			    &data[(idx - 1) * COVENANT_KEK_LEN],
			    COVENANT_KEK_LEN);
		}

		printf("wrote %d KEKs into %s\n", COVENANT_KEK_COUNT, path);
	} else {
		printf("recovery key is correct\n");
	}

	nyfe_zeroize(data, COVENANT_KEKS_DATA_LEN);
	free(backup);
	free(data);

	covenant_ctx_free(ctx);

	return (0);
}

/*
 * Obtain the recovery key from user.
 */
static void
restore_root_read(u_int8_t *root, size_t root_len)
{
	char			hex[3];
	struct termios		old, quiet;
	int			tty, ch, hi;
	size_t			off, digits;

	if ((tty = isatty(STDIN_FILENO))) {
		fprintf(stderr, "recovery key: ");

		if (tcgetattr(STDIN_FILENO, &old) == -1)
			fatal("tcgetattr");

		quiet = old;
		quiet.c_lflag &= ~ECHO;

		if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet) == -1)
			fatal("tcsetattr");
	}

	hi = 1;
	off = 0;
	digits = 0;
	nyfe_zeroize_register(hex, sizeof(hex));

	while ((ch = getchar()) != EOF && ch != '\n') {
		if (isspace(ch))
			continue;

		if (!isxdigit(ch) || off == root_len)
			break;

		hex[hi ? 0 : 1] = ch;
		digits++;

		if (!hi) {
			hex[2] = '\0';
			root[off++] = (u_int8_t)strtoul(hex, NULL, 16);
		}

		hi = !hi;
	}

	nyfe_zeroize(hex, sizeof(hex));

	if (tty) {
		(void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
		fprintf(stderr, "\n");
	}

	if (digits != root_len * 2 || (ch != EOF && ch != '\n'))
		fatal("a recovery key is %zu hex digits", root_len * 2);
}

/*
 * Read exactly len bytes from the given backup.
 */
static void
restore_backup_read(const char *path, u_int8_t *buf, size_t len)
{
	struct stat	st;
	int		fd;
	ssize_t		ret;

	if ((fd = open(path, O_RDONLY)) == -1)
		err(1, "open(%s)", path);

	if (fstat(fd, &st) == -1)
		err(1, "fstat");

	if ((size_t)st.st_size != len)
		errx(1, "%s is not a backup", path);

	if ((ret = read(fd, buf, len)) == -1)
		err(1, "read");

	if ((size_t)ret != len)
		errx(1, "short read %zd/%zu", ret, len);

	(void)close(fd);
}

/*
 * Write a single KEK as <dir>/kek-0xNN, refusing to overwrite one.
 */
static void
restore_kek_write(const char *dir, int id, const u_int8_t *kek, size_t len)
{
	int		fd, ret;
	char		path[1024];

	ret = snprintf(path, sizeof(path), "%s/kek-0x%02x", dir, id);
	if (ret < 0 || (size_t)ret >= sizeof(path))
		errx(1, "path to kek-0x%02x is too long", id);

	if ((fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600)) == -1)
		err(1, "open(%s)", path);

	if (write(fd, kek, len) != (ssize_t)len)
		err(1, "write(%s)", path);

	if (close(fd) == -1)
		err(1, "close(%s)", path);
}
