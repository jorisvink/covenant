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
#include <sys/file.h>
#include <sys/stat.h>

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "covenant-int.h"
#include "runner.h"

/* The name of the channel, the same as on android and ios. */
#define CHANNEL			"se.sanctorum.reliquary/core"

/* The length of a flock as hex. */
#define FLOCK_HEX_LEN		16

/* Whether a call needs the vault key and if it may make one. */
#define KEY_NONE		0
#define KEY_OPEN		1
#define KEY_CREATE		2

/* What a call asks the user for besides the passphrase. */
#define ASK_FOLDER		(1 << 0)
#define ASK_BACKUP		(1 << 1)
#define ASK_RECOVERY		(1 << 2)
#define ASK_PASSPHRASE		(1 << 3)
#define ASK_TARGET		(1 << 4)

/* The length of a device (cathedral id) as hex. */
#define DEVICE_HEX_LEN		8

/*
 * The files rlq keeps for a device, in the order we write them. The
 * cathedral_id and device_kek go last, rlq takes those as the sign that
 * the device was joined and has its KEK.
 */
#define KEYS_ID			0
#define KEYS_COSK		1
#define KEYS_COSK_PUB		2
#define KEYS_KEK		3
#define KEYS_CATHEDRAL_ID	4
#define KEYS_DEVICE_KEK		5
#define KEYS_MAX		6

struct job;

/*
 * The paths of the files rlq keeps for a device.
 */
struct keys_files {
	char		path[KEYS_MAX][PATH_MAX];
};

/*
 * A method on the channel.
 */
struct op {
	int		key;
	int		ask;
	const char	*name;
	const char	*reason;
	FlValue		*(*run)(struct job *, const u_int8_t *, size_t);
};

/*
 * A single call from the user interface, from the main thread to the
 * thread doing the work and back.
 */
struct job {
	const struct op		*op;
	FlMethodCall		*call;
	int			create;

	const char		*code;
	u_int8_t		*root;
	char			*pass;
	char			*fresh;
	FlValue			*result;
	char			*source;

	int64_t			error;
	size_t			pass_len;
	size_t			fresh_len;
	char			message[256];
};

static int	file_wipe(const char *);
static int	dir_path(char *, size_t);
static int	flock_valid(const char *);
static void	file_discard(const char *);
static int	device_valid(const char *);
static int	keys_default(char *, size_t);
static int	flock_has_keks(const char *);
static int	dir_flock_next(DIR *, char *, size_t);
static int	file_read(const char *, void *, size_t);
static int	file_write_all(int, const void *, size_t);
static int	file_write(const char *, const void *, size_t);
static int	file_path(char *, size_t, const char *, const char *);

static void		*job_run(void *);
static gboolean		job_done(gpointer);
static void		job_core_error(struct job *);
static int		keys_mkdir(struct job *, const char *);
static int		keys_joined(struct job *, const char *);
static int		job_unlock(struct job *, u_int8_t *, size_t);
static int		keys_absent(struct job *, const struct keys_files *);
static int		keys_write(struct job *, const char *,
			    const void *, size_t);
static int		keys_paths(struct job *, struct keys_files *,
			    const char *, const char *, u_int8_t);
static void		job_error(struct job *, const char *, const char *, ...)
			    __attribute__((format (printf, 3, 4)));
static int		keys_path(struct job *, struct keys_files *, int,
			    const char *, ...)
			    __attribute__((format (printf, 4, 5)));
static int		keys_save(struct job *, const struct keys_files *,
			    const char *, u_int8_t,
			    const struct covenant_device_keys *);

static int		arg_keys_dir(struct job *, char *, size_t);
static const char	*arg_string(struct job *, const char *, int);
static const char	*arg_file(struct job *, FlValue *, char *, size_t);
static int		arg_flock(struct job *, char *, size_t, u_int64_t *);
static int		arg_int(struct job *, const char *, int64_t, int64_t,
			    int64_t *);
static int		arg_keks(struct job *, char *, size_t,
			    u_int8_t *, size_t);

static FlValue	*op_wipe(struct job *, const u_int8_t *, size_t);
static FlValue	*op_vault(struct job *, const u_int8_t *, size_t);
static FlValue	*op_renew(struct job *, const u_int8_t *, size_t);
static FlValue	*op_bundle(struct job *, const u_int8_t *, size_t);
static FlValue	*op_forget(struct job *, const u_int8_t *, size_t);
static FlValue	*op_version(struct job *, const u_int8_t *, size_t);
static FlValue	*op_handoff(struct job *, const u_int8_t *, size_t);
static FlValue	*op_cosk_new(struct job *, const u_int8_t *, size_t);
static FlValue	*op_generate(struct job *, const u_int8_t *, size_t);
static FlValue	*op_cosk_drop(struct job *, const u_int8_t *, size_t);
static FlValue	*op_keys_pick(struct job *, const u_int8_t *, size_t);
static FlValue	*op_file_read(struct job *, const u_int8_t *, size_t);
static FlValue	*op_provision(struct job *, const u_int8_t *, size_t);
static FlValue	*op_passphrase(struct job *, const u_int8_t *, size_t);
static FlValue	*op_keys_check(struct job *, const u_int8_t *, size_t);
static FlValue	*op_file_write(struct job *, const u_int8_t *, size_t);
static FlValue	*op_remote_run(struct job *, const u_int8_t *, size_t);
static FlValue	*op_keys_folder(struct job *, const u_int8_t *, size_t);
static FlValue	*op_file_delete(struct job *, const u_int8_t *, size_t);
static FlValue	*op_remote_stop(struct job *, const u_int8_t *, size_t);
static FlValue	*op_remote_start(struct job *, const u_int8_t *, size_t);
static FlValue	*op_remote_words(struct job *, const u_int8_t *, size_t);
static FlValue	*op_import_ambry(struct job *, const u_int8_t *, size_t);
static FlValue	*op_import_backup(struct job *, const u_int8_t *, size_t);
static FlValue	*op_provision_keys(struct job *, const u_int8_t *, size_t);
static FlValue	*ambry_bundle(struct job *, const u_int8_t *, size_t,
		    const u_int8_t *, size_t, int64_t);

static void	channel_fatal(const char *, va_list);
static void	channel_call(FlMethodChannel *, FlMethodCall *, gpointer);

/* The methods we answer, anything else is not implemented. */
static const struct op ops[] = {
	{ KEY_NONE, 0, "vault", NULL, op_vault },
	{ KEY_CREATE, 0, "keksGenerate",
	    "Unlock your KEKs to set up the KEKs of a new flock.",
	    op_generate },
	{ KEY_OPEN, 0, "keksRenew",
	    "Unlock your KEKs to replace the KEK of a removed device.",
	    op_renew },
	{ KEY_OPEN, 0, "bundle",
	    "Unlock your KEKs to make new encrypted secrets.", op_bundle },
	{ KEY_NONE, 0, "keksDelete", NULL, op_forget },
	{ KEY_NONE, 0, "vaultWipe", NULL, op_wipe },
	{ KEY_NONE, 0, "coskNew", NULL, op_cosk_new },
	{ KEY_NONE, 0, "coskDrop", NULL, op_cosk_drop },
	{ KEY_OPEN, 0, "provision",
	    "Unlock your KEKs to add a new device.", op_provision },
	{ KEY_NONE, 0, "handoffAvailable", NULL, op_handoff },
	{ KEY_NONE, 0, "keysFolder", NULL, op_keys_folder },
	{ KEY_NONE, ASK_TARGET, "keysFolderPick", NULL, op_keys_pick },
	{ KEY_NONE, 0, "keysCheck", NULL, op_keys_check },
	{ KEY_OPEN, 0, "provisionKeys",
	    "Unlock your KEKs to write the keys of the new device.",
	    op_provision_keys },
	{ KEY_NONE, 0, "remoteWords", NULL, op_remote_words },
	{ KEY_OPEN, 0, "remoteStart",
	    "Unlock your KEKs to send the device its keys.", op_remote_start },
	{ KEY_NONE, 0, "remoteRun", NULL, op_remote_run },
	{ KEY_NONE, 0, "remoteStop", NULL, op_remote_stop },
	{ KEY_NONE, 0, "version", NULL, op_version },
	{ KEY_NONE, 0, "fileRead", NULL, op_file_read },
	{ KEY_NONE, 0, "fileWrite", NULL, op_file_write },
	{ KEY_NONE, 0, "fileDelete", NULL, op_file_delete },
	{ KEY_CREATE, ASK_FOLDER, "importAmbry",
	    "Unlock your KEKs to import the KEKs made by ambry.",
	    op_import_ambry },
	{ KEY_CREATE, ASK_BACKUP | ASK_RECOVERY, "importBackup",
	    "Unlock your KEKs to import the KEKs from this backup.",
	    op_import_backup },
	{ KEY_OPEN, ASK_PASSPHRASE, "passphraseChange",
	    "Unlock your KEKs with your current passphrase to change it.",
	    op_passphrase },
	{ KEY_NONE, 0, NULL, NULL, NULL },
};

/* The plain files the user interface may read and write. */
static const char *files[] = {
	"api", "token", "cathedral", "natport", "prefs", NULL
};

/* The largest plain file we read. */
#define FILE_MAX_LEN		(1024 * 1024)

/* What we tell the user when the passphrase is chosen. */
static const char	*create_reason =
    "Choose the passphrase that protects the KEKs on this computer. "
    "It is asked for every time they are used and cannot be recovered.";

/* What we tell the user when the passphrase is changed. */
static const char	*change_reason =
    "Choose the new passphrase that protects the KEKs on this computer. "
    "It is asked for every time they are used and cannot be recovered.";

/* The covenant context all calls run under. */
static COVENANT		*ctx = NULL;

/* The window, to put the passphrase dialog on top of. */
static GtkWindow	*window = NULL;

/*
 * Make sure only one covenant runs on our directory at a time, the lock
 * is held until we exit. Fails with EWOULDBLOCK if another one runs.
 */
int
runner_single(void)
{
	int		fd, saved;
	char		path[PATH_MAX];

	if (file_path(path, sizeof(path), NULL, "lock") == -1) {
		errno = ENOENT;
		return (-1);
	}

	if ((fd = open(path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC,
	    0600)) == -1)
		return (-1);

	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}

	return (0);
}

/*
 * Set up the covenant context and the channel to the user interface.
 */
int
runner_channel_init(FlView *view, GtkWindow *win)
{
	FlStandardMethodCodec	*codec;
	FlEngine		*engine;
	FlMethodChannel		*channel;

	PRECOND(view != NULL);
	PRECOND(win != NULL);

	window = win;
	covenant_fatal_callback(channel_fatal);

	if ((ctx = covenant_ctx_alloc()) == NULL)
		return (-1);

	engine = fl_view_get_engine(view);
	codec = fl_standard_method_codec_new();

	channel = fl_method_channel_new(fl_engine_get_binary_messenger(engine),
	    CHANNEL, FL_METHOD_CODEC(codec));
	g_object_unref(codec);

	fl_method_channel_set_method_call_handler(channel,
	    channel_call, NULL, NULL);

	return (0);
}

/*
 * A call from the user interface. Ask for the passphrase when the call
 * needs the vault key, then hand it off to a thread of its own.
 */
static void
channel_call(FlMethodChannel *channel, FlMethodCall *call, gpointer arg)
{
	struct stat		st;
	pthread_t		tid;
	size_t			idx;
	struct job		*job;
	int			exists;
	char			path[PATH_MAX];
	const char		*name, *reason, *start;

	name = fl_method_call_get_name(call);

	for (idx = 0; ops[idx].name != NULL; idx++) {
		if (!strcmp(ops[idx].name, name))
			break;
	}

	if (ops[idx].name == NULL) {
		if (fl_method_call_respond_not_implemented(call,
		    NULL) == FALSE) {
			fprintf(stderr,
			    "covenant: failed to answer %s\n", name);
		}
		return;
	}

	if ((job = calloc(1, sizeof(*job))) == NULL)
		covenant_fatal("calloc: failed to allocate a job");

	job->op = &ops[idx];
	job->call = g_object_ref(call);

	if (job->op->ask & ASK_FOLDER) {
		if (runner_pick(window, "Choose the flock folder ambry made",
		    1, NULL, &job->source) == -1) {
			job_error(job, "cancelled", "Nothing was imported.");
			job_done(job);
			return;
		}
	}

	if (job->op->ask & ASK_BACKUP) {
		if (runner_pick(window, "Choose a backup",
		    0, NULL, &job->source) == -1) {
			job_error(job, "cancelled", "Nothing was imported.");
			job_done(job);
			return;
		}
	}

	if (job->op->ask & ASK_TARGET) {
		start = NULL;
		if (keys_default(path, sizeof(path)) == 0)
			start = path;

		if (runner_pick(window, "Choose the folder for the keys",
		    1, start, &job->source) == -1) {
			job_error(job, "cancelled", "No folder was chosen.");
			job_done(job);
			return;
		}
	}

	if (job->op->ask & ASK_RECOVERY) {
		job->root = runner_alloc(COVENANT_BACKUP_ROOT_LEN);

		if (runner_recovery(window, "Enter the recovery key the phone "
		    "showed when you set up its backups.",
		    job->root, COVENANT_BACKUP_ROOT_LEN) == -1) {
			job_error(job, "cancelled", "Nothing was imported.");
			job_done(job);
			return;
		}
	}

	if (job->op->key != KEY_NONE) {
		exists = 0;

		if (file_path(path, sizeof(path), NULL, "key") == -1) {
			job_error(job, "failed", "Your home is not set.");
			job_done(job);
			return;
		}

		if (stat(path, &st) == -1) {
			if (errno != ENOENT) {
				job_error(job, "failed",
				    "Failed to check if key exists: %s",
				    strerror(errno));
				job_done(job);
				return;
			}
		} else {
			exists = 1;
		}

		reason = job->op->reason;

		if (!exists) {
			if (job->op->key != KEY_CREATE) {
				job_error(job, "missing",
				    "There are no KEKs on this computer yet.");
				job_done(job);
				return;
			}

			job->create = 1;
			reason = create_reason;
		}

		if (runner_passphrase(window, reason, job->create,
		    &job->pass, &job->pass_len) == -1) {
			job_error(job, "cancelled",
			    "Your KEKs were not unlocked.");
			job_done(job);
			return;
		}
	}

	if (job->op->ask & ASK_PASSPHRASE) {
		if (runner_passphrase(window, change_reason, 1,
		    &job->fresh, &job->fresh_len) == -1) {
			job_error(job, "cancelled",
			    "Your passphrase was not changed.");
			job_done(job);
			return;
		}
	}

	if (pthread_create(&tid, NULL, job_run, job) != 0)
		covenant_fatal("pthread_create: failed to start a job");

	if (pthread_detach(tid) != 0)
		covenant_fatal("pthread_detach: failed to detach a job");
}

/*
 * Do the work of a call, with the vault key when it needs one.
 */
static void *
job_run(void *arg)
{
	struct job	*job;
	u_int8_t	vk[COVENANT_VAULT_KEY_LEN];

	job = arg;

	if (job->op->key == KEY_NONE) {
		job->result = job->op->run(job, NULL, 0);
	} else {
		covenant_lock();
		nyfe_zeroize_register(vk, sizeof(vk));
		covenant_unlock();

		if (job_unlock(job, vk, sizeof(vk)) == 0)
			job->result = job->op->run(job, vk, sizeof(vk));

		covenant_lock();
		nyfe_zeroize(vk, sizeof(vk));
		covenant_unlock();
	}

	g_idle_add(job_done, job);

	return (NULL);
}

/*
 * Back on the main thread, answer the call and free the job.
 */
static gboolean
job_done(gpointer arg)
{
	gboolean	ok;
	struct job	*job;
	FlValue		*details;

	job = arg;

	if (job->code == NULL) {
		if (job->result == NULL)
			job->result = fl_value_new_string("");
		ok = fl_method_call_respond_success(job->call,
		    job->result, NULL);
	} else {
		details = NULL;
		if (job->error != -1)
			details = fl_value_new_int(job->error);

		ok = fl_method_call_respond_error(job->call,
		    job->code, job->message, details, NULL);

		if (details != NULL)
			fl_value_unref(details);
	}

	if (ok == FALSE) {
		fprintf(stderr, "covenant: failed to answer %s\n",
		    job->op->name);
	}

	if (job->result != NULL)
		fl_value_unref(job->result);

	if (job->pass != NULL)
		runner_free(job->pass, job->pass_len);

	if (job->fresh != NULL)
		runner_free(job->fresh, job->fresh_len);

	if (job->root != NULL)
		runner_free(job->root, COVENANT_BACKUP_ROOT_LEN);

	free(job->source);

	g_object_unref(job->call);
	free(job);

	return (G_SOURCE_REMOVE);
}

/*
 * Turn the passphrase into the vault key and wipe the passphrase. When
 * there is no vault key yet we make one and wrap it under the passphrase.
 * The caller registered vk and zeroizes it.
 */
static int
job_unlock(struct job *job, u_int8_t *vk, size_t len)
{
	int		ret;
	char		path[PATH_MAX];
	u_int8_t	wrapped[COVENANT_WRAPPED_KEY_LEN];

	PRECOND(job != NULL);
	PRECOND(vk != NULL);
	PRECOND(len == COVENANT_VAULT_KEY_LEN);

	ret = -1;

	if (file_path(path, sizeof(path), NULL, "key") == -1) {
		job_error(job, "failed", "Your home is not set.");
		goto cleanup;
	}

	if (job->create) {
		if (covenant_random_bytes(ctx, vk, len) == -1) {
			job_core_error(job);
			goto cleanup;
		}

		covenant_key_wrap(ctx, job->pass, job->pass_len,
		    vk, len, wrapped, sizeof(wrapped));

		if (file_write(path, wrapped, sizeof(wrapped)) == -1) {
			job_error(job, "failed", "Failed to save %s: %s",
			    path, strerror(errno));
			goto cleanup;
		}

		ret = 0;
		goto cleanup;
	}

	if (file_read(path, wrapped, sizeof(wrapped)) == -1) {
		job_error(job, "failed", "Failed to read %s: %s",
		    path, strerror(errno));
		goto cleanup;
	}

	if (covenant_key_unwrap(ctx, job->pass, job->pass_len,
	    wrapped, sizeof(wrapped), vk, len) == -1) {
		job_core_error(job);
		goto cleanup;
	}

	ret = 0;

cleanup:
	runner_free(job->pass, job->pass_len);

	job->pass = NULL;
	job->pass_len = 0;

	return (ret);
}

/*
 * Fail the call with the given code and message.
 */
static void
job_error(struct job *job, const char *code, const char *fmt, ...)
{
	int		len;
	va_list		args;

	PRECOND(job != NULL);
	PRECOND(code != NULL);
	PRECOND(fmt != NULL);

	job->code = code;
	job->error = -1;

	va_start(args, fmt);
	len = vsnprintf(job->message, sizeof(job->message), fmt, args);
	va_end(args);

	if (len < 0)
		job->message[0] = '\0';
}

/*
 * Fail the call with the last error of the covenant library, the user
 * interface turns its code into words.
 */
static void
job_core_error(struct job *job)
{
	PRECOND(job != NULL);

	job_error(job, "core", "covenant core error");
	job->error = covenant_last_error(ctx);
}

/*
 * What there is to know without the vault key, as json:
 *
 *	{ "ready": true, "hardware": "passphrase", "auth": "...",
 *	  "flocks": [ { "flock": "...", "created": 0 } ] }
 */
static FlValue *
op_vault(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	struct stat		st;
	FILE			*fp;
	size_t			len;
	DIR			*dir;
	struct covenant_info	info;
	FlValue			*result;
	char			path[PATH_MAX];
	char			*json, *sep, *ready;
	char			flock[FLOCK_HEX_LEN + 1];
	u_int8_t		sealed[COVENANT_KEKS_SEALED_LEN];

	if (file_path(path, sizeof(path), NULL, "key") == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	ready = "false";

	if (stat(path, &st) == 0)
		ready = "true";

	if ((fp = open_memstream(&json, &len)) == NULL) {
		job_error(job, "failed", "open_memstream: %s", strerror(errno));
		return (NULL);
	}

	fprintf(fp, "{\"ready\":%s,\"hardware\":\"passphrase\",", ready);
	fprintf(fp, "\"auth\":\"Your passphrase, every time\",\"flocks\":[");

	if (dir_path(path, sizeof(path)) == -1) {
		(void)fclose(fp);
		free(json);
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if ((dir = opendir(path)) == NULL) {
		(void)fclose(fp);
		free(json);
		job_error(job, "failed", "Failed to open %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	sep = "";

	while (dir_flock_next(dir, flock, sizeof(flock)) == 0) {
		if (file_path(path, sizeof(path), flock, "keks") == -1)
			continue;

		if (file_read(path, sealed, sizeof(sealed)) == -1)
			continue;

		if (covenant_keks_info(ctx, sealed,
		    sizeof(sealed), &info) == -1)
			continue;

		fprintf(fp, "%s{\"flock\":\"%s\",\"created\":%llu}",
		    sep, flock, (unsigned long long)info.created);
		sep = ",";
	}

	(void)closedir(dir);

	fprintf(fp, "]}");

	if (ferror(fp)) {
		(void)fclose(fp);
		free(json);
		job_error(job, "failed", "Failed to list the KEKs.");
		return (NULL);
	}

	if (fclose(fp) == EOF) {
		free(json);
		job_error(job, "failed", "Failed to list the KEKs.");
		return (NULL);
	}

	result = fl_value_new_string(json);
	free(json);

	return (result);
}

/*
 * Generate the KEKs of a flock and make its first bundle.
 */
static FlValue *
op_generate(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	u_int64_t	id;
	int64_t		days;
	FlValue		*result;
	char		path[PATH_MAX];
	char		flock[FLOCK_HEX_LEN + 1];
	u_int8_t	sealed[COVENANT_KEKS_SEALED_LEN];

	if (arg_flock(job, flock, sizeof(flock), &id) == -1)
		return (NULL);

	if (arg_int(job, "days", 1, COVENANT_AMBRY_DAYS_MAX, &days) == -1)
		return (NULL);

	covenant_keks_generate(ctx, vk, vk_len, id, sealed, sizeof(sealed));

	result = ambry_bundle(job, vk, vk_len, sealed, sizeof(sealed), days);
	if (result == NULL)
		return (NULL);

	if (file_path(path, sizeof(path), flock, "keks") == -1) {
		fl_value_unref(result);
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if (file_write(path, sealed, sizeof(sealed)) == -1) {
		fl_value_unref(result);
		job_error(job, "failed", "Failed to save %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	return (result);
}

/*
 * Replace a single KEK of a flock and make a new bundle.
 */
static FlValue *
op_renew(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	FlValue		*result;
	int64_t		kek, days;
	char		path[PATH_MAX];
	char		flock[FLOCK_HEX_LEN + 1];
	u_int8_t	sealed[COVENANT_KEKS_SEALED_LEN];
	u_int8_t	renewed[COVENANT_KEKS_SEALED_LEN];

	if (arg_keks(job, flock, sizeof(flock), sealed, sizeof(sealed)) == -1)
		return (NULL);

	if (arg_int(job, "kek", 1, COVENANT_KEK_COUNT, &kek) == -1)
		return (NULL);

	if (arg_int(job, "days", 1, COVENANT_AMBRY_DAYS_MAX, &days) == -1)
		return (NULL);

	if (covenant_keks_renew(ctx, vk, vk_len, sealed, sizeof(sealed),
	    (u_int8_t)kek, renewed, sizeof(renewed)) == -1) {
		job_core_error(job);
		return (NULL);
	}

	result = ambry_bundle(job, vk, vk_len, renewed, sizeof(renewed), days);
	if (result == NULL)
		return (NULL);

	if (file_path(path, sizeof(path), flock, "keks") == -1) {
		fl_value_unref(result);
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if (file_write(path, renewed, sizeof(renewed)) == -1) {
		fl_value_unref(result);
		job_error(job, "failed", "Failed to save %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	return (result);
}

/*
 * Make a new bundle for a flock.
 */
static FlValue *
op_bundle(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	int64_t		days;
	char		flock[FLOCK_HEX_LEN + 1];
	u_int8_t	sealed[COVENANT_KEKS_SEALED_LEN];

	if (arg_keks(job, flock, sizeof(flock), sealed, sizeof(sealed)) == -1)
		return (NULL);

	if (arg_int(job, "days", 1, COVENANT_AMBRY_DAYS_MAX, &days) == -1)
		return (NULL);

	return (ambry_bundle(job, vk, vk_len, sealed, sizeof(sealed), days));
}

/*
 * Make an ambry bundle, returned with its generation and expiry day.
 */
static FlValue *
ambry_bundle(struct job *job, const u_int8_t *vk, size_t vk_len,
    const u_int8_t *sealed, size_t sealed_len, int64_t days)
{
	u_int32_t	gen;
	u_int16_t	expires;
	FlValue		*result;
	u_int8_t	*bundle;

	if ((bundle = malloc(COVENANT_AMBRY_LEN)) == NULL) {
		job_error(job, "failed", "Out of memory.");
		return (NULL);
	}

	if (covenant_ambry_bundle(ctx, vk, vk_len, sealed, sealed_len,
	    (u_int16_t)days, bundle, COVENANT_AMBRY_LEN,
	    &gen, &expires) == -1) {
		free(bundle);
		job_core_error(job);
		return (NULL);
	}

	result = fl_value_new_map();

	fl_value_set_string_take(result, "bundle",
	    fl_value_new_uint8_list(bundle, COVENANT_AMBRY_LEN));
	fl_value_set_string_take(result, "generation", fl_value_new_int(gen));
	fl_value_set_string_take(result, "expires", fl_value_new_int(expires));

	free(bundle);

	return (result);
}

/*
 * Remove the KEKs of a flock from this computer.
 */
static FlValue *
op_forget(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	FlValue		*args;
	const char	*flock;
	char		path[PATH_MAX];

	args = fl_method_call_get_args(job->call);

	if (fl_value_get_type(args) != FL_VALUE_TYPE_STRING) {
		job_error(job, "invalid", "That is not a flock ID.");
		return (NULL);
	}

	flock = fl_value_get_string(args);

	if (flock_valid(flock) == -1) {
		job_error(job, "invalid", "That is not a flock ID.");
		return (NULL);
	}

	if (file_path(path, sizeof(path), flock, "keks") == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if (file_wipe(path) == -1) {
		job_error(job, "failed", "Failed to remove %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	if (file_path(path, sizeof(path), flock, NULL) == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if (rmdir(path) == -1) {
		if (errno == ENOENT || errno == ENOTEMPTY)
			return (NULL);
		job_error(job, "failed", "Failed to remove %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	return (NULL);
}

/*
 * Remove the KEKs of every flock and the vault key from this computer.
 */
static FlValue *
op_wipe(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	DIR		*dir;
	char		path[PATH_MAX];
	char		flock[FLOCK_HEX_LEN + 1];

	if (dir_path(path, sizeof(path)) == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if ((dir = opendir(path)) == NULL) {
		if (errno == ENOENT)
			return (NULL);
		job_error(job, "failed", "Failed to open %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	while (dir_flock_next(dir, flock, sizeof(flock)) == 0) {
		if (file_path(path, sizeof(path), flock, "keks") == -1)
			continue;

		if (file_wipe(path) == -1) {
			job_error(job, "failed", "Failed to remove %s: %s",
			    path, strerror(errno));
			break;
		}

		if (file_path(path, sizeof(path), flock, NULL) == -1)
			continue;

		if (rmdir(path) == -1 && errno != ENOTEMPTY) {
			job_error(job, "failed", "Failed to remove %s: %s",
			    path, strerror(errno));
			break;
		}
	}

	(void)closedir(dir);

	if (job->code != NULL)
		return (NULL);

	if (file_path(path, sizeof(path), NULL, "key") == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if (file_wipe(path) == -1) {
		job_error(job, "failed", "Failed to remove %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	return (NULL);
}

/*
 * Make a new cosk pair, returns its handle and public key.
 */
static FlValue *
op_cosk_new(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	u_int32_t	handle;
	FlValue		*result;
	u_int8_t	pk[COVENANT_COSK_PUBLIC_LEN];

	if (covenant_cosk_new(ctx, &handle, pk, sizeof(pk)) == -1) {
		job_core_error(job);
		return (NULL);
	}

	result = fl_value_new_map();

	fl_value_set_string_take(result, "handle", fl_value_new_int(handle));
	fl_value_set_string_take(result, "pk",
	    fl_value_new_uint8_list(pk, sizeof(pk)));

	return (result);
}

/*
 * Forget about a pending cosk pair, it may already be gone.
 */
static FlValue *
op_cosk_drop(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	FlValue		*args;

	args = fl_method_call_get_args(job->call);

	if (fl_value_get_type(args) != FL_VALUE_TYPE_INT) {
		job_error(job, "invalid", "That is not a cosk handle.");
		return (NULL);
	}

	if (covenant_cosk_drop(ctx, fl_value_get_int(args)) == -1)
		fprintf(stderr, "covenant: no cosk to drop\n");

	return (NULL);
}

/*
 * Provision a device into a QR code, returns its side and modules.
 */
static FlValue *
op_provision(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	struct covenant_device	dev;
	int			side;
	FlValue			*result;
	u_int8_t		*modules;
	int64_t			kek, handle;
	char			flock[FLOCK_HEX_LEN + 1];
	u_int8_t		sealed[COVENANT_KEKS_SEALED_LEN];

	if (arg_keks(job, flock, sizeof(flock), sealed, sizeof(sealed)) == -1)
		return (NULL);

	if (arg_int(job, "kek", 1, COVENANT_KEK_COUNT, &kek) == -1)
		return (NULL);

	if (arg_int(job, "handle", 0, UINT32_MAX, &handle) == -1)
		return (NULL);

	memset(&dev, 0, sizeof(dev));

	if ((dev.config = arg_string(job, "config", 0)) == NULL)
		return (NULL);

	if ((dev.cathedral_secret = arg_string(job, "secret", 0)) == NULL)
		return (NULL);

	dev.secret = vk;
	dev.secret_len = vk_len;

	dev.keks = sealed;
	dev.keks_len = sizeof(sealed);

	dev.kek = kek;
	dev.cosk = handle;

	modules = runner_alloc(COVENANT_QR_MAX_LEN);

	if (covenant_provision(ctx, &dev, modules,
	    COVENANT_QR_MAX_LEN, &side) == -1) {
		runner_free(modules, COVENANT_QR_MAX_LEN);
		job_core_error(job);
		return (NULL);
	}

	result = fl_value_new_map();

	fl_value_set_string_take(result, "side", fl_value_new_int(side));
	fl_value_set_string_take(result, "modules",
	    fl_value_new_uint8_list(modules, (size_t)side * (size_t)side));

	runner_free(modules, COVENANT_QR_MAX_LEN);

	return (result);
}

/*
 * Get the folder rlq keeps its keys in, the default for where we write
 * the keys of a device.
 */
static FlValue *
op_keys_folder(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	char		path[PATH_MAX];

	if (keys_default(path, sizeof(path)) == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	return (fl_value_new_string(path));
}

/*
 * Return the folder the user picked for the keys of a device.
 */
static FlValue *
op_keys_pick(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	return (fl_value_new_string(job->source));
}

/*
 * Check that the folder does not already hold the keys of a device in
 * the flock, before we register a new one.
 */
static FlValue *
op_keys_check(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	char		dir[PATH_MAX];

	if (arg_keys_dir(job, dir, sizeof(dir)) == -1)
		return (NULL);

	if (keys_joined(job, dir) == -1)
		return (NULL);

	return (NULL);
}

/*
 * Provision a device into its keys alone, written into the folder of
 * the flock under the given folder the way rlq lays them out. Returns
 * the folder of the flock.
 */
static FlValue *
op_provision_keys(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	struct covenant_device		dev;
	int				ret;
	struct keys_files		paths;
	struct covenant_device_keys	*keys;
	const char			*device;
	int64_t				kek, handle;
	char				dir[PATH_MAX];
	char				flock[FLOCK_HEX_LEN + 1];
	u_int8_t			sealed[COVENANT_KEKS_SEALED_LEN];

	if (arg_keks(job, flock, sizeof(flock), sealed, sizeof(sealed)) == -1)
		return (NULL);

	if (arg_int(job, "kek", 1, COVENANT_KEK_COUNT, &kek) == -1)
		return (NULL);

	if (arg_int(job, "handle", 0, UINT32_MAX, &handle) == -1)
		return (NULL);

	if ((device = arg_string(job, "device", 0)) == NULL)
		return (NULL);

	if (device_valid(device) == -1) {
		job_error(job, "invalid", "That is not a device ID.");
		return (NULL);
	}

	if (arg_keys_dir(job, dir, sizeof(dir)) == -1)
		return (NULL);

	if (keys_paths(job, &paths, dir, device, (u_int8_t)kek) == -1)
		return (NULL);

	if (keys_absent(job, &paths) == -1)
		return (NULL);

	memset(&dev, 0, sizeof(dev));

	if ((dev.cathedral_secret = arg_string(job, "secret", 0)) == NULL)
		return (NULL);

	if (keys_mkdir(job, dir) == -1)
		return (NULL);

	dev.secret = vk;
	dev.secret_len = vk_len;

	dev.keks = sealed;
	dev.keks_len = sizeof(sealed);

	dev.kek = kek;
	dev.cosk = handle;

	keys = runner_alloc(sizeof(*keys));

	if (covenant_provision_keys(ctx, &dev, keys) == -1) {
		runner_free(keys, sizeof(*keys));
		job_core_error(job);
		return (NULL);
	}

	ret = keys_save(job, &paths, device, (u_int8_t)kek, keys);
	runner_free(keys, sizeof(*keys));

	if (ret == -1)
		return (NULL);

	return (fl_value_new_string(dir));
}

/*
 * Wrap the vault key under the new passphrase, which is wiped as soon
 * as it is done. The old passphrase no longer opens it.
 */
static FlValue *
op_passphrase(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	char		path[PATH_MAX];
	u_int8_t	wrapped[COVENANT_WRAPPED_KEY_LEN];

	PRECOND(job->fresh != NULL);

	covenant_key_wrap(ctx, job->fresh, job->fresh_len,
	    vk, vk_len, wrapped, sizeof(wrapped));

	runner_free(job->fresh, job->fresh_len);

	job->fresh = NULL;
	job->fresh_len = 0;

	if (file_path(path, sizeof(path), NULL, "key") == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if (file_write(path, wrapped, sizeof(wrapped)) == -1) {
		job_error(job, "failed", "Failed to save %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	return (NULL);
}

/*
 * There is no vigil on this computer to hand a device over to.
 */
static FlValue *
op_handoff(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	return (fl_value_new_bool(FALSE));
}

/*
 * Make the words for a remote device.
 */
static FlValue *
op_remote_words(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	u_int64_t		id;
	struct covenant_route	route;
	char			*words;
	FlValue			*result;
	char			flock[FLOCK_HEX_LEN + 1];
	int64_t			identity, cathedral, port, kek, peer;

	if (arg_flock(job, flock, sizeof(flock), &id) == -1)
		return (NULL);

	if (arg_int(job, "identity", 0, UINT32_MAX, &identity) == -1)
		return (NULL);

	if (arg_int(job, "cathedral", 0, UINT32_MAX, &cathedral) == -1)
		return (NULL);

	if (arg_int(job, "port", 1, USHRT_MAX, &port) == -1)
		return (NULL);

	if (arg_int(job, "kek", 1, COVENANT_KEK_COUNT, &kek) == -1)
		return (NULL);

	if (arg_int(job, "peer", 1, COVENANT_KEK_COUNT, &peer) == -1)
		return (NULL);

	memset(&route, 0, sizeof(route));

	route.flock = id;
	route.kek = kek;
	route.peer = peer;
	route.port = port;
	route.identity = identity;
	route.cathedral = cathedral;

	words = runner_alloc(COVENANT_REMOTE_WORDS_LEN);

	if (covenant_remote_words(ctx, &route,
	    words, COVENANT_REMOTE_WORDS_LEN) == -1) {
		runner_free(words, COVENANT_REMOTE_WORDS_LEN);
		job_core_error(job);
		return (NULL);
	}

	result = fl_value_new_string(words);
	runner_free(words, COVENANT_REMOTE_WORDS_LEN);

	return (result);
}

/*
 * Set up the tunnel to the remote device that joined under the given
 * cathedral id. Without a config we only send its KEK.
 */
static FlValue *
op_remote_start(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	struct covenant_remote	rem;
	int64_t			handle, device;
	char			flock[FLOCK_HEX_LEN + 1];
	u_int8_t		sealed[COVENANT_KEKS_SEALED_LEN];

	if (arg_keks(job, flock, sizeof(flock), sealed, sizeof(sealed)) == -1)
		return (NULL);

	if (arg_int(job, "handle", 0, UINT32_MAX, &handle) == -1)
		return (NULL);

	if (arg_int(job, "device", 0, UINT32_MAX, &device) == -1)
		return (NULL);

	memset(&rem, 0, sizeof(rem));

	if ((rem.cathedral_secret = arg_string(job, "secret", 0)) == NULL)
		return (NULL);

	if ((rem.config = arg_string(job, "config", 1)) == NULL) {
		if (job->code != NULL)
			return (NULL);
	}

	rem.secret = vk;
	rem.secret_len = vk_len;

	rem.keks = sealed;
	rem.keks_len = sizeof(sealed);

	rem.cosk = handle;
	rem.device = device;

	if (covenant_remote_start(ctx, &rem) == -1) {
		job_core_error(job);
		return (NULL);
	}

	return (NULL);
}

/*
 * Run the tunnel to the remote device for up to a second, returns its
 * state.
 */
static FlValue *
op_remote_run(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	int		state;

	if ((state = covenant_remote_run(ctx)) == -1) {
		job_core_error(job);
		return (NULL);
	}

	return (fl_value_new_int(state));
}

/*
 * Tear down the tunnel to the remote device.
 */
static FlValue *
op_remote_stop(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	covenant_remote_stop(ctx);

	return (NULL);
}

/*
 * Returns the version of the covenant library.
 */
static FlValue *
op_version(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	return (fl_value_new_string(covenant_version()));
}

/*
 * Import the KEKs ambry made for a flock, the folder is named after the
 * flock and holds them in kek-data/kek-0x01 up to kek-0xff. They get a
 * new signing seed. Returns the flock.
 */
static FlValue *
op_import_ambry(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	u_int64_t	id;
	int		len;
	size_t		idx;
	u_int8_t	*data;
	const char	*flock;
	char		path[PATH_MAX];
	u_int8_t	sealed[COVENANT_KEKS_SEALED_LEN];

	if ((flock = strrchr(job->source, '/')) == NULL) {
		job_error(job, "invalid", "That is not a flock folder.");
		return (NULL);
	}

	flock++;

	if (flock_valid(flock) == -1) {
		job_error(job, "invalid", "Choose the folder named after the "
		    "flock that ambry made, not %s.", flock);
		return (NULL);
	}

	if (flock_has_keks(flock)) {
		job_error(job, "exists",
		    "The KEKs of %s are already on this computer.", flock);
		return (NULL);
	}

	data = runner_alloc(COVENANT_KEKS_DATA_LEN);

	for (idx = 0; idx < COVENANT_KEK_COUNT; idx++) {
		len = snprintf(path, sizeof(path), "%s/kek-data/kek-0x%02zx",
		    job->source, idx + 1);
		if (len < 0 || (size_t)len >= sizeof(path)) {
			job_error(job, "failed", "The path is too long.");
			break;
		}

		if (file_read(path, &data[idx * COVENANT_KEK_LEN],
		    COVENANT_KEK_LEN) == -1) {
			job_error(job, "failed", "Failed to read %s: %s",
			    path, strerror(errno));
			break;
		}
	}

	if (job->code != NULL) {
		runner_free(data, COVENANT_KEKS_DATA_LEN);
		return (NULL);
	}

	errno = 0;
	id = strtoull(flock, NULL, 16);

	if (errno != 0) {
		runner_free(data, COVENANT_KEKS_DATA_LEN);
		job_error(job, "invalid", "That is not a flock ID.");
		return (NULL);
	}

	covenant_keks_import(ctx, vk, vk_len, id, data,
	    COVENANT_KEKS_DATA_LEN, sealed, sizeof(sealed));

	runner_free(data, COVENANT_KEKS_DATA_LEN);

	if (file_path(path, sizeof(path), flock, "keks") == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	if (file_write(path, sealed, sizeof(sealed)) == -1) {
		job_error(job, "failed", "Failed to save %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	return (fl_value_new_string(flock));
}

/*
 * Import the KEKs of a flock from a phone backup, opened with its
 * recovery key. The recovery key is wiped as soon as we are done with
 * it. Returns the flock.
 */
static FlValue *
op_import_backup(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	int				len;
	struct covenant_backup_info	info;
	FlValue				*result;
	u_int8_t			*backup;
	char				path[PATH_MAX];
	char				flock[FLOCK_HEX_LEN + 1];
	u_int8_t			sealed[COVENANT_KEKS_SEALED_LEN];

	PRECOND(job->root != NULL);

	result = NULL;

	if ((backup = malloc(COVENANT_BACKUP_LEN)) == NULL) {
		job_error(job, "failed", "Out of memory.");
		goto cleanup;
	}

	if (file_read(job->source, backup, COVENANT_BACKUP_LEN) == -1) {
		job_error(job, "invalid", "That is not a Covenant backup.");
		goto cleanup;
	}

	if (covenant_backup_info(ctx, backup,
	    COVENANT_BACKUP_LEN, &info) == -1) {
		job_core_error(job);
		goto cleanup;
	}

	len = snprintf(flock, sizeof(flock), "%016llx",
	    (unsigned long long)info.flock);
	if (len < 0 || (size_t)len >= sizeof(flock)) {
		job_error(job, "failed", "Bad flock in the backup.");
		goto cleanup;
	}

	if (flock_has_keks(flock)) {
		job_error(job, "exists",
		    "The KEKs of %s are already on this computer.", flock);
		goto cleanup;
	}

	if (covenant_backup_restore(ctx, vk, vk_len, job->root,
	    COVENANT_BACKUP_ROOT_LEN, backup, COVENANT_BACKUP_LEN,
	    sealed, sizeof(sealed)) == -1) {
		job_core_error(job);
		goto cleanup;
	}

	runner_free(job->root, COVENANT_BACKUP_ROOT_LEN);
	job->root = NULL;

	if (file_path(path, sizeof(path), flock, "keks") == -1) {
		job_error(job, "failed", "Your home is not set.");
		goto cleanup;
	}

	if (file_write(path, sealed, sizeof(sealed)) == -1) {
		job_error(job, "failed", "Failed to save %s: %s",
		    path, strerror(errno));
		goto cleanup;
	}

	result = fl_value_new_string(flock);

cleanup:
	free(backup);

	if (job->root != NULL) {
		runner_free(job->root, COVENANT_BACKUP_ROOT_LEN);
		job->root = NULL;
	}

	return (result);
}

/*
 * Read one of the plain files, returns null when it is not there.
 */
static FlValue *
op_file_read(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	struct stat	st;
	char		*data;
	FlValue		*result;
	char		path[PATH_MAX];

	if (arg_file(job, fl_method_call_get_args(job->call),
	    path, sizeof(path)) == NULL)
		return (NULL);

	if (stat(path, &st) == -1) {
		if (errno == ENOENT)
			return (fl_value_new_null());
		job_error(job, "failed", "Failed to read %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	if (st.st_size == 0)
		return (fl_value_new_string(""));

	if (st.st_size > FILE_MAX_LEN) {
		job_error(job, "failed", "%s is too large", path);
		return (NULL);
	}

	if ((data = calloc(1, (size_t)st.st_size + 1)) == NULL) {
		job_error(job, "failed", "Out of memory.");
		return (NULL);
	}

	if (file_read(path, data, (size_t)st.st_size) == -1) {
		free(data);
		job_error(job, "failed", "Failed to read %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	result = fl_value_new_string(data);
	free(data);

	return (result);
}

/*
 * Write one of the plain files.
 */
static FlValue *
op_file_write(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	size_t		len;
	FlValue		*args;
	const char	*data;
	char		path[PATH_MAX];

	args = fl_method_call_get_args(job->call);

	if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
		job_error(job, "invalid", "Missing name.");
		return (NULL);
	}

	if (arg_file(job, fl_value_lookup_string(args, "name"),
	    path, sizeof(path)) == NULL)
		return (NULL);

	if ((data = arg_string(job, "data", 0)) == NULL)
		return (NULL);

	if ((len = strlen(data)) == 0) {
		job_error(job, "invalid", "Nothing to write to %s.", path);
		return (NULL);
	}

	if (file_write(path, data, len) == -1) {
		job_error(job, "failed", "Failed to save %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	return (NULL);
}

/*
 * Remove one of the plain files, it may already be gone.
 */
static FlValue *
op_file_delete(struct job *job, const u_int8_t *vk, size_t vk_len)
{
	char		path[PATH_MAX];

	if (arg_file(job, fl_method_call_get_args(job->call),
	    path, sizeof(path)) == NULL)
		return (NULL);

	if (file_wipe(path) == -1) {
		job_error(job, "failed", "Failed to remove %s: %s",
		    path, strerror(errno));
		return (NULL);
	}

	return (NULL);
}

/*
 * Check that value names one of the plain files and get its path.
 */
static const char *
arg_file(struct job *job, FlValue *value, char *path, size_t len)
{
	size_t		idx;
	const char	*name;

	PRECOND(job != NULL);
	PRECOND(path != NULL);
	PRECOND(len > 0);

	if (value == NULL) {
		job_error(job, "invalid", "Missing name.");
		return (NULL);
	}

	if (fl_value_get_type(value) != FL_VALUE_TYPE_STRING) {
		job_error(job, "invalid", "Missing name.");
		return (NULL);
	}

	name = fl_value_get_string(value);

	for (idx = 0; files[idx] != NULL; idx++) {
		if (!strcmp(files[idx], name))
			break;
	}

	if (files[idx] == NULL) {
		job_error(job, "invalid", "Unknown file %s.", name);
		return (NULL);
	}

	if (file_path(path, len, NULL, name) == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (NULL);
	}

	return (path);
}

/*
 * Get the flock argument of a call, as hex and as its id.
 */
static int
arg_flock(struct job *job, char *flock, size_t len, u_int64_t *id)
{
	const char	*hex;

	PRECOND(job != NULL);
	PRECOND(flock != NULL);
	PRECOND(len == FLOCK_HEX_LEN + 1);
	PRECOND(id != NULL);

	if ((hex = arg_string(job, "flock", 0)) == NULL)
		return (-1);

	if (flock_valid(hex) == -1) {
		job_error(job, "invalid", "That is not a flock ID.");
		return (-1);
	}

	memcpy(flock, hex, len);

	errno = 0;
	*id = strtoull(flock, NULL, 16);

	if (errno != 0) {
		job_error(job, "invalid", "That is not a flock ID.");
		return (-1);
	}

	return (0);
}

/*
 * Get the flock argument of a call and read its sealed KEKs.
 */
static int
arg_keks(struct job *job, char *flock, size_t len, u_int8_t *sealed,
    size_t sealed_len)
{
	u_int64_t	id;
	char		path[PATH_MAX];

	PRECOND(sealed != NULL);
	PRECOND(sealed_len == COVENANT_KEKS_SEALED_LEN);

	if (arg_flock(job, flock, len, &id) == -1)
		return (-1);

	if (file_path(path, sizeof(path), flock, "keks") == -1) {
		job_error(job, "failed", "Your home is not set.");
		return (-1);
	}

	if (file_read(path, sealed, sealed_len) == -1) {
		job_error(job, "missing",
		    "The KEKs of this flock are not on this computer.");
		return (-1);
	}

	return (0);
}

/*
 * Get the folder argument of a call and the folder of the flock under
 * it into dir, the way rlq lays them out.
 */
static int
arg_keys_dir(struct job *job, char *dir, size_t len)
{
	u_int64_t	id;
	int		ret;
	const char	*folder;
	char		flock[FLOCK_HEX_LEN + 1];

	PRECOND(job != NULL);
	PRECOND(dir != NULL);
	PRECOND(len > 0);

	if (arg_flock(job, flock, sizeof(flock), &id) == -1)
		return (-1);

	if ((folder = arg_string(job, "folder", 0)) == NULL)
		return (-1);

	if (folder[0] != '/') {
		job_error(job, "invalid", "Choose a folder for the keys.");
		return (-1);
	}

	ret = snprintf(dir, len, "%s/%s", folder, flock);
	if (ret < 0 || (size_t)ret >= len) {
		job_error(job, "failed", "The path is too long.");
		return (-1);
	}

	return (0);
}

/*
 * Get an integer argument of a call within min and max.
 */
static int
arg_int(struct job *job, const char *key, int64_t min, int64_t max,
    int64_t *out)
{
	FlValue		*args, *value;

	PRECOND(job != NULL);
	PRECOND(key != NULL);
	PRECOND(out != NULL);

	args = fl_method_call_get_args(job->call);

	if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
		job_error(job, "invalid", "Missing %s.", key);
		return (-1);
	}

	if ((value = fl_value_lookup_string(args, key)) == NULL) {
		job_error(job, "invalid", "Missing %s.", key);
		return (-1);
	}

	if (fl_value_get_type(value) != FL_VALUE_TYPE_INT) {
		job_error(job, "invalid", "Missing %s.", key);
		return (-1);
	}

	*out = fl_value_get_int(value);

	if (*out < min || *out > max) {
		job_error(job, "invalid", "Bad %s.", key);
		return (-1);
	}

	return (0);
}

/*
 * Get a string argument of a call. When optional is set a missing or
 * null argument returns NULL without failing the call.
 */
static const char *
arg_string(struct job *job, const char *key, int optional)
{
	FlValue		*args, *value;

	PRECOND(job != NULL);
	PRECOND(key != NULL);

	args = fl_method_call_get_args(job->call);

	if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
		job_error(job, "invalid", "Missing %s.", key);
		return (NULL);
	}

	value = fl_value_lookup_string(args, key);

	if (value == NULL) {
		if (!optional)
			job_error(job, "invalid", "Missing %s.", key);
		return (NULL);
	}

	if (fl_value_get_type(value) == FL_VALUE_TYPE_NULL) {
		if (!optional)
			job_error(job, "invalid", "Missing %s.", key);
		return (NULL);
	}

	if (fl_value_get_type(value) != FL_VALUE_TYPE_STRING) {
		job_error(job, "invalid", "Missing %s.", key);
		return (NULL);
	}

	return (fl_value_get_string(value));
}

/*
 * Get the directory we keep everything in, $COVENANT when it is set
 * and $HOME/.config/covenant when it is not. We make it when needed.
 */
static int
dir_path(char *path, size_t len)
{
	int		ret;
	const char	*env, *home;

	PRECOND(path != NULL);
	PRECOND(len > 0);

	if ((env = getenv("COVENANT")) != NULL) {
		ret = snprintf(path, len, "%s", env);
	} else {
		if ((home = getenv("HOME")) == NULL)
			return (-1);

		ret = snprintf(path, len, "%s/.config", home);
		if (ret < 0 || (size_t)ret >= len)
			return (-1);

		if (mkdir(path, 0755) == -1 && errno != EEXIST)
			return (-1);

		ret = snprintf(path, len, "%s/.config/covenant", home);
	}

	if (ret < 0 || (size_t)ret >= len)
		return (-1);

	if (mkdir(path, 0700) == -1 && errno != EEXIST)
		return (-1);

	return (0);
}

/*
 * Get the path of a file in our directory, or in the directory of the
 * given flock. Without a name we get the directory of the flock, which
 * we make when needed.
 */
static int
file_path(char *path, size_t len, const char *flock, const char *name)
{
	int		ret;
	char		dir[PATH_MAX];

	PRECOND(path != NULL);
	PRECOND(len > 0);

	if (dir_path(dir, sizeof(dir)) == -1)
		return (-1);

	if (flock == NULL) {
		ret = snprintf(path, len, "%s/%s", dir, name);
		if (ret < 0 || (size_t)ret >= len)
			return (-1);
		return (0);
	}

	ret = snprintf(path, len, "%s/%s", dir, flock);
	if (ret < 0 || (size_t)ret >= len)
		return (-1);

	if (name == NULL)
		return (0);

	if (mkdir(path, 0700) == -1 && errno != EEXIST)
		return (-1);

	ret = snprintf(path, len, "%s/%s/%s", dir, flock, name);
	if (ret < 0 || (size_t)ret >= len)
		return (-1);

	return (0);
}

/*
 * Get the next flock directory, skipping anything else in there.
 */
static int
dir_flock_next(DIR *dir, char *flock, size_t len)
{
	struct dirent	*dp;

	PRECOND(dir != NULL);
	PRECOND(flock != NULL);
	PRECOND(len == FLOCK_HEX_LEN + 1);

	while ((dp = readdir(dir)) != NULL) {
		if (flock_valid(dp->d_name) == -1)
			continue;

		memcpy(flock, dp->d_name, len);
		return (0);
	}

	return (-1);
}

/*
 * Check that a flock is 16 lowercase hex characters, as we name them.
 */
static int
flock_valid(const char *flock)
{
	PRECOND(flock != NULL);

	if (strlen(flock) != FLOCK_HEX_LEN)
		return (-1);

	if (strspn(flock, "0123456789abcdef") != FLOCK_HEX_LEN)
		return (-1);

	return (0);
}

/*
 * Get the folder rlq keeps everything in, $RELIQUARY when it is set
 * and $HOME/.config/reliquary when it is not.
 */
static int
keys_default(char *path, size_t len)
{
	int		ret;
	const char	*env, *home;

	PRECOND(path != NULL);
	PRECOND(len > 0);

	if ((env = getenv("RELIQUARY")) != NULL) {
		ret = snprintf(path, len, "%s", env);
	} else {
		if ((home = getenv("HOME")) == NULL)
			return (-1);

		ret = snprintf(path, len, "%s/.config/reliquary", home);
	}

	if (ret < 0 || (size_t)ret >= len)
		return (-1);

	return (0);
}

/*
 * Make sure dir does not hold the keys of a device yet, rlq refuses to
 * join a flock again for the same reason.
 */
static int
keys_joined(struct job *job, const char *dir)
{
	struct stat	st;
	int		ret;
	char		path[PATH_MAX];

	PRECOND(job != NULL);
	PRECOND(dir != NULL);

	ret = snprintf(path, sizeof(path), "%s/cathedral_id", dir);
	if (ret < 0 || (size_t)ret >= sizeof(path)) {
		job_error(job, "failed", "The path is too long.");
		return (-1);
	}

	if (stat(path, &st) == -1) {
		if (errno == ENOENT)
			return (0);

		job_error(job, "failed", "Failed to check %s: %s",
		    path, strerror(errno));
		return (-1);
	}

	job_error(job, "exists",
	    "%s already holds the keys of a device in this flock.", dir);

	return (-1);
}

/*
 * Make the folder of the flock and the folder it sits in when needed.
 */
static int
keys_mkdir(struct job *job, const char *dir)
{
	char		*sep;
	char		parent[PATH_MAX];

	PRECOND(job != NULL);
	PRECOND(dir != NULL);

	if (strlen(dir) >= sizeof(parent)) {
		job_error(job, "failed", "The path is too long.");
		return (-1);
	}

	memcpy(parent, dir, strlen(dir) + 1);

	if ((sep = strrchr(parent, '/')) == NULL) {
		job_error(job, "invalid", "Choose a folder for the keys.");
		return (-1);
	}

	*sep = '\0';

	if (parent[0] != '\0') {
		if (mkdir(parent, 0700) == -1 && errno != EEXIST) {
			job_error(job, "failed", "Failed to make %s: %s",
			    parent, strerror(errno));
			return (-1);
		}
	}

	if (mkdir(dir, 0700) == -1 && errno != EEXIST) {
		job_error(job, "failed", "Failed to make %s: %s",
		    dir, strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Get the paths of all files rlq keeps for the device in dir.
 */
static int
keys_paths(struct job *job, struct keys_files *paths, const char *dir,
    const char *device, u_int8_t kek)
{
	PRECOND(job != NULL);
	PRECOND(paths != NULL);
	PRECOND(dir != NULL);
	PRECOND(device != NULL);
	PRECOND(kek != 0);

	if (keys_path(job, paths, KEYS_ID, "%s/id-%s", dir, device) == -1)
		return (-1);

	if (keys_path(job, paths, KEYS_COSK, "%s/cosk-%s", dir, device) == -1)
		return (-1);

	if (keys_path(job, paths, KEYS_COSK_PUB,
	    "%s/cosk-pub-%s", dir, device) == -1)
		return (-1);

	if (keys_path(job, paths, KEYS_KEK, "%s/kek-0x%02x", dir, kek) == -1)
		return (-1);

	if (keys_path(job, paths, KEYS_CATHEDRAL_ID,
	    "%s/cathedral_id", dir) == -1)
		return (-1);

	if (keys_path(job, paths, KEYS_DEVICE_KEK,
	    "%s/device_kek", dir) == -1)
		return (-1);

	return (0);
}

/*
 * Put the path that fmt makes into the given slot of paths.
 */
static int
keys_path(struct job *job, struct keys_files *paths, int which,
    const char *fmt, ...)
{
	int		ret;
	va_list		args;

	PRECOND(job != NULL);
	PRECOND(paths != NULL);
	PRECOND(which >= 0);
	PRECOND(which < KEYS_MAX);
	PRECOND(fmt != NULL);

	va_start(args, fmt);
	ret = vsnprintf(paths->path[which], sizeof(paths->path[which]),
	    fmt, args);
	va_end(args);

	if (ret < 0 || (size_t)ret >= sizeof(paths->path[which])) {
		job_error(job, "failed", "The path is too long.");
		return (-1);
	}

	return (0);
}

/*
 * Make sure none of the files we are about to write exist yet, we never
 * write over keys that are already there.
 */
static int
keys_absent(struct job *job, const struct keys_files *paths)
{
	struct stat	st;
	int		idx;

	PRECOND(job != NULL);
	PRECOND(paths != NULL);

	for (idx = 0; idx < KEYS_MAX; idx++) {
		if (lstat(paths->path[idx], &st) == -1) {
			if (errno == ENOENT)
				continue;

			job_error(job, "failed", "Failed to check %s: %s",
			    paths->path[idx], strerror(errno));
			return (-1);
		}

		job_error(job, "exists",
		    "%s is already there, nothing was written over it.",
		    paths->path[idx]);
		return (-1);
	}

	return (0);
}

/*
 * Write the keys of the device into the files rlq keeps for it, in
 * the order of their slots. When one of them fails we wipe the ones
 * we already wrote, files that were there before are never touched.
 */
static int
keys_save(struct job *job, const struct keys_files *paths, const char *device,
    u_int8_t kek, const struct covenant_device_keys *keys)
{
	int		len, written;
	char		id[16], slot[16];

	PRECOND(job != NULL);
	PRECOND(paths != NULL);
	PRECOND(device != NULL);
	PRECOND(kek != 0);
	PRECOND(keys != NULL);

	len = snprintf(id, sizeof(id), "%s\n", device);
	if (len < 0 || (size_t)len >= sizeof(id)) {
		job_error(job, "invalid", "That is not a device ID.");
		return (-1);
	}

	len = snprintf(slot, sizeof(slot), "%02x\n", kek);
	if (len < 0 || (size_t)len >= sizeof(slot)) {
		job_error(job, "invalid", "That is not a KEK ID.");
		return (-1);
	}

	written = 0;

	if (keys_write(job, paths->path[KEYS_ID],
	    keys->secret, sizeof(keys->secret)) == -1)
		goto cleanup;
	written++;

	if (keys_write(job, paths->path[KEYS_COSK],
	    keys->cosk, sizeof(keys->cosk)) == -1)
		goto cleanup;
	written++;

	if (keys_write(job, paths->path[KEYS_COSK_PUB],
	    keys->cosk_pub, sizeof(keys->cosk_pub)) == -1)
		goto cleanup;
	written++;

	if (keys_write(job, paths->path[KEYS_KEK],
	    keys->kek, sizeof(keys->kek)) == -1)
		goto cleanup;
	written++;

	if (keys_write(job, paths->path[KEYS_CATHEDRAL_ID],
	    id, strlen(id)) == -1)
		goto cleanup;
	written++;

	if (keys_write(job, paths->path[KEYS_DEVICE_KEK],
	    slot, strlen(slot)) == -1)
		goto cleanup;

	return (0);

cleanup:
	while (written-- > 0) {
		if (file_wipe(paths->path[written]) == -1) {
			fprintf(stderr, "covenant: failed to wipe %s: %s\n",
			    paths->path[written], strerror(errno));
		}
	}

	return (-1);
}

/*
 * Write len bytes from buf into the file at path.
 */
static int
keys_write(struct job *job, const char *path, const void *buf, size_t len)
{
	PRECOND(job != NULL);
	PRECOND(path != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	if (file_write(path, buf, len) == -1) {
		job_error(job, "failed", "Failed to save %s: %s",
		    path, strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Check that a device is 8 lowercase hex characters, as the reliquary
 * hands them out.
 */
static int
device_valid(const char *device)
{
	PRECOND(device != NULL);

	if (strlen(device) != DEVICE_HEX_LEN)
		return (-1);

	if (strspn(device, "0123456789abcdef") != DEVICE_HEX_LEN)
		return (-1);

	return (0);
}

/*
 * Check if the KEKs of the given flock are already here.
 */
static int
flock_has_keks(const char *flock)
{
	struct stat	st;
	int		len;
	char		dir[PATH_MAX], path[PATH_MAX];

	PRECOND(flock != NULL);

	if (file_path(dir, sizeof(dir), flock, NULL) == -1)
		return (0);

	len = snprintf(path, sizeof(path), "%s/keks", dir);
	if (len < 0 || (size_t)len >= sizeof(path))
		return (0);

	if (stat(path, &st) == -1)
		return (0);

	return (1);
}

/*
 * Read exactly len bytes from the file at path.
 */
static int
file_read(const char *path, void *buf, size_t len)
{
	struct stat	st;
	ssize_t		ret;
	int		fd, saved;

	PRECOND(path != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) == -1)
		return (-1);

	if (fstat(fd, &st) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}

	if (st.st_size != (off_t)len) {
		(void)close(fd);
		errno = EINVAL;
		return (-1);
	}

	for (;;) {
		if ((ret = read(fd, buf, len)) == -1) {
			if (errno == EINTR)
				continue;
			saved = errno;
			(void)close(fd);
			errno = saved;
			return (-1);
		}
		break;
	}

	(void)close(fd);

	if ((size_t)ret != len) {
		errno = EIO;
		return (-1);
	}

	return (0);
}

/*
 * Write the file at path in one go, via a temporary file that is
 * synced and then renamed over it. When that fails the temporary file
 * is wiped, it may hold part of a key.
 */
static int
file_write(const char *path, const void *buf, size_t len)
{
	char		tmp[PATH_MAX];
	int		fd, ret, saved;

	PRECOND(path != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	ret = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	if (ret < 0 || (size_t)ret >= sizeof(tmp)) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	if ((fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY | O_NOFOLLOW,
	    0600)) == -1)
		return (-1);

	if (file_write_all(fd, buf, len) == -1) {
		saved = errno;
		(void)close(fd);
		file_discard(tmp);
		errno = saved;
		return (-1);
	}

	if (fsync(fd) == -1) {
		saved = errno;
		(void)close(fd);
		file_discard(tmp);
		errno = saved;
		return (-1);
	}

	if (close(fd) == -1) {
		saved = errno;
		file_discard(tmp);
		errno = saved;
		return (-1);
	}

	if (rename(tmp, path) == -1) {
		saved = errno;
		file_discard(tmp);
		errno = saved;
		return (-1);
	}

	return (0);
}

/*
 * Get rid of a temporary file that may hold part of a key, wipe it and
 * remove it anyway when the wipe fails.
 */
static void
file_discard(const char *path)
{
	PRECOND(path != NULL);

	if (file_wipe(path) == -1) {
		fprintf(stderr, "covenant: failed to wipe %s: %s\n",
		    path, strerror(errno));
		(void)unlink(path);
	}
}

/*
 * Write all of buf to fd.
 */
static int
file_write_all(int fd, const void *buf, size_t len)
{
	ssize_t		ret;
	size_t		off;
	const u_int8_t	*ptr;

	PRECOND(buf != NULL);

	ptr = buf;
	off = 0;

	while (off < len) {
		if ((ret = write(fd, &ptr[off], len - off)) == -1) {
			if (errno == EINTR)
				continue;
			return (-1);
		}

		off += (size_t)ret;
	}

	return (0);
}

/*
 * Overwrite the file at path with zeroes and remove it. A file that is
 * not there is fine.
 */
static int
file_wipe(const char *path)
{
	struct stat	st;
	off_t		off;
	size_t		len;
	int		fd, saved;
	u_int8_t	zero[4096];

	PRECOND(path != NULL);

	if ((fd = open(path, O_WRONLY | O_NOFOLLOW)) == -1) {
		if (errno == ENOENT)
			return (0);
		return (-1);
	}

	if (fstat(fd, &st) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}

	memset(zero, 0, sizeof(zero));

	for (off = 0; off < st.st_size; off += (off_t)len) {
		len = sizeof(zero);
		if (st.st_size - off < (off_t)len)
			len = (size_t)(st.st_size - off);

		if (file_write_all(fd, zero, len) == -1) {
			saved = errno;
			(void)close(fd);
			errno = saved;
			return (-1);
		}
	}

	if (fsync(fd) == -1) {
		saved = errno;
		(void)close(fd);
		errno = saved;
		return (-1);
	}

	(void)close(fd);

	if (unlink(path) == -1)
		return (-1);

	return (0);
}

/*
 * Allocate memory for something secret, it is locked into memory and
 * registered so it is wiped if we die.
 */
void *
runner_alloc(size_t len)
{
	void		*ptr;

	PRECOND(len > 0);

	covenant_lock();
	ptr = covenant_alloc(len);
	covenant_unlock();

	return (ptr);
}

/*
 * Zeroize and release memory from runner_alloc().
 */
void
runner_free(void *ptr, size_t len)
{
	PRECOND(ptr != NULL);
	PRECOND(len > 0);

	covenant_lock();
	covenant_free(ptr, len);
	covenant_unlock();
}

/*
 * The covenant library hit something it cannot go on from.
 */
static void
channel_fatal(const char *fmt, va_list args)
{
	fprintf(stderr, "covenant: ");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");

	abort();
}
