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

#include <android/log.h>

#include <jni.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "covenant-int.h"

/* Useful macro cause java names are fucking long. */
#define JNI(name)	Java_se_sanctorum_reliquary_Core_##name

/* Convert jlong into a correct COVENANT pointer. */
#define covenant_ctx(x)	((COVENANT *)(uintptr_t)x)

/*
 * A copy of a Java byte array in memory from covenant_alloc().
 */
struct jni_bytes {
	u_int8_t	*data;
	size_t		length;
};

/* Prototypes to keep -Wmissing-prototypes happy, JNI finds them by name. */
JNIEXPORT jlong JNICALL		JNI(ctxAlloc)(JNIEnv *, jclass);
JNIEXPORT jstring JNICALL	JNI(coreVersion)(JNIEnv *, jclass);
JNIEXPORT void JNICALL		JNI(ctxFree)(JNIEnv *, jclass, jlong);
JNIEXPORT jbyteArray JNICALL	JNI(coskNew)(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL		JNI(lastError)(JNIEnv *, jclass, jlong);
JNIEXPORT jint JNICALL		JNI(remoteRun)(JNIEnv *, jclass, jlong);
JNIEXPORT void JNICALL		JNI(remoteStop)(JNIEnv *, jclass, jlong);
JNIEXPORT jboolean JNICALL	JNI(coskDrop)(JNIEnv *, jclass, jlong, jint);
JNIEXPORT jlongArray JNICALL	JNI(keksInfo)(JNIEnv *, jclass,
				    jlong, jbyteArray);
JNIEXPORT jboolean JNICALL	JNI(keksCheck)(JNIEnv *, jclass,
				    jlong, jbyteArray, jbyteArray);
JNIEXPORT jbyteArray JNICALL	JNI(keksGenerate)(JNIEnv *, jclass,
				    jlong, jbyteArray, jlong);
JNIEXPORT jbyteArray JNICALL	JNI(keksRenew)(JNIEnv *, jclass,
				    jlong, jbyteArray, jbyteArray, jint);
JNIEXPORT jbyteArray JNICALL	JNI(ambryBundle)(JNIEnv *, jclass, jlong,
				    jbyteArray, jbyteArray, jint, jintArray);
JNIEXPORT jbyteArray JNICALL	JNI(provision)(JNIEnv *, jclass, jlong,
				    jbyteArray, jbyteArray, jint, jint,
				    jstring, jstring);
JNIEXPORT jbyteArray JNICALL	JNI(provisionConfig)(JNIEnv *, jclass, jlong,
				    jbyteArray, jbyteArray, jint, jint,
				    jstring, jstring);
JNIEXPORT jlongArray JNICALL	JNI(backupInfo)(JNIEnv *, jclass,
				    jlong, jbyteArray);
JNIEXPORT jboolean JNICALL	JNI(backupVerify)(JNIEnv *, jclass,
				    jlong, jbyteArray, jbyteArray);
JNIEXPORT jbyteArray JNICALL	JNI(backupKeygen)(JNIEnv *, jclass,
				    jlong, jbyteArray);
JNIEXPORT jbyteArray JNICALL	JNI(backupRecipient)(JNIEnv *, jclass,
				    jlong, jbyteArray, jbyteArray);
JNIEXPORT jbyteArray JNICALL	JNI(backupSeal)(JNIEnv *, jclass, jlong,
				    jbyteArray, jbyteArray, jbyteArray);
JNIEXPORT jbyteArray JNICALL	JNI(backupRestore)(JNIEnv *, jclass, jlong,
				    jbyteArray, jbyteArray, jbyteArray);
JNIEXPORT jbyteArray JNICALL	JNI(remoteWords)(JNIEnv *, jclass, jlong,
				    jlong, jint, jint, jint, jint, jint);
JNIEXPORT jboolean JNICALL	JNI(remoteStart)(JNIEnv *, jclass, jlong,
				    jbyteArray, jbyteArray, jstring, jstring,
				    jint, jint);

static void		jni_fatal(const char *, va_list);
static void		jni_bytes_free(struct jni_bytes *);
static jbyteArray	jni_array_create(JNIEnv *, const u_int8_t *, size_t);
static int		jni_bytes_copy(JNIEnv *, jbyteArray,
			    struct jni_bytes *);
static int		jni_bytes_copy_exact(JNIEnv *, jlong, jbyteArray,
			    size_t, struct jni_bytes *);
static jbyteArray	jni_device_provision(JNIEnv *, jlong, jbyteArray,
			    jbyteArray, jint, jint, jstring, jstring, int);

/*
 * Returns the version of the C library.
 */
JNIEXPORT jstring JNICALL
JNI(coreVersion)(JNIEnv *env, jclass cls)
{
	PRECOND(env != NULL);

	(void)cls;

	return ((*env)->NewStringUTF(env, covenant_version()));
}

/*
 * Allocate the context the Kotlin side keeps for us.
 */
JNIEXPORT jlong JNICALL
JNI(ctxAlloc)(JNIEnv *env, jclass cls)
{
	(void)env;
	(void)cls;

	covenant_fatal_callback(jni_fatal);

	return ((jlong)(uintptr_t)covenant_ctx_alloc());
}

/*
 * Free the context, forgetting about any pending cosk pairs.
 */
JNIEXPORT void JNICALL
JNI(ctxFree)(JNIEnv *env, jclass cls, jlong ctx)
{
	(void)env;
	(void)cls;

	covenant_ctx_free(covenant_ctx(ctx));
}

/*
 * Returns the last error that occurred on the context.
 */
JNIEXPORT jint JNICALL
JNI(lastError)(JNIEnv *env, jclass cls, jlong ctx)
{
	(void)env;
	(void)cls;

	return ((jint)covenant_last_error(covenant_ctx(ctx)));
}

/*
 * Make a new cosk pair, returns the handle (4 bytes, big endian)
 * followed by the public key.
 */
JNIEXPORT jbyteArray JNICALL
JNI(coskNew)(JNIEnv *env, jclass cls, jlong ctx)
{
	COVENANT	*cov;
	u_int32_t	handle;
	u_int8_t	out[sizeof(handle) + COVENANT_COSK_PUBLIC_LEN];

	PRECOND(env != NULL);

	(void)cls;

	cov = covenant_ctx(ctx);

	if (covenant_cosk_new(cov, &handle,
	    &out[sizeof(handle)], COVENANT_COSK_PUBLIC_LEN) == -1)
		return (NULL);

	handle = htobe32(handle);
	memcpy(out, &handle, sizeof(handle));

	return (jni_array_create(env, out, sizeof(out)));
}

/*
 * Forget about a pending cosk pair.
 */
JNIEXPORT jboolean JNICALL
JNI(coskDrop)(JNIEnv *env, jclass cls, jlong ctx, jint handle)
{
	COVENANT	*cov;

	(void)env;
	(void)cls;

	cov = covenant_ctx(ctx);

	if (covenant_cosk_drop(cov, handle) == -1)
		return (JNI_FALSE);

	return (JNI_TRUE);
}

/*
 * Returns the flock and the creation time of sealed KEKs.
 */
JNIEXPORT jlongArray JNICALL
JNI(keksInfo)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray in)
{
	jlongArray		out;
	COVENANT		*cov;
	struct covenant_info	info;
	struct jni_bytes	sealed;
	jlong			values[2];

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (jni_bytes_copy(env, in, &sealed) == -1)
		return (NULL);

	if (covenant_keks_info(cov, sealed.data, sealed.length, &info) == -1) {
		jni_bytes_free(&sealed);
		return (NULL);
	}

	jni_bytes_free(&sealed);

	values[0] = (jlong)info.flock;
	values[1] = (jlong)info.created;

	if ((out = (*env)->NewLongArray(env, 2)) == NULL)
		return (NULL);

	(*env)->SetLongArrayRegion(env, out, 0, 2, values);

	return (out);
}

/*
 * Check that the vault key opens the sealed KEKs.
 */
JNIEXPORT jboolean JNICALL
JNI(keksCheck)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray in)
{
	int			ret;
	COVENANT		*cov;
	struct jni_bytes	key, sealed;

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (JNI_FALSE);

	if (jni_bytes_copy_exact(env, ctx, secret,
	    COVENANT_VAULT_KEY_LEN, &key) == -1)
		return (JNI_FALSE);

	if (jni_bytes_copy_exact(env, ctx, in,
	    COVENANT_KEKS_SEALED_LEN, &sealed) == -1) {
		jni_bytes_free(&key);
		return (JNI_FALSE);
	}

	ret = covenant_keks_check(cov,
	    key.data, key.length, sealed.data, sealed.length);

	jni_bytes_free(&key);
	jni_bytes_free(&sealed);

	return (ret == 0);
}

/*
 * Generate the KEKs of a flock, returns them sealed.
 */
JNIEXPORT jbyteArray JNICALL
JNI(keksGenerate)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jlong flock)
{
	jbyteArray		out;
	struct jni_bytes	key;
	COVENANT		*cov;
	u_int8_t		sealed[COVENANT_KEKS_SEALED_LEN];

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, secret,
	    COVENANT_VAULT_KEY_LEN, &key) == -1)
		return (NULL);

	out = NULL;

	covenant_keks_generate(cov, key.data, key.length,
	    flock, sealed, sizeof(sealed));
	out = jni_array_create(env, sealed, sizeof(sealed));

	jni_bytes_free(&key);

	return (out);
}

/*
 * Renew a single KEK, returns all KEKs sealed again.
 */
JNIEXPORT jbyteArray JNICALL
JNI(keksRenew)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray in, jint kek)
{
	jbyteArray		out;
	COVENANT		*cov;
	struct jni_bytes	key, sealed;
	u_int8_t		renewed[COVENANT_KEKS_SEALED_LEN];

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (kek < 1 || kek > COVENANT_KEK_COUNT) {
		cov->last_error = COVENANT_ERROR_PARAMETER;
		return (NULL);
	}

	if (jni_bytes_copy_exact(env, ctx, secret,
	    COVENANT_VAULT_KEY_LEN, &key) == -1)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, in,
	    COVENANT_KEKS_SEALED_LEN, &sealed) == -1) {
		jni_bytes_free(&key);
		return (NULL);
	}

	out = NULL;

	if (covenant_keks_renew(cov, key.data, key.length,
	    sealed.data, sealed.length, kek, renewed, sizeof(renewed)) == 0)
		out = jni_array_create(env, renewed, sizeof(renewed));

	jni_bytes_free(&key);
	jni_bytes_free(&sealed);

	return (out);
}

/*
 * Make an ambry bundle, meta gets the generation and the expiry day.
 */
JNIEXPORT jbyteArray JNICALL
JNI(ambryBundle)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray in, jint days, jintArray meta)
{
	u_int32_t		gen;
	jbyteArray		out;
	COVENANT		*cov;
	u_int16_t		expires;
	u_int8_t		*bundle;
	jint			values[2];
	struct jni_bytes	key, sealed;

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (days < 1 || days > COVENANT_AMBRY_DAYS_MAX || meta == NULL ||
	    (*env)->GetArrayLength(env, meta) != 2) {
		cov->last_error = COVENANT_ERROR_PARAMETER;
		return (NULL);
	}

	if ((bundle = malloc(COVENANT_AMBRY_LEN)) == NULL) {
		cov->last_error = COVENANT_ERROR_SYSTEM;
		return (NULL);
	}

	if (jni_bytes_copy_exact(env, ctx, secret,
	    COVENANT_VAULT_KEY_LEN, &key) == -1) {
		free(bundle);
		return (NULL);
	}

	if (jni_bytes_copy_exact(env, ctx, in,
	    COVENANT_KEKS_SEALED_LEN, &sealed) == -1) {
		jni_bytes_free(&key);
		free(bundle);
		return (NULL);
	}

	out = NULL;

	if (covenant_ambry_bundle(cov, key.data, key.length,
	    sealed.data, sealed.length, days, bundle, COVENANT_AMBRY_LEN,
	    &gen, &expires) == 0) {
		values[0] = (jint)gen;
		values[1] = (jint)expires;
		(*env)->SetIntArrayRegion(env, meta, 0, 2, values);
		out = jni_array_create(env, bundle, COVENANT_AMBRY_LEN);
	}

	jni_bytes_free(&key);
	jni_bytes_free(&sealed);
	free(bundle);

	return (out);
}

/*
 * Provision a device, returns the QR modules (side * side bytes).
 */
JNIEXPORT jbyteArray JNICALL
JNI(provision)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray in, jint kek, jint handle, jstring cathedral, jstring config)
{
	PRECOND(env != NULL);

	(void)cls;

	return (jni_device_provision(env, ctx, secret, in, kek, handle,
	    cathedral, config, 1));
}

/*
 * Provision a device for vigil on this phone, returns its configuration
 * (without the NUL) so the platform can hand it over without a QR code.
 */
JNIEXPORT jbyteArray JNICALL
JNI(provisionConfig)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray in, jint kek, jint handle, jstring cathedral, jstring config)
{
	PRECOND(env != NULL);

	(void)cls;

	return (jni_device_provision(env, ctx, secret, in, kek, handle,
	    cathedral, config, 0));
}

/*
 * Returns the flock of a backup, when it was made and when its KEKs
 * were created.
 */
JNIEXPORT jlongArray JNICALL
JNI(backupInfo)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray in)
{
	jlongArray			out;
	struct covenant_backup_info	info;
	COVENANT			*cov;
	struct jni_bytes		backup;
	jlong				values[3];

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (jni_bytes_copy(env, in, &backup) == -1)
		return (NULL);

	if (covenant_backup_info(cov,
	    backup.data, backup.length, &info) == -1) {
		jni_bytes_free(&backup);
		return (NULL);
	}

	jni_bytes_free(&backup);

	values[0] = (jlong)info.flock;
	values[1] = (jlong)info.made;
	values[2] = (jlong)info.created;

	if ((out = (*env)->NewLongArray(env, 3)) == NULL)
		return (NULL);

	(*env)->SetLongArrayRegion(env, out, 0, 3, values);

	return (out);
}

/*
 * Check that the recovery key belongs to the recipient.
 */
JNIEXPORT jboolean JNICALL
JNI(backupVerify)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray root,
    jbyteArray recipient)
{
	int			ret;
	COVENANT		*cov;
	struct jni_bytes	key, rcpt;

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (JNI_FALSE);

	if (jni_bytes_copy_exact(env, ctx, root,
	    COVENANT_BACKUP_ROOT_LEN, &key) == -1)
		return (JNI_FALSE);

	if (jni_bytes_copy_exact(env, ctx, recipient,
	    COVENANT_BACKUP_RECIPIENT_LEN, &rcpt) == -1) {
		jni_bytes_free(&key);
		return (JNI_FALSE);
	}

	ret = covenant_backup_verify(cov,
	    key.data, key.length, rcpt.data, rcpt.length);

	jni_bytes_free(&key);
	jni_bytes_free(&rcpt);

	return (ret == 0);
}

/*
 * Make a new recovery key, returns it followed by its recipient.
 */
JNIEXPORT jbyteArray JNICALL
JNI(backupKeygen)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret)
{
	jbyteArray		out;
	struct jni_bytes	key;
	size_t			len;
	COVENANT		*cov;
	u_int8_t		*both;

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, secret,
	    COVENANT_VAULT_KEY_LEN, &key) == -1)
		return (NULL);

	len = COVENANT_BACKUP_ROOT_LEN + COVENANT_BACKUP_RECIPIENT_LEN;

	covenant_lock();
	both = covenant_alloc(len);
	covenant_unlock();

	covenant_backup_keygen(cov, key.data, key.length,
	    both, COVENANT_BACKUP_ROOT_LEN, both + COVENANT_BACKUP_ROOT_LEN,
	    COVENANT_BACKUP_RECIPIENT_LEN);

	out = jni_array_create(env, both, len);

	covenant_lock();
	covenant_free(both, len);
	covenant_unlock();

	jni_bytes_free(&key);

	return (out);
}

/*
 * Make the recipient for a recovery key.
 */
JNIEXPORT jbyteArray JNICALL
JNI(backupRecipient)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray root)
{
	jbyteArray		out;
	COVENANT		*cov;
	struct jni_bytes	key, rk;
	u_int8_t		rcpt[COVENANT_BACKUP_RECIPIENT_LEN];

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, secret,
	    COVENANT_VAULT_KEY_LEN, &key) == -1)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, root,
	    COVENANT_BACKUP_ROOT_LEN, &rk) == -1) {
		jni_bytes_free(&key);
		return (NULL);
	}

	covenant_backup_recipient(cov, key.data, key.length,
	    rk.data, rk.length, rcpt, sizeof(rcpt));

	out = jni_array_create(env, rcpt, sizeof(rcpt));

	jni_bytes_free(&key);
	jni_bytes_free(&rk);

	return (out);
}

/*
 * Back up the sealed KEKs to the recipient.
 */
JNIEXPORT jbyteArray JNICALL
JNI(backupSeal)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray recipient, jbyteArray in)
{
	jbyteArray		out;
	COVENANT		*cov;
	u_int8_t		*backup;
	struct jni_bytes	key, rcpt, sealed;

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, secret,
	    COVENANT_VAULT_KEY_LEN, &key) == -1)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, recipient,
	    COVENANT_BACKUP_RECIPIENT_LEN, &rcpt) == -1) {
		jni_bytes_free(&key);
		return (NULL);
	}

	if (jni_bytes_copy_exact(env, ctx, in,
	    COVENANT_KEKS_SEALED_LEN, &sealed) == -1) {
		jni_bytes_free(&key);
		jni_bytes_free(&rcpt);
		return (NULL);
	}

	if ((backup = malloc(COVENANT_BACKUP_LEN)) == NULL) {
		cov->last_error = COVENANT_ERROR_SYSTEM;
		jni_bytes_free(&key);
		jni_bytes_free(&rcpt);
		jni_bytes_free(&sealed);
		return (NULL);
	}

	out = NULL;

	if (covenant_backup_seal(cov, key.data, key.length,
	    rcpt.data, rcpt.length, sealed.data, sealed.length,
	    backup, COVENANT_BACKUP_LEN) == 0)
		out = jni_array_create(env, backup, COVENANT_BACKUP_LEN);

	jni_bytes_free(&key);
	jni_bytes_free(&rcpt);
	jni_bytes_free(&sealed);
	free(backup);

	return (out);
}

/*
 * Restore a backup, returns its KEKs sealed under the vault key.
 */
JNIEXPORT jbyteArray JNICALL
JNI(backupRestore)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray root, jbyteArray in)
{
	jbyteArray		out;
	COVENANT		*cov;
	struct jni_bytes	key, rk, backup;
	u_int8_t		sealed[COVENANT_KEKS_SEALED_LEN];

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, secret,
	    COVENANT_VAULT_KEY_LEN, &key) == -1)
		return (NULL);

	if (jni_bytes_copy_exact(env, ctx, root,
	    COVENANT_BACKUP_ROOT_LEN, &rk) == -1) {
		jni_bytes_free(&key);
		return (NULL);
	}

	if (jni_bytes_copy_exact(env, ctx, in,
	    COVENANT_BACKUP_LEN, &backup) == -1) {
		jni_bytes_free(&key);
		jni_bytes_free(&rk);
		return (NULL);
	}

	out = NULL;

	if (covenant_backup_restore(cov, key.data, key.length,
	    rk.data, rk.length, backup.data, backup.length,
	    sealed, sizeof(sealed)) == 0)
		out = jni_array_create(env, sealed, sizeof(sealed));

	jni_bytes_free(&key);
	jni_bytes_free(&rk);
	jni_bytes_free(&backup);

	return (out);
}

/*
 * Make the words for a remote device, the cathedral is an IPv4 address
 * in host byte order. The words carry the passphrase of the tunnel, the
 * caller only keeps them while they are shown.
 */
JNIEXPORT jbyteArray JNICALL
JNI(remoteWords)(JNIEnv *env, jclass cls, jlong ctx, jlong flock,
    jint identity, jint cathedral, jint port, jint kek, jint peer)
{
	jbyteArray		out;
	COVENANT		*cov;
	struct covenant_route	route;
	char			*words;

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (port < 1 || port > USHRT_MAX ||
	    kek < 1 || kek > COVENANT_KEK_COUNT ||
	    peer < 1 || peer > COVENANT_KEK_COUNT) {
		cov->last_error = COVENANT_ERROR_PARAMETER;
		return (NULL);
	}

	memset(&route, 0, sizeof(route));

	route.kek = (u_int8_t)kek;
	route.peer = (u_int8_t)peer;
	route.port = (u_int16_t)port;
	route.flock = (u_int64_t)flock;
	route.identity = (u_int32_t)identity;
	route.cathedral = (u_int32_t)cathedral;

	covenant_lock();
	words = covenant_alloc(COVENANT_REMOTE_WORDS_LEN);
	covenant_unlock();

	out = NULL;

	if (covenant_remote_words(cov, &route,
	    words, COVENANT_REMOTE_WORDS_LEN) == 0) {
		out = jni_array_create(env,
		    (const u_int8_t *)words, strlen(words));
	}

	covenant_lock();
	covenant_free(words, COVENANT_REMOTE_WORDS_LEN);
	covenant_unlock();

	return (out);
}

/*
 * Unseal the KEKs and set up the tunnel to the remote device that joined
 * under the given cathedral id. Without a config we only send its KEK.
 */
JNIEXPORT jboolean JNICALL
JNI(remoteStart)(JNIEnv *env, jclass cls, jlong ctx, jbyteArray secret,
    jbyteArray in, jstring config, jstring cathedral, jint handle,
    jint device)
{
	jboolean		ret;
	struct covenant_remote	rem;
	COVENANT		*cov;
	struct jni_bytes	key, sealed;

	PRECOND(env != NULL);

	(void)cls;

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (JNI_FALSE);

	if (cathedral == NULL) {
		cov->last_error = COVENANT_ERROR_PARAMETER;
		return (JNI_FALSE);
	}

	if (jni_bytes_copy(env, secret, &key) == -1)
		return (JNI_FALSE);

	if (jni_bytes_copy(env, in, &sealed) == -1) {
		jni_bytes_free(&key);
		return (JNI_FALSE);
	}

	memset(&rem, 0, sizeof(rem));

	rem.keks = sealed.data;
	rem.keks_len = sealed.length;

	rem.secret = key.data;
	rem.secret_len = key.length;

	rem.cosk = (u_int32_t)handle;
	rem.device = (u_int32_t)device;
	rem.cathedral_secret = (*env)->GetStringUTFChars(env, cathedral, NULL);

	if (config != NULL)
		rem.config = (*env)->GetStringUTFChars(env, config, NULL);

	ret = JNI_FALSE;

	if (rem.cathedral_secret != NULL &&
	    (config == NULL || rem.config != NULL) &&
	    covenant_remote_start(cov, &rem) == 0)
		ret = JNI_TRUE;

	if (rem.cathedral_secret != NULL) {
		(*env)->ReleaseStringUTFChars(env,
		    cathedral, rem.cathedral_secret);
	}

	if (rem.config != NULL)
		(*env)->ReleaseStringUTFChars(env, config, rem.config);

	jni_bytes_free(&key);
	jni_bytes_free(&sealed);

	return (ret);
}

/*
 * Run the tunnel to the remote device for up to a second, returns its
 * state or -1 when something went wrong.
 */
JNIEXPORT jint JNICALL
JNI(remoteRun)(JNIEnv *env, jclass cls, jlong ctx)
{
	(void)env;
	(void)cls;

	return ((jint)covenant_remote_run(covenant_ctx(ctx)));
}

/*
 * Tear down the tunnel to the remote device.
 */
JNIEXPORT void JNICALL
JNI(remoteStop)(JNIEnv *env, jclass cls, jlong ctx)
{
	(void)env;
	(void)cls;

	covenant_remote_stop(covenant_ctx(ctx));
}

/*
 * Provision a device into its QR modules when qr is set, or into its
 * configuration when it is not.
 */
static jbyteArray
jni_device_provision(JNIEnv *env, jlong ctx, jbyteArray secret, jbyteArray in,
    jint kek, jint handle, jstring cathedral, jstring config, int qr)
{
	COVENANT		*cov;
	int			side;
	size_t			len;
	u_int8_t		*buf;
	jbyteArray		out;
	struct covenant_device	dev;
	struct jni_bytes	key, sealed;

	PRECOND(env != NULL);

	if ((cov = covenant_ctx(ctx)) == NULL)
		return (NULL);

	if (kek < 1 || kek > COVENANT_KEK_COUNT ||
	    cathedral == NULL || config == NULL) {
		cov->last_error = COVENANT_ERROR_PARAMETER;
		return (NULL);
	}

	if (jni_bytes_copy(env, secret, &key) == -1)
		return (NULL);

	if (jni_bytes_copy(env, in, &sealed) == -1) {
		jni_bytes_free(&key);
		return (NULL);
	}

	len = qr ? COVENANT_QR_MAX_LEN : COVENANT_CONFIG_MAX_LEN;

	covenant_lock();
	buf = covenant_alloc(len);
	covenant_unlock();

	memset(&dev, 0, sizeof(dev));

	dev.secret = key.data;
	dev.secret_len = key.length;

	dev.keks = sealed.data;
	dev.keks_len = sealed.length;

	dev.kek = (u_int8_t)kek;
	dev.cosk = (u_int32_t)handle;
	dev.config = (*env)->GetStringUTFChars(env, config, NULL);
	dev.cathedral_secret = (*env)->GetStringUTFChars(env, cathedral, NULL);

	out = NULL;

	if (dev.cathedral_secret != NULL && dev.config != NULL) {
		if (qr && covenant_provision(cov, &dev, buf, len, &side) == 0) {
			out = jni_array_create(env,
			    buf, (size_t)side * (size_t)side);
		}

		if (!qr && covenant_provision_config(cov, &dev,
		    (char *)buf, len) == 0) {
			out = jni_array_create(env,
			    buf, strlen((const char *)buf));
		}
	}

	if (dev.cathedral_secret != NULL) {
		(*env)->ReleaseStringUTFChars(env,
		    cathedral, dev.cathedral_secret);
	}

	if (dev.config != NULL)
		(*env)->ReleaseStringUTFChars(env, config, dev.config);

	jni_bytes_free(&key);
	jni_bytes_free(&sealed);

	covenant_lock();
	covenant_free(buf, len);
	covenant_unlock();

	return (out);
}

/*
 * Copy a Java byte array into memory from covenant_alloc().
 */
static int
jni_bytes_copy(JNIEnv *env, jbyteArray array, struct jni_bytes *out)
{
	jsize		len;

	PRECOND(env != NULL);
	PRECOND(out != NULL);

	memset(out, 0, sizeof(*out));

	if (array == NULL || (len = (*env)->GetArrayLength(env, array)) <= 0)
		return (-1);

	covenant_lock();
	out->data = covenant_alloc((size_t)len);
	covenant_unlock();

	out->length = (size_t)len;
	(*env)->GetByteArrayRegion(env, array, 0, len, (jbyte *)out->data);

	return (0);
}

/*
 * Copy a Java byte array that must be exactly len bytes long.
 */
static int
jni_bytes_copy_exact(JNIEnv *env, jlong ctx, jbyteArray array, size_t len,
    struct jni_bytes *out)
{
	COVENANT	*cov;

	PRECOND(env != NULL);
	PRECOND(out != NULL);

	if (jni_bytes_copy(env, array, out) == -1)
		return (-1);

	cov = covenant_ctx(ctx);

	if (out->length != len) {
		cov->last_error = COVENANT_ERROR_PARAMETER;
		jni_bytes_free(out);
		return (-1);
	}

	return (0);
}

/*
 * Zeroize and release a copy from jni_bytes_copy().
 */
static void
jni_bytes_free(struct jni_bytes *bytes)
{
	PRECOND(bytes != NULL);

	if (bytes->data == NULL)
		return;

	covenant_lock();
	covenant_free(bytes->data, bytes->length);
	covenant_unlock();

	memset(bytes, 0, sizeof(*bytes));
}

/*
 * Create a new Java byte array holding a copy of the given data.
 */
static jbyteArray
jni_array_create(JNIEnv *env, const u_int8_t *data, size_t len)
{
	jbyteArray	out;

	PRECOND(env != NULL);
	PRECOND(data != NULL);
	PRECOND(len > 0);

	if ((out = (*env)->NewByteArray(env, (jsize)len)) == NULL)
		return (NULL);

	(*env)->SetByteArrayRegion(env, out, 0, (jsize)len,
	    (const jbyte *)data);

	return (out);
}

/*
 * Log why we are about to abort.
 */
static void
jni_fatal(const char *fmt, va_list args)
{
	__android_log_vprint(ANDROID_LOG_ERROR, "covenant", fmt, args);
}
