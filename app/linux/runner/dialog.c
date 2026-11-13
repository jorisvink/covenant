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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "covenant-int.h"
#include "runner.h"

static GtkWidget	*dialog_error(GtkWidget *);
static void		dialog_fail(GtkWidget *, const char *);
static int		dialog_hex(const char *, u_int8_t *, size_t);
static GtkWidget	*dialog_entry(GtkWidget *, const char *, int);
static GtkWidget	*dialog_new(GtkWindow *, const char *, GtkWidget **);

/*
 * Ask for the passphrase, twice when confirm is set (when it is chosen).
 * On success out holds a copy of len bytes from runner_alloc() that the
 * caller must release with runner_free(). Returns -1 when the user cancelled.
 */
int
runner_passphrase(GtkWindow *parent, const char *reason, int confirm,
    char **out, size_t *len)
{
	int			ret;
	size_t			plen;
	GtkWidget		*dialog;
	const char		*pass, *again;
	GtkWidget		*box, *error, *first, *second;

	PRECOND(parent != NULL);
	PRECOND(reason != NULL);
	PRECOND(out != NULL);
	PRECOND(len != NULL);

	*len = 0;
	*out = NULL;

	ret = -1;
	second = NULL;
	dialog = dialog_new(parent, reason, &box);
	first = dialog_entry(box, "Passphrase", 1);

	if (confirm)
		second = dialog_entry(box, "Repeat the passphrase", 1);

	error = dialog_error(dialog);

	while (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
		pass = gtk_entry_get_text(GTK_ENTRY(first));
		if ((plen = strlen(pass)) == 0) {
			dialog_fail(error, "The passphrase cannot be empty.");
			continue;
		}

		if (second != NULL) {
			again = gtk_entry_get_text(GTK_ENTRY(second));
			if (strcmp(pass, again)) {
				dialog_fail(error,
				    "The passphrases do not match.");
				gtk_entry_set_text(GTK_ENTRY(second), "");
				continue;
			}
		}

		*len = plen;
		*out = runner_alloc(plen);
		nyfe_memcpy(*out, pass, plen);
		ret = 0;
		break;
	}

	gtk_entry_set_text(GTK_ENTRY(first), "");

	if (second != NULL)
		gtk_entry_set_text(GTK_ENTRY(second), "");

	gtk_widget_destroy(dialog);

	return (ret);
}

/*
 * Ask for the recovery key of a backup, 64 hex characters that may be
 * split up by whitespace the way the phone shows it. Root comes from
 * runner_alloc(), on failure it is wiped. Returns -1 when the user
 * cancelled.
 */
int
runner_recovery(GtkWindow *parent, const char *reason, u_int8_t *root,
    size_t len)
{
	int			ret;
	GtkWidget		*dialog;
	GtkWidget		*box, *error, *entry;

	PRECOND(parent != NULL);
	PRECOND(reason != NULL);
	PRECOND(root != NULL);
	PRECOND(len > 0);

	dialog = dialog_new(parent, reason, &box);
	entry = dialog_entry(box, "Recovery key", 0);
	gtk_entry_set_width_chars(GTK_ENTRY(entry), 72);
	error = dialog_error(dialog);

	ret = -1;

	while (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
		if (dialog_hex(gtk_entry_get_text(GTK_ENTRY(entry)),
		    root, len) == -1) {
			dialog_fail(error, "A recovery key is 64 letters "
			    "and digits, check it again.");
			continue;
		}

		ret = 0;
		break;
	}

	gtk_entry_set_text(GTK_ENTRY(entry), "");
	gtk_widget_destroy(dialog);

	return (ret);
}

/*
 * Let the user pick a folder, or a backup file when folder is not set.
 * The dialog opens in start when it is given. On success path holds the
 * path from malloc() that the caller must free. Returns -1 when the user
 * cancelled.
 */
int
runner_pick(GtkWindow *parent, const char *title, int folder,
    const char *start, char **path)
{
	int			ret;
	GtkFileChooserAction	action;
	GtkWidget		*dialog;
	GtkFileFilter		*filter;
	char			*filename;

	PRECOND(parent != NULL);
	PRECOND(title != NULL);
	PRECOND(path != NULL);

	*path = NULL;
	action = GTK_FILE_CHOOSER_ACTION_OPEN;

	if (folder)
		action = GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER;

	dialog = gtk_file_chooser_dialog_new(title, parent, action,
	    "_Cancel", GTK_RESPONSE_CANCEL, "_Open", GTK_RESPONSE_ACCEPT, NULL);

	gtk_file_chooser_set_local_only(GTK_FILE_CHOOSER(dialog), TRUE);

	if (start != NULL) {
		if (gtk_file_chooser_set_current_folder(
		    GTK_FILE_CHOOSER(dialog), start) == FALSE)
			fprintf(stderr, "covenant: cannot open %s\n", start);
	}

	if (!folder) {
		filter = gtk_file_filter_new();
		gtk_file_filter_set_name(filter, "Covenant backups");
		gtk_file_filter_add_pattern(filter, "*.rlqb");
		gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);
	}

	ret = -1;

	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		filename = gtk_file_chooser_get_filename(
		    GTK_FILE_CHOOSER(dialog));

		if (filename != NULL) {
			if ((*path = strdup(filename)) != NULL)
				ret = 0;
			g_free(filename);
		}
	}

	gtk_widget_destroy(dialog);

	return (ret);
}

/*
 * Make a dialog with the given reason in it, box is where the entries
 * go.
 */
static GtkWidget *
dialog_new(GtkWindow *parent, const char *reason, GtkWidget **box)
{
	GtkWidget	*dialog, *label;

	PRECOND(parent != NULL);
	PRECOND(reason != NULL);
	PRECOND(box != NULL);

	dialog = gtk_dialog_new_with_buttons("Covenant", parent,
	    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
	    "_Cancel", GTK_RESPONSE_CANCEL, "_OK", GTK_RESPONSE_OK, NULL);

	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);
	gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);

	*box = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	gtk_container_set_border_width(GTK_CONTAINER(*box), 18);
	gtk_box_set_spacing(GTK_BOX(*box), 8);

	label = gtk_label_new(reason);
	gtk_label_set_xalign(GTK_LABEL(label), 0);
	gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
	gtk_label_set_max_width_chars(GTK_LABEL(label), 48);
	gtk_container_add(GTK_CONTAINER(*box), label);

	return (dialog);
}

/*
 * Add an entry with the given label to box, hidden for a passphrase.
 */
static GtkWidget *
dialog_entry(GtkWidget *box, const char *text, int hidden)
{
	GtkWidget	*entry, *label;

	PRECOND(box != NULL);
	PRECOND(text != NULL);

	label = gtk_label_new(text);
	gtk_label_set_xalign(GTK_LABEL(label), 0);
	gtk_widget_set_margin_top(label, 8);
	gtk_container_add(GTK_CONTAINER(box), label);

	entry = gtk_entry_new();
	gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);

	if (hidden) {
		gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
		gtk_entry_set_input_purpose(GTK_ENTRY(entry),
		    GTK_INPUT_PURPOSE_PASSWORD);
	}

	gtk_container_add(GTK_CONTAINER(box), entry);

	return (entry);
}

/*
 * Add the label that tells what is wrong with the input, shows the
 * dialog and keeps the label hidden until there is something to say.
 */
static GtkWidget *
dialog_error(GtkWidget *dialog)
{
	GtkWidget	*box, *error;

	PRECOND(dialog != NULL);

	box = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

	error = gtk_label_new(NULL);
	gtk_label_set_xalign(GTK_LABEL(error), 0);
	gtk_container_add(GTK_CONTAINER(box), error);

	gtk_widget_show_all(dialog);
	gtk_widget_hide(error);

	return (error);
}

/*
 * Tell the user what is wrong with the input.
 */
static void
dialog_fail(GtkWidget *error, const char *text)
{
	PRECOND(error != NULL);
	PRECOND(text != NULL);

	gtk_label_set_text(GTK_LABEL(error), text);
	gtk_widget_show(error);
}

/*
 * Decode exactly len bytes of hex from text, skipping whitespace. On
 * failure out is wiped.
 */
static int
dialog_hex(const char *text, u_int8_t *out, size_t len)
{
	int		val, shift;
	size_t		idx, digits;

	PRECOND(text != NULL);
	PRECOND(out != NULL);
	PRECOND(len > 0);

	digits = 0;
	nyfe_mem_zero(out, len);

	for (idx = 0; text[idx] != '\0'; idx++) {
		if (isspace((unsigned char)text[idx]))
			continue;

		if (!isxdigit((unsigned char)text[idx]))
			break;

		if (digits == len * 2)
			break;

		if (isdigit((unsigned char)text[idx]))
			val = text[idx] - '0';
		else
			val = tolower((unsigned char)text[idx]) - 'a' + 10;

		shift = 4;
		if (digits % 2)
			shift = 0;

		out[digits / 2] |= (u_int8_t)(val << shift);
		digits++;
	}

	if (text[idx] != '\0') {
		nyfe_mem_zero(out, len);
		return (-1);
	}

	if (digits != len * 2) {
		nyfe_mem_zero(out, len);
		return (-1);
	}

	return (0);
}
