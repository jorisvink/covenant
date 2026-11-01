package se.sanctorum.reliquary

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.DocumentsContract.Document

/**
 * The backup folder, through the storage access framework.
 */
object BackupFolder {
    private const val SUFFIX = ".rlqb"
    private const val MIME = "application/octet-stream"

    private const val ACCESS =
        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION

    fun pick(): Intent =
        Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
            .addFlags(ACCESS or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)

    fun keep(context: Context, tree: Uri) =
        context.contentResolver.takePersistableUriPermission(tree, ACCESS)

    fun file(flock: String) = "reliquary-$flock$SUFFIX"

    fun name(context: Context, tree: Uri): String? =
        try {
            context.contentResolver.query(
                root(tree), arrayOf(Document.COLUMN_DISPLAY_NAME), null, null, null
            )?.use { c -> if (c.moveToFirst()) c.getString(0) else null }
        } catch (e: Exception) {
            null
        }

    fun write(context: Context, tree: Uri, name: String, data: ByteArray) {
        val resolver = context.contentResolver
        val doc = children(context, tree)[name]
            ?: DocumentsContract.createDocument(resolver, root(tree), MIME, name)
            ?: throw IllegalStateException("Could not write $name to the backup folder.")

        val out = try {
            resolver.openOutputStream(doc, "wt")
        } catch (e: IllegalArgumentException) {
            resolver.openOutputStream(doc, "w")
        } ?: throw IllegalStateException("Could not write $name to the backup folder.")

        out.use { it.write(data) }
    }

    fun list(context: Context, tree: Uri): Map<String, Uri> =
        children(context, tree).filterKeys { it.endsWith(SUFFIX) }

    fun read(context: Context, doc: Uri): ByteArray =
        context.contentResolver.openInputStream(doc)?.use { it.readBytes() }
            ?: throw IllegalStateException("Could not read a backup from the backup folder.")

    private fun root(tree: Uri): Uri =
        DocumentsContract.buildDocumentUriUsingTree(tree, DocumentsContract.getTreeDocumentId(tree))

    private fun children(context: Context, tree: Uri): Map<String, Uri> {
        val uri = DocumentsContract.buildChildDocumentsUriUsingTree(
            tree, DocumentsContract.getTreeDocumentId(tree)
        )
        val out = mutableMapOf<String, Uri>()

        context.contentResolver.query(
            uri, arrayOf(Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME), null, null, null
        )?.use { c ->
            while (c.moveToNext()) {
                out[c.getString(1)] = DocumentsContract.buildDocumentUriUsingTree(tree, c.getString(0))
            }
        }

        return out
    }
}
