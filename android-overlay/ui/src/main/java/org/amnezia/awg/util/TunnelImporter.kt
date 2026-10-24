/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg.util

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Log
import androidx.fragment.app.FragmentManager
import org.amnezia.awg.Application
import org.amnezia.awg.R
import org.amnezia.awg.fragment.ConfigNamingDialogFragment
import org.amnezia.awg.model.ObservableTunnel
import org.amnezia.awg.config.Config
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream

object TunnelImporter {
    suspend fun importTunnel(contentResolver: ContentResolver, uri: Uri, messageCallback: (CharSequence) -> Unit) {
        try {
            val count = withContext(Dispatchers.IO) {
                var name = ""
                contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                    if (it.moveToFirst() && !it.isNull(0)) name = it.getString(0)
                }
                if (name.isEmpty()) name = uri.lastPathSegment.orEmpty().substringAfterLast('/')
                val bytes = contentResolver.openInputStream(uri)?.use { org.amnezia.awg.r013.ArchiveReader.bounded(it, 8_388_608) }
                    ?: error("Не удалось открыть файл")
                val bundle = if (name.endsWith(".zip", true) || (bytes.size >= 4 && bytes[0] == 80.toByte() && bytes[1] == 75.toByte()))
                    org.amnezia.awg.r013.ArchiveReader.read(bytes)
                else {
                    require(name.endsWith(".conf", true)) { "Выберите .conf или .zip" }
                    org.amnezia.awg.r013.ArchiveReader.Bundle(listOf(org.amnezia.awg.r013.ArchiveReader.Item(name.dropLast(5), String(bytes, Charsets.UTF_8))), null)
                }
                // Parse EVERY profile before changing anything; fail as a whole on malformed input.
                val parsed = bundle.profiles().map { it.name() to org.amnezia.awg.r013.ProfileRegistry.parse(it.text()) }
                val registry = org.amnezia.awg.r013.ProfileRegistry.get(Application.get())
                val access = bundle.accessDocument()?.let { org.amnezia.awg.r013.ClientProtocol.androidAccess(org.amnezia.awg.r013.ClientProtocol.access(it), parsed) }
                org.amnezia.awg.r013.OfflineChanges.apply {
                    if (access != null) org.amnezia.awg.r013.ClientProtocol.apply(registry, access)
                    else registry.importOrdinary(parsed)
                }
            }
            withContext(Dispatchers.Main.immediate) { messageCallback("Добавлено профилей: $count") }
        } catch (e: Exception) {
            withContext(Dispatchers.Main.immediate) { messageCallback(e.message ?: "Импорт не выполнен. Прежние профили сохранены.") }
        }
    }

    fun importTunnel(parentFragmentManager: FragmentManager, configText: String, messageCallback: (CharSequence) -> Unit) {
        try {
            // Ensure the config text is parseable before proceeding…
            Config.parse(ByteArrayInputStream(configText.toByteArray(StandardCharsets.UTF_8)))

            // Config text is valid, now create the tunnel…
            ConfigNamingDialogFragment.newInstance(configText).show(parentFragmentManager, null)
        } catch (e: Throwable) {
            onTunnelImportFinished(emptyList(), listOf<Throwable>(e), messageCallback)
        }
    }

    private fun onTunnelImportFinished(tunnels: List<ObservableTunnel>, throwables: Collection<Throwable>, messageCallback: (CharSequence) -> Unit) {
        val context = Application.get().applicationContext
        var message = ""
        for (throwable in throwables) {
            val error = ErrorMessages[throwable]
            message = context.getString(R.string.import_error, error)
            Log.e(TAG, message, throwable)
        }
        if (tunnels.size == 1 && throwables.isEmpty())
            message = context.getString(R.string.import_success, tunnels[0].name)
        else if (tunnels.isEmpty() && throwables.size == 1)
        else if (throwables.isEmpty())
            message = context.resources.getQuantityString(
                R.plurals.import_total_success,
                tunnels.size, tunnels.size
            )
        else if (!throwables.isEmpty())
            message = context.resources.getQuantityString(
                R.plurals.import_partial_success,
                tunnels.size + throwables.size,
                tunnels.size, tunnels.size + throwables.size
            )

        messageCallback(message)
    }

    private const val TAG = "AmneziaWG/TunnelImporter"
}