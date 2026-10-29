// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.amnezia.awg.Application
import org.amnezia.awg.BuildConfig
import org.json.JSONObject
import java.io.File
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

/** Same order protocol as iOS/Windows; APK identity is additionally checked before OS install. */
object ClientUpdates {
    private var checking = false
    private var refreshing = false
    private var downloading = false
    private var applying = false
    private var resumingInstall = false
    private val failedPending = HashMap<String, String>()
    suspend fun refreshOrders(onlyOrder: String? = null): String {
        if (onlyOrder != null) require(Regex("^[a-f0-9]{12}$").matches(onlyOrder))
        check(!refreshing) { "Обновление конфигураций уже выполняется" }
        refreshing = true
        try {
        val registry = ProfileRegistry.get(Application.get())
        val orders = withContext(Dispatchers.IO) { registry.vault.read().getJSONObject("orders") }
        if (orders.length() == 0) return "Нет привязанных заявок. Импортируйте ZIP с документом VPN013-Access.json."
        val subscriptions = mutableListOf<String>()
        for (order in orders.keys()) {
            if (onlyOrder != null && order != onlyOrder) continue
            val document = orders.getJSONObject(order).getJSONObject("document")
            val snapshot = withContext(Dispatchers.IO) {
                ClientProtocol.request("/client/awg/$order/android", document.getString("capability")).also { ClientProtocol.snapshot(it, order) }
            }
            withContext(Dispatchers.IO) {
                registry.vault.edit { root ->
                    val binding = root.getJSONObject("orders").getJSONObject(order)
                    val current = binding.getJSONObject("document").getJSONObject("snapshot")
                    val map = binding.getJSONObject("mapping")
                    val profiles = root.getJSONObject("profiles")
                    val complete = ClientProtocol.mappingComplete(map, snapshot, profiles)
                    if (current.getString("revision") != snapshot.getString("revision") || current.getLong("expiry") != snapshot.getLong("expiry") || !complete)
                        binding.put("pending",snapshot)
                }
            }
            failedPending.remove(order)
            val expiry = java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT,java.text.DateFormat.SHORT)
                .format(java.util.Date(snapshot.getLong("expiry")))
            subscriptions.add("Подписка №$order: ${snapshot.getJSONArray("servers").length()} серверов. Действует до $expiry.")
        }
        if (applyPending()) return (listOf("Состав серверов восстановлен и обновлён.") + subscriptions).joinToString("\n\n")
        val pending = withContext(Dispatchers.IO) { registry.vault.read().getJSONObject("orders").let { current -> current.keys().asSequence().any { current.getJSONObject(it).has("pending") } } }
        return (listOf(if (pending) "Обновления загружены. Они применятся при открытом приложении после отключения VPN." else "Конфигурации проверены. Состав серверов актуален.") + subscriptions).joinToString("\n\n")
        } finally { refreshing = false }
    }
    suspend fun applyPending(): Boolean {
        if (applying) return false
        applying = true
        try {
            if (withContext(Dispatchers.IO) { Application.getBackend().runningTunnelNames.isNotEmpty() }) return false
            val registry = ProfileRegistry.get(Application.get())
            val state = withContext(Dispatchers.IO) { registry.vault.read() }
            val orders = state.getJSONObject("orders")
            var complete = true
            var applied = false
            for (order in orders.keys()) {
                val binding = orders.getJSONObject(order); val pending = binding.optJSONObject("pending") ?: continue
                val identity = ProfileRegistry.digest(pending.toString()+state.getJSONObject("profiles").toString())
                if (failedPending[order] == identity) { complete = false; continue }
                val document = JSONObject(binding.getJSONObject("document").toString()).put("snapshot", pending)
                try {
                    OfflineChanges.apply { ClientProtocol.apply(registry, document) }
                    failedPending.remove(order)
                    applied = true
                } catch (_: OfflineChanges.ActiveVPNException) { return false }
                catch (e: Exception) { failedPending[order] = identity; throw e }
            }
            return applied && complete
        } finally { applying = false }
    }
    suspend fun checkDaily(activity: AppCompatActivity, notify: (String) -> Unit) {
        if (checking || resumingInstall || BuildConfig.DEBUG) return
        val registry = ProfileRegistry.get(activity)
        val now = System.currentTimeMillis()
        val state = withContext(Dispatchers.IO) { registry.vault.read() }
        if (now - state.optLong("lastDailySuccess") < 86_400_000L || now - state.optLong("lastDailyAttempt") < 3_600_000L) return
        checking = true
        try {
            withContext(Dispatchers.IO) { registry.vault.edit { it.put("lastDailyAttempt", now) } }
            var complete = true
            try {
                val release = withContext(Dispatchers.IO) { ClientProtocol.request("/client/releases/vpn013-wg/android").also { validateRelease(it) } }
                if (newer(release) && !downloading && !resumingInstall) {
                    downloading = true
                    try {
                        val file = withContext(Dispatchers.IO) { downloadChecked(activity, release) }
                        if (!activity.isFinishing && !activity.isDestroyed) MaterialAlertDialogBuilder(activity).setTitle("Обновление ${release.getString("version")} скачано")
                            .setMessage("Файл проверен. Android предложит подтвердить установку; ваши профили сохранятся при обновлении поверх этой версии.")
                            .setPositiveButton("Установить обновление") { _, _ -> installChecked(activity, file, release) }.setNegativeButton("Позже", null).show()
                    } finally { downloading = false; resumePendingInstall(activity) }
                }
            } catch (_: Exception) { complete = false }
            try { val message = refreshOrders(); if (state.getJSONObject("orders").length() > 0) notify(message) }
            catch (_: Exception) { complete = false }
            if (complete) withContext(Dispatchers.IO) { registry.vault.edit { it.put("lastDailySuccess", now) } }
        } catch (_: Exception) { /* Manual checks report errors; daily checks back off without interrupting VPN. */ }
        finally { checking = false }
    }
    fun offerUpdate(activity: AppCompatActivity) {
        if (checking || downloading || resumingInstall) return
        if (BuildConfig.DEBUG) { message(activity, "Тестовая сборка", "Для обновлений нужна подписанная версия VPN013."); return }
        checking = true
        activity.lifecycleScope.launch {
            try {
                val release = withContext(Dispatchers.IO) { ClientProtocol.request("/client/releases/vpn013-wg/android").also { validateRelease(it) } }
                if (newer(release)) promptDownload(activity, release) else message(activity, "Обновление", "Установлена актуальная версия ${BuildConfig.VERSION_NAME}.")
            } catch (e: Exception) { message(activity, "Не удалось проверить обновление", e.message ?: "Проверьте интернет и повторите позже.") }
            finally { checking = false }
        }
    }
    private fun newer(release: JSONObject) = release.getInt("build") > BuildConfig.VERSION_CODE && compareVersions(release.getString("version"), BuildConfig.VERSION_NAME) >= 0
    private fun compareVersions(a: String, b: String): Int {
        for ((left, right) in a.split('.').map { it.toInt() }.zip(b.split('.').map { it.toInt() })) { if (left != right) return left.compareTo(right) }; return 0
    }
    private fun validateRelease(release: JSONObject) {
        val url = URL(release.getString("downloadURL"))
        require(release.getInt("schema") == 1 && release.getString("app") == "vpn013-wg" && release.getString("platform") == "android" &&
            release.getInt("build") > 0 && release.getString("version").matches(Regex("^[0-9]{1,6}[.][0-9]{1,6}[.][0-9]{1,6}$")) &&
            release.getString("sha256").matches(Regex("^[a-f0-9]{64}$")) && release.optString("notes").length <= 2000 &&
            url.protocol == "https" && url.host == "github.com" && url.userInfo == null && url.port == -1 && url.query == null && url.ref == null &&
            url.path.startsWith("/2njz45z86r-commits/vpn013-wg-ios/releases/download/") && url.path.endsWith(".apk")) { "Не удалось проверить сведения о выпуске" }
    }
    private fun promptDownload(activity: AppCompatActivity, release: JSONObject) {
        MaterialAlertDialogBuilder(activity).setTitle("Доступна версия ${release.getString("version")}")
            .setMessage(release.optString("notes") + "\n\nПриложение проверит файл и откроет системную установку. Android попросит разрешение; профили сохраняются при обновлении поверх существующей версии.")
            .setPositiveButton("Установить обновление") { _, _ -> download(activity, release) }.setNegativeButton("Позже", null).show()
    }
    private fun download(activity: AppCompatActivity, release: JSONObject) {
        if (downloading) return; downloading = true
        activity.lifecycleScope.launch {
            try {
                val file = withContext(Dispatchers.IO) { downloadChecked(activity, release) }
                installChecked(activity, file, release)
            } catch (e: Exception) { message(activity, "Обновление не установлено", e.message ?: "Не удалось скачать и проверить APK. Прежняя версия сохранена.") }
            finally { downloading = false; resumePendingInstall(activity) }
        }
    }
    private fun installChecked(activity: AppCompatActivity, file: File, release: JSONObject) {
        if (activity.isFinishing || activity.isDestroyed) return
        try {
        // Persist only after the owner taps Install. A background download or
        // a Later choice must never become an unsolicited install on resume.
        val directory = File(activity.cacheDir, "updates").apply { mkdirs() }
        check(file.canonicalFile == File(directory, "VPN013WG.apk").canonicalFile)
        val marker = File(directory, "requested-install.json")
        val temporary = File(directory, "requested-install.part")
        temporary.outputStream().use { out -> out.write(release.toString().toByteArray(Charsets.UTF_8)); out.fd.sync() }
        check(temporary.renameTo(marker)) { "Не удалось сохранить запрос обновления" }
        if (Build.VERSION.SDK_INT >= 26 && !activity.packageManager.canRequestPackageInstalls()) {
            MaterialAlertDialogBuilder(activity).setTitle("Разрешите обновления VPN013")
                .setMessage("Android требует один раз разрешить установку из VPN013. Включите разрешение и вернитесь в приложение — установка уже скачанного обновления продолжится. Профили и привязка к заявке сохранятся.")
                .setPositiveButton("Открыть разрешение") { _, _ -> activity.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${activity.packageName}"))) }
                .setNegativeButton("Позже") { _, _ -> marker.delete() }
                .setOnCancelListener { marker.delete() }.show()
        } else {
            resumePendingInstall(activity)
        }
        } catch (e: Exception) {
            message(activity, "Обновление не установлено", e.message ?: "Не удалось подготовить установку. Профили сохранены.")
        }
    }
    fun resumePendingInstall(activity: AppCompatActivity) {
        if (resumingInstall || downloading || activity.isFinishing || activity.isDestroyed) return
        if (Build.VERSION.SDK_INT >= 26 && !activity.packageManager.canRequestPackageInstalls()) return
        val directory = File(activity.cacheDir, "updates")
        val marker = File(directory, "requested-install.json")
        if (!marker.isFile) return
        resumingInstall = true
        activity.lifecycleScope.launch {
            try {
                val file = withContext(Dispatchers.IO) {
                    require(marker.length() in 1..16384) { "Запрос обновления повреждён" }
                    val release = JSONObject(marker.readText(Charsets.UTF_8))
                    validateRelease(release)
                    val apk = File(directory, "VPN013WG.apk")
                    require(apk.isFile && apk.length() in 1..268_435_456L) { "Файл обновления недоступен. Повторите проверку обновлений." }
                    val digest = MessageDigest.getInstance("SHA-256")
                    apk.inputStream().use { input -> val buffer = ByteArray(32768)
                        while (true) { val count = input.read(buffer); if (count < 0) break; digest.update(buffer, 0, count) }
                    }
                    require(digest.digest().joinToString("") { "%02x".format(it) } == release.getString("sha256")) { "Файл обновления изменился. Повторите проверку обновлений." }
                    verifyUpgradeIdentity(activity, apk, release)
                    apk
                }
                if (activity.isFinishing || activity.isDestroyed) return@launch
                val uri = FileProvider.getUriForFile(activity, activity.packageName + ".updates", file)
                check(marker.delete()) { "Не удалось подтвердить запрос установки" }
                activity.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive").addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (e: Exception) {
                marker.delete()
                message(activity, "Обновление не установлено", e.message ?: "Не удалось проверить обновление. Профили сохранены.")
            } finally { resumingInstall = false }
        }
    }
    private fun verifyUpgradeIdentity(activity: Activity, file: File, release: JSONObject) {
        val flags = if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES
        @Suppress("DEPRECATION") val incoming = activity.packageManager.getPackageArchiveInfo(file.absolutePath, flags) ?: error("Android не распознал подпись APK")
        @Suppress("DEPRECATION") val installed = activity.packageManager.getPackageInfo(activity.packageName, flags)
        require(incoming.packageName == activity.packageName && incoming.versionName == release.getString("version") &&
            versionCode(incoming) == release.getInt("build").toLong() && versionCode(incoming) > versionCode(installed) &&
            signers(incoming).isNotEmpty() && signers(incoming) == signers(installed)) { "APK относится к другому приложению, версии или подписи" }
    }
    private fun downloadChecked(activity: Activity, release: JSONObject): File {
        validateRelease(release)
        val dir = File(activity.cacheDir, "updates").apply { mkdirs() }
        val pending = File(dir, "release.part"); val result = File(dir, "VPN013WG.apk")
        try {
            var url = URL(release.getString("downloadURL")); var finished = false
            val digest = MessageDigest.getInstance("SHA-256")
            for (redirect in 0..4) {
                require(url.protocol == "https" && url.host in listOf("github.com", "release-assets.githubusercontent.com") && url.userInfo == null && url.port == -1) { "Недопустимый адрес обновления" }
                val connection = url.openConnection() as HttpsURLConnection
                try {
                    connection.instanceFollowRedirects = false; connection.connectTimeout = 15000; connection.readTimeout = 30000; connection.useCaches = false
                    val code = connection.responseCode
                    if (code in listOf(301,302,303,307,308)) { url = URL(url, connection.getHeaderField("Location") ?: error("Нет адреса файла")); continue }
                    require(code == 200 && connection.contentLengthLong <= 268_435_456L) { "Файл обновления недоступен или слишком велик" }
                    var total = 0L
                    connection.inputStream.use { input -> pending.outputStream().use { out -> val buffer = ByteArray(32768)
                        while (true) { val n = input.read(buffer); if (n < 0) break; total += n
                            require(total <= 268_435_456L) { "Файл обновления слишком велик" }; digest.update(buffer, 0, n); out.write(buffer, 0, n) }
                        out.fd.sync()
                    } }
                    finished = true; break
                } finally { connection.disconnect() }
            }
            require(finished && digest.digest().joinToString("") { "%02x".format(it) } == release.getString("sha256")) { "Не совпадает контрольная сумма APK" }
            verifyUpgradeIdentity(activity, pending, release)
            if (result.exists()) check(result.delete())
            check(pending.renameTo(result)) { "Не удалось сохранить обновление" }; return result
        } finally { if (pending.exists()) pending.delete() }
    }
    @Suppress("DEPRECATION") private fun versionCode(info: PackageInfo): Long = if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
    @Suppress("DEPRECATION") private fun signers(info: PackageInfo): Set<String> =
        (if (Build.VERSION.SDK_INT >= 28) info.signingInfo?.apkContentsSigners else info.signatures)?.map { it.toCharsString() }?.toSet().orEmpty()
    private fun message(activity: Activity, title: String, text: String) { if (!activity.isFinishing && !activity.isDestroyed) MaterialAlertDialogBuilder(activity).setTitle(title).setMessage(text).setPositiveButton("Понятно", null).show() }
}
