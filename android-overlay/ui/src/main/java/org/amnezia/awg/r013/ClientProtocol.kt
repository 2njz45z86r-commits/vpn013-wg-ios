// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import org.json.JSONArray
import org.json.JSONObject
import java.net.URL
import javax.net.ssl.HttpsURLConnection

object ClientProtocol {
    const val BOT = "https://t.me/vpn013_com_bot"
    const val WEBSITE = "https://vpn013.com"
    val origins = listOf("https://connect.vpn555.shop:8443", "https://connect.vpn555.shop:8444")
    private val id = Regex("^[a-f0-9]{12}$")
    private val hash = Regex("^[a-f0-9]{64}$")
    fun access(text: String): JSONObject {
        require(text.toByteArray(Charsets.UTF_8).size <= 1_048_576)
        val d = JSONObject(text)
        require(d.getInt("schema") == 1 && d.getString("kind") == "vpn013-access" &&
            Regex("^[A-Za-z0-9_-]{43}$").matches(d.getString("capability"))) { "Документ заявки повреждён" }
        snapshot(d.getJSONObject("snapshot")); return d
    }
    /** Bind the Android-preferred files by exact cryptographic/endpoint identity.
     * A legacy iPhone manifest must never replace Android-specific routes or MTU.
     */
    fun androidAccess(original: JSONObject, files: List<Pair<String, org.amnezia.awg.config.Config>>): JSONObject {
        val document = access(original.toString())
        val snapshot = document.getJSONObject("snapshot"); val servers = snapshot.getJSONArray("servers")
        val used = HashSet<Int>(); val revision = StringBuilder()
        fun identity(c: org.amnezia.awg.config.Config): String {
            require(c.peers.size == 1 && c.peers[0].endpoint.isPresent) { "Не удалось связать Android-файл с сервером заявки" }
            val peer = c.peers[0]
            return ProfileRegistry.digest(c.`interface`.keyPair.privateKey.toBase64() + "|" + peer.publicKey.toBase64() + "|" +
                peer.preSharedKey.orElse(null)?.toBase64().orEmpty() + "|" + peer.endpoint.get().toString())
        }
        for (i in 0 until servers.length()) {
            val server = servers.getJSONObject(i); val expected = identity(ProfileRegistry.parse(server.getString("config")))
            val matches = files.indices.filter { identity(files[it].second) == expected }
            require(matches.size == 1 && used.add(matches.single())) { "Состав Android-файлов не совпадает с заявкой. Прежние профили сохранены." }
            val selected = files[matches.single()]
            server.put("name",selected.first).put("config",selected.second.toAwgQuickString())
            revision.append(server.getString("id")).append('\n').append(server.getString("name")).append('\n').append(server.getString("config")).append('\n')
        }
        require(used.size == files.size) { "В ZIP есть файлы вне заявки. Импортируйте дополнительные профили отдельно." }
        snapshot.put("revision",ProfileRegistry.digest(revision.toString()))
        return access(document.toString())
    }
    fun snapshot(s: JSONObject, expected: String? = null) {
        val order = s.getString("orderID")
        require(s.getInt("schema") == 1 && s.getString("kind") == "vpn013-awg" && id.matches(order) &&
            (expected == null || expected == order) && s.getBoolean("complete") && hash.matches(s.getString("revision")) &&
            s.getLong("expiry") > 0) { "Неполный или чужой ответ заявки" }
        val servers = s.getJSONArray("servers"); require(servers.length() in 1..30)
        val ids = HashSet<String>(); val names = HashSet<String>(); val digest = StringBuilder()
        for (i in 0 until servers.length()) {
            val server = servers.getJSONObject(i); val sid = server.getString("id"); val name = server.getString("name"); val config = server.getString("config")
            require(Regex("^[A-Za-z0-9_-]{1,64}$").matches(sid) && ids.add(sid) && names.add(name) &&
                name.isNotBlank() && name.length <= 128 && name.none { it.code < 32 } && config.isNotEmpty()) { "Неверный список серверов" }
            ProfileRegistry.parse(config)
            digest.append(sid).append('\n').append(name).append('\n').append(config).append('\n')
        }
        require(ProfileRegistry.digest(digest.toString()) == s.getString("revision")) { "Не совпадает контрольная сумма списка" }
    }
    /** All ownership, local-edit checks and replacements commit in ONE atomic document. */
    fun apply(registry: ProfileRegistry, document: JSONObject): Int {
        val checked = access(document.toString()); val snapshot = checked.getJSONObject("snapshot")
        check(snapshot.getLong("expiry") > System.currentTimeMillis()) { "Доступ закончился. Откройте «Мои заявки» в боте." }
        return registry.vault.edit { root ->
            val order = snapshot.getString("orderID"); val orders = root.getJSONObject("orders"); val profiles = root.getJSONObject("profiles")
            val previous = orders.optJSONObject(order)
            val mapping = previous?.getJSONObject("mapping") ?: JSONObject()
            // A name collision never grants ownership. A manually changed bound profile blocks the whole update.
            for (sid in mapping.keys()) {
                val bound = mapping.getJSONObject(sid); val record = profiles.optJSONObject(bound.getString("profileID")) ?: continue
                check(ProfileRegistry.digest(record.getString("config")) == bound.getString("hash")) {
                    "«${record.getString("name")}» изменён вручную. Обновление остановлено; настройки сохранены."
                }
            }
            val servers = snapshot.getJSONArray("servers"); val newMapping = JSONObject()
            for (i in 0 until servers.length()) {
                val server = servers.getJSONObject(i); val sid = server.getString("id")
                val canonical = ProfileRegistry.parse(server.getString("config")).toAwgQuickString()
                val oldID = mapping.optJSONObject(sid)?.optString("profileID")
                val record = oldID?.let { profiles.optJSONObject(it) } ?: ProfileRegistry.add(profiles,
                    ProfileRegistry.uniqueName(profiles, server.getString("name")), ProfileRegistry.parse(canonical))
                // Keep the user's chosen display name; backend server ID is authoritative.
                record.put("config", canonical)
                newMapping.put(sid, JSONObject().put("profileID", record.getString("id")).put("hash", ProfileRegistry.digest(canonical)))
            }
            for (sid in mapping.keys()) if (!newMapping.has(sid)) profiles.remove(mapping.getJSONObject(sid).getString("profileID"))
            val oldIDs = mapping.keys().asSequence().map { mapping.getJSONObject(it).getString("profileID") }.toSet()
            val newIDs = newMapping.keys().asSequence().map { newMapping.getJSONObject(it).getString("profileID") }.toList()
            // Refresh only linked members from this order, preserving unrelated snapshots and every original route/key.
            for (pid in profiles.keys()) {
                val auto = profiles.getJSONObject(pid); val members = auto.optJSONArray("members") ?: continue
                if ((0 until members.length()).none { members.getJSONObject(it).getString("sourceID") in oldIDs }) continue
                val replacement = JSONArray()
                for (j in 0 until members.length()) { val m = members.getJSONObject(j); if (m.getString("sourceID") !in oldIDs) replacement.put(m) }
                for (sourceID in newIDs) { val r = profiles.getJSONObject(sourceID)
                    replacement.put(JSONObject().put("sourceID", sourceID).put("name", r.getString("name")).put("config", r.getString("config"))) }
                check(replacement.length() in 1..30) { "Обновлённый состав Авто должен содержать 1–30 серверов" }
                check((0 until replacement.length()).all { registry.eligible(ProfileRegistry.parse(replacement.getJSONObject(it).getString("config"))) }) { "Обновлённый сервер не подходит для безопасного Авто. Прежние настройки сохранены." }
                auto.put("members", replacement).put("config", replacement.getJSONObject(0).getString("config"))
                if (auto.getString("name").matches(Regex("^Авто · [0-9]{1,2}( \\([0-9]+\\))?$")))
                    auto.put("name",ProfileRegistry.uniqueName(profiles,"Авто · ${replacement.length()}",auto.getString("id")))
            }
            orders.put(order, JSONObject().put("document", checked).put("mapping", newMapping))
            servers.length()
        }
    }
    /** Credentials are sent only to fixed HTTPS origins, never to redirects. */
    fun request(path: String, capability: String? = null): JSONObject {
        require(path.matches(Regex("^/client/(releases/vpn013-wg/android|awg/[a-f0-9]{12}/android)$")))
        if (capability != null) require(Regex("^[A-Za-z0-9_-]{43}$").matches(capability))
        var last: Exception? = null
        for (origin in origins) {
            val connection = URL(origin + path).openConnection() as HttpsURLConnection
            try {
                connection.connectTimeout = 15000; connection.readTimeout = 95000; connection.instanceFollowRedirects = false; connection.useCaches = false
                connection.setRequestProperty("Accept", "application/json")
                if (capability != null) { connection.requestMethod = "POST"; connection.setRequestProperty("Authorization", "Bearer $capability"); connection.doOutput = true; connection.setFixedLengthStreamingMode(0); connection.outputStream.close() }
                val code = connection.responseCode
                check(code !in listOf(401,403,410)) { "Доступ к заявке закончился или отозван. Откройте бота." }
                check(code == 200 && connection.contentType.orEmpty().substringBefore(';') == "application/json") { "Сервис обновления вернул неподходящий ответ" }
                return JSONObject(connection.inputStream.use { String(ArchiveReader.bounded(it, 1_048_576), Charsets.UTF_8) })
            } catch (e: java.io.IOException) { last = e }
            finally { connection.disconnect() }
        }
        throw last ?: IllegalStateException("Сервис обновлений недоступен")
    }
}
