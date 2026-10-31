// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import org.json.JSONObject
import java.util.UUID

/** Separate namespace in the same authenticated vault; AWG records are never rewritten. */
class ProxyRegistry(private val vault: PrivateVault) {
    data class Record(val id: String, val profile: ProxyProfile)

    fun list(section: ProxyProfile.Section): List<Record> {
        val records = vault.read().optJSONObject("proxyProfiles") ?: return emptyList()
        return records.keys().asSequence().map { key -> records.getJSONObject(key) }
            .filter { it.getString("section") == section.name }
            .map { record -> Record(record.getString("id"), decode(record)) }.toList()
    }

    /** Parse everything before entering the vault transaction: invalid imports preserve prior data. */
    fun importText(section: ProxyProfile.Section, text: String): List<String> {
        val profiles = ProxyImport.parse(text, section)
        return vault.edit { document ->
            val records = document.optJSONObject("proxyProfiles") ?: JSONObject().also { document.put("proxyProfiles", it) }
            check(records.length() + profiles.size <= 300) { "Достигнут предел: 300 профилей" }
            profiles.map { profile ->
                val id = UUID.randomUUID().toString()
                records.put(id, encode(id, profile)); id
            }
        }
    }

    fun delete(id: String) {
        UUID.fromString(id)
        vault.edit { document -> document.optJSONObject("proxyProfiles")?.remove(id); Unit }
    }
    data class Source(val id: String, val section: ProxyProfile.Section, val url: String, val hwid: String)
    fun sources(): List<Source> {
        val sources = vault.read().optJSONObject("proxySources") ?: return emptyList()
        return sources.keys().asSequence().map { id -> val s = sources.getJSONObject(id)
            Source(id, ProxyProfile.Section.valueOf(s.getString("section")), s.getString("url"), s.getString("hwid")) }.toList()
    }
    fun source(section: ProxyProfile.Section, url: String): Source {
        val uri = java.net.URI(url)
        require(uri.scheme.equals("https", true) && !uri.host.isNullOrBlank() && uri.rawUserInfo == null && uri.rawFragment == null && url.length <= 8192) { "Нужна HTTPS-ссылка подписки без имени пользователя и пароля" }
        sources().firstOrNull { it.section == section && it.url == url }?.let { return it }
        return vault.edit { document ->
            val sources = document.optJSONObject("proxySources") ?: JSONObject().also { document.put("proxySources", it) }
            check(sources.length() < 30) { "Достигнут предел подписок" }
            val origin = uri.host.lowercase(java.util.Locale.ROOT) + ":" + (if (uri.port == -1) 443 else uri.port)
            val origins = document.optJSONObject("proxyOrigins") ?: JSONObject().also { document.put("proxyOrigins", it) }
            val hash = ProfileRegistry.digest(origin)
            val hwid = origins.optString(hash).takeIf { it.isNotEmpty() } ?: run {
                check(origins.length() < 256) { "Достигнут предел источников подписок" }
                UUID.randomUUID().toString().also { origins.put(hash, it) }
            }
            val id = UUID.randomUUID().toString()
            sources.put(id, JSONObject().put("section", section.name).put("url", url).put("hwid", hwid))
            Source(id, section, url, hwid)
        }
    }
    /** The provider's new complete roster replaces only this source's managed members. */
    fun reconcile(source: Source, body: String): Int {
        val profiles = ProxyImport.parse(body, source.section)
        return vault.edit { document ->
            val sources = document.getJSONObject("proxySources")
            val owned = sources.getJSONObject(source.id)
            check(owned.getString("url") == source.url && owned.getString("section") == source.section.name)
            val records = document.optJSONObject("proxyProfiles") ?: JSONObject().also { document.put("proxyProfiles", it) }
            val previous = owned.optJSONObject("members") ?: JSONObject()
            val next = JSONObject()
            val additions = linkedMapOf<String, JSONObject>()
            for (profile in profiles) {
                val identity = ProfileRegistry.digest(encode("", profile).toString())
                val id = previous.optString(identity).takeIf { it.isNotEmpty() } ?: UUID.randomUUID().toString()
                next.put(identity, id); additions[id] = encode(id, profile).put("source", source.id)
            }
            val retired = records.keys().asSequence().filter { records.getJSONObject(it).optString("source") == source.id }.toList()
            check(records.length() - retired.size + additions.size <= 300) { "Достигнут предел: 300 профилей" }
            retired.forEach { records.remove(it) }; additions.forEach { (id, profile) -> records.put(id, profile) }
            owned.put("members", next).put("updatedAt", System.currentTimeMillis()); additions.size
        }
    }

    private fun encode(id: String, p: ProxyProfile): JSONObject = JSONObject()
        .put("id", id).put("section", p.section.name).put("name", p.name)
        .put("host", p.host).put("port", p.port).put("user", p.userId)
        .put("options", JSONObject(p.options))

    private fun decode(record: JSONObject): ProxyProfile {
        val options = record.getJSONObject("options")
        val encoded = options.keys().asSequence().map { key ->
            percent(key) + "=" + percent(options.getString(key))
        }.joinToString("&")
        val host = record.getString("host").let { if (it.contains(':')) "[$it]" else it }
        val uri = "vless://${record.getString("user")}@$host:${record.getInt("port")}?$encoded#${percent(record.getString("name"))}"
        return ProxyImport.parse(uri, ProxyProfile.Section.valueOf(record.getString("section"))).single()
    }

    private fun percent(value: String): String = java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20")
}
