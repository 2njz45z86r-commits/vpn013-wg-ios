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
        val profiles = ProxyProfile.parseList(text, section)
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
        return ProxyProfile.parse(uri, ProxyProfile.Section.valueOf(record.getString("section")))
    }

    private fun percent(value: String): String = java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20")
}
