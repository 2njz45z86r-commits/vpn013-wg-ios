// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import org.amnezia.awg.backend.GoBackend
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** An explicit overlay. OFF keeps each server's original policy and config. */
object ApplicationRoutingStore {
    data class Selection(val mode: String = "unchanged", val only: Set<String> = emptySet(), val bypass: Set<String> = emptySet()) {
        val active: Set<String> get() = if (mode == "only") only else if (mode == "bypass") bypass else emptySet()
        fun plan(): GoBackend.ApplicationRoute? = if (mode == "unchanged") null else GoBackend.ApplicationRoute(mode, active)
    }
    private fun valid(value: Selection) {
        require(value.mode in setOf("unchanged", "only", "bypass"))
        for (apps in listOf(value.only, value.bypass)) require(apps.size <= 200 && apps.all {
            it.length <= 255 && it.matches(Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+"))
        })
        if (value.mode != "unchanged") require(value.active.isNotEmpty()) { "Выберите хотя бы одно приложение" }
    }
    fun read(document: JSONObject, reference: String): Selection {
        val raw = document.optJSONObject("applicationRouting")?.optJSONObject(reference) ?: return Selection()
        fun apps(name: String): Set<String> {
            val values = raw.getJSONArray(name); require(values.length() <= 200)
            val result = (0 until values.length()).map { values.getString(it) }
            require(result.toSet().size == result.size); return result.toSet()
        }
        return Selection(raw.getString("mode"), apps("only"), apps("bypass")).also(::valid)
    }
    fun read(vault: PrivateVault, reference: String): Selection = read(vault.read(), reference)
    fun reference(section: String, id: String): String {
        require(section in setOf("AMNEZIAWG", "HAPP", "INCY", "BLACKTEMPLE"))
        require(UUID.fromString(id).toString() == id)
        return "$section:$id"
    }
    /** Caller holds OfflineChanges; the entire selected set validates before one atomic write. */
    fun save(vault: PrivateVault, section: String, ids: Set<String>, selection: Selection) {
        require(ids.isNotEmpty() && ids.size <= 300); valid(selection)
        val references = ids.map { reference(section, it) }
        vault.edit { document ->
            val records = document.optJSONObject(if (section == "AMNEZIAWG") "profiles" else "proxyProfiles") ?: error("Профили не найдены")
            for (id in ids) {
                val record = records.optJSONObject(id) ?: error("Список профилей изменился. Выберите серверы заново.")
                check(record.getString("id") == id && (section == "AMNEZIAWG" || record.getString("section") == section))
            }
            val settings = document.optJSONObject("applicationRouting") ?: JSONObject().also { document.put("applicationRouting", it) }
            require(settings.length() + references.count { !settings.has(it) } <= 1200) { "Достигнут предел сохранённых правил" }
            for (reference in references) settings.put(reference, JSONObject().put("mode", selection.mode)
                .put("only", JSONArray(selection.only.sorted())).put("bypass", JSONArray(selection.bypass.sorted())))
        }
    }
    fun wireGuard(vault: PrivateVault, name: String): GoBackend.ApplicationRoute? {
        val document = vault.read()
        val records = document.getJSONObject("profiles")
        val matches = records.keys().asSequence().map { records.getJSONObject(it) }.filter { it.getString("name") == name }.toList()
        check(matches.size <= 1)
        val record = matches.firstOrNull() ?: return null
        return read(document, reference("AMNEZIAWG", record.getString("id"))).plan()
    }
    fun effectiveKey(document: JSONObject, reference: String, included: Set<String>, excluded: Set<String>, ownPackage: String): String {
        val overlay = read(document, reference).plan()
        val allowed = if (overlay == null) included else if (overlay.mode() == "only") overlay.packages() + ownPackage else emptySet()
        val denied = if (overlay == null) excluded else if (overlay.mode() == "bypass") overlay.packages() - ownPackage else emptySet()
        return allowed.sorted().joinToString("\n", "only:") + "\n" + denied.sorted().joinToString("\n", "bypass:")
    }
    fun candidateKey(document: JSONObject, section: String, id: String, ownPackage: String): String {
        if (section == "AMNEZIAWG") {
            val record = ProfileRegistry.find(document.getJSONObject("profiles"), id)
            val config = ProfileRegistry.parse(record.getString("config"))
            return effectiveKey(document, reference(section, record.getString("id")),
                config.`interface`.includedApplications, config.`interface`.excludedApplications, ownPackage) + "\nru:true"
        }
        val baseline = ProxyRouting.read(document, id)
        val included = if (baseline.mode == "only") baseline.packages + ownPackage else emptySet()
        val excluded = if (baseline.mode == "except") baseline.packages - ownPackage else emptySet()
        return effectiveKey(document, reference(section, id), included, excluded, ownPackage) + "\nru:${baseline.russianDirect}"
    }
}
