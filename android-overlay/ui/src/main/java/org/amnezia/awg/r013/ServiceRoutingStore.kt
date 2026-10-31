// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import org.amnezia.awg.backend.GoBackend
import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** Atomic per-owned-profile service selection, independent of imported configuration. */
object ServiceRoutingStore {
    fun read(document: JSONObject, reference: String): ServiceRoutingCatalog.Selection {
        val raw = document.optJSONObject("serviceRouting")?.optJSONObject(reference) ?: return ServiceRoutingCatalog.Selection()
        fun ids(key: String): Set<String> {
            val array = raw.getJSONArray(key); require(array.length() <= 412)
            val values = (0 until array.length()).map { array.getString(it) }
            require(values.size == values.toSet().size)
            return values.toSet()
        }
        val mode = raw.getString("mode"); require(mode in setOf("unchanged", "only", "bypass"))
        return ServiceRoutingCatalog.Selection(mode, ids("only"), ids("bypass"))
    }
    fun save(vault: PrivateVault, section: String, ids: Set<String>, value: ServiceRoutingCatalog.Selection, catalog: ServiceRoutingCatalog) {
        require(ids.isNotEmpty() && ids.size <= 300)
        val plan = catalog.resolve(value)
        if (plan != null && section != "AMNEZIAWG") validateRoutes(plan, listOf("1.1.1.1/32"))
        val references = ids.map { ApplicationRoutingStore.reference(section, it) }
        vault.edit { document ->
            val profiles = document.getJSONObject(if (section == "AMNEZIAWG") "profiles" else "proxyProfiles")
            for (id in ids) {
                val record = profiles.optJSONObject(id) ?: error("Список профилей изменился. Выберите серверы заново.")
                check(record.getString("id") == id && (section == "AMNEZIAWG" || record.getString("section") == section))
                if (section == "AMNEZIAWG" && plan != null) {
                    fun validate(config: String) { val parsed = ProfileRegistry.parse(config); require(parsed.peers.size == 1 && parsed.peers[0].endpoint.isPresent && parsed.peers[0].allowedIps.any { it.address.address.size == 4 && it.mask == 0 }) { "Нужен один сервер с полным IPv4-туннелем" }; validateRoutes(plan, parsed.`interface`.dnsServers.filter { it.address.size == 4 }.map { "${it.hostAddress}/32" }) }
                    validate(record.getString("config"))
                    record.optJSONArray("members")?.let { members -> for (i in 0 until members.length()) validate(members.getJSONObject(i).getString("config")) }
                }
            }
            val all = document.optJSONObject("serviceRouting") ?: JSONObject().also { document.put("serviceRouting", it) }
            require(all.length() + references.count { !all.has(it) } <= 1200)
            for (ref in references) all.put(ref, JSONObject().put("mode", value.mode)
                .put("only", JSONArray(value.only.sorted())).put("bypass", JSONArray(value.bypass.sorted())))
        }
    }
    fun validateRoutes(plan: ServiceRoutingCatalog.Plan, dns: List<String>) {
        try {
            val selected = ServiceIPv4Routes.subtract(plan.ipv4, dns)
            if (plan.mode == "bypass" && android.os.Build.VERSION.SDK_INT < 33) ServiceIPv4Routes.calculate(selected, true)
            else ServiceIPv4Routes.calculate(selected, false)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Не удалось подготовить маршруты. Уменьшите число выбранных сервисов. Прежние правила сохранены.", error)
        }
    }
    fun plan(document: JSONObject, reference: String, catalog: ServiceRoutingCatalog): ServiceRoutingCatalog.Plan? =
        catalog.resolve(read(document, reference))
    fun activePlan(document: JSONObject, reference: String, context: Context): ServiceRoutingCatalog.Plan? {
        val selection = read(document, reference)
        if (selection.mode == "unchanged") return null
        return ServiceRoutingCatalog.shared(context).resolve(selection)
    }
    fun wireGuard(vault: PrivateVault, name: String, context: Context): GoBackend.ServiceRoute? {
        val document = vault.read()
        val records = document.getJSONObject("profiles")
        val matches = records.keys().asSequence().map { records.getJSONObject(it) }.filter { it.getString("name") == name }.toList()
        check(matches.size <= 1)
        val record = matches.firstOrNull() ?: return null
        val plan = activePlan(document, ApplicationRoutingStore.reference("AMNEZIAWG", record.getString("id")), context) ?: return null
        return GoBackend.ServiceRoute(plan.mode, plan.ipv4)
    }
    fun key(document: JSONObject, reference: String, context: Context): String {
        val plan = activePlan(document, reference, context) ?: return "service:unchanged"
        return ServiceIPv4Routes.calculate(plan.ipv4, false).joinToString("\n", "service:${plan.mode}:\n")
    }}




