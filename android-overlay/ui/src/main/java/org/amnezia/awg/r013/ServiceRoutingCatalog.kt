// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

/** Owner-supplied, release-pinned inert catalog; never executes catalog content. */
class ServiceRoutingCatalog private constructor(
    val groups: List<Group>, private val rules: Map<String, Rules>
) {
    data class Item(val id: String, val name: String, val iconKind: String, val iconText: String, val category: String, val archivedOnly: Boolean)
    data class Group(val id: String, val title: String, val services: List<Item>)
    data class Rules(val ipv4: List<String>, val domains: List<String>)
    data class Selection(val mode: String = "unchanged", val only: Set<String> = emptySet(), val bypass: Set<String> = emptySet()) {
        val active get() = when (mode) { "only" -> only; "bypass" -> bypass; else -> emptySet() }
    }
    data class Plan(val mode: String, val ipv4: List<String>)
    fun supported(id: String): Boolean = rules[id]?.let { it.ipv4.isNotEmpty() && it.domains.isEmpty() } == true
    fun resolve(selection: Selection): Plan? {
        require(selection.mode in setOf("unchanged", "only", "bypass"))
        require((selection.only + selection.bypass).all { it in rules })
        if (selection.mode == "unchanged") return null
        require(selection.active.isNotEmpty() && selection.active.all(::supported)) { "Выберите доступные сервисы с IPv4-маршрутами" }
        val networks = selection.active.flatMap { rules.getValue(it).ipv4 }.distinct().sorted()
        require(networks.size <= 16384)
        return Plan(selection.mode, networks)
    }
    companion object {
        @Volatile private var cached: ServiceRoutingCatalog? = null
        fun shared(context: Context): ServiceRoutingCatalog = cached ?: synchronized(this) { cached ?: load(context.applicationContext).also { cached = it } }
        private val hashes = mapOf(
            "ServiceCatalogUI.json" to "4fbaf9d8985c50b47465034165180393e11546c396027e5ded57e7c53f5475a3",
            "ServiceCatalogRules.json" to "f69a0c79f3077981dca0600657b49a4a085610f76ef407a5f5e0d4874083476b",
            "ServiceCatalogGroups.json" to "a88d52da61ab4e596bb6050843bf11619148de40235a00a8162c660aba1ab882")
        private fun strings(a: JSONArray): List<String> = (0 until a.length()).map { a.getString(it) }
        private fun item(o: JSONObject): Item = Item(o.getString("id"), o.getString("name"), o.getJSONObject("icon").getString("kind"), o.getJSONObject("icon").getString("text"), o.getString("category"), o.getBoolean("archivedOnly"))
        fun load(context: Context): ServiceRoutingCatalog {
            fun read(name: String): JSONObject {
                val bytes = context.assets.open(name).use { it.readBytes() }
                require(bytes.size in 1..2_097_152)
                val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
                require(digest == hashes.getValue(name))
                return JSONObject(String(bytes, Charsets.UTF_8)).also { require(it.getInt("version") == 1) }
            }
            val ui = read("ServiceCatalogUI.json").getJSONArray("services")
            val display = (0 until ui.length()).map { item(ui.getJSONObject(it)) }
            require(display.size == 412 && display.map { it.id }.toSet().size == 412)
            val raw = read("ServiceCatalogRules.json").getJSONObject("services")
            val rules = raw.keys().asSequence().associateWith { key -> raw.getJSONObject(key).let { Rules(strings(it.getJSONArray("ipv4")), strings(it.getJSONArray("domains"))) } }
            require(rules.keys == display.map { it.id }.toSet())
            val rawGroups = read("ServiceCatalogGroups.json").getJSONArray("groups")
            val groups = (0 until rawGroups.length()).map { i -> rawGroups.getJSONObject(i).let { g ->
                val values = g.getJSONArray("services")
                Group(g.getString("id"), g.getString("title"), (0 until values.length()).map { item(values.getJSONObject(it)) })
            } }
            val flattened = groups.flatMap { it.services }
            require(groups.size == 23 && groups.map { it.id }.toSet().size == groups.size && flattened.size == display.size && flattened.toSet() == display.toSet())
            return ServiceRoutingCatalog(groups, rules)
        }
    }
}


