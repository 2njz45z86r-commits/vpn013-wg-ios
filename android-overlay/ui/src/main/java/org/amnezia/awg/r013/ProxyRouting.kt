// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.net.IpPrefix
import android.net.VpnService
import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject

object ProxyRouting {
    data class Rules(val mode: String = "all", val packages: Set<String> = emptySet(), val russianDirect: Boolean = true)
    fun read(vault: PrivateVault, id: String): Rules = read(vault.read(), id)
    fun read(document: JSONObject, id: String): Rules {
        val rule = document.optJSONObject("proxyRouting")?.optJSONObject(id) ?: return Rules()
        val apps = rule.optJSONArray("packages") ?: JSONArray()
        check(apps.length() <= 200)
        val mode = rule.getString("mode"); check(mode in listOf("all", "only", "except"))
        return Rules(mode, (0 until apps.length()).map { apps.getString(it) }.toSet(), rule.optBoolean("russianDirect", true))
    }
    fun effective(vault: PrivateVault, section: String, id: String): Rules {
        val baseline = read(vault, id)
        val overlay = ApplicationRoutingStore.read(vault, ApplicationRoutingStore.reference(section, id)).plan() ?: return baseline
        return baseline.copy(mode = if (overlay.mode() == "only") "only" else "except", packages = overlay.packages())
    }
    fun save(vault: PrivateVault, id: String, rules: Rules) {
        require(rules.mode in listOf("all", "only", "except") && rules.packages.size <= 200)
        require(rules.packages.all { it.length <= 255 && it.matches(Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")) })
        vault.edit { document ->
            val settings = document.optJSONObject("proxyRouting") ?: JSONObject().also { document.put("proxyRouting", it) }
            settings.put(id, JSONObject().put("mode", rules.mode).put("packages", JSONArray(rules.packages.sorted())).put("russianDirect", rules.russianDirect))
        }
    }
    fun apply(context: Context, builder: VpnService.Builder, rules: Rules) {
        if (rules.mode == "only") {
            check(rules.packages.isNotEmpty()) { "Выберите хотя бы одно приложение" }
            for (name in rules.packages + context.packageName) builder.addAllowedApplication(name)
        } else if (rules.mode == "except") {
            for (name in rules.packages - context.packageName) builder.addDisallowedApplication(name)
        }
        if (rules.russianDirect && Build.VERSION.SDK_INT >= 33) {
            val prefixes = RussianIPPolicy.get(context.assets.open("ru-networks.cidr"))
            for (prefix in prefixes) builder.excludeRoute(IpPrefix(prefix.address(), prefix.bits()))
        }
    }
}
