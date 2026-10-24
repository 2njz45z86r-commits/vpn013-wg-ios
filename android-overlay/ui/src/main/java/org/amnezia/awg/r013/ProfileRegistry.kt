// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Context
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.config.Config
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.util.UUID

/** Stable profile identities and immutable Auto snapshots inside one vault. */
class ProfileRegistry private constructor(context: Context) {
    val vault = PrivateVault(context)
    private val packageName = context.packageName
    fun names(): Set<String> = records().map { it.getString("name") }.toSet()
    fun records(): List<JSONObject> = vault.read().getJSONObject("profiles").let { p -> p.keys().asSequence().map { p.getJSONObject(it) }.toList() }
    fun record(name: String): JSONObject = records().singleOrNull { it.getString("name") == name } ?: error("Профиль не найден")
    fun config(name: String): Config = parse(record(name).getString("config"))
    fun isAuto(name: String): Boolean = records().any { it.getString("name") == name && it.has("members") }
    fun members(name: String): List<Pair<String, Config>> {
        val members = record(name).optJSONArray("members") ?: return emptyList()
        return (0 until members.length()).map { members.getJSONObject(it).let { it.getString("name") to parse(it.getString("config")) } }
    }
    fun create(name: String, config: Config) { vault.edit { d -> add(d.getJSONObject("profiles"), name, config) } }
    fun delete(name: String) { vault.edit { d -> val p = d.getJSONObject("profiles"); p.remove(find(p, name).getString("id")) }; Unit }
    fun rename(name: String, replacement: String) { vault.edit { d -> val p = d.getJSONObject("profiles")
        require(validName(replacement) && p.keys().asSequence().none { p.getJSONObject(it).getString("name") == replacement }) { "Такое имя уже есть или содержит недопустимые символы" }
        find(p, name).put("name", replacement) }; Unit }
    fun save(name: String, config: Config) { vault.edit { d -> val r = find(d.getJSONObject("profiles"), name)
        check(!r.has("members")) { "Чтобы изменить состав Авто, создайте его заново" }; r.put("config", config.toAwgQuickString()) }; Unit }
    fun createAuto(): String = vault.edit { d ->
        val profiles = d.getJSONObject("profiles")
        val sources = profiles.keys().asSequence().map { profiles.getJSONObject(it) }.filter { !it.has("members") }.sortedBy { it.getString("name") }.toList()
        require(sources.size in 1..30) { "Для Авто нужно от 1 до 30 обычных профилей" }
        val members = JSONArray()
        for (source in sources) {
            val config = parse(source.getString("config"))
            require(eligible(config)) { "«${source.getString("name")}» не подходит: нужен один сервер с адресом подключения и полным IPv4-туннелем 0.0.0.0/0. Исходный профиль сохранён." }
            members.put(JSONObject().put("sourceID", source.getString("id")).put("name", source.getString("name")).put("config", source.getString("config")))
        }
        profiles.keys().asSequence().filter { profiles.getJSONObject(it).has("members") }.toList().forEach { profiles.remove(it) }
        val name = uniqueName(profiles, "Авто · ${sources.size}")
        add(profiles, name, parse(sources.first().getString("config"))).put("members", members)
        name
    }
    fun importOrdinary(items: List<Pair<String, Config>>): Int = vault.edit { d ->
        val p = d.getJSONObject("profiles"); items.forEach { (name, config) -> add(p, uniqueName(p, name), config) }; items.size
    }
    fun eligible(c: Config): Boolean = c.peers.size == 1 && c.peers[0].endpoint.isPresent &&
        c.peers[0].allowedIps.any { it.address.address.size == 4 && it.mask == 0 } &&
        !c.`interface`.excludedApplications.contains(packageName) &&
        (c.`interface`.includedApplications.isEmpty() || c.`interface`.includedApplications.contains(packageName))
    companion object {
        @Volatile private var instance: ProfileRegistry? = null
        fun get(context: Context): ProfileRegistry = instance ?: synchronized(this) { instance ?: ProfileRegistry(context.applicationContext).also { instance = it } }
        fun parse(text: String): Config { require(text.toByteArray(Charsets.UTF_8).size <= 65_536); return Config.parse(ByteArrayInputStream(text.toByteArray(Charsets.UTF_8))) }
        fun digest(text: String): String = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        fun validName(name: String): Boolean = !Tunnel.isNameInvalid(name) && name.trim() == name && name != "." && name != ".."
        fun find(p: JSONObject, name: String): JSONObject = p.keys().asSequence().map { p.getJSONObject(it) }.singleOrNull { it.getString("name") == name } ?: error("Профиль не найден")
        fun add(p: JSONObject, name: String, config: Config): JSONObject {
            require(validName(name)) { "Недопустимое имя профиля" }
            require(p.keys().asSequence().none { p.getJSONObject(it).getString("name") == name }) { "Профиль с таким именем уже есть" }
            require(p.length() < 300) { "Достигнут предел: 300 профилей" }
            val id = UUID.randomUUID().toString()
            val record = JSONObject().put("id", id).put("name", name).put("config", config.toAwgQuickString())
            p.put(id, record); return record
        }
        fun uniqueName(p: JSONObject, requested: String): String {
            val base = requested.replace(Regex("[^\\p{L}\\p{N} _=+.()·-]"), "_").trim().take(54).ifEmpty { "Профиль" }
            val names = p.keys().asSequence().map { p.getJSONObject(it).getString("name") }.toSet()
            if (base !in names) return base
            return (2..1000).map { "$base ($it)" }.first { it !in names }
        }
    }
}
