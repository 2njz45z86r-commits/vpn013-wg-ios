// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import org.json.JSONArray
import org.json.JSONObject

/** A JSON document is data, never a runnable core configuration. Only typed VLESS leaves survive. */
object ProxyImport {
    private fun invalid(): Nothing = throw IllegalArgumentException("Нужна совместимая VLESS-конфигурация TLS или REALITY")
    private fun fields(value: JSONObject, allowed: Set<String>) {
        if (value.keys().asSequence().any { it !in allowed }) invalid()
    }
    private fun string(value: JSONObject, key: String, fallback: String = ""): String {
        if (!value.has(key)) return fallback
        return value.opt(key) as? String ?: invalid()
    }
    private fun one(value: JSONObject, key: String): JSONObject {
        val array = value.optJSONArray(key) ?: invalid()
        if (array.length() != 1) invalid()
        return array.optJSONObject(0) ?: invalid()
    }
    fun parse(text: String, section: ProxyProfile.Section): List<ProxyProfile> {
        if (text.toByteArray(Charsets.UTF_8).size > 1_048_576) invalid()
        val trimmed = text.trim()
        if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return ProxyProfile.parseList(text, section)
        // Bound parser recursion before allocating JSONObject/JSONArray on a caller-supplied document.
        var depth = 0; var quoted = false; var escaped = false
        for (character in trimmed) {
            if (quoted) {
                if (escaped) escaped = false
                else if (character == '\\') escaped = true
                else if (character == '"') quoted = false
            } else when (character) {
                '"' -> quoted = true
                '{', '[' -> { depth++; if (depth > 24) invalid() }
                '}', ']' -> { depth--; if (depth < 0) invalid() }
            }
        }
        if (depth != 0 || quoted) invalid()
        try {
            val documents = if (trimmed.startsWith('[')) JSONArray(trimmed) else JSONArray().put(JSONObject(trimmed))
            if (documents.length() !in 1..100) invalid()
            val result = mutableListOf<ProxyProfile>()
            for (i in 0 until documents.length()) {
                val document = documents.optJSONObject(i) ?: invalid()
                val outbounds = document.optJSONArray("outbounds") ?: JSONArray().put(document)
                if (outbounds.length() !in 1..100) invalid()
                for (j in 0 until outbounds.length()) {
                    val outbound = outbounds.optJSONObject(j) ?: invalid()
                    val protocol = string(outbound, "protocol")
                    if (protocol in setOf("freedom", "blackhole", "dns")) continue
                    if (protocol != "vless") invalid()
                    result.add(fromOutbound(outbound, section))
                    if (result.size > 100) invalid()
                }
            }
            if (result.isEmpty()) invalid()
            return result.toList()
        } catch (_: org.json.JSONException) { invalid() }
    }
    private fun fromOutbound(outbound: JSONObject, section: ProxyProfile.Section): ProxyProfile {
        fields(outbound, setOf("tag", "protocol", "settings", "streamSettings"))
        val settings = outbound.optJSONObject("settings") ?: invalid()
        fields(settings, setOf("vnext"))
        val node = one(settings, "vnext")
        fields(node, setOf("address", "port", "users"))
        val user = one(node, "users")
        fields(user, setOf("id", "encryption", "flow", "level", "email"))
        if (user.has("level") && user.opt("level") != 0) invalid()
        val stream = outbound.optJSONObject("streamSettings") ?: invalid()
        val type = string(stream, "network", "tcp")
        val security = string(stream, "security")
        if (type !in setOf("tcp", "ws", "grpc", "xhttp") || security !in setOf("tls", "reality")) invalid()
        val transportKey = mapOf("ws" to "wsSettings", "grpc" to "grpcSettings", "xhttp" to "xhttpSettings")[type]
        fields(stream, setOfNotNull("network", "security", if (security == "tls") "tlsSettings" else "realitySettings", transportKey))
        val tls = stream.optJSONObject(if (security == "tls") "tlsSettings" else "realitySettings") ?: invalid()
        fields(tls, setOf("serverName", "fingerprint", "alpn", "allowInsecure", "publicKey", "shortId", "spiderX", "mldsa65Verify", "show"))
        if (tls.has("allowInsecure") && tls.opt("allowInsecure") != false) invalid()
        if (tls.has("show") && tls.opt("show") != false) invalid()
        val query = linkedMapOf("type" to type, "security" to security,
            "encryption" to string(user, "encryption", "none"))
        for ((json, uri) in listOf("serverName" to "sni", "fingerprint" to "fp", "publicKey" to "pbk",
                "shortId" to "sid", "spiderX" to "spx", "mldsa65Verify" to "pqv")) {
            if (tls.has(json)) query[uri] = string(tls, json)
        }
        if (user.has("flow")) query["flow"] = string(user, "flow")
        tls.optJSONArray("alpn")?.let { alpn ->
            if (alpn.length() !in 1..3) invalid()
            query["alpn"] = (0 until alpn.length()).map { alpn.opt(it) as? String ?: invalid() }.joinToString(",")
        }
        if (tls.has("alpn") && tls.optJSONArray("alpn") == null) invalid()
        transportKey?.let { key ->
            val transport = stream.optJSONObject(key) ?: JSONObject()
            when (type) {
                "ws" -> {
                    fields(transport, setOf("path", "headers"))
                    query["path"] = string(transport, "path", "/")
                    transport.optJSONObject("headers")?.let { headers ->
                        fields(headers, setOf("Host")); if (headers.has("Host")) query["host"] = string(headers, "Host")
                    }
                    if (transport.has("headers") && transport.optJSONObject("headers") == null) invalid()
                }
                "grpc" -> {
                    fields(transport, setOf("serviceName", "authority", "multiMode"))
                    query["serviceName"] = string(transport, "serviceName")
                    if (transport.has("authority")) query["authority"] = string(transport, "authority")
                    if (transport.has("multiMode") && transport.opt("multiMode") !is Boolean) invalid()
                    query["mode"] = if (transport.optBoolean("multiMode", false)) "multi" else "gun"
                }
                "xhttp" -> {
                    fields(transport, setOf("path", "host", "mode"))
                    query["path"] = string(transport, "path", "/"); query["mode"] = string(transport, "mode", "auto")
                    if (transport.has("host")) query["host"] = string(transport, "host")
                }
            }
            if (stream.has(key) && stream.optJSONObject(key) == null) invalid()
        }
        val host = string(node, "address").let { if (it.contains(':')) "[$it]" else it }
        val port = node.opt("port")
        if (port !is Number || port.toDouble() != port.toInt().toDouble()) invalid()
        val encoded = query.entries.joinToString("&") { percent(it.key) + "=" + percent(it.value) }
        return ProxyProfile.parse("vless://${percent(string(user, "id"))}@$host:${port.toInt()}?$encoded#${percent(string(outbound, "tag", section.name))}", section)
    }
    private fun percent(value: String): String = java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20")
}
