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
        if (text.toByteArray(Charsets.UTF_8).size > 8_388_608) invalid()
        val trimmed = text.trim()
        if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return ProxyProfile.parseList(text, section) { raw ->
            ProxyXHTTPOptions.checked(ProxyProfile.parseTransportURI(raw, section))
        }
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
            // Only collapse the provider's documented failover bundle. Ordinary
            // multi-document Xray input may legitimately contain several nodes.
            val reserveDescriptions = setOf("Автоматический резерв", "Россия напрямую · Автоматический резерв", "Маршрутизация сайтов · Автоматический резерв")
            fun description(index: Int): String = documents.optJSONObject(index)?.optJSONObject("meta")
                ?.optString("serverDescription", "")?.substringBefore(". Тест на ") ?: ""
            val autoDescription = description(0)
            val autoIsProvider = autoDescription == "Автовыбор по задержке" ||
                reserveDescriptions.any { autoDescription == "Автовыбор по задержке · $it" }
            val providerBundle = documents.length() > 1 && autoIsProvider &&
                documents.optJSONObject(0)?.optString("remarks") == "⚡ Авто · минимальный пинг" &&
                (1 until documents.length()).all { index ->
                    val doc = documents.optJSONObject(index)
                    val outbounds = doc?.optJSONArray("outbounds")
                    val primary = outbounds?.optJSONObject(0)
                    description(index) in reserveDescriptions && doc != null && outbounds != null && primary != null &&
                        primary.optString("protocol") == "vless" && primary.optString("tag") == doc.optString("remarks") &&
                        (1 until outbounds.length()).all { j ->
                            val outbound = outbounds.optJSONObject(j)
                            outbound != null && (outbound.optString("protocol") != "vless" ||
                                listOf("backup-", "lte-entry-").any { outbound.optString("tag").startsWith(it) })
                        }
                }
            val result = mutableListOf<ProxyProfile>()
            for (i in 0 until documents.length()) {
                val document = documents.optJSONObject(i) ?: invalid()
                val outbounds = document.optJSONArray("outbounds") ?: JSONArray().put(document)
                if (outbounds.length() !in 1..100) invalid()
                val remark = document.optString("remarks", "")
                val automatic = remark == "⚡ Авто · минимальный пинг"
                // Multi-entry subscriptions include an automatic aggregate and
                // copies of all backup nodes in every named entry. The named
                // entry's first VLESS node is its primary server.
                if (providerBundle && automatic) continue
                var primaryAdded = false
                for (j in 0 until outbounds.length()) {
                    val outbound = outbounds.optJSONObject(j) ?: invalid()
                    val protocol = string(outbound, "protocol")
                    if (protocol in setOf("freedom", "blackhole", "dns", "loopback")) continue
                    if (protocol != "vless") invalid()
                    if (providerBundle && primaryAdded) continue
                    result.add(fromOutbound(outbound, section))
                    primaryAdded = true
                    if (result.size > 100) invalid()
                }
            }
            if (result.isEmpty()) invalid()
            return result.toList()
        } catch (_: org.json.JSONException) { invalid() }
    }
    internal fun fromOutbound(outbound: JSONObject, section: ProxyProfile.Section): ProxyProfile {
        fields(outbound, setOf("tag", "protocol", "settings", "streamSettings"))
        val settings = outbound.optJSONObject("settings") ?: invalid()
        fields(settings, setOf("vnext"))
        val node = one(settings, "vnext")
        fields(node, setOf("address", "port", "users"))
        val user = one(node, "users")
        fields(user, setOf("id", "encryption", "flow", "level", "email"))
        if (user.has("level") && user.opt("level") != 0) invalid()
        val stream = outbound.optJSONObject("streamSettings") ?: invalid()
        val rawType = string(stream, "network", "tcp").lowercase(java.util.Locale.ROOT)
        val type = when (rawType) { "raw" -> "tcp"; "splithttp" -> "xhttp"; else -> rawType }
        val security = string(stream, "security").lowercase(java.util.Locale.ROOT)
        if (type !in setOf("tcp", "ws", "grpc", "xhttp") || security !in setOf("tls", "reality")) invalid()
        val transportKey = when (type) {
            "tcp" -> if (stream.has("rawSettings")) "rawSettings" else "tcpSettings"
            "xhttp" -> if (stream.has("splithttpSettings")) "splithttpSettings" else "xhttpSettings"
            "ws" -> "wsSettings"
            else -> "grpcSettings"
        }
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
        transportKey.let { key ->
            val transport = stream.optJSONObject(key) ?: JSONObject()
            when (type) {
                "tcp" -> {
                    fields(transport, setOf("header"))
                    if (transport.has("header")) {
                        val header = transport.optJSONObject("header") ?: invalid()
                        fields(header, setOf("type"))
                        if (string(header, "type", "none") != "none") invalid()
                    }
                }
                "ws" -> {
                    fields(transport, setOf("path", "headers", "host"))
                    query["path"] = string(transport, "path", "/")
                    if (transport.has("host")) query["host"] = string(transport, "host")
                    transport.optJSONObject("headers")?.let { headers ->
                        fields(headers, setOf("Host")); if (headers.has("Host")) {
                            val host = string(headers, "Host")
                            if (query.containsKey("host") && query["host"] != host) invalid()
                            query["host"] = host
                        }
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
                    query["path"] = string(transport, "path", "/"); query["mode"] = string(transport, "mode", "auto")
                    if (transport.has("host")) query["host"] = string(transport, "host")
                    val extra = JSONObject(transport.toString()).apply { remove("path"); remove("host"); remove("mode"); remove("xPaddingBytes") }
                    if (extra.length() > 0) query["extra"] = extra.toString()
                    if (transport.has("xPaddingBytes")) {
                        val padding = transport.opt("xPaddingBytes")
                        query["x_padding_bytes"] = when (padding) {
                            is String -> padding
                            is Int -> padding.toString()
                            is Long -> padding.toString()
                            else -> invalid()
                        }
                    }
                }
            }
            if (stream.has(key) && stream.optJSONObject(key) == null) invalid()
        }
        val host = string(node, "address").let { if (it.contains(':')) "[$it]" else it }
        val port = node.opt("port")
        if (port !is Number || port.toDouble() != port.toInt().toDouble()) invalid()
        val encoded = query.entries.joinToString("&") { percent(it.key) + "=" + percent(it.value) }
        return ProxyXHTTPOptions.checked(ProxyProfile.parseTransportURI("vless://${percent(string(user, "id"))}@$host:${port.toInt()}?$encoded#${percent(string(outbound, "tag", section.name))}", section))
    }
    private fun percent(value: String): String = java.net.URLEncoder.encode(value, "UTF-8").replace("+", "%20")
}
