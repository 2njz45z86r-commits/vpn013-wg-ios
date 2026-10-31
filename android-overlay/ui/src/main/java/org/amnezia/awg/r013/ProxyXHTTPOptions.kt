// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/** Pinned client transport subset, matching the iPhone model. It rebuilds
 * download transports too; imported socket/listener/log/API fields never run. */
object ProxyXHTTPOptions {
    private fun invalid(): Nothing = throw IllegalArgumentException("Параметры XHTTP повреждены или не поддерживаются")
    private val ranges = mapOf("xPaddingBytes" to 65_536L, "scMaxEachPostBytes" to 4_194_304L,
        "scMinPostsIntervalMs" to 600_000L, "scStreamUpServerSecs" to 3_600L,
        "uplinkChunkSize" to 1_048_576L, "sessionIDLength" to 256L)
    private val flags = setOf("noGRPCHeader", "noSSEHeader", "xPaddingObfsMode")
    private val serverNumbers = setOf("scMaxBufferedPosts", "serverMaxHeaderBytes")
    private val strings = setOf("xPaddingKey", "xPaddingHeader", "xPaddingPlacement", "xPaddingMethod", "uplinkHTTPMethod",
        "sessionIDPlacement", "sessionIDKey", "seqPlacement", "seqKey", "uplinkDataPlacement", "uplinkDataKey", "sessionIDTable")
    private val muxLimits = mapOf("maxConcurrency" to 1024L, "maxConnections" to 64L, "cMaxReuseTimes" to 1_000_000L,
        "hMaxRequestTimes" to 1_000_000L, "hMaxReusableSecs" to 86_400L, "hKeepAlivePeriod" to 3_600L)
    private fun text(value: Any?, limit: Int = 1024): String {
        val result = value as? String ?: invalid()
        if (result.toByteArray(Charsets.UTF_8).size > limit || result.any { it.code < 32 || it.code == 127 }) invalid()
        return result
    }
    private fun integer(value: Any?, signed: Boolean = false): Long {
        val number = value as? Number ?: invalid()
        val n = number.toDouble()
        if (!n.isFinite() || n != kotlin.math.floor(n) || n < (if (signed) -1 else 0) || n > 1_000_000_000) invalid()
        return n.toLong()
    }
    private fun bounds(value: Any?): Pair<Long, Long> {
        if (value is Number) return integer(value).let { it to it }
        val raw = value as? String ?: invalid()
        if (!raw.matches(Regex("(?:0|[1-9][0-9]{0,9})(?:-(?:0|[1-9][0-9]{0,9}))?"))) invalid()
        val parts = raw.split('-'); val first = parts.first().toLongOrNull() ?: invalid()
        val last = parts.last().toLongOrNull() ?: invalid()
        if (first > last || last > 1_000_000_000) invalid()
        return first to last
    }
    private fun json(raw: String): JSONObject {
        if (raw.toByteArray(Charsets.UTF_8).size > 16_384) invalid()
        var depth = 0; var quoted = false; var escaped = false
        for (c in raw) {
            if (quoted) {
                if (escaped) escaped = false else if (c == '\\') escaped = true else if (c == '"') quoted = false
            } else when (c) {
                '"' -> quoted = true
                '{', '[' -> { depth++; if (depth > 16) invalid() }
                '}', ']' -> { depth--; if (depth < 0) invalid() }
            }
        }
        if (quoted || depth != 0) invalid()
        val decoder = JSONTokener(raw)
        val result = decoder.nextValue() as? JSONObject ?: invalid()
        if (decoder.nextClean() != '\u0000') invalid()
        return result
    }
    private fun host(value: String) {
        // Reuse the URI model's host validation without performing DNS.
        val address = if (value.contains(':')) "[$value]" else value
        ProxyProfile.parse("vless://00000000-0000-4000-8000-000000000001@$address:443?security=tls", ProxyProfile.Section.INCY)
    }
    fun checked(profile: ProxyProfile): ProxyProfile {
        if (profile.transport == "xhttp") settings(profile)
        return profile
    }
    fun additionalHosts(profile: ProxyProfile): Set<String> {
        if (profile.transport != "xhttp") return emptySet()
        val download = settings(profile).optJSONObject("downloadSettings") ?: return emptySet()
        return setOf(download.getString("address"))
    }
    fun settings(profile: ProxyProfile): JSONObject {
        return try { settingsChecked(profile) } catch (_: Exception) { invalid() }
    }
    private fun settingsChecked(profile: ProxyProfile): JSONObject {
        require(profile.transport == "xhttp")
        val q = profile.options
        val input = q["extra"]?.takeIf { it.isNotEmpty() }?.let(::json) ?: JSONObject()
        val result = JSONObject()
        for (name in listOf("path", "host", "mode")) {
            val supplied = if (input.has(name)) text(input.get(name), if (name == "path") 2048 else 253) else null
            if (supplied != null && q.containsKey(name) && supplied != q[name]) invalid()
            val value = q[name] ?: supplied ?: if (name == "path") "/" else if (name == "mode") "auto" else ""
            text(value, if (name == "path") 2048 else 253)
            if (name == "host" && value.isNotEmpty()) host(value)
            if (name == "mode" && value !in setOf("auto", "packet-up", "stream-up", "stream-one", "")) invalid()
            if (name != "host" || value.isNotEmpty()) result.put(name, if (name == "mode" && value.isEmpty()) "auto" else value)
            input.remove(name)
        }
        q["x_padding_bytes"]?.let { padding ->
            if (input.has("xPaddingBytes")) {
                val v = input.get("xPaddingBytes")
                val same = v is String && v == padding || v is Number && integer(v).toString() == padding
                if (!same) invalid()
            }
            input.put("xPaddingBytes", padding)
        }
        for (key in input.keys().asSequence().toList()) {
            val value = input.get(key)
            when {
                key in ranges -> {
                    val (low, high) = bounds(value)
                    if (high > ranges.getValue(key) || key == "scMaxEachPostBytes" && low == 0L) invalid()
                    result.put(key, value)
                }
                key in flags -> { if (value !is Boolean) invalid(); result.put(key, value) }
                key in strings -> result.put(key, text(value))
                key in serverNumbers -> { integer(value) /* Server-only fields are inert in this client SDK. */ }
                key == "headers" -> result.put(key, headers(value))
                key == "xmux" -> result.put(key, mux(value))
                key == "downloadSettings" -> result.put(key, download(value, profile.section))
                else -> invalid()
            }
        }
        if (result.toString().toByteArray(Charsets.UTF_8).size > 16_384) invalid()
        return result
    }
    private fun headers(value: Any): JSONObject {
        val source = value as? JSONObject ?: invalid()
        if (source.length() > 32) invalid()
        val result = JSONObject()
        for (key in source.keys()) {
            if (key.isEmpty() || key.length > 128 || !key.matches(Regex("[A-Za-z0-9_.-]+")) || key.equals("host", true)) invalid()
            result.put(key, text(source.get(key)))
        }
        return result
    }
    private fun mux(value: Any): JSONObject {
        val source = value as? JSONObject ?: invalid(); val result = JSONObject()
        for (key in source.keys()) {
            val item = source.get(key)
            if (key == "cMaxLifetimeMs") { if (integer(item) != 0L) invalid(); continue }
            val limit = muxLimits[key] ?: invalid()
            val high = if (key == "hKeepAlivePeriod") integer(item, true) else bounds(item).second
            if (high > limit) invalid()
            result.put(key, item)
        }
        return result
    }
    private fun download(value: Any, section: ProxyProfile.Section): JSONObject {
        val source = value as? JSONObject ?: invalid()
        val allowed = setOf("address", "port", "network", "security", "tlsSettings", "realitySettings", "xhttpSettings", "splithttpSettings")
        if (source.keys().asSequence().any { it !in allowed }) invalid()
        val address = text(source.opt("address"), 253); host(address)
        val port = integer(source.opt("port")); if (port !in 1L..65535L) invalid()
        if (source.optString("network") !in setOf("xhttp", "splithttp")) invalid()
        val http = source.optJSONObject("xhttpSettings") ?: source.optJSONObject("splithttpSettings") ?: invalid()
        if (http.has("downloadSettings") || http.has("extra")) invalid()
        val stream = JSONObject(source.toString()).apply { remove("address"); remove("port") }
        val user = JSONObject().put("id", "00000000-0000-4000-8000-000000000001").put("encryption", "none")
        val node = JSONObject().put("address", address).put("port", port).put("users", JSONArray().put(user))
        val outbound = JSONObject().put("protocol", "vless").put("settings", JSONObject().put("vnext", JSONArray().put(node))).put("streamSettings", stream)
        val profile = ProxyImport.fromOutbound(outbound, section)
        return ProxyConfiguration.outbound(profile).getJSONObject("streamSettings").put("address", address).put("port", port)
    }
}
