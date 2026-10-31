// SPDX-License-Identifier: MIT
// Shared host-JVM and Android semantic checks. Native TUN traffic is separate.
package org.amnezia.awg.r013

import org.json.JSONObject
import org.json.JSONArray
import java.net.URLEncoder

object ProxyXHTTPModelTests {
    @JvmStatic fun main(args: Array<String>) {
        println("ProxyXHTTPModelTests: ${runChecks()} checks passed; semantic models only; no VPN traffic proof")
    }
    fun runChecks(): Int {
        var checks = 0
        fun check(value: Boolean) { checks++; require(value) { "XHTTP model case $checks failed" } }
        fun canonical(value: Any?): String = when (value) {
            is JSONObject -> value.keys().asSequence().toList().sorted().joinToString(prefix = "{", postfix = "}") { JSONObject.quote(it) + ":" + canonical(value.get(it)) }
            is JSONArray -> (0 until value.length()).joinToString(prefix = "[", postfix = "]") { canonical(value.get(it)) }
            null, JSONObject.NULL -> "null"
            is String -> JSONObject.quote(value)
            is Number, is Boolean -> value.toString()
            else -> error("Unexpected semantic test value")
        }
        val root = "vless://00000000-0000-4000-8000-000000000001@example.invalid:443?security=tls&type=xhttp"
        fun uri(extra: JSONObject) = root + "&extra=" + URLEncoder.encode(extra.toString(), "UTF-8").replace("+", "%20")
        fun reject(value: String, section: ProxyProfile.Section) {
            try { ProxyImport.parse(value, section); error("Unsafe XHTTP accepted") }
            catch (e: IllegalArgumentException) { check(!e.message.orEmpty().contains("vless://") && !e.message.orEmpty().contains("00000000")) }
        }
        for (section in ProxyProfile.Section.values()) {
            val raw = JSONObject().put("path", "/model").put("mode", "stream-one").put("host", "front.example.invalid")
                .put("xPaddingBytes", "16-32").put("noGRPCHeader", true).put("scMaxEachPostBytes", 1_048_576)
                .put("scMaxBufferedPosts", 1_000_000_000).put("serverMaxHeaderBytes", 1_000_000_000)
                .put("headers", JSONObject().put("X-Model", "ok"))
                .put("xmux", JSONObject().put("maxConcurrency", "1-2").put("hKeepAlivePeriod", -1).put("cMaxLifetimeMs", 0))
            val profile = ProxyImport.parse(uri(raw), section).single()
            val rebuilt = ProxyConfiguration.outbound(profile)
            val http = rebuilt.getJSONObject("streamSettings").getJSONObject("xhttpSettings")
            check(http.getString("path") == "/model" && http.getString("mode") == "stream-one")
            check(http.getString("host") == "front.example.invalid" && http.getString("xPaddingBytes") == "16-32")
            check(!http.has("scMaxBufferedPosts") && !http.has("serverMaxHeaderBytes"))
            check(!http.getJSONObject("xmux").has("cMaxLifetimeMs") && http.getJSONObject("xmux").getLong("hKeepAlivePeriod") == -1L)
            check(rebuilt.getJSONObject("streamSettings").getJSONObject("tlsSettings").getBoolean("allowInsecure") == false)
            val roundTrip = ProxyImport.parse(rebuilt.toString(), section).single()
            check(canonical(ProxyConfiguration.outbound(roundTrip)) == canonical(rebuilt))
            val alias = JSONObject(rebuilt.toString())
            val stream = alias.getJSONObject("streamSettings")
            stream.put("network", "SPLITHTTP").put("splithttpSettings", stream.remove("xhttpSettings"))
            check(ProxyImport.parse(alias.toString(), section).single().transport == "xhttp")
            val tcp = ProxyConfiguration.outbound(ProxyProfile.parse(root.replace("xhttp", "raw"), section))
            tcp.getJSONObject("streamSettings").put("network", "RAW").put("rawSettings", JSONObject().put("header", JSONObject().put("type", "none")))
            check(ProxyImport.parse(tcp.toString(), section).single().transport == "tcp")
            reject(uri(JSONObject(raw.toString()).put("sockopt", JSONObject())), section)
            reject(uri(JSONObject().put("xPaddingBytes", 65_537)), section)
            reject(uri(JSONObject().put("scMaxEachPostBytes", "0-100")), section)
            reject(uri(JSONObject().put("scMinPostsIntervalMs", "600001")), section)
            reject(uri(JSONObject().put("noGRPCHeader", "true")), section)
            reject(uri(JSONObject().put("xmux", JSONObject().put("maxConnections", 65))), section)
            reject(uri(JSONObject().put("xmux", JSONObject().put("cMaxLifetimeMs", 1))), section)
            reject(uri(JSONObject().put("xmux", JSONObject().put("hKeepAlivePeriod", -2))), section)
            reject(uri(JSONObject().put("headers", JSONObject().put("Host", "bad.example.invalid"))), section)
            reject(uri(JSONObject().put("headers", JSONObject().put("X-Test", "x\r\nInjected: 1"))), section)
            reject(uri(JSONObject().put("mode", "unknown")), section)
            reject(uri(JSONObject().put("path", "/different")) + "&path=/explicit", section)
            reject(uri(JSONObject().put("xPaddingBytes", "1-2")) + "&x_padding_bytes=3-4", section)
            reject(uri(JSONObject().put("headers", JSONObject().put("X-Big", "x".repeat(1025)))), section)
            val download = JSONObject().put("address", "secondary.example.invalid").put("port", 8443).put("network", "splithttp")
                .put("security", "tls").put("tlsSettings", JSONObject().put("serverName", "secondary.example.invalid").put("allowInsecure", false))
                .put("splithttpSettings", JSONObject().put("path", "/download").put("mode", "stream-one").put("xPaddingBytes", 32))
            val dual = ProxyImport.parse(uri(JSONObject().put("downloadSettings", download)), section).single()
            check(ProxyXHTTPOptions.additionalHosts(dual) == setOf("secondary.example.invalid"))
            try { ProxyConfiguration.outbound(dual, "192.0.2.1"); error("Unresolved secondary accepted") } catch (_: IllegalStateException) { check(true) }
            val actual = ProxyConfiguration.outbound(dual, "192.0.2.1", mapOf("secondary.example.invalid" to "192.0.2.2"))
                .getJSONObject("streamSettings").getJSONObject("xhttpSettings").getJSONObject("downloadSettings")
            check(actual.getString("address") == "192.0.2.2" && actual.getJSONObject("tlsSettings").getString("serverName") == "secondary.example.invalid")
            for (invalidAddress in listOf("example.invalid", "999.1.2.3")) {
                try { ProxyConfiguration.outbound(profile, invalidAddress); error("Unresolved primary accepted") }
                catch (_: IllegalArgumentException) { check(true) }
            }
            try { ProxyConfiguration.outbound(dual, "192.0.2.1", mapOf("secondary.example.invalid" to "unresolved.invalid")); error("Non-numeric secondary accepted") }
            catch (_: IllegalStateException) { check(true) }
            val unsafe = JSONObject(download.toString()); unsafe.getJSONObject("tlsSettings").put("allowInsecure", true)
            reject(uri(JSONObject().put("downloadSettings", unsafe)), section)
            val nested = JSONObject(download.toString()); nested.getJSONObject("splithttpSettings").put("downloadSettings", download)
            reject(uri(JSONObject().put("downloadSettings", nested)), section)
            reject(uri(JSONObject().put("downloadSettings", JSONObject(download.toString()).put("sockopt", JSONObject()))), section)
            reject(uri(JSONObject().put("downloadSettings", JSONObject(download.toString()).put("network", "tcp"))), section)
            reject(uri(JSONObject().put("downloadSettings", JSONObject(download.toString()).put("port", 0))), section)
            reject(uri(raw) + "\ninvalid", section)
        }
        return checks
    }
}
