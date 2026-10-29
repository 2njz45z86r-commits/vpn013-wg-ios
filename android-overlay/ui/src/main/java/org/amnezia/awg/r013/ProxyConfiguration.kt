// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import org.json.JSONArray
import org.json.JSONObject

/** Constructs only the supported outbound. Imported JSON is never passed into the core. */
object ProxyConfiguration {
    fun outbound(profile: ProxyProfile, resolvedHost: String? = null): JSONObject {
        val q = profile.options
        val user = JSONObject().put("id", profile.userId).put("encryption", "none")
        q["flow"]?.takeIf { it.isNotEmpty() }?.let { user.put("flow", it) }
        val node = JSONObject().put("address", resolvedHost ?: profile.host).put("port", profile.port)
            .put("users", JSONArray().put(user))
        val stream = JSONObject().put("network", profile.transport).put("security", profile.security)
        val tls = JSONObject().put("serverName", profile.serverName)
        q["fp"]?.takeIf { it.isNotEmpty() }?.let { tls.put("fingerprint", it) }
        q["alpn"]?.let { tls.put("alpn", JSONArray(it.split(','))) }
        if (profile.security == "tls") {
            tls.put("allowInsecure", false)
            stream.put("tlsSettings", tls)
        } else {
            tls.put("publicKey", q.getValue("pbk")).put("shortId", q["sid"] ?: "")
            q["spx"]?.let { tls.put("spiderX", it) }
            q["pqv"]?.let { tls.put("mldsa65Verify", it) }
            stream.put("realitySettings", tls)
        }
        when (profile.transport) {
            "ws" -> {
                val ws = JSONObject().put("path", q["path"] ?: "/")
                q["host"]?.takeIf { it.isNotEmpty() }?.let { ws.put("headers", JSONObject().put("Host", it)) }
                stream.put("wsSettings", ws)
            }
            "grpc" -> {
                val grpc = JSONObject().put("serviceName", q["serviceName"] ?: "")
                    .put("multiMode", q["mode"] == "multi")
                q["authority"]?.takeIf { it.isNotEmpty() }?.let { grpc.put("authority", it) }
                stream.put("grpcSettings", grpc)
            }
            "xhttp" -> {
                val xhttp = JSONObject().put("path", q["path"] ?: "/").put("mode", q["mode"]?.takeIf { it.isNotEmpty() } ?: "auto")
                q["host"]?.takeIf { it.isNotEmpty() }?.let { xhttp.put("host", it) }
                q["x_padding_bytes"]?.let { xhttp.put("xPaddingBytes", it) }
                stream.put("xhttpSettings", xhttp)
            }
        }
        return JSONObject().put("tag", "proxy").put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(node)))
            .put("streamSettings", stream)
    }
    fun tunnel(profile: ProxyProfile, resolvedHost: String): String = JSONObject()
        .put("log", JSONObject().put("loglevel", "none"))
        .put("inbounds", JSONArray().put(JSONObject().put("tag", "vpn013-tun").put("protocol", "tun")
            .put("settings", JSONObject().put("name", "vpn013").put("MTU", 1280).put("userLevel", 0))))
        .put("outbounds", JSONArray().put(outbound(profile, resolvedHost)))
        .put("stats", JSONObject())
        .put("policy", JSONObject().put("system", JSONObject().put("statsInboundUplink", true).put("statsInboundDownlink", true)))
        .toString()
    fun probe(profile: ProxyProfile, resolvedHost: String): String = JSONObject()
        .put("log", JSONObject().put("loglevel", "none"))
        .put("outbounds", JSONArray().put(outbound(profile, resolvedHost))).toString()
}
