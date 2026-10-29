// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import java.net.HttpURLConnection
import java.net.URI
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

object ProxySubscription {
    fun normalizeInput(raw: String): String {
        val text = raw.trim()
        val prefix = listOf("blacktemple://import/", "happ://add/", "incy://import/").firstOrNull { text.startsWith(it, ignoreCase=true) } ?: return text
        require(text.length <= 16_384) { "Слишком длинная ссылка подписки" }
        val payload = text.substring(prefix.length)
        val result = if (payload.startsWith("https://", ignoreCase = true)) payload
            else java.net.URLDecoder.decode(payload.replace("+", "%2B"), "UTF-8")
        val uri = URI(result)
        require(uri.scheme.equals("https", true) && !uri.host.isNullOrBlank() && uri.rawUserInfo == null && uri.rawFragment == null && result.none { it.code < 32 || it.code == 127 }) { "Нужна HTTPS-ссылка подписки" }
        return result
    }
    fun handoff(raw: String): Pair<String,String?> {
        require(raw.toByteArray(Charsets.UTF_8).size <= 16384)
        val uri=URI(raw)
        require(uri.scheme.equals("vpn013",true) && uri.host=="import" && uri.rawUserInfo==null && uri.port == -1 && uri.rawQuery==null)
        val section=uri.path.removePrefix("/").uppercase(java.util.Locale.ROOT)
        require(section in listOf("HAPP","INCY","AMNEZIAWG","BLACKTEMPLE") && uri.path=="/"+section.lowercase(java.util.Locale.ROOT))
        if(section=="AMNEZIAWG") { require(uri.rawFragment.isNullOrEmpty());return section to null }
        val text=java.net.URLDecoder.decode(requireNotNull(uri.rawFragment).replace("+","%2B"),"UTF-8")
        val target=URI(text)
        require(target.scheme.equals("https",true) && !target.host.isNullOrBlank() && target.rawUserInfo==null && target.rawFragment==null && text.none { it.code<33 || it.code==127 })
        return section to text
    }
    fun fetch(source: ProxyRegistry.Source): String {
        val uri = URI(source.url)
        require(uri.scheme.equals("https", true) && uri.host != null && uri.rawUserInfo == null && uri.rawFragment == null)
        val connection = uri.toURL().openConnection() as HttpURLConnection
        val deadline = System.nanoTime() + 12_000_000_000L
        try {
            connection.instanceFollowRedirects = false; connection.connectTimeout = 4000; connection.readTimeout = 4000
            connection.useCaches = false
            connection.setRequestProperty("User-Agent", "VPN013/1.7.0 Android")
            connection.setRequestProperty("x-hwid", source.hwid)
            connection.setRequestProperty("Cache-Control", "no-store")
            check(connection.responseCode == 200) { "Подписка не обновлена. Проверьте срок доступа и привязку устройства." }
            val output = ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    check(System.nanoTime() < deadline) { "Сервер подписки не ответил вовремя" }
                    val count = input.read(buffer); if (count < 0) break
                    check(output.size() + count <= 8_388_608) { "Слишком большая подписка" }; output.write(buffer, 0, count)
                }
            }
            check(System.nanoTime() < deadline) { "Сервер подписки не ответил вовремя" }
            return Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(output.toByteArray())).toString()
        } finally { connection.disconnect() }
    }
}
