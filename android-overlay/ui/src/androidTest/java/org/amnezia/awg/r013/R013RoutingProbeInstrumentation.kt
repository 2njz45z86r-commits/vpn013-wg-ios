// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.app.Activity
import android.app.Instrumentation
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import java.net.InetSocketAddress
import java.net.Socket

/** Runs only inside the disposable TEST APK, never the app or a release APK. */
class R013RoutingProbeInstrumentation : Instrumentation() {
    private var input = Bundle()
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments); input = Bundle(arguments ?: Bundle()); start()
    }
    override fun onStart() {
        val result = Bundle()
        check(targetContext.packageName == "com.vpn013.awg.debug.test")
        val port = input.getString("port")?.toIntOrNull()
        val nonce = input.getString("nonce") ?: ""
        check(port != null && port in 1..65535 && nonce.matches(Regex("[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")))
        val manager = targetContext.getSystemService(ConnectivityManager::class.java)
        result.putString("r013_probe_vpn", (manager.getNetworkCapabilities(manager.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true).toString())
        result.putString("r013_probe_uid", android.os.Process.myUid().toString())
        var verified = false
        try {
            Socket().use { socket ->
                socket.soTimeout = 2_000
                // Fixed benchmark-network target exists only on the hosted peer.
                // The caller cannot choose a URL, hostname or arbitrary address.
                socket.connect(InetSocketAddress("198.18.0.1", port), 2_000)
                socket.getOutputStream().write(("GET /$nonce HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
                val bytes = socket.getInputStream().readNBytes(4097)
                val body = String(bytes, Charsets.US_ASCII)
                verified = bytes.size <= 4096 && body.startsWith("HTTP/1.1 200") && body.contains(nonce)
            }
        } catch (_: Exception) { /* A bypassed UID has no route to this peer. */ }
        result.putString("r013_probe_nonce", verified.toString())
        finish(Activity.RESULT_OK, result)
    }
}
