// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.app.Activity
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ResultReceiver
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference

/** DUMP-protected TEST APK UID probe. Only a fixed disposable peer; no VPN or files. */
class R013RoutingProbeBootstrapService : Service() {
    private val timer = Handler(Looper.getMainLooper())
    private val deadline = Runnable { stopSelf() }
    private val socket = AtomicReference<Socket?>()
    private var worker: Thread? = null
    override fun onCreate() {
        super.onCreate()
        val channel = "routing-probe-test-only"
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(channel, "Disposable routing check", NotificationManager.IMPORTANCE_MIN))
        startForeground(71, Notification.Builder(this, channel).setContentTitle("Disposable routing check")
            .setSmallIcon(android.R.drawable.stat_sys_download).build())
        timer.postDelayed(deadline, 10_000)
    }
    override fun onBind(intent: Intent?) = null
    @Suppress("DEPRECATION")
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val reply = intent?.getParcelableExtra<ResultReceiver>("r013_probe_reply")
        val port = intent?.getIntExtra("r013_probe_port", 0) ?: 0
        val nonce = intent?.getStringExtra("r013_probe_nonce") ?: ""
        if (reply == null || port !in 1..65535 || !nonce.matches(Regex("[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")) || worker?.isAlive == true) {
            stopSelf(startId); return START_NOT_STICKY
        }
        worker = Thread({
            val result = Bundle()
            result.putString("r013_probe_uid", android.os.Process.myUid().toString())
            val manager = getSystemService(ConnectivityManager::class.java)
            result.putString("r013_probe_vpn", (manager.getNetworkCapabilities(manager.activeNetwork)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true).toString())
            var verified = false
            try {
                Socket().use { connection ->
                    socket.set(connection); connection.soTimeout = 2_000
                    connection.connect(InetSocketAddress("198.18.0.1", port), 2_000)
                    connection.getOutputStream().write(("GET /$nonce HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII))
                    val bytes = connection.getInputStream().readNBytes(4097)
                    val response = String(bytes, Charsets.US_ASCII)
                    verified = bytes.size <= 4096 && response.startsWith("HTTP/1.1 200") && response.contains(nonce)
                }
            } catch (_: Exception) { /* Direct/bypassed UID cannot reach the private peer. */ }
            finally { socket.getAndSet(null)?.close() }
            result.putString("r013_probe_nonce", verified.toString())
            reply.send(Activity.RESULT_OK, result)
            stopSelf(startId)
        }, "r013-independent-uid-probe").apply { isDaemon = true; start() }
        return START_NOT_STICKY
    }
    override fun onDestroy() {
        timer.removeCallbacks(deadline)
        socket.getAndSet(null)?.close(); worker?.interrupt()
        super.onDestroy()
    }
}
