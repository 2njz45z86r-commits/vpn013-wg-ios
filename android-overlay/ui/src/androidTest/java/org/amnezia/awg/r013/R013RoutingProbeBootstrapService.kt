// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.Looper

/** Shell-only TEST APK process bootstrap. No network, VPN, files or credentials. */
class R013RoutingProbeBootstrapService : Service() {
    private val timer = Handler(Looper.getMainLooper())
    private val deadline = Runnable { stopSelf() }
    override fun onCreate() {
        super.onCreate()
        val channel = "routing-probe-test-only"
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(channel, "Disposable routing check", NotificationManager.IMPORTANCE_MIN))
        startForeground(71, Notification.Builder(this, channel).setContentTitle("Disposable routing check")
            .setSmallIcon(android.R.drawable.stat_sys_download).build())
        timer.postDelayed(deadline, 60_000)
    }
    override fun onBind(intent: Intent?) = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int) = START_NOT_STICKY
    override fun onDestroy() { timer.removeCallbacks(deadline); super.onDestroy() }
}
