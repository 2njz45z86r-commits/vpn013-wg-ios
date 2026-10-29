// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.amnezia.awg.Application
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.GoBackend as Native
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

/** Service owns the TUN, physical gate and core lifetime; Activity owns none of them. */
class ProxyVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()
    private var tun: ParcelFileDescriptor? = null
    private var gate: ProxySocketGate? = null
    private var started = false
    override fun onCreate() {
        super.onCreate(); instance = this
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) manager.createNotificationChannel(NotificationChannel("r013-proxy", "VPN013", NotificationManager.IMPORTANCE_LOW))
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, "r013-proxy") else Notification.Builder(this)
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        builder.setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("VPN013")
            .setContentText("VPN-служба работает · управление в приложении").setOngoing(true)
        launch?.let { builder.setContentIntent(PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)) }
        if (Build.VERSION.SDK_INT >= 34) startForeground(1302, builder.build(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(1302, builder.build())
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val token = intent?.getLongExtra("epoch", -1) ?: -1
        if (token != revision.get()) return START_NOT_STICKY
        val id = intent?.getStringExtra("profile")
        scope.launch {
            lock.withLock {
                try {
                    stopNative()
                    if (id == null || token != revision.get()) { activeId = null; stopSelf(); return@withLock }
                    val manager = Application.getTunnelManager()
                    Application.getBackend() // Load the single native archive before its ABI is used.
                    for (tunnel in manager.getTunnels().toList()) if (tunnel.state == Tunnel.State.UP) tunnel.setStateAsync(Tunnel.State.DOWN)
                    val store = ProxyRegistry(ProfileRegistry.get(this@ProxyVpnService).vault)
                    val record = ProxyProfile.Section.values().flatMap { store.list(it) }.single { it.id == id }
                    val captured = ProxySocketGate.capture(this@ProxyVpnService); gate = captured
                    val address = captured.resolve(record.profile.host)
                    check(token == revision.get()) { "Подключение отменено" }
                    val ticket = Native.r013PrimaryBegin(); check(ticket != 0L) { "Прежнее подключение ещё завершается" }
                    try {
                        val descriptor = Builder().setSession("VPN013").setMtu(1280)
                            .addAddress("10.13.0.2", 32).addAddress("fd13::2", 128)
                            .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("1.1.1.1")
                            .setBlocking(false).apply { setUnderlyingNetworks(arrayOf(captured.network)) }.establish()
                            ?: error("Не удалось создать VPN")
                        tun = descriptor
                        check(token == revision.get() && captured.current()) { "Сеть изменилась" }
                        check(Native.r013ProxyStart(ticket, ProxyConfiguration.tunnel(record.profile, address), descriptor.fd, captured) == 0) { "Не удалось запустить подключение" }
                        started = true; activeId = id; lastError = null; requestedId = null
                    } finally { Native.r013PrimaryEnd(ticket) }
                } catch (_: Exception) {
                    stopNative(); activeId = null; requestedId = null; lastError = "Подключение не удалось. Проверьте конфигурацию и доступность сети."; stopSelf()
                }
            }
        }
        return START_NOT_STICKY
    }
    private fun stopNative() {
        gate?.close()
        if (started) {
            val ticket = Native.r013PrimaryBegin(); check(ticket != 0L) { "Прежнее подключение ещё завершается" }
            try { check(Native.r013ProxyStop(ticket) == 0); started = false }
            finally { Native.r013PrimaryEnd(ticket) }
        }
        tun?.close(); tun = null; gate = null; activeId = null
    }
    override fun onRevoke() { revision.incrementAndGet(); scope.launch { lock.withLock { stopNative(); stopSelf() } }; super.onRevoke() }
    override fun onDestroy() {
        revision.incrementAndGet()
        scope.launch { lock.withLock { stopNative(); if (instance === this@ProxyVpnService) instance = null }; scope.cancel() }
        super.onDestroy()
    }
    companion object {
        @Volatile private var instance: ProxyVpnService? = null
        @Volatile var activeId: String? = null; private set
        @Volatile var requestedId: String? = null; private set
        @Volatile var lastError: String? = null; private set
        private val revision = AtomicLong()
        fun start(context: Context, id: String) {
            require(VpnService.prepare(context) == null)
            requestedId = id; lastError = null
            val intent = Intent(context, ProxyVpnService::class.java).putExtra("profile", id).putExtra("epoch", revision.incrementAndGet())
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }
        suspend fun stopAndWait() = withContext(Dispatchers.IO) {
            revision.incrementAndGet()
            requestedId = null
            instance?.let { service -> service.lock.withLock { service.stopNative(); service.stopSelf() } }
        }
        fun statistics(): JSONObject? = try { if (activeId == null) null else Native.r013ProxyStats()?.let(::JSONObject) } catch (_: Exception) { null }
        suspend fun measure(profile: ProxyProfile): Long? = withContext(Dispatchers.IO) {
            val captured = instance?.gate ?: return@withContext null
            try {
                val address = captured.resolve(profile.host)
                val result = Native.r013ProxyProbe(ProxyConfiguration.probe(profile, address), captured)
                if (result >= 0 && captured.current()) result else null
            } catch (_: Exception) { null }
        }
    }
}
