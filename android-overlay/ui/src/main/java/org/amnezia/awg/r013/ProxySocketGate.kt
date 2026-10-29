// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.annotation.Keep
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** Immutable physical Network; never falls back to a newly installed VPN route. */
@Keep
class ProxySocketGate(private val service: VpnService, val network: Network) {
    private val manager = service.getSystemService(ConnectivityManager::class.java)
    private val closed = AtomicBoolean()
    private val identity = fingerprint()
    private fun fingerprint(): String {
        val caps = manager.getNetworkCapabilities(network) ?: error("Сеть недоступна")
        check(!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
        val link = manager.getLinkProperties(network) ?: error("Сеть недоступна")
        check(link.routes.size <= 512 && link.linkAddresses.size <= 128 && link.dnsServers.size <= 128)
        return listOf(network.networkHandle.toString(), link.interfaceName.orEmpty(), link.mtu.toString(),
            link.routes.map { it.toString() }.sorted().joinToString(), link.linkAddresses.map { it.toString() }.sorted().joinToString(),
            link.dnsServers.map { it.hostAddress }.joinToString()).joinToString("|")
    }
    fun current(): Boolean = try { !closed.get() && VpnService.prepare(service) == null && identity == fingerprint() } catch (_: Exception) { false }
    @Keep fun prepareSocket(route: Int, fd: Int): Boolean {
        if (route != 1 || fd < 0 || !current()) return false
        return try {
            ParcelFileDescriptor.fromFd(fd).use { owned ->
                if (!service.protect(owned.fd)) false
                else { network.bindSocket(owned.fileDescriptor); current() }
            }
        } catch (_: Exception) { false }
    }
    fun resolve(host: String): String {
        check(current()) { "Сеть изменилась" }
        val task = resolver.submit<java.util.ArrayList<java.net.InetAddress>> { java.util.ArrayList(network.getAllByName(host).toList()) }
        val addresses = try { task.get(4, TimeUnit.SECONDS) } finally { task.cancel(true) }
        check(current() && addresses.isNotEmpty() && addresses.size <= 64) { "Сеть изменилась" }
        return addresses.first().hostAddress!!.substringBefore('%')
    }
    fun close() { closed.set(true) }
    companion object {
        private val resolver = ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS, ArrayBlockingQueue(8),
            java.util.concurrent.ThreadFactory { runnable -> Thread(runnable, "VPN013-Resolve").apply { isDaemon = true } })
        fun capture(service: VpnService): ProxySocketGate {
            val manager = service.getSystemService(ConnectivityManager::class.java)
            val preferred = manager.activeNetwork
            val physical = manager.allNetworks.filter { network ->
                manager.getNetworkCapabilities(network)?.let {
                    !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                } == true
            }
            check(physical.size in 1..64) { "Нет доступной сети" }
            val chosen = physical.firstOrNull { it == preferred } ?: physical.firstOrNull {
                manager.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
            } ?: physical.first()
            return ProxySocketGate(service, chosen)
        }
    }
}
