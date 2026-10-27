// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.amnezia.awg.util.NetworkState
import org.amnezia.awg.util.NetworkType
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Exercise the actual callback adapter without changing the emulator's network or VPN. */
@RunWith(AndroidJUnit4::class)
class R013NetworkRecoveryTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val manager get() = instrumentation.targetContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val physical: Network by lazy {
        manager.allNetworks.first { network ->
            val value = manager.getNetworkCapabilities(network)
            value != null && !value.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                value.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }
    }
    private fun caps(ready: Boolean): NetworkCapabilities = if (ready)
        NetworkCapabilities(requireNotNull(manager.getNetworkCapabilities(physical))) else NetworkCapabilities()
    private val physicalType get() = when {
        caps(true).hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
        caps(true).hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.CELLULAR
        else -> NetworkType.OTHER
    }

    private fun callback(state: NetworkState): ConnectivityManager.NetworkCallback {
        val field = NetworkState::class.java.getDeclaredField("networkCallback\$delegate")
        field.isAccessible = true
        return (field.get(state) as Lazy<*>).value as ConnectivityManager.NetworkCallback
    }

    @Test fun lostThenReturnedNetworkRequestsRecovery() {
        val events = mutableListOf<Pair<NetworkType, NetworkType>>()
        val state = NetworkState(instrumentation.targetContext) { old, new -> events.add(old to new) }
        val cb = callback(state)
        cb.onCapabilitiesChanged(physical, caps(true)); instrumentation.waitForIdleSync()
        assertTrue(events.isEmpty())
        cb.onLost(physical); instrumentation.waitForIdleSync()
        cb.onCapabilitiesChanged(physical, caps(true)); instrumentation.waitForIdleSync()
        assertEquals(listOf(physicalType to NetworkType.NONE, NetworkType.NONE to physicalType), events)
        assertTrue(state.isConnected())
    }

    @Test fun unknownCapabilitiesClearValidationAndThenRecover() {
        val events = mutableListOf<Pair<NetworkType, NetworkType>>()
        val state = NetworkState(instrumentation.targetContext) { old, new -> events.add(old to new) }
        val cb = callback(state)
        cb.onCapabilitiesChanged(physical, caps(true)); instrumentation.waitForIdleSync()
        cb.onCapabilitiesChanged(physical, caps(false)); instrumentation.waitForIdleSync()
        assertFalse(state.isConnected())
        cb.onCapabilitiesChanged(physical, caps(true)); instrumentation.waitForIdleSync()
        cb.onCapabilitiesChanged(physical, caps(true)); instrumentation.waitForIdleSync()
        assertEquals(listOf(NetworkType.OTHER to physicalType), events)
    }

    @Test fun queuedOldLossCannotOverwriteReturnedNetwork() {
        val events = mutableListOf<Pair<NetworkType, NetworkType>>()
        val state = NetworkState(instrumentation.targetContext) { old, new -> events.add(old to new) }
        val cb = callback(state)
        instrumentation.runOnMainSync {
            cb.onCapabilitiesChanged(physical, caps(true))
            cb.onLost(physical)
            cb.onCapabilitiesChanged(physical, caps(true))
        }
        instrumentation.waitForIdleSync()
        assertEquals(listOf(NetworkType.NONE to physicalType), events)
    }
}
