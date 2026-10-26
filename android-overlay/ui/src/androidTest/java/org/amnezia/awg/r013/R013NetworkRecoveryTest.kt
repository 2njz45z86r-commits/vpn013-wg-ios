// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
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
    private val wifi = Network.fromNetworkHandle((1L shl 32) or 0xcafed00dL)
    private fun caps(ready: Boolean) = NetworkCapabilities.Builder()
        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .apply { if (ready) addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) }
        .build()

    private fun callback(state: NetworkState): ConnectivityManager.NetworkCallback {
        val field = NetworkState::class.java.getDeclaredField("networkCallback\$delegate")
        field.isAccessible = true
        return (field.get(state) as Lazy<*>).value as ConnectivityManager.NetworkCallback
    }

    @Test fun lostThenReturnedNetworkRequestsRecovery() {
        val events = mutableListOf<Pair<NetworkType, NetworkType>>()
        val state = NetworkState(instrumentation.targetContext) { old, new -> events.add(old to new) }
        val cb = callback(state)
        cb.onCapabilitiesChanged(wifi, caps(true)); instrumentation.waitForIdleSync()
        assertTrue(events.isEmpty())
        cb.onLost(wifi); instrumentation.waitForIdleSync()
        cb.onCapabilitiesChanged(wifi, caps(true)); instrumentation.waitForIdleSync()
        assertEquals(listOf(NetworkType.WIFI to NetworkType.NONE, NetworkType.NONE to NetworkType.WIFI), events)
        assertTrue(state.isConnected())
    }

    @Test fun sameNetworkCanLoseAndRecoverValidation() {
        val events = mutableListOf<Pair<NetworkType, NetworkType>>()
        val state = NetworkState(instrumentation.targetContext) { old, new -> events.add(old to new) }
        val cb = callback(state)
        cb.onCapabilitiesChanged(wifi, caps(true)); instrumentation.waitForIdleSync()
        cb.onCapabilitiesChanged(wifi, caps(false)); instrumentation.waitForIdleSync()
        assertFalse(state.isConnected())
        cb.onCapabilitiesChanged(wifi, caps(true)); instrumentation.waitForIdleSync()
        cb.onCapabilitiesChanged(wifi, caps(true)); instrumentation.waitForIdleSync()
        assertEquals(listOf(NetworkType.WIFI to NetworkType.WIFI), events)
    }

    @Test fun queuedOldLossCannotOverwriteReturnedNetwork() {
        val events = mutableListOf<Pair<NetworkType, NetworkType>>()
        val state = NetworkState(instrumentation.targetContext) { old, new -> events.add(old to new) }
        val cb = callback(state)
        instrumentation.runOnMainSync {
            cb.onCapabilitiesChanged(wifi, caps(true))
            cb.onLost(wifi)
            cb.onCapabilitiesChanged(wifi, caps(true))
        }
        instrumentation.waitForIdleSync()
        assertEquals(listOf(NetworkType.NONE to NetworkType.WIFI), events)
    }
}
