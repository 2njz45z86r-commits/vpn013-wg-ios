// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.amnezia.awg.Application
import org.amnezia.awg.BuildConfig
import org.amnezia.awg.crypto.KeyPair
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Synthetic keys and profiles only; no tunnel or network is started. */
@RunWith(AndroidJUnit4::class)
class R013PrimaryResourceTest {
    @Test fun rejectedBulkImportPreservesExistingProfile() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        check(BuildConfig.DEBUG && context.packageName == "com.vpn013.awg.debug")
        val zero = intArrayOf(0, 0, 0, 0)
        org.amnezia.awg.config.PrimaryResourcePolicy.validate(1, 0, 1, zero,
            arrayOf("<r\u00a04>", "<rc\u20034>", "<rd\u202f4>", "<dz\u00854>", "<b\u3000aabb>"))
        try {
            org.amnezia.awg.config.PrimaryResourcePolicy.validate(0, 0, 0, zero,
                arrayOf("<r\u00a04097>", "", "", "", ""))
            fail("Unicode-separated value over the resource limit was accepted")
        } catch (_: IllegalArgumentException) { }
        val registry = ProfileRegistry.get(context)
        Application.getTunnelManager().getTunnels(); UnifiedAutoCoordinator.stop()
        val client = KeyPair(); val peer = KeyPair()
        val head = "[Interface]\nPrivateKey = ${client.privateKey.toBase64()}\nAddress = 10.13.99.2/32\n"
        val tail = "[Peer]\nPublicKey = ${peer.publicKey.toBase64()}\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.invalid:51820\n"
        OfflineChanges.apply {
            registry.vault.write(JSONObject().put("schema", 1).put("profiles", JSONObject()).put("orders", JSONObject()).put("automaticEnabled", false))
            registry.create("Existing", ProfileRegistry.parse(head + tail))
        }
        val before = registry.vault.read().toString()
        val bad = listOf("Jc = 65535\nJmin = 65535\nJmax = 65535\n", "Jc = 1\nJmin = 2\nJmax = 1\n", "I1 = <r -1>\n", "I1 = <r 4097>\n", "S1 = 4097\n")
        for (invalid in bad) {
            try {
                OfflineChanges.apply {
                    val items = listOf("Valid" to ProfileRegistry.parse(head + tail), "Invalid" to ProfileRegistry.parse(head + invalid + tail))
                    registry.importOrdinary(items)
                }
                fail("Unsafe resource settings were accepted")
            } catch (_: org.amnezia.awg.config.BadConfigException) { }
            assertEquals(before, registry.vault.read().toString())
        }
        assertEquals(listOf("Existing"), registry.records().map { it.getString("name") })
        assertTrue(Application.getBackend().runningTunnelNames.isEmpty())
        assertNull(ProxyVpnService.activeId)
    }
}
