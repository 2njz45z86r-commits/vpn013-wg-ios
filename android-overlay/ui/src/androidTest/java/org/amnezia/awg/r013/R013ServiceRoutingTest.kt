// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.amnezia.awg.Application
import org.amnezia.awg.BuildConfig
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.crypto.KeyPair
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Synthetic records only; no connection or external network is started. */
@RunWith(AndroidJUnit4::class)
class R013ServiceRoutingTest {
    @Test fun catalogAndAtomicSelectionsAcrossAllFamilies() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        check(BuildConfig.DEBUG && context.packageName == "com.vpn013.awg.debug")
        val registry = ProfileRegistry.get(context)
        Application.getTunnelManager().getTunnels(); UnifiedAutoCoordinator.stop()
        val catalog = ServiceRoutingCatalog.load(context)
        assertEquals(23, catalog.groups.size)
        val services = catalog.groups.flatMap { it.services }
        assertEquals(412, services.size)
        assertEquals(1, services.count { !catalog.supported(it.id) })
        assertEquals("Codeium", services.single { !catalog.supported(it.id) }.name)
        assertNull(catalog.resolve(ServiceRoutingCatalog.Selection()))
        val service = services.first { catalog.supported(it.id) }
        val only = ServiceRoutingCatalog.Selection("only", setOf(service.id))
        val bypass = ServiceRoutingCatalog.Selection("bypass", bypass = setOf(service.id))
        assertTrue(catalog.resolve(only)!!.ipv4.isNotEmpty())
        try { catalog.resolve(ServiceRoutingCatalog.Selection("only", setOf(services.single { !catalog.supported(it.id) }.id))); fail("domain-only service enabled") } catch (_: IllegalArgumentException) { }
        OfflineChanges.apply {
            registry.vault.write(JSONObject().put("schema", 1).put("profiles", JSONObject()).put("orders", JSONObject()).put("automaticEnabled", false).put("selectedSection", "AMNEZIAWG"))
            for (index in 1..3) {
                val client = KeyPair(); val peer = KeyPair()
                registry.create("Service Test $index", ProfileRegistry.parse("[Interface]\nPrivateKey = ${client.privateKey.toBase64()}\nAddress = 10.13.99.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = ${peer.publicKey.toBase64()}\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.invalid:51820\n"))
            }
            val store = ProxyRegistry(registry.vault)
            for (section in ProxyProfile.Section.values()) for (index in 1..3)
                store.importText(section, "vless://00000000-0000-4000-8000-000000000001@example.invalid:443?security=tls#${section.name}%20Service%20$index")
        }
        (Application.getBackend() as GoBackend).setAutomaticEnabled(false)
        for (section in listOf("AMNEZIAWG", "HAPP", "INCY", "BLACKTEMPLE")) {
            val records = if (section == "AMNEZIAWG") registry.records().sortedBy { it.getString("name") }.map { it.getString("id") to it.getString("name") }
                else ProxyRegistry(registry.vault).list(ProxyProfile.Section.valueOf(section)).sortedBy { it.profile.name }.map { it.id to it.id }
            assertEquals(3, records.size)
            val ids = records.map { it.first }
            val field = if (section == "AMNEZIAWG") "profiles" else "proxyProfiles"
            val before = registry.vault.read().getJSONObject(field).toString()
            OfflineChanges.apply { ServiceRoutingStore.save(registry.vault, section, ids.take(2).toSet(), only, catalog) }
            var document = registry.vault.read()
            assertEquals(before, document.getJSONObject(field).toString())
            for (id in ids.take(2)) assertEquals(only, ServiceRoutingStore.read(document, ApplicationRoutingStore.reference(section, id)))
            assertEquals(ServiceRoutingCatalog.Selection(), ServiceRoutingStore.read(document, ApplicationRoutingStore.reference(section, ids[2])))
            assertNotEquals(ApplicationRoutingStore.candidateKey(document, section, records[0].second, context.packageName), ApplicationRoutingStore.candidateKey(document, section, records[2].second, context.packageName))
            if (section == "AMNEZIAWG") {
                val expected = listOf(records[0].second, records[1].second)
                assertEquals(expected, registry.automaticMembers(records[0].second).map { it.first })
                OfflineChanges.apply { ServiceRoutingStore.save(registry.vault, section, setOf(ids[2]), bypass, catalog) }
                assertEquals(expected, registry.automaticMembers(records[0].second).map { it.first })
                assertEquals(before, registry.vault.read().getJSONObject(field).toString())
                OfflineChanges.apply { ServiceRoutingStore.save(registry.vault, section, setOf(ids[2]), ServiceRoutingCatalog.Selection(), catalog) }
                document = registry.vault.read()
            }
            val snapshot = document.toString()
            try {
                OfflineChanges.apply { ServiceRoutingStore.save(registry.vault, section, setOf(ids[0], "00000000-0000-4000-8000-000000000002"), bypass, catalog) }
                fail("Unknown server accepted")
            } catch (_: IllegalStateException) { }
            assertEquals(snapshot, registry.vault.read().toString())
            val remembered = ServiceRoutingCatalog.Selection("unchanged", setOf(service.id), setOf(service.id))
            OfflineChanges.apply { ServiceRoutingStore.save(registry.vault, section, ids.take(2).toSet(), remembered, catalog) }
            document = registry.vault.read()
            assertEquals(remembered, ServiceRoutingStore.read(document, ApplicationRoutingStore.reference(section, ids[0])))
            assertNull(ServiceRoutingStore.plan(document, ApplicationRoutingStore.reference(section, ids[0]), catalog))
            assertEquals(before, document.getJSONObject(field).toString())
            assertEquals(ApplicationRoutingStore.candidateKey(document, section, records[0].second, context.packageName), ApplicationRoutingStore.candidateKey(document, section, records[2].second, context.packageName))
            if (section == "AMNEZIAWG") {
                assertEquals(records.map { it.second }, registry.automaticMembers(records[0].second).map { it.first })
                assertEquals(before, registry.vault.read().getJSONObject(field).toString())
            }
        }
        assertNull(ProxyVpnService.activeId)
        assertTrue(Application.getBackend().runningTunnelNames.isEmpty())
    }
}
