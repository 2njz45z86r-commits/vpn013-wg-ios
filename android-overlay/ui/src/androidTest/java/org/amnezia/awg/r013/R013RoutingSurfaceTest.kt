// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Intent
import android.graphics.Bitmap
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.amnezia.awg.Application
import org.amnezia.awg.BuildConfig
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.crypto.KeyPair
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Synthetic offline records only; native TCP/XHTTP packet checks run separately. */
@RunWith(AndroidJUnit4::class)
class R013RoutingSurfaceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val registry get() = ProfileRegistry.get(context)
    private var activity: R013HomeActivity? = null
    private val sections = listOf("HAPP", "INCY", "AMNEZIAWG", "BLACKTEMPLE")
    @Before fun prepare() = runBlocking {
        check(BuildConfig.DEBUG && context.packageName == "com.vpn013.awg.debug")
        Application.getTunnelManager().getTunnels(); UnifiedAutoCoordinator.stop()
        OfflineChanges.apply {
            registry.vault.write(JSONObject().put("schema", 1).put("profiles", JSONObject()).put("orders", JSONObject()).put("automaticEnabled", false).put("selectedSection", "AMNEZIAWG"))
            for (index in 1..3) {
                val client = KeyPair(); val peer = KeyPair()
                registry.create("AMNEZIAWG Server $index", ProfileRegistry.parse("[Interface]\nPrivateKey = ${client.privateKey.toBase64()}\nAddress = 10.13.99.2/32\n[Peer]\nPublicKey = ${peer.publicKey.toBase64()}\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.invalid:51820\n"))
            }
            val store = ProxyRegistry(registry.vault)
            for (section in ProxyProfile.Section.values()) for (index in 1..3)
                store.importText(section, "vless://00000000-0000-4000-8000-000000000001@example.invalid:443?security=tls#${section.name}%20Server%20$index")
        }
        (Application.getBackend() as GoBackend).setAutomaticEnabled(false)
    }
    @After fun finish() = runBlocking {
        UnifiedAutoCoordinator.stop()
        instrumentation.runOnMainSync { activity?.finish() }
    }
    private fun ids(section: String): List<String> = if (section == "AMNEZIAWG") registry.records().sortedBy { it.getString("name") }.map { it.getString("id") }
        else ProxyRegistry(registry.vault).list(ProxyProfile.Section.valueOf(section)).sortedBy { it.profile.name }.map { it.id }
    @Test fun aBulkOverlayPreservesOriginalConfigurationsAndEveryUnselectedServer() = runBlocking {
        for (section in sections) {
            val ids = ids(section)
            if (section != "AMNEZIAWG") OfflineChanges.apply {
                ProxyRouting.save(registry.vault, ids[0], ProxyRouting.Rules("except", setOf("com.android.settings"), false))
            }
            val before = registry.vault.read()
            val field = if (section == "AMNEZIAWG") "profiles" else "proxyProfiles"
            val records = before.getJSONObject(field).toString()
            OfflineChanges.apply { ApplicationRoutingStore.save(registry.vault, section, ids.take(2).toSet(), ApplicationRoutingStore.Selection("only", setOf("com.android.settings"))) }
            assertEquals(records, registry.vault.read().getJSONObject(field).toString())
            for (id in ids.take(2)) assertEquals("only", ApplicationRoutingStore.read(registry.vault, ApplicationRoutingStore.reference(section, id)).plan()!!.mode())
            assertNull(ApplicationRoutingStore.read(registry.vault, ApplicationRoutingStore.reference(section, ids[2])).plan())
            val document = registry.vault.read()
            val selected = if (section == "AMNEZIAWG") "AMNEZIAWG Server 1" else ids[0]
            val other = if (section == "AMNEZIAWG") "AMNEZIAWG Server 3" else ids[2]
            assertNotEquals(ApplicationRoutingStore.candidateKey(document, section, selected, context.packageName), ApplicationRoutingStore.candidateKey(document, section, other, context.packageName))
            val atomic = registry.vault.read().toString()
            try {
                OfflineChanges.apply { ApplicationRoutingStore.save(registry.vault, section, setOf(ids[0], "00000000-0000-4000-8000-000000000002"), ApplicationRoutingStore.Selection()) }
                fail("Unknown last member accepted")
            } catch (_: IllegalStateException) { }
            assertEquals(atomic, registry.vault.read().toString())
            OfflineChanges.apply { ApplicationRoutingStore.save(registry.vault, section, ids.take(2).toSet(), ApplicationRoutingStore.Selection("unchanged", setOf("com.android.settings"))) }
            assertEquals(records, registry.vault.read().getJSONObject(field).toString())
            if (section != "AMNEZIAWG") assertEquals(ProxyRouting.Rules("except", setOf("com.android.settings"), false), ProxyRouting.effective(registry.vault, section, ids[0]))
        }
        assertNull(ProxyVpnService.activeId)
        assertTrue(Application.getBackend().runningTunnelNames.isEmpty())
    }
    private fun node(predicate: (AccessibilityNodeInfo) -> Boolean): AccessibilityNodeInfo? {
        val root = instrumentation.uiAutomation.rootInActiveWindow ?: return null
        val queue = java.util.ArrayDeque<AccessibilityNodeInfo>(); queue.add(root)
        var count = 0
        while (queue.isNotEmpty() && count++ < 2000) {
            val current = queue.removeFirst()
            if (predicate(current)) return current
            for (index in 0 until current.childCount) current.getChild(index)?.let(queue::addLast)
        }
        return null
    }
    private fun await(predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 15_000
        while (System.currentTimeMillis() < deadline) { if (predicate()) return; Thread.sleep(100) }
        assertTrue("Native routing UI did not reach the required state", predicate())
    }
    private fun tap(text: String, description: Boolean = false) {
        await { node { (if (description) it.contentDescription else it.text)?.toString() == text } != null }
        var target = node { (if (description) it.contentDescription else it.text)?.toString() == text }!!
        while (!target.isClickable && target.parent != null) target = target.parent
        assertTrue(target.isEnabled && target.performAction(AccessibilityNodeInfo.ACTION_CLICK))
    }
    @Test fun bNativeSelectorsAndExclusiveOffDefaultModesRunInEverySection() = runBlocking {
        activity = instrumentation.startActivitySync(Intent(context, R013HomeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as R013HomeActivity
        for (section in sections) {
            tap(UnifiedAutoCoordinator.label(section))
            tap("Настройки и обновления", true); tap("Маршрутизация")
            await { node { it.text?.toString() == "Далее (0)" && !it.isEnabled } != null }
            tap("Выбрать все"); await { node { it.text?.toString() == "Далее (3)" && it.isEnabled } != null }
            tap("Снять выбор"); await { node { it.text?.toString() == "Далее (0)" && !it.isEnabled } != null }
            tap("$section Server 1"); tap("$section Server 2"); tap("Далее (2)")
            val only = "VPN только для выбранных"; val bypass = "Выбранные без VPN"
            await { node { it.text?.toString() == only && !it.isChecked } != null && node { it.text?.toString() == bypass && !it.isChecked } != null }
            tap(only); await { node { it.text?.toString() == only && it.isChecked } != null }
            tap(bypass); await { node { it.text?.toString() == only && !it.isChecked } != null && node { it.text?.toString() == bypass && it.isChecked } != null }
            tap(bypass); tap("Сохранить")
            await { node { it.text?.toString() == "Маршрутизация приложений" } == null }
            withContext(Dispatchers.IO) {
                for (id in ids(section)) assertNull(ApplicationRoutingStore.read(registry.vault, ApplicationRoutingStore.reference(section, id)).plan())
            }
            val folder = File(context.getExternalFilesDir(null), "review").apply { mkdirs() }
            instrumentation.uiAutomation.takeScreenshot().also { image -> File(folder, "routing-ui-${section.lowercase()}.png").outputStream().use { image.compress(Bitmap.CompressFormat.PNG, 100, it) }; image.recycle() }
        }
        assertNull(ProxyVpnService.activeId)
        assertTrue(Application.getBackend().runningTunnelNames.isEmpty())
    }
}
