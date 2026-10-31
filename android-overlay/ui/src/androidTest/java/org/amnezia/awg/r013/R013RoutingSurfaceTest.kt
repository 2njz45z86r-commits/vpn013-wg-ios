// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Intent
import android.app.Instrumentation
import android.app.Activity
import android.graphics.Bitmap
import android.graphics.Rect
import android.os.SystemClock
import android.view.MotionEvent
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
import java.util.concurrent.atomic.AtomicReference

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
    private fun await(message: String = "Native routing UI did not reach the required state", predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 15_000
        while (System.currentTimeMillis() < deadline) { if (predicate()) return; Thread.sleep(100) }
        assertTrue(message, predicate())
    }
    private fun tap(text: String, description: Boolean = false) {
        try { tapChecked(text, description) } catch (failure: AssertionError) {
            if (text == "Установленные приложения") captureButtonDiagnostics()
            throw failure
        }
    }
    private fun captureButtonDiagnostics() {
        val folder = File(context.getExternalFilesDir(null), "review").apply { mkdirs() }
        instrumentation.uiAutomation.takeScreenshot()?.also { bitmap ->
            File(folder, "routing-app-button-failure.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }; bitmap.recycle()
        }
        val labels = listOf("Маршрутизация сервисов", "Установленные приложения", "VPN только для выбранных сервисов", "Выбранные сервисы без VPN")
        val safe = org.json.JSONArray()
        for (label in labels) node { it.text?.toString() == label }?.let { item ->
            val bounds = Rect(); item.getBoundsInScreen(bounds)
            safe.put(JSONObject().put("label", label).put("enabled", item.isEnabled).put("visible", item.isVisibleToUser)
                .put("clickable", item.isClickable).put("bounds", listOf(bounds.left, bounds.top, bounds.right, bounds.bottom)))
        }
        File(folder, "routing-app-button-failure.json").writeText(JSONObject().put("nodes", safe).toString())
    }
    private fun tapChecked(text: String, description: Boolean) {
        var direction = AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
        await("Native routing UI target was not visible: $text") {
            val target = node { (if (description) it.contentDescription else it.text)?.toString() == text }
            if (target == null || !target.isVisibleToUser) {
                val scrollable = node { it.isScrollable }
                if (scrollable != null && !scrollable.performAction(direction)) {
                    direction = if (direction == AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD)
                        AccessibilityNodeInfo.ACTION_SCROLL_FORWARD else AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD
                }
                false
            } else true
        }
        var target = node { (if (description) it.contentDescription else it.text)?.toString() == text }!!
        while (!target.isClickable && target.parent != null) target = target.parent
        assertTrue("Native routing UI target must be enabled: $text", target.isEnabled)
        if (!target.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
            if (text == "Установленные приложения") captureButtonDiagnostics()
            val bounds = Rect(); target.getBoundsInScreen(bounds)
            val windowBounds = Rect(); instrumentation.uiAutomation.rootInActiveWindow?.getBoundsInScreen(windowBounds)
            assertTrue("Native routing UI target must have visible bounds: $text", target.isVisibleToUser && !bounds.isEmpty && bounds.intersect(windowBounds))
            val now = SystemClock.uptimeMillis()
            val down = MotionEvent.obtain(now, now, MotionEvent.ACTION_DOWN, bounds.exactCenterX(), bounds.exactCenterY(), 0)
            val up = MotionEvent.obtain(now, now + 50, MotionEvent.ACTION_UP, bounds.exactCenterX(), bounds.exactCenterY(), 0)
            try { instrumentation.sendPointerSync(down); instrumentation.sendPointerSync(up) }
            finally { down.recycle(); up.recycle() }
        }
    }
    @Test fun bNativeSelectorsAndExclusiveOffDefaultModesRunInEverySection() = runBlocking {
        activity = instrumentation.startActivitySync(Intent(context, R013HomeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as R013HomeActivity
        for (section in sections) {
            tap(UnifiedAutoCoordinator.label(section))
            val documentIntent = AtomicReference<Intent?>()
            val monitor = object : Instrumentation.ActivityMonitor() {
                override fun onStartActivity(intent: Intent): Instrumentation.ActivityResult? {
                    if (intent.action != Intent.ACTION_OPEN_DOCUMENT) return null
                    documentIntent.set(Intent(intent))
                    return Instrumentation.ActivityResult(Activity.RESULT_CANCELED, null)
                }
            }
            instrumentation.addMonitor(monitor)
            try {
                tap("Добавить", true)
                tap(if (section == "AMNEZIAWG") "Импорт из файла или ZIP" else "Импортировать файл")
                await { documentIntent.get() != null }
                val types = documentIntent.get()!!.getStringArrayExtra(Intent.EXTRA_MIME_TYPES)!!.toSet()
                assertTrue("System picker hides ordinary ZIP", "*/*" in types || "application/zip" in types)
                assertTrue("System picker hides Windows ZIP MIME", "*/*" in types || "application/x-zip-compressed" in types)
            } finally { instrumentation.removeMonitor(monitor) }
            tap("Настройки и обновления", true); tap("Маршрутизация")
            await { node { it.text?.toString() == "Далее (0)" && !it.isEnabled } != null }
            tap("Выбрать все"); await { node { it.text?.toString() == "Далее (3)" && it.isEnabled } != null }
            tap("Снять выбор"); await { node { it.text?.toString() == "Далее (0)" && !it.isEnabled } != null }
            tap("$section Server 1"); tap("$section Server 2"); tap("Далее (2)")
            val serviceOnly = "VPN только для выбранных сервисов"; val serviceBypass = "Выбранные сервисы без VPN"
            await { node { it.text?.toString() == serviceOnly && !it.isChecked } != null && node { it.text?.toString() == serviceBypass && !it.isChecked } != null }
            tap(serviceOnly); await { node { it.text?.toString() == serviceOnly && it.isChecked } != null }
            tap(serviceBypass); await { node { it.text?.toString() == serviceOnly && !it.isChecked } != null && node { it.text?.toString() == serviceBypass && it.isChecked } != null }
            tap(serviceBypass)
            val catalog = ServiceRoutingCatalog.shared(context)
            val group = catalog.groups.first { it.services.any { service -> catalog.supported(service.id) } }
            val item = group.services.first { catalog.supported(it.id) }
            tap(serviceOnly)
            tap("▸ ${group.title} (${group.services.size})")
            tap("${item.iconText}  ${item.name}")
            tap("Сохранить")
            await { node { it.text?.toString() == "Маршрутизация сервисов" } == null }
            withContext(Dispatchers.IO) {
                val stored = registry.vault.read()
                val selectedIds = ids(section)
                for (id in selectedIds.take(2)) assertEquals(setOf(item.id), ServiceRoutingStore.read(stored, ApplicationRoutingStore.reference(section, id)).only)
                assertEquals(ServiceRoutingCatalog.Selection(), ServiceRoutingStore.read(stored, ApplicationRoutingStore.reference(section, selectedIds[2])) )
            }
            tap("Настройки и обновления", true); tap("Маршрутизация")
            tap("$section Server 1"); tap("$section Server 2"); tap("Далее (2)")
            await { node { it.text?.toString() == serviceOnly && it.isChecked } != null }
            tap(serviceOnly); tap("Сохранить")
            await { node { it.text?.toString() == "Маршрутизация сервисов" } == null }
            tap("Настройки и обновления", true); tap("Маршрутизация")
            tap("$section Server 1"); tap("$section Server 2"); tap("Далее (2)")
            await { node { it.text?.toString() == "Маршрутизация сервисов" } != null }
            tap("Установленные приложения")
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
