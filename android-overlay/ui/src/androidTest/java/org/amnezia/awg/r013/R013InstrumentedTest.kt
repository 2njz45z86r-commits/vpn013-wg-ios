// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Intent
import android.graphics.Bitmap
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.amnezia.awg.Application
import org.amnezia.awg.BuildConfig
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.crypto.KeyPair
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.io.File
import java.security.SecureRandom

@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class R013InstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val registry get() = ProfileRegistry.get(context)
    private var activity: R013HomeActivity? = null
    @Before fun prepare() = runBlocking {
        check(BuildConfig.DEBUG && context.packageName == "com.vpn013.awg.debug")
        Application.getTunnelManager().getTunnels()
        stopAll()
        OfflineChanges.apply { registry.vault.write(JSONObject().put("schema",1).put("profiles",JSONObject()).put("orders",JSONObject())) }
    }
    @After fun finish() = runBlocking { stopAll(); instrumentation.runOnMainSync { activity?.finish() }; Unit }
    private suspend fun stopAll() { for (t in Application.getTunnelManager().getTunnels().toList()) if (t.state == Tunnel.State.UP) t.setStateAsync(Tunnel.State.DOWN) }
    private fun config(name: String = "unused"): String {
        val client = KeyPair(); val server = KeyPair()
        return "[Interface]\nPrivateKey = ${client.privateKey.toBase64()}\nAddress = 10.13.99.2/32\nDNS = 1.1.1.1\nJc = 3\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 30\nH1 = 1001\nH2 = 1002\nH3 = 1003\nH4 = 1004\n[Peer]\nPublicKey = ${server.publicKey.toBase64()}\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 15\n"
    }
    private fun document(order: String, configs: List<Pair<String,String>>): JSONObject {
        val servers = JSONArray(); val digest = StringBuilder()
        configs.forEach { (id, text) -> val name = "Server-$id"; servers.put(JSONObject().put("id",id).put("name",name).put("config",text)); digest.append(id).append('\n').append(name).append('\n').append(text).append('\n') }
        val token = android.util.Base64.encodeToString(ByteArray(32).also { SecureRandom().nextBytes(it) }, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
        return JSONObject().put("schema",1).put("kind","vpn013-access").put("capability",token).put("snapshot",JSONObject()
            .put("schema",1).put("kind","vpn013-awg").put("orderID",order).put("expiry",System.currentTimeMillis()+86_400_000)
            .put("revision",ProfileRegistry.digest(digest.toString())).put("complete",true).put("servers",servers))
    }
    @Test fun aEncryptedAtomicVault() = runBlocking {
        val text = config(); OfflineChanges.apply { registry.create("Дом", ProfileRegistry.parse(text)) }
        val disk = File(context.filesDir,"r013-vault.bin"); val bytes = disk.readBytes()
        assertFalse(String(bytes,Charsets.ISO_8859_1).contains("PrivateKey"))
        assertFalse(String(bytes,Charsets.ISO_8859_1).contains(text.substringAfter("PrivateKey = ").substringBefore('\n')))
        assertEquals(registry.config("Дом").toAwgQuickString(), ProfileRegistry.parse(text).toAwgQuickString())
        val altered = bytes.clone().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        try { disk.writeBytes(altered); try { PrivateVault(context).read(); fail("Tampering accepted") } catch (_: javax.crypto.AEADBadTagException) { } }
        finally { disk.writeBytes(bytes) }
        assertEquals(1,PrivateVault(context).read().getJSONObject("profiles").length())
        val before = registry.vault.read().toString()
        try { OfflineChanges.apply { registry.vault.edit { it.put("schema",2) } }; fail("Invalid schema accepted") } catch (_: IllegalStateException) { }
        assertEquals(before,registry.vault.read().toString())
    }
    @Test fun bScopedOrderRosterAndRollback() = runBlocking {
        OfflineChanges.apply { registry.create("Unrelated",ProfileRegistry.parse(config())) }
        val unrelated = registry.record("Unrelated").toString()
        val one = config(); val two = config(); val three = config()
        val first = document("001122334455",listOf("one" to one,"two" to two))
        OfflineChanges.apply { ClientProtocol.apply(registry,first) }
        assertEquals(3,registry.names().size)
        OfflineChanges.apply { registry.createAuto() }
        val auto = registry.records().single { it.has("members") }.getString("name")
        OfflineChanges.apply { registry.rename("Server-one","Моё имя") }
        val changed = document("001122334455",listOf("one" to one,"three" to three))
        OfflineChanges.apply { ClientProtocol.apply(registry,changed) }
        assertTrue(registry.names().contains("Моё имя")); assertFalse(registry.names().contains("Server-two"))
        assertEquals(unrelated,registry.record("Unrelated").toString())
        assertEquals(3,registry.members(auto).size)
        assertTrue(registry.members(auto).any { it.first == "Server-three" })
        val before = registry.vault.read().toString()
        val incomplete = JSONObject(changed.toString()); incomplete.getJSONObject("snapshot").put("complete",false)
        try { OfflineChanges.apply { ClientProtocol.apply(registry,incomplete) }; fail("Partial roster accepted") } catch (_: IllegalArgumentException) { }
        assertEquals(before,registry.vault.read().toString())
        OfflineChanges.apply { registry.save("Моё имя",ProfileRegistry.parse(config())) }
        val edited = registry.vault.read().toString()
        try { OfflineChanges.apply { ClientProtocol.apply(registry,changed) }; fail("Manual edits overwritten") } catch (_: IllegalStateException) { }
        assertEquals(edited,registry.vault.read().toString())
    }
    @Test fun cAutoSnapshotAndOrdering() = runBlocking {
        val items = (1..30).map { "Server$it" to ProfileRegistry.parse(config()) }
        OfflineChanges.apply { registry.importOrdinary(items); registry.createAuto() }
        val manager = Application.getTunnelManager(); val auto = manager.getTunnels().first()
        assertTrue(registry.isAuto(auto.name)); assertEquals(30,registry.members(auto.name).size)
        val before = registry.members(auto.name).first().second.toAwgQuickString()
        OfflineChanges.apply { registry.save("Server1",ProfileRegistry.parse(config())) }
        assertEquals(before,registry.members(auto.name).first().second.toAwgQuickString())
        OfflineChanges.apply { registry.create("0 First",ProfileRegistry.parse(config())) }
        assertTrue(registry.isAuto(manager.getTunnels().first().name))
        val vault = registry.vault.read().toString()
        try { OfflineChanges.apply { registry.createAuto() }; fail("31 members accepted") } catch (_: IllegalArgumentException) { }
        assertEquals(vault,registry.vault.read().toString())
        OfflineChanges.apply { registry.delete("0 First"); registry.rename(auto.name,"Z Automatic") }
        assertEquals("Z Automatic",manager.getTunnels().first().name)
        assertTrue(registry.isAuto(manager.getTunnels().first().name))
    }
    @Test fun dNativeIcmpLoopback() { assertNotNull("Real ICMP loopback echo failed",EndpointPing.measure("127.0.0.1")) }
    @Test fun eNativeScreen() = runBlocking {
        OfflineChanges.apply { registry.importOrdinary(listOf("Finland" to ProfileRegistry.parse(config()),"Дом" to ProfileRegistry.parse(config()))); registry.createAuto() }
        startHome(); waitFor { texts().any { it.startsWith("Профили ·") } }
        assertTrue(texts().contains("Проверить пинг"))
        val labels = texts(); assertTrue(labels.indexOfFirst { it.startsWith("Авто ·") } < labels.indexOf("Finland"))
        assertTrue(allViews().any { it.contentDescription == "Проверить пинг текущего сервера" && it.width >= 48 * context.resources.displayMetrics.density })
        assertTrue(allViews().any { it.contentDescription == "Добавить" || it.contentDescription == "Добавить профиль" })
        screenshot(InstrumentationRegistry.getArguments().getString("reviewLabel") ?: "phone-main")
        val settings = allViews().first { it.contentDescription == "Настройки и обновления" }
        instrumentation.runOnMainSync { settings.performClick() }
        waitFor { texts().contains("Обновить конфигурации") }
        screenshot("menu-"+(InstrumentationRegistry.getArguments().getString("reviewLabel") ?: "phone"))
    }
    @Test fun fRealManualAmneziaTraffic() = runBlocking {
        val text = fixture(); OfflineChanges.apply { registry.create("CI Manual",ProfileRegistry.parse(text)) }
        startHome(); val tunnel = Application.getTunnelManager().getTunnels().single()
        assertNull(GoBackend.VpnService.prepare(context))
        tunnel.setStateAsync(Tunnel.State.UP)
        waitFor(30000) { EndpointPing.measure("10.13.99.1") != null }
        val backend = Application.getBackend() as GoBackend
        assertTrue(backend.getLastHandshake(tunnel) > 0)
        assertTrue(backend.getStatistics(tunnel).totalRx() > 0)
        assertEquals("CI Manual",backend.connectionView().profile())
        val before = registry.config(tunnel.name).toAwgQuickString()
        val connected = backend.connectionRevision
        assertNotNull(EndpointPing.measure("10.13.99.1"))
        assertEquals(connected,backend.connectionRevision)
        assertEquals(before,registry.config(tunnel.name).toAwgQuickString())
        screenshot("manual-vpn")
    }
    @Test fun gRealAutoFailoverStopAndManualOverride() = runBlocking {
        val good = fixture().replace("AllowedIPs = 10.13.99.1/32","AllowedIPs = 0.0.0.0/0")
        val bad = good.replace(Regex("Endpoint = [^\\n]+"),"Endpoint = 10.0.2.2:9")
        OfflineChanges.apply { registry.importOrdinary(listOf("A Unavailable" to ProfileRegistry.parse(bad),"B Responder" to ProfileRegistry.parse(good))); registry.createAuto() }
        startHome(); val manager = Application.getTunnelManager(); val auto = manager.getTunnels().first(); val backend = Application.getBackend() as GoBackend
        auto.setStateAsync(Tunnel.State.UP)
        waitFor(100000) { backend.automaticMemberName == "B Responder" }
        waitFor(20000) { EndpointPing.measure("10.13.99.1") != null }
        assertTrue(backend.getLastHandshake(auto) > 0); assertTrue(backend.isAutomaticRunning)
        screenshot("auto-vpn")
        auto.setStateAsync(Tunnel.State.DOWN); Thread.sleep(7000)
        assertFalse(backend.isAutomaticRunning); assertNull(backend.currentProfileName)
        auto.setStateAsync(Tunnel.State.UP)
        manager.getTunnels()["B Responder"]!!.setStateAsync(Tunnel.State.UP)
        waitFor(20000) { EndpointPing.measure("10.13.99.1") != null }
        Thread.sleep(7000)
        assertEquals("B Responder",backend.currentProfileName); assertFalse(backend.isAutomaticRunning)
    }
    private fun fixture(): String {
        val encoded = InstrumentationRegistry.getArguments().getString("syntheticConfig") ?: error("Synthetic peer fixture missing")
        return String(android.util.Base64.decode(encoded,android.util.Base64.DEFAULT),Charsets.UTF_8)
    }
    private fun startHome() { activity = instrumentation.startActivitySync(Intent(context,R013HomeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as R013HomeActivity; instrumentation.waitForIdleSync() }
    private fun allViews(): List<View> { val views = ArrayList<View>(); instrumentation.runOnMainSync {
        fun walk(v: View) { views.add(v); if (v is ViewGroup) for (i in 0 until v.childCount) walk(v.getChildAt(i)) }
        activity?.window?.decorView?.let { walk(it) }
        // Dialog windows are separate roots; queries below use UiAutomation for their text.
    }; return views }
    private fun texts(): List<String> {
        val strings = allViews().filterIsInstance<TextView>().map { it.text.toString() }.toMutableList()
        fun walk(node: android.view.accessibility.AccessibilityNodeInfo?) { if (node == null) return; node.text?.let { strings.add(it.toString()) }; for (i in 0 until node.childCount) walk(node.getChild(i)) }
        walk(instrumentation.uiAutomation.rootInActiveWindow); return strings
    }
    private fun waitFor(timeout: Long = 15000, test: () -> Boolean) { val until = System.currentTimeMillis()+timeout; while (System.currentTimeMillis()<until) { if (test()) return; Thread.sleep(250) }; assertTrue("Timed out waiting for native behavior",test()) }
    private fun screenshot(name: String) { Thread.sleep(700); val dir = File(context.getExternalFilesDir(null),"review").apply { mkdirs() }; instrumentation.uiAutomation.takeScreenshot().also { bitmap -> File(dir,"$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG,100,it) }; bitmap.recycle() } }
}
