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
import org.amnezia.awg.backend.R013SocketRoutes
import androidx.annotation.Keep
import java.util.concurrent.atomic.AtomicInteger
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
    @Test fun bPlatformPreferredBinding() = runBlocking {
        val base = config(); val iphone = base.replace("Address = 10.13.99.2/32", "Address = 10.13.99.2/32\nMTU = 1280")
        val android = base.replace("Address = 10.13.99.2/32", "Address = 10.13.99.2/32\nMTU = 1420")
        val old = document("001122334455",listOf("one" to iphone))
        val converted = ClientProtocol.androidAccess(old,listOf("Android One" to ProfileRegistry.parse(android)))
        OfflineChanges.apply { ClientProtocol.apply(registry,converted) }
        assertEquals(1420,registry.config("Android One").`interface`.mtu.get().toInt())
        assertEquals(ProfileRegistry.parse(android).`interface`.keyPair.privateKey,registry.config("Android One").`interface`.keyPair.privateKey)
        try { ClientProtocol.androidAccess(old,listOf("Wrong" to ProfileRegistry.parse(config()))); fail("Foreign key adopted") } catch (_: IllegalArgumentException) { }
        assertEquals(1,registry.names().size)
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
        registry.vault.edit { it.getJSONObject("orders").getJSONObject("001122334455").put("pending",changed.getJSONObject("snapshot")) }
        try { ClientUpdates.applyPending(); fail("Modified managed profile overwritten") } catch (_: IllegalStateException) { }
        val diskAfterFailure = File(context.filesDir,"r013-vault.bin").readBytes()
        assertFalse(ClientUpdates.applyPending())
        assertArrayEquals("Rejected pending update was repeatedly rewritten",diskAfterFailure,File(context.filesDir,"r013-vault.bin").readBytes())
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
        val backend = Application.getBackend() as GoBackend
        val revision = backend.connectionRevision
        val batch = allViews().filterIsInstance<TextView>().first { it.text.toString() == "Проверить пинг" }
        instrumentation.runOnMainSync { assertTrue(batch.performClick()) }
        waitFor { allViews().filterIsInstance<TextView>().count { it.contentDescription?.startsWith("Пинг адреса ") == true && it.text.toString().matches(Regex("[0-9]+ мс")) } == 2 }
        assertNull(backend.currentProfileName); assertEquals(revision,backend.connectionRevision)
        screenshot("ping-"+(InstrumentationRegistry.getArguments().getString("reviewLabel") ?: "phone"))
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
        waitFor { allViews().any { it.contentDescription == "Проверить пинг текущего сервера" && it.isEnabled } }
        val pingButton = allViews().first { it.contentDescription == "Проверить пинг текущего сервера" }
        instrumentation.runOnMainSync { assertTrue(pingButton.performClick()) }
        waitFor { texts().any { it.contains("Пинг адреса:") || it.contains("Пинг адреса недоступен") } }
        assertEquals(connected,backend.connectionRevision)
        assertEquals("CI Manual",backend.currentProfileName)
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
    @Keep class CountedRoutes(private val routes: R013SocketRoutes) {
        val physical = AtomicInteger(); val through = AtomicInteger()
        @Keep fun prepareSocket(role: Int, fd: Int): Boolean {
            if (!routes.prepareSocket(role,fd)) return false
            if (role == 1) physical.incrementAndGet() else if (role == 2) through.incrementAndGet()
            return true
        }
    }
    @Test fun hRealProtectedCandidateAndUninterruptedCurrentDns() = runBlocking {
        val full = fixture().replace("AllowedIPs = 10.13.99.1/32","AllowedIPs = 0.0.0.0/0")
        val encoded = InstrumentationRegistry.getArguments().getString("syntheticCandidate") ?: error("Second isolated peer missing")
        val candidate = ProfileRegistry.parse(String(android.util.Base64.decode(encoded,android.util.Base64.DEFAULT),Charsets.UTF_8)
            .replace("AllowedIPs = 10.13.99.1/32","AllowedIPs = 0.0.0.0/0"))
        OfflineChanges.apply { registry.create("CI Uninterrupted",ProfileRegistry.parse(full)) }
        startHome(); val tunnel = Application.getTunnelManager().getTunnels().single()
        tunnel.setStateAsync(Tunnel.State.UP)
        val backend = Application.getBackend() as GoBackend
        waitFor(30000) { EndpointPing.measure("10.13.99.1") != null }
        val handleField = GoBackend::class.java.getDeclaredField("currentTunnelHandle").apply { isAccessible = true }
        val serviceField = GoBackend::class.java.getDeclaredField("activeService").apply { isAccessible = true }
        val handle = handleField.getInt(backend)
        val iface = org.amnezia.awg.GoBackend.awgGetInterfaceName(handle) ?: error("No actual native TUN name")
        val service = serviceField.get(backend) as GoBackend.VpnService
        var routes: R013SocketRoutes? = null
        waitFor { try { routes = R013SocketRoutes(context,service,iface); true } catch (_: IllegalStateException) { false } }
        val counted = CountedRoutes(routes!!)
        val scope = org.amnezia.awg.GoBackend.r013ProbeCreate(counted)
        assertTrue("Native scope was not created",scope > 0)
        val revision = backend.connectionRevision
        val initialRx = backend.getStatistics(tunnel).totalRx()
        try {
            assertEquals(0,org.amnezia.awg.GoBackend.r013ProbeRefresh(scope))
            fun snapshot(id: String, config: org.amnezia.awg.config.Config) = JSONObject()
                .put("id",id).put("config",config.toAwgUserspaceString()).put("source","10.13.99.2")
            val input = JSONObject().put("auto_active",true).put("resolver","1.1.1.1:53").put("start_index",0)
                .put("candidates",JSONArray().put(snapshot("active-alias",ProfileRegistry.parse(full))).put(snapshot("other",candidate)))
            val operation = org.amnezia.awg.GoBackend.r013ProbeStart(scope,input.toString())
            assertTrue("Native scan rejected",operation > 0)
            var result = JSONObject()
            waitFor(100000) {
                val wire = org.amnezia.awg.GoBackend.r013ProbePoll(scope,operation) ?: error("Scan unexpectedly invalidated")
                result = JSONObject(wire); result.getString("status") != "pending"
            }
            assertEquals("complete",result.getString("status"))
            assertEquals(3,result.getJSONObject("before").getInt("samples"))
            assertEquals(3,result.getJSONObject("after").getInt("samples"))
            val rows = result.getJSONArray("rows")
            assertEquals(2,rows.length())
            assertEquals("active_identity_skipped",rows.getJSONObject(0).getString("status"))
            assertEquals("measured",rows.getJSONObject(1).getString("status"))
            assertEquals(3,rows.getJSONObject(1).getJSONObject("metric").getInt("samples"))
            assertEquals("Unexpected physical gate count; active identity must never open UDP",1,counted.physical.get())
            assertEquals("Both baselines must explicitly bind the actual VPN Network",2,counted.through.get())
            assertEquals(handle,handleField.getInt(backend)); assertEquals(revision,backend.connectionRevision)
            assertEquals("CI Uninterrupted",backend.currentProfileName)
            assertTrue(backend.getStatistics(tunnel).totalRx() > initialRx)
            assertNotNull("Primary traffic lost during candidate scan",EndpointPing.measure("10.13.99.1"))
            // Stop must invalidate old handles and metrics before changing the TUN.
            tunnel.setStateAsync(Tunnel.State.DOWN)
            assertNull("Stopped native owner must not remain observable",backend.actualRouteInterfaceName)
            assertFalse("Old interface identity must be rejected even before explicit scope invalidation",routes!!.isCurrent)
            assertNull(org.amnezia.awg.GoBackend.r013ProbePoll(scope,operation))
            assertEquals(0L,org.amnezia.awg.GoBackend.r013ProbeStart(scope,input.toString()))
        } finally {
            routes!!.invalidate()
            org.amnezia.awg.GoBackend.r013ProbeInvalidate(scope)
            assertEquals("Real JNI/UDP callbacks did not drain",0,org.amnezia.awg.GoBackend.r013ProbeRelease(scope))
        }
    }
    @Test fun iProductionHourlyTimerKeepsRealPrimaryAndCancelsOnManualChoice() = runBlocking {
        val slow = fixture().replace("AllowedIPs = 10.13.99.1/32","AllowedIPs = 0.0.0.0/0")
        OfflineChanges.apply { registry.create("A Timer Fixture",ProfileRegistry.parse(slow)); registry.createAuto() }
        startHome(); val manager = Application.getTunnelManager(); val auto = manager.getTunnels().first()
        val backend = Application.getBackend() as GoBackend
        val started = android.os.SystemClock.elapsedRealtime()
        auto.setStateAsync(Tunnel.State.UP)
        // A one-member Auto cannot rotate because these isolated peers don't
        // implement public HTTPS origins. Real second-peer routing is tested
        // separately; this case isolates the production timer from health.
        waitFor(20000) { EndpointPing.measure("10.13.99.1") != null }
        val revision = backend.connectionRevision
        val handleField = GoBackend::class.java.getDeclaredField("currentTunnelHandle").apply { isAccessible = true }
        val handle = handleField.getInt(backend)
        val rx = backend.getStatistics(auto).totalRx()
        assertNotNull(EndpointPing.measure("10.13.99.1"))
        waitFor(40000) { backend.connectionView().hourlySummary()?.contains("сравнено") == true }
        assertTrue("Production timer fired before its initial 30 seconds",android.os.SystemClock.elapsedRealtime()-started >= 30_000)
        assertEquals("Scan unexpectedly restarted the primary",revision,backend.connectionRevision)
        assertEquals(handle,handleField.getInt(backend))
        assertEquals("A Timer Fixture",backend.automaticMemberName)
        assertTrue(backend.getStatistics(auto).totalRx() > rx)
        assertNotNull(EndpointPing.measure("10.13.99.1"))
        screenshot("hourly-real-vpn")
        manager.getTunnels()["A Timer Fixture"]!!.setStateAsync(Tunnel.State.UP)
        assertFalse(backend.isAutomaticRunning)
        assertNull(backend.connectionView().hourlySummary())
        val manualRevision = backend.connectionRevision
        Thread.sleep(1500)
        assertEquals(manualRevision,backend.connectionRevision)
        assertEquals("A Timer Fixture",backend.currentProfileName)
    }
    @Test fun jRealCoordinatorChoosesFasterPeerWithActualPolicyAndUnchangedProfiles() = runBlocking {
        val slow = fixture().replace("AllowedIPs = 10.13.99.1/32","AllowedIPs = 0.0.0.0/0")
        val encoded = InstrumentationRegistry.getArguments().getString("syntheticCandidate") ?: error("Second isolated peer missing")
        val fast = String(android.util.Base64.decode(encoded,android.util.Base64.DEFAULT),Charsets.UTF_8)
            .replace("AllowedIPs = 10.13.99.1/32","AllowedIPs = 0.0.0.0/0")
        OfflineChanges.apply { registry.importOrdinary(listOf("A Slow Fixture" to ProfileRegistry.parse(slow),"B Fast Fixture" to ProfileRegistry.parse(fast))); registry.createAuto() }
        startHome(); val manager = Application.getTunnelManager(); val auto = manager.getTunnels().first()
        val backend = Application.getBackend() as GoBackend
        auto.setStateAsync(Tunnel.State.UP)
        waitFor(20000) { EndpointPing.measure("10.13.99.1") != null }
        assertEquals("A Slow Fixture",backend.automaticMemberName)
        val saved = registry.vault.read().toString()
        val policy = GoBackend::class.java.getDeclaredField("automaticPolicy").apply { isAccessible = true }.get(backend) as AutoPolicy
        val epoch = (GoBackend::class.java.getDeclaredField("autoEpoch").apply { isAccessible = true }.get(backend) as java.util.concurrent.atomic.AtomicLong).get()
        val members = registry.members(auto.name).map { GoBackend.AutoMember(it.first,it.second) }
        val compare = GoBackend::class.java.getDeclaredMethod("compareHourly",Tunnel::class.java,List::class.java,
            AutoPolicy::class.java,java.lang.Long.TYPE,Integer.TYPE).apply { isAccessible = true }
        // Same production coordinator; invoke its due work directly so the
        // synthetic HTTPS health failure can't win before the comparison.
        compare.invoke(backend,auto,members,policy,epoch,0)
        assertEquals("B Fast Fixture",backend.automaticMemberName)
        assertEquals(1,policy.current())
        assertTrue(backend.connectionView().hourlySummary()!!.contains("выбран более быстрый"))
        waitFor(20000) { EndpointPing.measure("10.13.99.1") != null }
        assertTrue(backend.getLastHandshake(auto) > 0)
        assertEquals("Comparison rewrote a saved profile or membership",saved,registry.vault.read().toString())
        screenshot("hourly-selected-real-vpn")
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
