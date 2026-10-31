// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Intent
import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.amnezia.awg.Application
import org.amnezia.awg.BuildConfig
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.UUID

/** Hosted disposable peers only. Never receives provider or customer credentials. */
@RunWith(AndroidJUnit4::class)
class R013ProxyRuntimeTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val registry get() = ProfileRegistry.get(context)
    private lateinit var fixture: JSONObject
    private var activity: R013HomeActivity? = null
    @Before fun prepare() = runBlocking {
        check(BuildConfig.DEBUG && context.packageName == "com.vpn013.awg.debug")
        fixture = JSONObject(String(android.util.Base64.decode(
            InstrumentationRegistry.getArguments().getString("proxyFixture") ?: error("Hosted proxy fixture missing"),
            android.util.Base64.DEFAULT), Charsets.UTF_8))
        check(fixture.getString("host") == "198.18.0.1")
        check(fixture.getString("nonce").matches(Regex("[a-f0-9-]{36}")))
        val parsed = ProxyImport.parse(fixture.getString("uri"), ProxyProfile.Section.HAPP).single()
        check(parsed.host == "10.0.2.2" && parsed.security == "reality" && parsed.port > 1024)
        val xhttp = ProxyImport.parse(fixture.getString("xhttpURI"), ProxyProfile.Section.HAPP).single()
        check(xhttp.host == "10.0.2.2" && xhttp.security == "reality" && xhttp.transport == "xhttp" && xhttp.port > 1024)
        Application.getTunnelManager().getTunnels()
        UnifiedAutoCoordinator.stop()
        for (t in Application.getTunnelManager().getTunnels().toList()) if (t.state == Tunnel.State.UP) t.setStateAsync(Tunnel.State.DOWN)
        withContext(Dispatchers.IO) {
            registry.vault.write(JSONObject().put("schema",1).put("profiles",JSONObject()).put("orders",JSONObject())
                .put("automaticEnabled",false).put("selectedSection","HAPP"))
            (Application.getBackend() as GoBackend).setAutomaticEnabled(false)
        }
        activity = instrumentation.startActivitySync(Intent(context,R013HomeActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as R013HomeActivity
        instrumentation.waitForIdleSync()
        verifyOtherApplication(false)
    }
    @After fun finish() = runBlocking {
        UnifiedAutoCoordinator.stop()
        assertNull(ProxyVpnService.activeId)
        instrumentation.runOnMainSync { activity?.finish() }
        val manager = context.getSystemService(ConnectivityManager::class.java)
        await { manager.getNetworkCapabilities(manager.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true }
    }
    private fun await(timeout: Long = 20_000, condition: () -> Boolean) {
        val until = System.currentTimeMillis()+timeout
        while (System.currentTimeMillis()<until) { if (condition()) return; Thread.sleep(100) }
        assertTrue("Native proxy condition timed out; error="+ProxyVpnService.lastError,condition())
    }
    private fun exchange(label: String) {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val folder = File(context.getExternalFilesDir(null), "review").apply { mkdirs() }
        File(folder, "proxy-traffic-process.json").writeText(JSONObject()
            .put("processUID", android.os.Process.myUid())
            .put("appUID", context.applicationInfo.uid)
            .put("instrumentationPackageUID", context.packageManager.getApplicationInfo("com.vpn013.awg.debug.test", 0).uid)
            .put("probePackageUID", context.packageManager.getApplicationInfo("com.vpn013.routingprobe", 0).uid)
            .put("vpnCapabilityBeforeWait", manager.getNetworkCapabilities(manager.activeNetwork)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true).toString())
        // Service startup and Android's publication of the default VPN network
        // are separate events, particularly when immediately restarting it.
        // Wait for the actual system capability; never replace it with the
        // service flag, a fixed delay or an assumed connected state.
        await { manager.getNetworkCapabilities(manager.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }
        assertTrue("The application must use the actual VPN network",manager.getNetworkCapabilities(manager.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        try { Socket().use { socket ->
            socket.soTimeout=6_000
            socket.connect(InetSocketAddress(fixture.getString("host"),fixture.getInt("port")),6_000)
            val nonce=fixture.getString("nonce")
            socket.getOutputStream().write(("GET /$nonce HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n").toByteArray())
            val bytes=socket.getInputStream().readNBytes(4097)
            assertTrue(bytes.size<=4096)
            val response=String(bytes,Charsets.US_ASCII)
            assertTrue("Disposable peer must return its unpredictable response",response.startsWith("HTTP/1.1 200") && response.contains(nonce))
        } } catch (failure: java.net.ConnectException) {
            val current = manager.activeNetwork
            val target = java.net.InetAddress.getByName("198.18.0.1")
            var cause: Throwable? = failure
            var errno: Int? = null
            while (cause != null) {
                if (cause is android.system.ErrnoException) errno = cause.errno
                cause = cause.cause
            }
            val stats = ProxyVpnService.statistics()
            File(folder, "proxy-connect-failure-$label.json").writeText(JSONObject()
                .put("processUID", android.os.Process.myUid())
                .put("vpnCapability", manager.getNetworkCapabilities(current)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
                .put("activeNetworkHasControlRoute", manager.getLinkProperties(current)?.routes?.any { it.matches(target) } == true)
                .put("errno", errno ?: JSONObject.NULL)
                .put("statisticsAvailable", stats != null)
                .put("rxPositive", (stats?.optLong("rx") ?: 0) > 0)
                .put("txPositive", (stats?.optLong("tx") ?: 0) > 0).toString())
            throw failure
        }
        await { val stats=ProxyVpnService.statistics(); stats != null && stats.optLong("rx")>0 && stats.optLong("tx")>0 }
    }
    private fun verifyOtherApplication(throughVPN: Boolean) {
        val testPackage = "com.vpn013.routingprobe"
        val nonce = fixture.getString("nonce"); val port = fixture.getInt("port")
        check(fixture.getString("host") == "198.18.0.1" && port in 1024..65535 && nonce.matches(Regex("[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")))
        fun shell(command: String): String = ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command)).use { stream ->
            val bytes = stream.readNBytes(16385); check(bytes.size <= 16384); String(bytes, Charsets.UTF_8)
        }
        val request = UUID.randomUUID().toString()
        // Shell has DUMP permission; the receiver runs as a separate installed app,
        // writes only its own private fixed result and accepts no arbitrary URL.
        val broadcast = shell("am broadcast -f 0x20 -n $testPackage/.RoutingProbeReceiver --es request $request --es nonce $nonce --ei port $port")
        var result: JSONObject? = null
        var reads = 0; var parseable = false; var stale = false
        try {
            assertTrue("Independent UID probe broadcast must complete", broadcast.contains("Broadcast completed") && !broadcast.contains("Permission Denial"))
            await(10_000) {
                reads++
                val candidate = runCatching { JSONObject(shell("run-as $testPackage cat files/probe.json")) }.getOrNull()
                if (candidate != null) parseable = true
                if (candidate?.optString("requestID") == request) { result = candidate; true }
                else { if (candidate != null) stale = true; false }
            }
        } catch (failure: AssertionError) {
            val folder = File(context.getExternalFilesDir(null), "review").apply { mkdirs() }
            File(folder, "independent-uid-probe-failure.json").writeText(JSONObject()
                .put("expectedVPN", throughVPN).put("broadcastCompleted", broadcast.contains("Broadcast completed"))
                .put("permissionDenied", broadcast.contains("Permission Denial"))
                .put("reads", reads).put("parseableResult", parseable).put("staleResultSeen", stale).toString())
            throw failure
        }
        val proof = checkNotNull(result)
        val otherUID = context.packageManager.getApplicationInfo(testPackage, 0).uid
        assertNotEquals("The probe must have a different application UID", context.applicationInfo.uid, otherUID)
        assertNotEquals("The probe must also differ from the instrumentation UID", context.packageManager.getApplicationInfo("com.vpn013.awg.debug.test", 0).uid, otherUID)
        assertEquals("The second package must actually run under its own UID", otherUID, proof.getInt("uid"))
        assertEquals("The OS must publish the expected network for that UID", throughVPN, proof.getBoolean("vpn"))
        assertEquals("The independent UID must exchange the unpredictable nonce only when routed into VPN", throughVPN, proof.getBoolean("matched"))
        if (throughVPN) assertEquals("The routed probe must complete without socket errors", "", proof.getString("errorClass"))
    }
    private fun capture(name: String) {
        val folder=File(context.getExternalFilesDir(null),"review").apply { mkdirs() }
        instrumentation.uiAutomation.takeScreenshot().also { bitmap ->
            File(folder,"$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG,100,it) };bitmap.recycle()
        }
    }
    private fun views(): List<View> {
        val result = mutableListOf<View>()
        fun visit(view: View) { result.add(view); if (view is ViewGroup) for (index in 0 until view.childCount) visit(view.getChildAt(index)) }
        visit(activity!!.window.decorView); return result
    }
    private fun selectSection(section: ProxyProfile.Section) {
        instrumentation.runOnMainSync {
            val tab = views().filterIsInstance<TextView>().first { it.text.toString() == UnifiedAutoCoordinator.label(section.name) && it.isClickable }
            check(tab.performClick())
        }
    }
    @Test fun actualRealityTrafficInAllThreeProxySectionsAndCompleteStop() = runBlocking {
        val store=ProxyRegistry(registry.vault)
        val sections = ProxyProfile.Section.values().toList()
        // Cross the two factors in HAPP as well as retaining all six original
        // combinations, so a policy failure cannot be misreported as XHTTP.
        val cases = sections.map { Triple(it, "tcp", "only") } +
            listOf(Triple(ProxyProfile.Section.HAPP, "tcp", "bypass"),
                Triple(ProxyProfile.Section.HAPP, "xhttp", "only")) +
            sections.map { Triple(it, "xhttp", "bypass") }
        for ((index, case) in cases.withIndex()) {
            val (section, transport, applicationMode) = case
            var stage = "import"
            try {
            val id=withContext(Dispatchers.IO) { store.importText(section,fixture.getString(if (transport == "tcp") "uri" else "xhttpURI")).single() }
            OfflineChanges.apply {
                val packages = setOf("com.vpn013.routingprobe")
                val selection = if (applicationMode == "only") ApplicationRoutingStore.Selection("only", only = packages)
                    else ApplicationRoutingStore.Selection("bypass", bypass = packages)
                ApplicationRoutingStore.save(registry.vault, section.name, setOf(id), selection)
            }
            selectSection(section)
            val control = if (index % 2 == 0) "vpn013.proxy.globe.$id" else "vpn013.proxy.body.$id"
            await { var found = false; instrumentation.runOnMainSync { found = views().any { it.tag == control && it.isEnabled } }; found }
            stage = "start"
            instrumentation.runOnMainSync { check(views().single { it.tag == control }.performClick()) }
            await { ProxyVpnService.activeId == id }
            stage = "traffic"
            if (applicationMode == "bypass") verifyOtherApplication(false)
            exchange("${section.name.lowercase()}-$transport-$applicationMode")
            verifyOtherApplication(applicationMode == "only")
            assertEquals(id,ProxyVpnService.activeId)
            val proofFolder = File(context.getExternalFilesDir(null), "review").apply { mkdirs() }
            val originalMode = (transport == "tcp" && applicationMode == "only") || (transport == "xhttp" && applicationMode == "bypass")
            val suffix = if (originalMode) "" else "-$applicationMode"
            val proof = JSONObject()
                .put("section", section.name).put("transport", transport).put("mode", applicationMode)
                .put("realVPNTransport", true).put("nonceResponseVerified", true).put("rxTxPositive", true)
                .put("otherApplicationUIDTrafficVerified", true).toString()
            File(proofFolder, "application-routing-${section.name.lowercase()}-$transport-$applicationMode.json").writeText(proof)
            if (originalMode) File(proofFolder, "application-routing-${section.name.lowercase()}-$transport.json").writeText(proof)
            await { var rendered = false; instrumentation.runOnMainSync {
                rendered = views().filterIsInstance<TextView>().any { it.tag == "vpn013.current.traffic" && it.text.contains("Всего:") } &&
                    views().any { it.tag == "vpn013.current.ping" && it.contentDescription == "Проверить пинг текущего сервера" }
            }; rendered }
            val revision = ProxyVpnService.trafficRevision()
            instrumentation.runOnMainSync { check(views().single { it.tag == "vpn013.proxy.details.$id" }.performClick()) }
            await { instrumentation.uiAutomation.rootInActiveWindow?.findAccessibilityNodeInfosByText("Закрыть")?.any { it.isClickable } == true }
            check(requireNotNull(instrumentation.uiAutomation.rootInActiveWindow).findAccessibilityNodeInfosByText("Закрыть").first { it.isClickable }
                .performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK))
            await { instrumentation.uiAutomation.rootInActiveWindow?.findAccessibilityNodeInfosByText("Закрыть")?.none { it.isClickable } == true }
            assertEquals("Opening configuration restarted the real tunnel", revision, ProxyVpnService.trafficRevision())
            assertEquals(id, ProxyVpnService.activeId)
            stage = "capture"
            capture("proxy-"+section.name.lowercase()+"-"+transport+suffix)
            stage = "stop"
            withContext(Dispatchers.IO) { UnifiedAutoCoordinator.stop() }
            assertNull(ProxyVpnService.activeId)
            assertNull(ProxyVpnService.statistics())
            val manager = context.getSystemService(ConnectivityManager::class.java)
            await { manager.getNetworkCapabilities(manager.activeNetwork)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) != true }
            stage = "delete"
            withContext(Dispatchers.IO) { store.delete(id) }
            } catch (failure: Throwable) {
                // Keep only the synthetic stage and type in retained evidence.
                // Do not copy URI, host, key, nonce or core output to the summary.
                throw AssertionError("Synthetic proxy section=${section.name} transport=$transport stage=$stage exception=${failure.javaClass.simpleName}", failure)
            }
        }
    }
    @Test fun automaticFailureFallsBackToAnotherSectionAndStopsBothEngines() = runBlocking {
        val store=ProxyRegistry(registry.vault)
        val original=ProxyImport.parse(fixture.getString("uri"),ProxyProfile.Section.HAPP).single()
        // Port 9 is closed on the disposable host; no provider access is involved.
        val bad=fixture.getString("uri").replace(":${original.port}?",":9?")
        check(bad != fixture.getString("uri"))
        val ids=withContext(Dispatchers.IO) {
            val unavailable=store.importText(ProxyProfile.Section.HAPP,bad).single()
            val available=store.importText(ProxyProfile.Section.BLACKTEMPLE,fixture.getString("uri")).single()
            registry.setAutomaticEnabled(true);Pair(unavailable,available)
        }
        UnifiedAutoCoordinator.connect(context,UnifiedAutoCoordinator.Candidate("HAPP",ids.first))
        val observations = linkedSetOf<String>()
        try {
            await(65_000) {
                val active = when (ProxyVpnService.activeId) { ids.first -> "unavailable"; ids.second -> "available"; null -> "none"; else -> "other" }
                observations.add("active=$active confirmed=${UnifiedAutoCoordinator.confirmedAt != null} busy=${UnifiedAutoCoordinator.busy} status=${UnifiedAutoCoordinator.status}")
                ProxyVpnService.activeId==ids.second && UnifiedAutoCoordinator.confirmedAt!=null && !UnifiedAutoCoordinator.busy
            }
        } catch (failure: AssertionError) {
            throw AssertionError("Synthetic auto fallback states: " + observations.joinToString(" | "), failure)
        }
        exchange("automatic")
        assertEquals(ids.second,ProxyVpnService.activeId)
        capture("proxy-auto-cross-section")
        UnifiedAutoCoordinator.stop()
        assertNull(ProxyVpnService.activeId)
        assertNull(UnifiedAutoCoordinator.confirmedAt)
        assertFalse(UnifiedAutoCoordinator.busy)
        for (t in Application.getTunnelManager().getTunnels().toList()) assertEquals(Tunnel.State.DOWN,t.state)
    }
}
