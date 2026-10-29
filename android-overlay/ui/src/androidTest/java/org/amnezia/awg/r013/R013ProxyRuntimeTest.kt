// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Intent
import android.graphics.Bitmap
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
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

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
    }
    @After fun finish() = runBlocking {
        UnifiedAutoCoordinator.stop()
        assertNull(ProxyVpnService.activeId)
        instrumentation.runOnMainSync { activity?.finish() }
    }
    private fun await(timeout: Long = 20_000, condition: () -> Boolean) {
        val until = System.currentTimeMillis()+timeout
        while (System.currentTimeMillis()<until) { if (condition()) return; Thread.sleep(100) }
        assertTrue("Native proxy condition timed out; error="+ProxyVpnService.lastError,condition())
    }
    private fun exchange() {
        val manager = context.getSystemService(ConnectivityManager::class.java)
        assertTrue("The application must use the actual VPN network",manager.getNetworkCapabilities(manager.activeNetwork)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        Socket().use { socket ->
            socket.soTimeout=6_000
            socket.connect(InetSocketAddress(fixture.getString("host"),fixture.getInt("port")),6_000)
            val nonce=fixture.getString("nonce")
            socket.getOutputStream().write(("GET /$nonce HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n").toByteArray())
            val bytes=socket.getInputStream().readNBytes(4097)
            assertTrue(bytes.size<=4096)
            val response=String(bytes,Charsets.US_ASCII)
            assertTrue("Disposable peer must return its unpredictable response",response.startsWith("HTTP/1.1 200") && response.contains(nonce))
        }
        await { val stats=ProxyVpnService.statistics(); stats != null && stats.optLong("rx")>0 && stats.optLong("tx")>0 }
    }
    private fun capture(name: String) {
        val folder=File(context.getExternalFilesDir(null),"review").apply { mkdirs() }
        instrumentation.uiAutomation.takeScreenshot().also { bitmap ->
            File(folder,"$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG,100,it) };bitmap.recycle()
        }
    }
    @Test fun actualRealityTrafficInAllThreeProxySectionsAndCompleteStop() = runBlocking {
        val store=ProxyRegistry(registry.vault)
        for (section in ProxyProfile.Section.values()) {
            val id=withContext(Dispatchers.IO) { store.importText(section,fixture.getString("uri")).single() }
            ProxyVpnService.start(context,id)
            await { ProxyVpnService.activeId == id }
            exchange()
            assertEquals(id,ProxyVpnService.activeId)
            capture("proxy-"+section.name.lowercase())
            withContext(Dispatchers.IO) { ProxyVpnService.stopAndWait() }
            assertNull(ProxyVpnService.activeId)
            assertNull(ProxyVpnService.statistics())
            withContext(Dispatchers.IO) { store.delete(id) }
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
        await(65_000) { ProxyVpnService.activeId==ids.second && UnifiedAutoCoordinator.confirmedAt!=null && !UnifiedAutoCoordinator.busy }
        exchange()
        assertEquals(ids.second,ProxyVpnService.activeId)
        capture("proxy-auto-cross-section")
        UnifiedAutoCoordinator.stop()
        assertNull(ProxyVpnService.activeId)
        assertNull(UnifiedAutoCoordinator.confirmedAt)
        assertFalse(UnifiedAutoCoordinator.busy)
        for (t in Application.getTunnelManager().getTunnels().toList()) assertEquals(Tunnel.State.DOWN,t.state)
    }
}
