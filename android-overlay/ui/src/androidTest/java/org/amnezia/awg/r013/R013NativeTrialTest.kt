// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.app.Activity
import android.app.Instrumentation
import android.app.NotificationManager
import android.content.Intent
import android.graphics.Bitmap
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.amnezia.awg.Application
import org.amnezia.awg.BuildConfig
import org.amnezia.awg.backend.Tunnel
import org.amnezia.awg.crypto.KeyPair
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.Collections
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Synthetic API/archive responses only. Real UI, protected vault and OS notifications. */
@RunWith(AndroidJUnit4::class)
class R013NativeTrialTest {
    private val instrumentation=InstrumentationRegistry.getInstrumentation()
    private val context get()=instrumentation.targetContext
    private val registry get()=ProfileRegistry.get(context)
    private var activity:R013HomeActivity?=null
    private val outside=Collections.synchronizedList(mutableListOf<String>())
    private val monitor=object:Instrumentation.ActivityMonitor() {
        override fun onStartActivity(intent:Intent):Instrumentation.ActivityResult? {
            if(intent.action==Intent.ACTION_VIEW) {
                outside.add(intent.dataString.orEmpty())
                return Instrumentation.ActivityResult(Activity.RESULT_CANCELED,null)
            }
            return null
        }
    }
    private val oid="012345abcdef"
    private val ticket="A".repeat(43)
    private val capability="B".repeat(43)
    private val renewal="https://t.me/vpn013_com_bot?start=trial_"+"C".repeat(43)
    private var expires=System.currentTimeMillis()+259200000L
    private var issued=expires-259200000L
    private var creates=0
    private var downloads=0
    private var badZIP=false
    private val configs=linkedMapOf<String,String>()
    private fun config(port:Int):String {
        val client=KeyPair();val peer=KeyPair()
        return "[Interface]\nPrivateKey = ${client.privateKey.toBase64()}\nAddress = 10.13.0.2/32\nDNS = 1.1.1.1\nJc = 3\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 30\nH1 = 1001\nH2 = 1002\nH3 = 1003\nH4 = 1004\n[Peer]\nPublicKey = ${peer.publicKey.toBase64()}\nEndpoint = 127.0.0.1:$port\nAllowedIPs = 0.0.0.0/0\n"
    }
    private fun snapshot():JSONObject {
        val servers=JSONArray();val digest=StringBuilder()
        configs.forEach { (name,text)->
            servers.put(JSONObject().put("id",name).put("name",name).put("config",text))
            digest.append(name).append('\n').append(name).append('\n').append(text).append('\n')
        }
        return JSONObject().put("schema",1).put("kind","vpn013-awg").put("orderID",oid).put("expiry",expires)
            .put("complete",true).put("revision",ProfileRegistry.digest(digest.toString())).put("servers",servers)
    }
    private fun info():JSONObject = JSONObject().put("schema",1).put("kind","vpn013-native-trial").put("app","vpn013-wg")
        .put("orderID",oid).put("state",if(expires<=System.currentTimeMillis())"expired" else "active")
        .put("issuedAt",issued).put("expiresAt",expires).put("serverTime",System.currentTimeMillis())
        .put("durationSeconds",259200).put("isTrial",true).put("renewalURL",renewal)
    private fun archive():ByteArray {
        val bytes=ByteArrayOutputStream()
        ZipOutputStream(bytes).use { z ->
            if(badZIP) { z.putNextEntry(ZipEntry("../escape.conf"));z.write(configs.values.first().toByteArray());z.closeEntry() }
            else {
                configs.forEach { (name,text)->z.putNextEntry(ZipEntry("$name.conf"));z.write(text.toByteArray());z.closeEntry() }
                val document=JSONObject().put("schema",1).put("kind","vpn013-access").put("capability",capability).put("snapshot",snapshot())
                    .put("trial",JSONObject().put("durationSeconds",259200).put("renewalURL",renewal))
                z.putNextEntry(ZipEntry("VPN013-Access.json"));z.write(document.toString().toByteArray());z.closeEntry()
            }
        }
        return bytes.toByteArray()
    }
    @Before fun prepare()=runBlocking {
        check(BuildConfig.DEBUG && context.packageName=="com.vpn013.awg.debug")
        Application.getTunnelManager().getTunnels()
        for(t in Application.getTunnelManager().getTunnels().toList())if(t.state==Tunnel.State.UP)t.setStateAsync(Tunnel.State.DOWN)
        OfflineChanges.apply { registry.vault.write(JSONObject().put("schema",1).put("profiles",JSONObject()).put("orders",JSONObject()));registry.create("Existing manual",ProfileRegistry.parse(config(51999))) }
        configs.clear();listOf("Alpha","Beta","Gamma").forEachIndexed { index,name->configs[name]=config(51820+index) }
        (context.getSystemService(NotificationManager::class.java)).cancelAll()
        context.getSharedPreferences("trial-expiry-notifications",0).edit().clear().commit()
        instrumentation.addMonitor(monitor)
        NativeTrial.installDebugFixture(NativeTrial.FixtureTransport { action,body,auth,binary->
            when(action) {
                "create"->{ creates++;assertEquals("android",body.getString("platform"));assertEquals(43,body.getString("requestID").length);assertNull(auth);info().put("ticket",ticket).toString().toByteArray() }
                "info"->{ assertEquals(ticket,auth);info().toString().toByteArray() }
                "file"->{ downloads++;assertTrue(binary);assertEquals(ticket,auth);assertEquals("android",body.getString("platform"));archive() }
                else->error("Unexpected native trial action")
            }
        })
    }
    @After fun finish() {
        NativeTrial.installDebugFixture(null);ClientProtocol.installNativeTrialDebugFixture(null)
        instrumentation.removeMonitor(monitor)
        instrumentation.runOnMainSync { activity?.finish() }
        context.getSystemService(NotificationManager::class.java).cancelAll()
    }
    private fun start() {
        activity=instrumentation.startActivitySync(Intent(context,R013HomeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as R013HomeActivity
        instrumentation.waitForIdleSync()
    }
    private fun node(text:String):AccessibilityNodeInfo? {
        fun find(n:AccessibilityNodeInfo?):AccessibilityNodeInfo? {
            if(n==null)return null
            if(n.text?.toString()==text || n.contentDescription?.toString()==text)return n
            for(i in 0 until n.childCount)find(n.getChild(i))?.let { return it }
            return null
        }
        return find(instrumentation.uiAutomation.rootInActiveWindow)
    }
    private fun waitFor(check:()->Boolean) {
        val until=android.os.SystemClock.elapsedRealtime()+15000
        while(android.os.SystemClock.elapsedRealtime()<until) { if(check())return;Thread.sleep(100) }
        assertTrue("Native trial state did not arrive",check())
    }
    private fun click(text:String) { waitFor { node(text)!=null };assertTrue(node(text)!!.performAction(AccessibilityNodeInfo.ACTION_CLICK)) }
    private fun getTrial() { click("Добавить");waitFor { node(NativeTrial.LABEL)!=null };assertNull(node("1 час бесплатно"));click(NativeTrial.LABEL) }
    private fun importTrial() {
        start();getTrial();waitFor { node("Тестовые профили добавлены")!=null };click("Готово")
        waitFor { registry.vault.read().getJSONObject("orders").has(oid) }
    }
    private fun screenshot(name:String) {
        val root=File(context.getExternalFilesDir(null),"review").apply { mkdirs() }
        val image=instrumentation.uiAutomation.takeScreenshot()
        File(root,"native-trial-$name.png").outputStream().use { image.compress(Bitmap.CompressFormat.PNG,100,it) };image.recycle()
    }
    @Test fun directButtonImportsFullZIPWithoutOpeningWebsite() {
        start();click("Добавить");waitFor { node(NativeTrial.LABEL)!=null };assertNotNull(node("Продлить конфигурацию"));assertNull(node("1 час бесплатно"));screenshot("menu")
        click(NativeTrial.LABEL);waitFor { node("Тестовые профили добавлены")!=null };screenshot("imported")
        assertEquals(1,creates);assertEquals(1,downloads);assertTrue(outside.isEmpty())
        assertEquals(4,registry.records().size);assertEquals(1,registry.vault.read().getJSONObject("orders").length())
        val state=registry.vault.read();assertEquals(expires,state.getJSONObject("orders").getJSONObject(oid).getJSONObject("document").getJSONObject("snapshot").getLong("expiry"))
        val encrypted=File(context.filesDir,"r013-vault.bin").readBytes().toString(Charsets.ISO_8859_1)
        assertFalse(encrypted.contains(ticket));assertFalse(encrypted.contains(renewal))
        assertEquals(0,Application.getBackend().runningTunnelNames.size)
    }
    @Test fun repeatedButtonResumesSameTrialWithoutDuplicateProfiles() {
        importTrial();val before=registry.records().associate { it.getString("id") to it.getString("config") }
        getTrial();waitFor { node("Тестовые профили добавлены")!=null }
        assertEquals(1,creates);assertEquals(2,downloads)
        assertEquals(before,registry.records().associate { it.getString("id") to it.getString("config") })
        assertTrue(outside.isEmpty())
    }
    @Test fun unsafeZIPDoesNotChangeExistingProfilesOrOrders() {
        badZIP=true;val before=registry.vault.read().getJSONObject("profiles").toString();start();getTrial()
        waitFor { node("Тест не добавлен")!=null }
        assertEquals(before,registry.vault.read().getJSONObject("profiles").toString());assertEquals(0,registry.vault.read().getJSONObject("orders").length())
        assertTrue(outside.isEmpty());screenshot("rejected-zip")
    }
    @Test fun expiredTrialOffersOnlyPersonalBotRenewal() {
        expires=System.currentTimeMillis()-1000;issued=expires-259200000L
        start();getTrial();waitFor { node("Срок доступа закончился")!=null };screenshot("expired")
        click("Продлить конфигурацию");waitFor { outside.size==1 }
        assertEquals(renewal,outside.single());assertEquals(0,downloads);assertEquals(1,registry.records().size)
    }
    @Test fun paidSnapshotRefreshKeepsKeysAndCancelsOldExpiryNotice()=runBlocking {
        importTrial()
        val before=registry.records().associate { it.getString("id") to it.getString("config") }
        val old=System.currentTimeMillis()-1000
        OfflineChanges.lock.lock()
        try { registry.vault.edit { it.getJSONObject("orders").getJSONObject(oid).getJSONObject("document").getJSONObject("snapshot").put("expiry",old) } }
        finally { OfflineChanges.lock.unlock() }
        instrumentation.runOnMainSync { TrialExpiryNotifications.expired(context,oid) }
        val manager=context.getSystemService(NotificationManager::class.java)
        waitFor { manager.activeNotifications.any { it.tag==oid } }
        instrumentation.runOnMainSync { NativeTrial.renewalMenu(activity!!) };click("Заявка №$oid");waitFor { outside.size==1 };assertEquals(renewal,outside.single())
        expires=System.currentTimeMillis()+30L*86400000L
        ClientProtocol.installNativeTrialDebugFixture { path,auth->assertEquals("/client/awg/$oid/android",path);assertEquals(capability,auth);snapshot() }
        instrumentation.runOnMainSync { NativeTrial.resumeRenewal(activity!!) {} }
        waitFor { registry.vault.read().getJSONObject("orders").getJSONObject(oid).getJSONObject("document").getJSONObject("snapshot").getLong("expiry")==expires }
        assertEquals(before,registry.records().associate { it.getString("id") to it.getString("config") })
        waitFor { manager.activeNotifications.none { it.tag==oid } }
        assertEquals(1,creates);assertEquals(1,downloads)
    }
}
