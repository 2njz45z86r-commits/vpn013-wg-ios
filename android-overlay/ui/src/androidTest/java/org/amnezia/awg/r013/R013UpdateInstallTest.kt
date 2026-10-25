// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Intent
import android.graphics.Bitmap
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.amnezia.awg.BuildConfig
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

@RunWith(AndroidJUnit4::class)
class R013UpdateInstallTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val directory get() = File(context.cacheDir,"updates").apply { mkdirs() }
    private val marker get() = File(directory,"requested-install.json")
    private var activity: R013HomeActivity? = null
    private var vaultBefore = ""
    @Before fun prepare() {
        check(BuildConfig.DEBUG && context.packageName == "com.vpn013.awg.debug")
        vaultBefore = PrivateVault(context).read().toString()
        marker.delete()
        if (InstrumentationRegistry.getArguments().getString("initialInstallPermission") != "denied") {
            shell("appops set ${context.packageName} REQUEST_INSTALL_PACKAGES allow")
        }
        startHome()
    }
    @After fun finish() {
        marker.delete()
        assertEquals("Update flow changed profiles/order bindings",vaultBefore,PrivateVault(context).read().toString())
        instrumentation.runOnMainSync { activity?.finish() }
    }
    @Test fun noConsentDoesNotOpenInstaller() {
        val fixture = futureFile()
        assertTrue(fixture.isFile)
        instrumentation.runOnMainSync { ClientUpdates.resumePendingInstall(activity!!) }
        Thread.sleep(700)
        assertFalse(marker.exists())
        assertEquals(context.packageName,instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString())
    }
    @Test fun changedAPKIsRejectedBeforeInstaller() {
        val file = futureFile()
        val release = release(file)
        file.appendBytes(byteArrayOf(1))
        marker.writeText(release.toString(),Charsets.UTF_8)
        instrumentation.runOnMainSync { ClientUpdates.resumePendingInstall(activity!!) }
        waitFor { !marker.exists() }
        assertEquals(context.packageName,instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString())
        waitFor { findText("Файл обновления изменился") != null }
        instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK)
    }
    @Test fun permissionReturnResumesSameVerifiedUpdateAndCancelDoesNotLoop() {
        val file = futureFile(); val release = release(file)
        // The host establishes denied permission BEFORE this process starts.
        // Revoking it while instrumentation owns this UID can terminate the test.
        assertEquals("denied",InstrumentationRegistry.getArguments().getString("initialInstallPermission"))
        assertFalse(context.packageManager.canRequestPackageInstalls())
        // Invoke the exact Install-button handler; the test never writes a
        // production signing key and never confirms the OS installer.
        val method = ClientUpdates::class.java.getDeclaredMethod("installChecked",androidx.appcompat.app.AppCompatActivity::class.java,File::class.java,JSONObject::class.java).apply { isAccessible = true }
        instrumentation.runOnMainSync { method.invoke(ClientUpdates,activity!!,file,release) }
        assertTrue(marker.exists())
        waitFor { findText("Открыть разрешение") != null }
        val permission = findText("Открыть разрешение") ?: error("Permission action not shown")
        assertTrue(permission.performAction(AccessibilityNodeInfo.ACTION_CLICK))
        waitFor { instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString() == "com.android.settings" }
        // This is the disposable emulator's system permission, not an app
        // bypass. Returning to the app must continue without another check.
        shell("appops set ${context.packageName} REQUEST_INSTALL_PACKAGES allow")
        // Return from the actual Settings activity, as the owner does. Starting
        // an existing task with `am start` can leave Settings above the app and
        // never deliver onResume (confirmed by the captured native UI state).
        assertTrue(instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        waitFor {
            val pkg=instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString().orEmpty()
            !marker.exists() && (pkg.contains("packageinstaller") || pkg.contains("permissioncontroller"))
        }
        val review=File(context.getExternalFilesDir(null),"review").apply { mkdirs() }
        instrumentation.uiAutomation.takeScreenshot().also { bitmap -> File(review,"update-install-confirmation.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG,100,it) }; bitmap.recycle() }
        assertTrue(instrumentation.uiAutomation.performGlobalAction(android.accessibilityservice.AccessibilityService.GLOBAL_ACTION_BACK))
        waitFor { instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString() == context.packageName }
        assertFalse(marker.exists())
        assertEquals(context.packageName,instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString())
        assertEquals(12,context.packageManager.getPackageInfo(context.packageName,0).longVersionCode.toInt())
    }
    private fun futureFile(): File = File(context.getExternalFilesDir(null),"update-fixture.apk").copyTo(File(directory,"VPN013WG.apk"),overwrite=true)
    private fun release(file: File) = JSONObject().put("schema",1).put("app","vpn013-wg").put("platform","android")
        .put("version","1.5.2").put("build",13).put("notes","")
        .put("downloadURL","https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/download/ci-never-published/fixture.apk")
        .put("sha256",MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) })
    private fun startHome() {
        activity=instrumentation.startActivitySync(Intent(context,R013HomeActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as R013HomeActivity
        instrumentation.waitForIdleSync()
    }
    private fun shell(command: String) { instrumentation.uiAutomation.executeShellCommand(command).use { fd -> java.io.FileInputStream(fd.fileDescriptor).use { it.readBytes() } } }
    private fun findText(text: String): AccessibilityNodeInfo? = instrumentation.uiAutomation.rootInActiveWindow?.findAccessibilityNodeInfosByText(text)?.firstOrNull()
    private fun waitFor(test: () -> Boolean) { val until=android.os.SystemClock.elapsedRealtime()+15000
        while(android.os.SystemClock.elapsedRealtime()<until) { if(test()) return; Thread.sleep(100) }
        if (test()) return
        val review=File(context.getExternalFilesDir(null),"review").apply { mkdirs() }
        instrumentation.uiAutomation.takeScreenshot()?.also { bitmap -> File(review,"update-install-failure.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG,100,it) }; bitmap.recycle() }
        val root=instrumentation.uiAutomation.rootInActiveWindow
        fun visible(node: AccessibilityNodeInfo?): String = if (node == null) "null" else buildString {
            append(node.packageName); append(':'); append(node.className); append(':'); append(node.text); append('\n')
            for (i in 0 until node.childCount) append(visible(node.getChild(i)))
        }
        // This fixture contains only synthetic APKs and synthetic vault data.
        // Persist bounded visible UI diagnostics, never production logs/keys.
        File(review,"update-install-failure.txt").writeText("marker=${marker.exists()} permission=${context.packageManager.canRequestPackageInstalls()} finishing=${activity?.isFinishing} destroyed=${activity?.isDestroyed}\n"+visible(root).take(16000))
        fail("Native update flow timed out; marker=${marker.exists()} permission=${context.packageManager.canRequestPackageInstalls()} package=${root?.packageName}")
    }
}
