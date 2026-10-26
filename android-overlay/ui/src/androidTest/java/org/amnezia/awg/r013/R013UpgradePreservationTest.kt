// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.amnezia.awg.BuildConfig
import org.amnezia.awg.crypto.KeyPair
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/** Runs once against the installed1.5.2 debug source and again after adb install-r.
 * Only synthetic local data is used. No device/order registration or network. */
@RunWith(AndroidJUnit4::class)
class R013UpgradePreservationTest {
    @Test fun existingInstallationSurvivesPackageReplacement() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        check(BuildConfig.DEBUG && context.packageName == "com.vpn013.awg.debug")
        val root = File(context.filesDir,"ci-update-proof").apply { mkdirs() }
        val expected = File(root,"before.json")
        val vault = PrivateVault(context)
        fun diskHash() = MessageDigest.getInstance("SHA-256").digest(File(context.filesDir,"r013-vault.bin").readBytes()).joinToString("") { "%02x".format(it) }
        if (InstrumentationRegistry.getArguments().getString("upgradePhase") == "seed") {
            assertEquals("Historical debug source must be1.5.2",13L,context.packageManager.getPackageInfo(context.packageName,0).longVersionCode)
            val registry = ProfileRegistry.get(context)
            val key = KeyPair().privateKey.toBase64()
            val peer = KeyPair().publicKey.toBase64()
            registry.create("Existing CI profile",ProfileRegistry.parse("[Interface]\nPrivateKey = $key\nAddress = 10.99.88.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = $peer\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0\n"))
            registry.vault.edit { it.getJSONObject("orders").put("ci-existing-order",JSONObject().put("expiry",1893456000000L).put("binding","synthetic-existing-binding")) }
            expected.writeText(JSONObject().put("uid",context.applicationInfo.uid).put("package",context.packageName)
                .put("vault",vault.read()).put("diskHash",diskHash()).toString(),Charsets.UTF_8)
        } else {
            assertEquals(14L,context.packageManager.getPackageInfo(context.packageName,0).longVersionCode)
            val before=JSONObject(expected.readText(Charsets.UTF_8))
            assertEquals(before.getInt("uid"),context.applicationInfo.uid)
            assertEquals(before.getString("package"),context.packageName)
            assertEquals("Ciphertext changed during package replacement",before.getString("diskHash"),diskHash())
            val current=vault.read()
            assertEquals("Android Keystore key or stored content was lost",before.getJSONObject("vault").toString(),current.toString())
            assertEquals(1,current.getJSONObject("profiles").length())
            assertEquals(1,current.getJSONObject("orders").length())
            assertEquals(1893456000000L,current.getJSONObject("orders").getJSONObject("ci-existing-order").getLong("expiry"))
            assertEquals("Existing CI profile",ProfileRegistry.get(context).records().single().getString("name"))
            val review=File(context.getExternalFilesDir(null),"review").apply { mkdirs() }
            File(review,"in-place-upgrade.json").writeText(JSONObject().put("fromVersionCode",13).put("toVersionCode",14)
                .put("samePackageAndUID",true).put("ciphertextPreserved",true).put("keystoreDecryption",true)
                .put("profilesKeysOrdersExpiryPreserved",true).put("historicalDebugSourceFixture",true)
                .put("productionSigningCertificateTested",false).put("physicalPhone",false).toString(),Charsets.UTF_8)
        }
    }
}
