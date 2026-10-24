// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Authenticated atomic storage. Never falls back to plaintext on key failure. */
class PrivateVault(context: Context) {
    private val file = AtomicFile(java.io.File(context.filesDir, "r013-vault.bin"))
    private val alias = context.packageName + ".private-vault-v1"
    private var cached: JSONObject? = null
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        check(!file.baseFile.exists()) { "Защищённое хранилище недоступно. Не удаляйте данные приложения." }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).setKeySize(256).build())
        }.generateKey()
    }
    @Synchronized fun read(): JSONObject {
        cached?.let { return JSONObject(it.toString()) }
        if (!file.baseFile.exists() && !java.io.File(file.baseFile.path + ".bak").exists())
            return JSONObject().put("schema", 1).put("profiles", JSONObject()).put("orders", JSONObject())
        val bytes = file.openRead().use { input ->
            val out = ByteArrayOutputStream(); val buf = ByteArray(8192)
            while (true) { val n = input.read(buf); if (n < 0) break
                check(out.size() + n <= MAX_BYTES + 64) { "Хранилище слишком велико" }; out.write(buf, 0, n) }
            out.toByteArray()
        }
        check(bytes.size >= 32 && bytes.copyOfRange(0, 4).contentEquals(MAGIC)) { "Хранилище повреждено" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(4, 16))); cipher.updateAAD(MAGIC)
        val decoded = JSONObject(String(cipher.doFinal(bytes.copyOfRange(16, bytes.size)), Charsets.UTF_8))
        check(decoded.getInt("schema") == 1) { "Неизвестный формат хранилища" }
        cached = decoded; return JSONObject(decoded.toString())
    }
    @Synchronized fun write(document: JSONObject) {
        check(document.getInt("schema") == 1)
        val plain = document.toString().toByteArray(Charsets.UTF_8)
        check(plain.size <= MAX_BYTES) { "Хранилище заполнено" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key()); cipher.updateAAD(MAGIC)
        val encrypted = MAGIC + cipher.iv + cipher.doFinal(plain)
        var stream: java.io.FileOutputStream? = null
        try { stream = file.startWrite(); stream.write(encrypted); file.finishWrite(stream) }
        catch (e: Exception) { file.failWrite(stream); throw e }
        cached = JSONObject(document.toString())
    }
    @Synchronized fun <T> edit(block: (JSONObject) -> T): T {
        val document = read(); val result = block(document); write(document); return result
    }
    companion object { private val MAGIC = byteArrayOf(82, 48, 49, 51); const val MAX_BYTES = 8_388_608 }
}
