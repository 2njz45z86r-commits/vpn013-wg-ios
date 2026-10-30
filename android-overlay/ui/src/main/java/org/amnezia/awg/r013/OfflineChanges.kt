// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.amnezia.awg.Application
import org.json.JSONObject
import java.util.UUID

object OfflineChanges {
    class ActiveVPNException : IllegalStateException("Сначала отключите VPN. Прежние профили сохранены.")
    val lock = Mutex()
    // A provider can bind the HWID when it returns data, before that data is
    // parsed. Keep new origin IDs on rollback so a retry does not look like a
    // different device; all sources and profiles still revert atomically.
    private fun retainNewOriginIds(before: JSONObject, after: JSONObject) {
        val discovered = after.optJSONObject("proxyOrigins") ?: return
        val previous = before.optJSONObject("proxyOrigins") ?: JSONObject().also { before.put("proxyOrigins", it) }
        for (key in discovered.keys()) {
            if (previous.has(key) || previous.length() >= 256 || !key.matches(Regex("^[a-f0-9]{64}$"))) continue
            val value = discovered.opt(key) as? String ?: continue
            try { if (UUID.fromString(value).toString() == value) previous.put(key, value) } catch (_: IllegalArgumentException) { }
        }
        if (previous.length() == 0) before.remove("proxyOrigins")
    }
    suspend fun <T> apply(block: () -> T): T = lock.withLock {
        val manager = Application.getTunnelManager()
        manager.getTunnels()
        val registry = ProfileRegistry.get(Application.get())
        val before = withContext(Dispatchers.IO) {
            if (Application.getBackend().runningTunnelNames.isNotEmpty() || ProxyVpnService.activeId != null ||
                ProxyVpnService.requestedId != null || UnifiedAutoCoordinator.busy) throw ActiveVPNException()
            registry.vault.read()
        }
        try {
            val result = withContext(Dispatchers.IO) { block() }
            manager.reloadPrivateStore(); result
        } catch (e: Exception) {
            withContext(NonCancellable) {
                withContext(Dispatchers.IO) {
                    runCatching { retainNewOriginIds(before, registry.vault.read()) }
                    registry.vault.write(before)
                }
                manager.reloadPrivateStore()
            }
            throw e
        }
    }
}
