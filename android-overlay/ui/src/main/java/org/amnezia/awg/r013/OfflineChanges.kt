// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.amnezia.awg.Application

object OfflineChanges {
    class ActiveVPNException : IllegalStateException("Сначала отключите VPN. Прежние профили сохранены.")
    val lock = Mutex()
    suspend fun <T> apply(block: () -> T): T = lock.withLock {
        val manager = Application.getTunnelManager()
        manager.getTunnels()
        val registry = ProfileRegistry.get(Application.get())
        val before = withContext(Dispatchers.IO) {
            if (Application.getBackend().runningTunnelNames.isNotEmpty()) throw ActiveVPNException()
            registry.vault.read()
        }
        try {
            val result = withContext(Dispatchers.IO) { block() }
            manager.reloadPrivateStore(); result
        } catch (e: Exception) {
            withContext(Dispatchers.IO) { registry.vault.write(before) }
            manager.reloadPrivateStore()
            throw e
        }
    }
}
