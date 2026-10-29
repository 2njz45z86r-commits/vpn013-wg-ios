// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.content.Context
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.amnezia.awg.Application
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicLong

/** One process owner survives Activity recreation and cancels late connection results. */
object UnifiedAutoCoordinator {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lock = Mutex()
    private val epoch = AtomicLong()
    private var worker: Job? = null
    private var comparison: Job? = null
    @Volatile var busy = false; private set
    @Volatile var confirmedAt: Long? = null; private set
    @Volatile var status: String? = null; private set
    data class Candidate(val section: String, val id: String)

    fun connect(context: Context, selected: Candidate, measuredChoice: Boolean = false) {
        val owner = context.applicationContext
        val generation = epoch.incrementAndGet()
        val previous = worker
        previous?.cancel()
        comparison?.cancel()
        worker = scope.launch {
            previous?.join()
            lock.withLock {
                busy = true; confirmedAt = null
                try {
                    val registry = ProfileRegistry.get(owner)
                    val order = candidates(registry, selected)
                    var failures = 0
                    for (candidate in order) {
                        if (!isActive || generation != epoch.get()) break
                        if (candidate != selected && !registry.automaticEnabled()) break
                        status = "Подключаем ${label(candidate.section)}…"
                        if (!start(owner, candidate, generation)) continue
                        var connected = false
                        repeat(2) {
                            if (!connected && isActive && generation == epoch.get()) connected = healthy()
                        }
                        if (!isActive || generation != epoch.get()) break
                        if (!connected) { stopEngines(); continue }
                        confirmedAt = System.currentTimeMillis(); busy = false; status = "Передача данных подтверждена"
                        (Application.getBackend() as GoBackend).setAutomaticEnabled(registry.automaticEnabled())
                        if (candidate.section != "AMNEZIAWG") comparison = scope.launch {
                            if (measuredChoice) delay(300_000)
                            while (isActive && generation == epoch.get()) {
                                if (registry.automaticEnabled()) {
                                    val store = ProxyRegistry(registry.vault)
                                    val section = ProxyProfile.Section.valueOf(candidate.section)
                                    val records = store.list(section).take(30)
                                    val current = records.singleOrNull { it.id == candidate.id }
                                    if (current != null) {
                                        val baseline = ProxyVpnService.measure(current.profile)
                                        var bestId = candidate.id; var best = baseline
                                        for (record in records.filter { it.id != candidate.id }) {
                                            if (!isActive || generation != epoch.get() || !registry.automaticEnabled()) break
                                            val measured = ProxyVpnService.measure(record.profile) ?: continue
                                            if (best == null || measured < best) { best = measured; bestId = record.id }
                                        }
                                        if (isActive && generation == epoch.get() && bestId != candidate.id && best != null &&
                                            (baseline == null || (!measuredChoice && baseline > best) || (baseline - best >= 30 && best * 5 <= baseline * 4))) {
                                            connect(owner, Candidate(candidate.section, bestId), true); return@launch
                                        }
                                    }
                                }
                                delay(300_000)
                            }
                        }
                        while (isActive && generation == epoch.get()) {
                            delay(15_000)
                            if (!registry.automaticEnabled()) { failures = 0; continue }
                            if (healthy()) { failures = 0; confirmedAt = System.currentTimeMillis() }
                            else failures++
                            if (failures >= 2) { busy = true; confirmedAt = null; break }
                        }
                        comparison?.cancelAndJoin(); comparison = null
                        // Each owned candidate is attempted at most once in this failure cycle.
                        // No key renewal or new provider access is performed here.
                    }
                    if (generation == epoch.get() && isActive) {
                        stopEngines(); status = "Доступные подключения не ответили. Проверьте сеть и срок доступа."
                    }
                } catch (_: CancellationException) { throw CancellationException() }
                catch (_: Exception) {
                    if (generation == epoch.get()) withContext(NonCancellable) { stopEngines() }
                    status = "Не удалось подключиться. Конфигурации сохранены."
                }
                finally { if (generation == epoch.get()) busy = false }
            }
        }
    }
    private fun candidates(registry: ProfileRegistry, selected: Candidate): List<Candidate> {
        val proxy = ProxyRegistry(registry.vault)
        val all = mutableListOf<Candidate>()
        val awg = registry.vault.read().getJSONObject("profiles")
        awg.keys().asSequence().map { awg.getJSONObject(it) }.filter { !it.has("members") }
            .take(30).forEach { all.add(Candidate("AMNEZIAWG", it.getString("name"))) }
        ProxyProfile.Section.values().forEach { section -> proxy.list(section).take(30).forEach { all.add(Candidate(section.name, it.id)) } }
        return (listOf(selected) + all.filter { it.section == selected.section && it != selected } + all.filter { it.section != selected.section }).distinct().take(120)
    }
    private suspend fun start(context: Context, candidate: Candidate, generation: Long): Boolean = try {
        stopEngines()
        if (generation != epoch.get()) false else if (candidate.section == "AMNEZIAWG") {
            val manager = Application.getTunnelManager()
            val tunnel = manager.getTunnels().single { it.name == candidate.id }
            (Application.getBackend() as GoBackend).setAutomaticEnabled(ProfileRegistry.get(context).automaticEnabled())
            tunnel.setStateAsync(Tunnel.State.UP); true
        } else {
            ProxyVpnService.start(context, candidate.id)
            withTimeout(20_000) {
                while (ProxyVpnService.activeId != candidate.id) {
                    if (ProxyVpnService.lastError != null || generation != epoch.get()) error("Connection stopped")
                    delay(50)
                }
            }; true
        }
    } catch (_: CancellationException) { throw CancellationException() } catch (_: Exception) { false }

    private suspend fun stopEngines() {
        ProxyVpnService.stopAndWait()
        for (tunnel in Application.getTunnelManager().getTunnels().toList()) if (tunnel.state == Tunnel.State.UP) tunnel.setStateAsync(Tunnel.State.DOWN)
    }
    suspend fun stop() {
        epoch.incrementAndGet(); comparison?.cancelAndJoin(); comparison = null
        val previous = worker; worker = null; previous?.cancelAndJoin()
        lock.withLock { withContext(NonCancellable + Dispatchers.IO) { stopEngines() }; busy = false; confirmedAt = null; status = null }
    }
    private fun healthy(): Boolean {
        var connection: HttpURLConnection? = null
        return try {
            connection = URL("https://www.gstatic.com/generate_204").openConnection() as HttpURLConnection
            connection.connectTimeout = 4000; connection.readTimeout = 4000; connection.instanceFollowRedirects = false
            connection.useCaches = false; connection.setRequestProperty("Cache-Control", "no-store")
            connection.responseCode == 204
        } catch (_: Exception) { false } finally { connection?.disconnect() }
    }
    fun label(section: String): String = when(section) { "HAPP" -> "Happ"; "INCY" -> "INCY"; "BLACKTEMPLE" -> "BlackTemple"; else -> "AmneziaWG" }
}
