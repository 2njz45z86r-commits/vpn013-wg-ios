// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013

import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.net.InetAddress
import java.security.SecureRandom

/** ICMP echo, bound to the current OS route. It does not start or switch VPN. */
object EndpointPing {
    fun measure(host: String): Long? {
        require(host.isNotBlank() && host.length <= 253 && host.none { it.isWhitespace() })
        val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
        for (address in InetAddress.getAllByName(host).take(2)) {
            var fd: java.io.FileDescriptor? = null
            try {
                val v4 = address.address.size == 4
                fd = Os.socket(if (v4) OsConstants.AF_INET else OsConstants.AF_INET6, OsConstants.SOCK_DGRAM,
                    if (v4) OsConstants.IPPROTO_ICMP else OsConstants.IPPROTO_ICMPV6)
                val packet = ByteArray(24); packet[0] = (if (v4) 8 else 128).toByte(); packet[7] = 1
                nonce.copyInto(packet, 8)
                if (v4) {
                    var sum = 0; for (i in packet.indices step 2) sum += ((packet[i].toInt() and 255) shl 8) or (packet[i + 1].toInt() and 255)
                    while (sum ushr 16 != 0) sum = (sum and 65535) + (sum ushr 16)
                    val checksum = sum.inv() and 65535; packet[2] = (checksum ushr 8).toByte(); packet[3] = checksum.toByte()
                }
                val start = SystemClock.elapsedRealtimeNanos()
                Os.sendto(fd, packet, 0, packet.size, 0, address, 0)
                val poll = StructPollfd().apply { this.fd = fd; events = OsConstants.POLLIN.toShort() }
                val response = ByteArray(2048)
                while ((SystemClock.elapsedRealtimeNanos() - start) < 1_500_000_000L) {
                    val remaining = ((1_500_000_000L - (SystemClock.elapsedRealtimeNanos() - start)) / 1_000_000L).toInt().coerceAtLeast(1)
                    if (Os.poll(arrayOf(poll), remaining) <= 0) break
                    val n = Os.read(fd, response, 0, response.size)
                    val offset = if (n > 20 && response[0].toInt().ushr(4) == 4) (response[0].toInt() and 15) * 4 else 0
                    if (n >= offset + 24 && (response[offset].toInt() and 255) == (if (v4) 0 else 129)) {
                        if (response.copyOfRange(offset + 8, offset + 24).contentEquals(nonce))
                            return ((SystemClock.elapsedRealtimeNanos() - start) / 1_000_000L).coerceAtLeast(1)
                    }
                }
            } catch (_: Exception) { /* Missing ICMP support/response is unavailable, never a fabricated latency. */ }
            finally { if (fd != null) try { Os.close(fd) } catch (_: Exception) {} }
        }
        return null
    }
}
