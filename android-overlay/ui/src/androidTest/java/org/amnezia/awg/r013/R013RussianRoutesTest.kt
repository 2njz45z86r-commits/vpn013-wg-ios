// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.amnezia.awg.Application
import org.amnezia.awg.BuildConfig
import org.amnezia.awg.backend.GoBackend
import org.amnezia.awg.backend.Tunnel
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.Socket
import java.net.InetSocketAddress
@RunWith(AndroidJUnit4::class)
class R013RussianRoutesTest {
 private fun echo(ip:String):Boolean = try {
  Socket().use { socket->socket.connect(InetSocketAddress(ip,13013),1500);socket.soTimeout=1500
   socket.getOutputStream().write("vpn013-route-check\n".toByteArray())
   socket.getInputStream().bufferedReader().readLine()=="vpn013-route-ok"
  }
 }catch(_:Exception){false}
 @Test fun realDirectRUAndForeignVPNWithOriginalKeys()=runBlocking{
  val context=InstrumentationRegistry.getInstrumentation().targetContext
  check(BuildConfig.DEBUG&&context.packageName=="com.vpn013.awg.debug")
  val tunnels=Application.getTunnelManager().getTunnels()
  for(t in tunnels.toList())if(t.state==Tunnel.State.UP)t.setStateAsync(Tunnel.State.DOWN)
  assertTrue("RU fixture must be physically reachable before VPN",echo("2.56.24.1"))
  assertTrue("Control fixture must be physically reachable before VPN",echo("198.18.0.1"))
  val raw=InstrumentationRegistry.getArguments().getString("syntheticConfig")!!
  val text=String(android.util.Base64.decode(raw,android.util.Base64.DEFAULT))
      .replace("AllowedIPs = 10.13.99.1/32","AllowedIPs = 0.0.0.0/0, 2001:db8::/32")
  val registry=ProfileRegistry.get(context)
  OfflineChanges.apply{registry.importOrdinary(listOf("CI RU routing" to ProfileRegistry.parse(text)))}
  val tunnel=tunnels["CI RU routing"]!!
  val before=registry.config(tunnel.name).toAwgQuickString()
  try{
   tunnel.setStateAsync(Tunnel.State.UP)
   val cm=context.getSystemService(ConnectivityManager::class.java)
   val vpn=cm.allNetworks.first{cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true}
   val routes=cm.getLinkProperties(vpn)!!.routes
   assertEquals("All production RU exclusions must reach Android",10838,routes.count{it.type==9})
   assertTrue("A narrow IPv6 crypto route must not create foreign cleartext fallback",routes.any{it.type==1 && it.destination.address is java.net.Inet6Address && it.destination.prefixLength==0})
   assertTrue("Registered RU destination must bypass VPN",echo("2.56.24.1"))
   assertFalse("Foreign control must not escape via direct network",echo("198.18.0.1"))
   assertEquals(before,registry.config(tunnel.name).toAwgQuickString())
   assertEquals("CI RU routing",(Application.getBackend() as GoBackend).currentProfileName)
  }finally{if(tunnel.state==Tunnel.State.UP)tunnel.setStateAsync(Tunnel.State.DOWN)}
  assertTrue("Physical control route must recover after stop",echo("198.18.0.1"))
 }
}
