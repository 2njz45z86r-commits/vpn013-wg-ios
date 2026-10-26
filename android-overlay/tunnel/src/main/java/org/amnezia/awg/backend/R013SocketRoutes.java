// SPDX-License-Identifier: MIT
package org.amnezia.awg.backend;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.ParcelFileDescriptor;
import android.os.Build;
import android.os.Process;
import androidx.annotation.Keep;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicBoolean;

/** Immutable explicit routes for one bounded comparison, never a default fallback.
 * JNI invokes this object without taking the GoBackend monitor. Primary mutation
 * may be waiting for an in-flight socket gate to drain, so that is essential. */
@Keep
public final class R013SocketRoutes {
    private final Context context;
    private final GoBackend.VpnService service;
    private final ConnectivityManager connectivity;
    private final Network vpn;
    private final String interfaceName;
    private final int interfaceIndex;
    private final GoBackend.NativeRouteBinding nativeBinding;
    private final String physicalFingerprint;
    private final AtomicBoolean closed = new AtomicBoolean();

    public R013SocketRoutes(Context context, GoBackend.VpnService service, String interfaceName) {
        if (interfaceName == null || interfaceName.isEmpty() || interfaceName.length() > 64)
            throw new IllegalStateException("Actual VPN interface unavailable");
        this.context = context.getApplicationContext();
        this.service = service;
        this.interfaceName = interfaceName;
        nativeBinding = service.routeBinding();
        if (nativeBinding == null || !interfaceName.equals(nativeBinding.interfaceName))
            throw new IllegalStateException("Actual native VPN owner unavailable");
        try {
            java.net.NetworkInterface actual = java.net.NetworkInterface.getByName(interfaceName);
            if (actual == null || !actual.isUp()) throw new IllegalStateException("Actual VPN interface unavailable");
            interfaceIndex = actual.getIndex();
        } catch (java.net.SocketException error) { throw new IllegalStateException("Actual VPN interface unavailable"); }
        connectivity = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network found = null;
        for (Network network : connectivity.getAllNetworks()) {
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            if (!isOwnedVPN(network, caps)) continue;
            if (found != null) throw new IllegalStateException("Ambiguous VPN interface");
            found = network;
        }
        if (found == null) throw new IllegalStateException("Actual VPN Network unavailable");
        vpn = found;
        physicalFingerprint = physicalFingerprint();
        if (physicalFingerprint.isEmpty()) throw new IllegalStateException("Physical network unavailable");
    }

    private boolean isOwnedVPN(Network network, NetworkCapabilities caps) {
        if (caps == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return false;
        // On Android 11+ the owner UID is exposed to the VPN owner. Avoid
        // transferring thousands of VPN routes in a single Binder response.
        if (Build.VERSION.SDK_INT >= 30) return caps.getOwnerUid() == Process.myUid();
        LinkProperties link = connectivity.getLinkProperties(network);
        return link != null && interfaceName.equals(link.getInterfaceName());
    }

    private String physicalFingerprint() {
        ArrayList<String> values = new ArrayList<>();
        Network[] networks = connectivity.getAllNetworks();
        if (networks.length > 64) return "";
        for (Network network : networks) {
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(network);
            if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
            // Filter VPN before asking for LinkProperties, including foreign VPNs.
            LinkProperties link = connectivity.getLinkProperties(network);
            if (link == null || link.getRoutes().size() > 512 || link.getLinkAddresses().size() > 128) return "";
            // Memory-only route identity. It is never logged, returned or saved.
            values.add(network.getNetworkHandle() + ":" + link.getInterfaceName() + ":" + link.getLinkAddresses() +
                ":" + link.getRoutes() + ":" + link.getDnsServers() + ":" + link.getMtu());
        }
        Collections.sort(values);
        return String.join("|", values);
    }

    public boolean isCurrent() {
        try {
            if (closed.get() || nativeBinding != service.routeBinding() || android.net.VpnService.prepare(context) != null) return false;
            java.net.NetworkInterface actual = java.net.NetworkInterface.getByName(interfaceName);
            if (actual == null || !actual.isUp() || actual.getIndex() != interfaceIndex) return false;
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(vpn);
            return isOwnedVPN(vpn, caps) && physicalFingerprint.equals(physicalFingerprint());
        } catch (Exception ignored) { return false; }
    }

    @Keep
    public boolean prepareSocket(int route, int fd) {
        if (fd < 0 || (route != 1 && route != 2) || !isCurrent()) return false;
        // fromFd DUPLICATES the descriptor. Closing this Java owner does not
        // close the Go socket held by RawConn.Control before connect/send.
        try (ParcelFileDescriptor duplicate = ParcelFileDescriptor.fromFd(fd)) {
            if (route == 1) {
                // Primary upstream channels use protect with the system default
                // underlying network too (setUnderlyingNetworks(null)).
                if (!service.protect(duplicate.getFd())) return false;
            } else {
                vpn.bindSocket(duplicate.getFileDescriptor());
            }
            return isCurrent();
        } catch (Exception ignored) { return false; }
    }

    public void invalidate() { closed.set(true); }
}
