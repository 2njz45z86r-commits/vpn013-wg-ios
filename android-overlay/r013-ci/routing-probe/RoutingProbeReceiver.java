// SPDX-License-Identifier: MIT
package com.vpn013.routingprobe;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.Process;
import android.util.AtomicFile;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/** CI-only separate-UID probe; accepts only the disposable host and UUID inputs. */
public final class RoutingProbeReceiver extends BroadcastReceiver {
    private static boolean uuid(String value) {
        if (value == null || !value.matches("[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")) return false;
        try { return UUID.fromString(value).toString().equals(value); } catch (IllegalArgumentException ignored) { return false; }
    }
    @Override public void onReceive(Context context, Intent intent) {
        final String request = intent.getStringExtra("request");
        final String nonce = intent.getStringExtra("nonce");
        final int port = intent.getIntExtra("port", -1);
        if (!uuid(request) || !uuid(nonce) || port < 1024 || port > 65535) return;
        final PendingResult pending = goAsync();
        final Context owner = context.getApplicationContext();
        new Thread(() -> {
            boolean vpn = false, matched = false;
            String errorClass = "";
            try {
                final long deadline = android.os.SystemClock.elapsedRealtime() + 6000;
                ConnectivityManager cm = (ConnectivityManager) owner.getSystemService(Context.CONNECTIVITY_SERVICE);
                NetworkCapabilities caps = cm.getNetworkCapabilities(cm.getActiveNetwork());
                vpn = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress("198.18.0.1", port), 2500);
                    socket.getOutputStream().write(("GET /" + nonce + " HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    ByteArrayOutputStream body = new ByteArrayOutputStream(); byte[] buffer = new byte[1024];
                    while (true) {
                        long remaining = deadline - android.os.SystemClock.elapsedRealtime();
                        if (remaining <= 0) throw new java.net.SocketTimeoutException("deadline");
                        socket.setSoTimeout((int) Math.min(2500, remaining));
                        int n = socket.getInputStream().read(buffer);
                        if (n == -1) break;
                        if (body.size() + n > 4096) throw new java.io.IOException("response bound");
                        body.write(buffer, 0, n);
                    }
                    String response = body.toString("US-ASCII");
                    matched = response.startsWith("HTTP/1.1 200") && response.contains(nonce);
                }
            } catch (Exception failure) { errorClass = failure.getClass().getSimpleName(); }
            try {
                JSONObject result = new JSONObject().put("uid", Process.myUid()).put("vpn", vpn)
                    .put("matched", matched).put("requestID", request).put("errorClass", errorClass);
                AtomicFile output = new AtomicFile(new File(owner.getFilesDir(), "probe.json"));
                FileOutputStream stream = null;
                try { stream = output.startWrite(); stream.write(result.toString().getBytes(StandardCharsets.UTF_8)); output.finishWrite(stream); }
                catch (Exception failure) { if (stream != null) output.failWrite(stream); }
            } catch (Exception ignored) { }
            finally { pending.finish(); }
        }, "vpn013-ci-probe").start();
    }
}
