/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg.backend;

import android.content.Context;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import org.amnezia.awg.r013.AutoPolicy;
import org.amnezia.awg.r013.HourlySchedule;
import org.json.JSONArray;
import org.json.JSONObject;
import java.net.URL;
import java.net.HttpURLConnection;
import java.util.List;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicLong;
import android.content.Intent;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;
import android.util.Log;

import org.amnezia.awg.backend.BackendException.Reason;
import org.amnezia.awg.backend.Tunnel.State;
import org.amnezia.awg.util.SharedLibraryLoader;
import org.amnezia.awg.config.Config;
import org.amnezia.awg.config.InetEndpoint;
import org.amnezia.awg.config.InetNetwork;
import org.amnezia.awg.config.Peer;
import org.amnezia.awg.crypto.Key;
import org.amnezia.awg.crypto.KeyFormatException;
import org.amnezia.awg.util.NonNullForAll;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

import static org.amnezia.awg.GoBackend.*;

/**
 * Implementation of {@link Backend} that uses the amneziawg-go userspace implementation to provide
 * AmneziaWG tunnels.
 */
@NonNullForAll
public final class GoBackend implements Backend {
    private static final int DNS_RESOLUTION_RETRIES = 10;
    private static final String TAG = "AmneziaWG/GoBackend";
    @Nullable private static AlwaysOnCallback alwaysOnCallback;
    private static GhettoCompletableFuture<VpnService> vpnService = new GhettoCompletableFuture<>();
    private final Context context;
    @Nullable private Config currentConfig;
    @Nullable private Tunnel currentTunnel;
    private int currentTunnelHandle = -1;
    @Nullable private Thread statusThread;
    @Nullable private StatusCallback statusCallback;

    // A single generation owns all Auto work; neither an Activity nor a UI timer does.
    public record AutoMember(String name, Config config) { }
    public interface AutomaticSource { List<AutoMember> members(String profileName); }
    private AutomaticSource automaticSource = name -> Collections.emptyList();
    private final AtomicLong autoEpoch = new AtomicLong();
    private final AtomicLong physicalPathRevision = new AtomicLong();
    @Nullable private volatile Thread autoThread;
    @Nullable private volatile HttpURLConnection healthConnection;
    @Nullable private volatile AutoMember activeMember;
    @Nullable private AutoPolicy automaticPolicy;
    private final java.util.concurrent.ThreadPoolExecutor probeExecutor = new java.util.concurrent.ThreadPoolExecutor(
        1, 1, 30, TimeUnit.SECONDS, new java.util.concurrent.ArrayBlockingQueue<>(1), task -> {
            Thread thread = new Thread(task, "R013-Traffic-Probe"); thread.setDaemon(true); return thread;
        }, new java.util.concurrent.ThreadPoolExecutor.AbortPolicy());
    @Nullable private volatile java.util.concurrent.Future<Double> pendingProbe;
    @Nullable private volatile VpnService activeService;
    @Nullable private volatile Thread hourlyThread;
    @Nullable private volatile HourlyScope hourlyScope;
    @Nullable private volatile String hourlySummary;
    private final Object hourlyCleanupLock = new Object();
    private final java.util.ArrayList<HourlyScope> retiredHourlyScopes = new java.util.ArrayList<>(2);
    // Resolution is bounded independently of the health worker. A blocked OS
    // resolver cannot accumulate one new thread per start/stop or per candidate.
    private final java.util.concurrent.ThreadPoolExecutor snapshotExecutor = new java.util.concurrent.ThreadPoolExecutor(
        1, 1, 30, TimeUnit.SECONDS, new java.util.concurrent.SynchronousQueue<>(), task -> {
            Thread thread = new Thread(task, "R013-Snapshot"); thread.setDaemon(true); return thread;
        }, new java.util.concurrent.ThreadPoolExecutor.AbortPolicy());
    private boolean replacing;
    private long connectionRevision;
    public synchronized long getConnectionRevision() { return connectionRevision; }
    public record ConnectionView(String profile, String member, Config config, Statistics statistics, long revision, String hourlySummary) { }
    public synchronized ConnectionView connectionView() {
        return new ConnectionView(currentTunnel == null ? null : currentTunnel.getName(), getAutomaticMemberName(), currentConfig,
            currentTunnel == null ? null : getStatistics(currentTunnel), connectionRevision, autoThread == null ? null : hourlySummary);
    }
    private void stopVpnService() {
        try {
            VpnService service = vpnService.get(0, TimeUnit.NANOSECONDS);
            vpnService = vpnService.newIncompleteFuture();
            service.stopSelf();
        } catch (Exception ignored) { }
    }
    public void setAutomaticSource(AutomaticSource source) { automaticSource = source; }
    @Nullable public synchronized Config getCurrentConfiguration() { return currentConfig; }
    @Nullable public synchronized String getCurrentProfileName() { return currentTunnel == null ? null : currentTunnel.getName(); }
    @Nullable public String getAutomaticMemberName() { AutoMember member = activeMember; return member == null ? null : member.name(); }
    public boolean isAutomaticRunning() { return autoThread != null; }
    /** Nonblocking path notification, before any delayed reconnect callback. */
    public void onPhysicalPathChanged() { physicalPathRevision.incrementAndGet(); invalidateHourly(); }
    private void cancelAutomatic() {
        autoEpoch.incrementAndGet();
        invalidateHourly();
        Thread hourly = hourlyThread; hourlyThread = null; hourlySummary = null;
        if (hourly != null) hourly.interrupt();
        Thread worker = autoThread; autoThread = null; activeMember = null;
        automaticPolicy = null;
        java.util.concurrent.Future<Double> future = pendingProbe; if (future != null) future.cancel(true);
        probeExecutor.purge();
        HttpURLConnection probe = healthConnection; if (probe != null) probe.disconnect();
        if (worker != null) worker.interrupt();
    }
    /** An obsolete network callback may never restart a stopped or different profile. */
    public synchronized void reconnectIfCurrent(@Nullable String expectedName, long expectedRevision) throws Exception {
        if (currentTunnel == null || currentConfig == null || connectionRevision != expectedRevision ||
                !currentTunnel.getName().equals(expectedName) || !physicalNetworkAvailable()) return;
        Tunnel tunnel = currentTunnel;
        Config config = currentConfig;
        AutoMember member = activeMember;
        replacing = true;
        try {
            setStateInternal(tunnel, null, State.DOWN);
            setStateInternal(tunnel, config, State.UP);
            activeMember = member;
        } catch (Exception e) {
            if (autoThread != null) { currentTunnel = tunnel; currentConfig = null; activeMember = null; }
            else { stopVpnService(); tunnel.onStateChange(State.DOWN); }
            throw e;
        } finally { replacing = false; }
    }

    private boolean physicalNetworkAvailable() {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        for (Network network : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return true;
        }
        return false;
    }
    @Nullable private Double trafficProbe() {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network vpn = null;
        for (Network network : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) { vpn = network; break; }
        }
        if (vpn == null) return null;
        Double first = null;
        for (String url : new String[] {"https://cp.cloudflare.com/generate_204", "https://www.apple.com/library/test/success.html"}) {
            if (Thread.currentThread().isInterrupted()) return null;
            HttpURLConnection connection = null;
            try {
                long before = android.os.SystemClock.elapsedRealtimeNanos();
                connection = (HttpURLConnection) vpn.openConnection(new URL(url));
                healthConnection = connection;
                connection.setConnectTimeout(4500); connection.setReadTimeout(4500);
                connection.setInstanceFollowRedirects(false); connection.setUseCaches(false);
                int status = connection.getResponseCode();
                boolean ok = status == 204;
                if (status == 200 && url.contains("apple.com")) {
                    byte[] body = new byte[4096];
                    try (java.io.InputStream in = connection.getInputStream()) {
                        int n = in.read(body); ok = n > 0 && new String(body, 0, n, java.nio.charset.StandardCharsets.UTF_8).contains("Success");
                    }
                }
                if (!ok) continue;
                double millis = (android.os.SystemClock.elapsedRealtimeNanos() - before) / 1_000_000.0;
                if (millis <= 1200) return millis;
                if (first != null) return Math.min(first, millis);
                first = millis; // A slow origin alone must not force a server switch.
            } catch (Exception ignored) {
                // No keys, configuration, response body or capability goes to logs.
            } finally { if (connection != null) connection.disconnect(); healthConnection = null; }
        }
        // One successful slow origin is insufficient evidence to switch a healthy peer.
        return first == null ? null : 1200.0;
    }
    private void startAutomatic(final Tunnel tunnel, final List<AutoMember> members) {
        if (members.isEmpty()) return;
        if (members.size() > 30) throw new IllegalArgumentException("Auto supports 1–30 members");
        final long epoch = autoEpoch.incrementAndGet();
        activeMember = members.get(0);
        final AutoPolicy policy = new AutoPolicy(members.size(), 0);
        automaticPolicy = policy;
        final Thread worker = new Thread(() -> {
            long nextHealthyLog = 0;
            try {
                Thread.sleep(2500);
                while (autoEpoch.get() == epoch && !Thread.currentThread().isInterrupted()) {
                    final long probeRevision = getConnectionRevision();
                    boolean available = physicalNetworkAvailable();
                    Double latency = null;
                    if (available) {
                        try {
                            pendingProbe = probeExecutor.submit(this::trafficProbe);
                            latency = pendingProbe.get(11, TimeUnit.SECONDS);
                        } catch (java.util.concurrent.TimeoutException | java.util.concurrent.ExecutionException | java.util.concurrent.RejectedExecutionException | java.util.concurrent.CancellationException ignored) {
                            if (pendingProbe != null) pendingProbe.cancel(true);
                            HttpURLConnection connection = healthConnection; if (connection != null) connection.disconnect();
                            probeExecutor.purge();
                        } finally { pendingProbe = null; }
                    }
                    final AutoPolicy.Decision decision;
                    synchronized (this) {
                        if (autoEpoch.get() != epoch || currentTunnel != tunnel) break;
                        if (connectionRevision != probeRevision) continue;
                        boolean handshakePresent = getLastHandshake(tunnel) > 0;
                        boolean healthy = latency != null && handshakePresent;
                        available = physicalNetworkAvailable();
                        decision = policy.record(healthy, available, latency);
                        long now = android.os.SystemClock.elapsedRealtime();
                        if (!healthy || decision.action != AutoPolicy.Action.STAY || now >= nextHealthyLog) {
                            Log.i(TAG, "Auto health: physical=" + available + " traffic=" + (latency != null) +
                                " handshake=" + handshakePresent + " action=" + decision.action +
                                " waitSeconds=" + decision.waitSeconds);
                            nextHealthyLog = now + 60_000;
                        }
                        if (decision.action == AutoPolicy.Action.SWITCH) {
                            AutoMember next = members.get(decision.index);
                            replacing = true;
                            try {
                                activeMember = null;
                                setStateInternal(tunnel, null, State.DOWN);
                                setStateInternal(tunnel, next.config(), State.UP);
                                activeMember = next;
                            } catch (Exception ignored) {
                                // Retain logical Auto ownership for a bounded retry; never invent a handshake.
                                currentTunnel = tunnel; currentConfig = null;
                                Log.w(TAG, "Auto switch failed; health worker retains retry ownership");
                            } finally { replacing = false; }
                        }
                    }
                    Thread.sleep(decision.waitSeconds > 0 ? decision.waitSeconds * 1000L :
                            decision.action == AutoPolicy.Action.SWITCH ? 2500 : 15000);
                }
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            finally { synchronized (this) {
                Log.i(TAG, "Auto health worker ended: superseded=" + (autoEpoch.get() != epoch));
                if (autoEpoch.get() == epoch) { autoThread = null; activeMember = null; }
            } }
        }, "R013-Auto");
        autoThread = worker; worker.start();
        startHourly(tunnel, members, policy, epoch);
    }

    private record HourlyScope(long handle, R013SocketRoutes routes) { }
    private record HourlySnapshot(long revision, int handle, Config config, VpnService service, AutoMember member, long pathRevision) { }

    private void releaseHourly(@Nullable HourlyScope scope) {
        // A failed drain retains its native/global-reference ownership. Retry
        // on the next comparison instead of forgetting a potentially live FD.
        synchronized (hourlyCleanupLock) {
            if (scope != null && !retiredHourlyScopes.contains(scope)) retiredHourlyScopes.add(scope);
            java.util.Iterator<HourlyScope> iterator = retiredHourlyScopes.iterator();
            while (iterator.hasNext()) {
                HourlyScope retired = iterator.next();
                retired.routes().invalidate(); r013ProbeInvalidate(retired.handle());
                if (r013ProbeRelease(retired.handle()) == 0) iterator.remove();
            }
        }
    }

    private void invalidateHourly() {
        if (autoThread != null) hourlySummary = "Авто: подключение изменилось; сравнение по расписанию";
        HourlyScope scope = hourlyScope;
        if (scope != null) { scope.routes().invalidate(); r013ProbeInvalidate(scope.handle()); }
    }
    private static boolean sameMembers(List<AutoMember> a, List<AutoMember> b) {
        if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++)
            if (!a.get(i).name().equals(b.get(i).name()) ||
                !a.get(i).config().toAwgQuickString().equals(b.get(i).config().toAwgQuickString())) return false;
        return true;
    }
    private boolean sameHourly(Tunnel tunnel, List<AutoMember> members, long epoch, HourlySnapshot snapshot) {
        return autoEpoch.get() == epoch && autoThread != null && currentTunnel == tunnel &&
            currentTunnelHandle == snapshot.handle() && currentConfig == snapshot.config() &&
            activeService == snapshot.service() && connectionRevision == snapshot.revision() && physicalPathRevision.get() == snapshot.pathRevision() &&
            sameMembers(members, automaticSource.members(tunnel.getName()));
    }
    private static JSONObject hourlyCandidate(int index, Config config) throws Exception {
        String source = null;
        for (InetNetwork address : config.getInterface().getAddresses())
            if (address.getAddress() instanceof java.net.Inet4Address) { source = address.getAddress().getHostAddress(); break; }
        if (source == null || config.getPeers().size() != 1) throw new IllegalArgumentException("Unsupported comparison snapshot");
        String wire = config.toAwgUserspaceString();
        if (wire.length() > 65536 || !wire.contains("\nendpoint=")) throw new IllegalArgumentException("Unresolved comparison snapshot");
        return new JSONObject().put("id",Integer.toString(index)).put("source",source).put("config",wire);
    }
    private static JSONObject hourlyInput(JSONArray candidates, int cursor) throws Exception {
        return new JSONObject().put("auto_active",true).put("resolver","1.1.1.1:53")
            .put("start_index",Math.floorMod(cursor,candidates.length())).put("candidates",candidates);
    }
    private void startHourly(Tunnel tunnel, List<AutoMember> members, AutoPolicy policy, long epoch) {
        final Thread worker = new Thread(() -> {
            HourlySchedule schedule = new HourlySchedule(android.os.SystemClock.elapsedRealtime());
            int cursor = 0;
            try {
                while (autoEpoch.get() == epoch && autoThread != null && !Thread.currentThread().isInterrupted()) {
                    long remaining = schedule.remaining(android.os.SystemClock.elapsedRealtime());
                    if (remaining > 0) { Thread.sleep(Math.min(remaining,60_000)); continue; }
                    if (!schedule.take(android.os.SystemClock.elapsedRealtime())) continue;
                    cursor = compareHourly(tunnel,members,policy,epoch,cursor);
                }
            } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            finally { synchronized (this) { if (hourlyThread == Thread.currentThread()) hourlyThread = null; } }
        },"R013-Hourly");
        hourlySummary = "Авто: сравнение VPN через 30 секунд, затем раз в час";
        hourlyThread = worker; worker.setDaemon(true); worker.start();
    }
    private int compareHourly(Tunnel tunnel, List<AutoMember> members, AutoPolicy policy, long epoch, int cursor)
            throws InterruptedException {
        HourlyScope scope = null;
        java.util.concurrent.Future<JSONArray> preparing = null;
        try {
            releaseHourly(null);
            final HourlySnapshot snapshot;
            synchronized (this) {
                if (autoEpoch.get() != epoch || autoThread == null || currentTunnel != tunnel ||
                        currentTunnelHandle < 0 || currentConfig == null || activeMember == null || activeService == null ||
                        !physicalNetworkAvailable() || !sameMembers(members,automaticSource.members(tunnel.getName()))) return cursor;
                snapshot = new HourlySnapshot(connectionRevision,currentTunnelHandle,currentConfig,activeService,activeMember,physicalPathRevision.get());
            }
            preparing = snapshotExecutor.submit(() -> {
                JSONArray candidates = new JSONArray();
                for (int i = 0; i < members.size(); i++) {
                    if (Thread.currentThread().isInterrupted()) break;
                    try { candidates.put(hourlyCandidate(i,members.get(i).config())); }
                    catch (Exception ignored) { /* Unmeasured is not an unhealthy VPN. */ }
                }
                return candidates;
            });
            JSONArray candidates = preparing.get(10,TimeUnit.SECONDS);
            if (candidates.length() == 0) return cursor;
            synchronized (this) {
                if (!sameHourly(tunnel,members,epoch,snapshot)) return cursor;
                R013SocketRoutes routes = new R013SocketRoutes(context,snapshot.service(),awgGetInterfaceName(snapshot.handle()));
                long handle = r013ProbeCreate(routes);
                if (handle == 0) { routes.invalidate(); return cursor; }
                scope = new HourlyScope(handle,routes); hourlyScope = scope;
                if (r013ProbeRefresh(handle) != 0 || !routes.isCurrent()) return cursor;
                hourlySummary = "Авто: сравниваем DNS через VPN, текущее соединение работает";
            }
            long operation = r013ProbeStart(scope.handle(),hourlyInput(candidates,cursor).toString());
            if (operation == 0) return cursor;
            long deadline = android.os.SystemClock.elapsedRealtime()+95_000;
            JSONObject status = null;
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                synchronized (this) {
                    if (!sameHourly(tunnel,members,epoch,snapshot) || !scope.routes().isCurrent()) return cursor;
                }
                String wire = r013ProbePoll(scope.handle(),operation);
                if (wire == null) return cursor;
                status = new JSONObject(wire);
                if (!status.getString("status").equals("pending")) break;
                Thread.sleep(250);
            }
            synchronized (this) {
                if (!sameHourly(tunnel,members,epoch,snapshot) || !scope.routes().isCurrent()) return cursor;
                if (status == null || !status.optString("status").equals("complete")) {
                    hourlySummary = "Авто: сравнение DNS недоступно; текущий VPN сохранён"; return cursor;
                }
                cursor = status.getInt("next_index");
                double baseline = status.getJSONObject("after").getDouble("milliseconds");
                int measured = 0; JSONArray rows = status.getJSONArray("rows");
                for (int i = 0; i < rows.length(); i++) if (rows.getJSONObject(i).getString("status").equals("measured")) measured++;
                hourlySummary = String.format(java.util.Locale.ROOT,"Авто: DNS %.0f мс · сравнено %d · следующая проверка через час",baseline,measured);
                String choice = status.optString("choice_id","");
                if (choice.isEmpty()) return cursor;
                int index = Integer.parseInt(choice);
                if (index < 0 || index >= members.size()) return cursor;
                AutoMember next = members.get(index);
                JSONObject fresh = hourlyInput(new JSONArray().put(hourlyCandidate(index,next.config())),0);
                // Recheck actual Java ownership immediately before the native
                // one-shot guard drains UDP and authorizes the primary change.
                if (!sameHourly(tunnel,members,epoch,snapshot) || !scope.routes().isCurrent()) return cursor;
                long ticket = r013ProbeChoose(scope.handle(),operation,fresh.toString());
                if (ticket == 0) return cursor;
                replacing = true;
                try {
                    if (!sameHourly(tunnel,members,epoch,snapshot) || !scope.routes().isCurrent() ||
                            Thread.currentThread().isInterrupted()) return cursor;
                    java.util.concurrent.Future<Double> health = pendingProbe; if (health != null) health.cancel(true);
                    HttpURLConnection connection = healthConnection; if (connection != null) connection.disconnect();
                    invalidateHourly();
                    setStateInternalGuarded(tunnel,null,State.DOWN,ticket);
                    activeMember = null;
                    if (autoEpoch.get() != epoch || physicalPathRevision.get() != snapshot.pathRevision() ||
                            Thread.currentThread().isInterrupted()) throw new IllegalStateException("Comparison cancelled");
                    setStateInternalGuarded(tunnel,next.config(),State.UP,ticket);
                    activeMember = next; policy.selectMeasuredCandidate(index);
                    hourlySummary = "Авто: выбран более быстрый VPN по одинаковой проверке DNS";
                } catch (Exception ignored) {
                    // Restore the exact previous configuration if establishing
                    // the selected backend failed, using the same guarded span.
                    if (currentTunnelHandle < 0 && autoEpoch.get() == epoch && VpnService.prepare(context) == null) {
                        try { setStateInternalGuarded(tunnel,snapshot.config(),State.UP,ticket); activeMember = snapshot.member(); }
                        catch (Exception retryFailed) { currentTunnel = tunnel; currentConfig = null; }
                    }
                    hourlySummary = "Авто: смена VPN не завершена; работает обычная проверка подключения";
                } finally { replacing = false; r013PrimaryEnd(ticket); }
            }
            return cursor;
        } catch (InterruptedException interrupted) { throw interrupted; }
        catch (Exception ignored) {
            synchronized (this) { if (autoEpoch.get() == epoch) hourlySummary = "Авто: сравнение DNS недоступно; настройки сохранены"; }
            return cursor;
        } finally {
            if (preparing != null && !preparing.isDone()) preparing.cancel(true);
            if (scope != null) {
                scope.routes().invalidate(); r013ProbeInvalidate(scope.handle());
                synchronized (this) { if (hourlyScope == scope) hourlyScope = null; }
                releaseHourly(scope);
            }
        }
    }

    /**
     * Public constructor for GoBackend.
     *
     * @param context An Android {@link Context}
     */
    public GoBackend(final Context context) {
        SharedLibraryLoader.loadSharedLibrary(context, "wg-go");
        this.context = context;
    }

    /**
     * Set a {@link AlwaysOnCallback} to be invoked when {@link VpnService} is started by the
     * system's Always-On VPN mode.
     *
     * @param cb Callback to be invoked
     */
    public static void setAlwaysOnCallback(final AlwaysOnCallback cb) {
        alwaysOnCallback = cb;
    }



    /**
     * Method to get the names of running tunnels.
     *
     * @return A set of string values denoting names of running tunnels.
     */
    @Override
    public synchronized Set<String> getRunningTunnelNames() {
        if (currentTunnel != null) {
            final Set<String> runningTunnels = new ArraySet<>();
            runningTunnels.add(currentTunnel.getName());
            return runningTunnels;
        }
        return Collections.emptySet();
    }

    /**
     * Get the associated {@link State} for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to examine the state of.
     * @return {@link State} associated with the given tunnel.
     */
    @Override
    public synchronized State getState(final Tunnel tunnel) {
        return currentTunnel == tunnel ? State.UP : State.DOWN;
    }

    /**
     * Get the associated {@link Statistics} for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to retrieve statistics for.
     * @return {@link Statistics} associated with the given tunnel.
     */
    @Override
    public synchronized Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        if (tunnel != currentTunnel || currentTunnelHandle == -1)
            return stats;
        final String config = awgGetConfig(currentTunnelHandle);
        if (config == null)
            return stats;
        Key key = null;
        long rx = 0;
        long tx = 0;
        long latestHandshakeMSec = 0;
        for (final String line : config.split("\\n")) {
            if (line.startsWith("public_key=")) {
                if (key != null)
                    stats.add(key, rx, tx, latestHandshakeMSec);
                rx = 0;
                tx = 0;
                latestHandshakeMSec = 0;
                try {
                    key = Key.fromHex(line.substring(11));
                } catch (final KeyFormatException ignored) {
                    key = null;
                }
            } else if (line.startsWith("rx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    rx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    rx = 0;
                }
            } else if (line.startsWith("tx_bytes=")) {
                if (key == null)
                    continue;
                try {
                    tx = Long.parseLong(line.substring(9));
                } catch (final NumberFormatException ignored) {
                    tx = 0;
                }
            } else if (line.startsWith("last_handshake_time_sec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(24)) * 1000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            } else if (line.startsWith("last_handshake_time_nsec=")) {
                if (key == null)
                    continue;
                try {
                    latestHandshakeMSec += Long.parseLong(line.substring(25)) / 1000000;
                } catch (final NumberFormatException ignored) {
                    latestHandshakeMSec = 0;
                }
            }
        }
        if (key != null)
            stats.add(key, rx, tx, latestHandshakeMSec);
        return stats;
    }


    /**
     * Get the last handshake time for a given {@link Tunnel}.
     *
     * @param tunnel The tunnel to retrieve the last handshake time for.
     * @return Last handshake time in seconds (>=0), -1 if no handshake found, -2 on error, -3 if tunnel not active.
     */
    @Override
    public synchronized long getLastHandshake(final Tunnel tunnel) {
        if (tunnel != currentTunnel || currentTunnelHandle == -1)
            return -3; // Tunnel not active
        final String config = awgGetConfig(currentTunnelHandle);
        if (config == null) {
            Log.e(TAG, "Failed to get tunnel config");
            return -2;
        }

        for (final String line : config.split("\\n")) {
            if (line.startsWith("last_handshake_time_sec=")) {
                try {
                    return Long.parseLong(line.substring(24));
                } catch (final NumberFormatException ignored) {
                    Log.e(TAG, "Failed to parse last_handshake_time_sec");
                    return -2;
                }
            }
        }

        Log.e(TAG, "Failed to get last_handshake_time_sec");
        return -1;
    }

    /**
     * Set a callback to be notified when connection status changes.
     *
     * @param callback The callback to invoke on status change
     */
    public void setStatusCallback(@Nullable final StatusCallback callback) {
        this.statusCallback = callback;
    }

    /**
     * Launch a background thread to poll handshake status and determine connection state.
     * This is called after tunnel creation to wait for the first successful handshake.
     */
    private void launchStatusJob() {
        stopStatusJob();
        Log.d(TAG, "Launch status job");
        final long generation = connectionRevision;
        final Tunnel statusTunnel = currentTunnel;
        statusThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                final long lastHandshake;
                synchronized (this) {
                    if (generation != connectionRevision || statusTunnel != currentTunnel) break;
                    lastHandshake = getLastHandshake(statusTunnel);
                }

                // Check if tunnel is no longer active (race condition protection)
                if (lastHandshake == -3L) {
                    Log.d(TAG, "Tunnel is no longer active, stopping status job");
                    break;
                }

                // 0 means no handshake yet, wait and retry
                if (lastHandshake == 0L) {
                    try {
                        Thread.sleep(1000);
                    } catch (final InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                    continue;
                }

                // Only positive handshake time indicates successful connection
                // -1 may be returned if unable to parse output (doesn't mean no connection)
                // -2 indicates command execution error (also doesn't mean no connection)
                if (lastHandshake > 0L) {
                    synchronized (this) {
                        if (generation == connectionRevision && statusTunnel == currentTunnel && statusCallback != null)
                            statusCallback.onStatusChanged(true);
                    }
                    break;
                }

                // For -1 or -2, retry after delay instead of reporting disconnected
                try {
                    Thread.sleep(1000);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            synchronized (this) { if (statusThread == Thread.currentThread()) statusThread = null; }
        }, "StatusJob");
        statusThread.start();
    }

    /**
     * Stop the status polling thread if running.
     */
    private void stopStatusJob() {
        if (statusThread != null) {
            statusThread.interrupt();
            statusThread = null;
        }
    }

    /**
     * Get the version of the underlying amneziawg-go library.
     *
     * @return {@link String} value of the version of the amneziawg-go library.
     */
    @Override
    public String getVersion() {
        return awgVersion();
    }

    /**
     * Change the state of a given {@link Tunnel}, optionally applying a given {@link Config}.
     *
     * @param tunnel The tunnel to control the state of.
     * @param state  The new state for this tunnel. Must be {@code UP}, {@code DOWN}, or
     *               {@code TOGGLE}.
     * @param config The configuration for this tunnel, may be null if state is {@code DOWN}.
     * @return {@link State} of the tunnel after state changes are applied.
     * @throws Exception Exception raised while changing tunnel state.
     */
    @Override
    public synchronized State setState(final Tunnel tunnel, State state, @Nullable final Config config) throws Exception {
        final State originalState = getState(tunnel);

        if (state == State.TOGGLE)
            state = originalState == State.UP ? State.DOWN : State.UP;
        if (state == originalState && tunnel == currentTunnel && config == currentConfig)
            return originalState;
        if (state == State.DOWN && tunnel != currentTunnel) return originalState;
        cancelAutomatic();
        final List<AutoMember> autoMembers = state == State.UP ? Collections.unmodifiableList(new java.util.ArrayList<>(automaticSource.members(tunnel.getName()))) : Collections.emptyList();
        if (autoMembers.size() > 30) throw new IllegalArgumentException("Invalid Auto membership");
        if (state == State.UP) {
            final Config originalConfig = currentConfig;
            final Tunnel originalTunnel = currentTunnel;
            replacing = currentTunnel != null;
            if (currentTunnel != null)
                setStateInternal(currentTunnel, null, State.DOWN);
            try {
                setStateInternal(tunnel, autoMembers.isEmpty() ? config : autoMembers.get(0).config(), state);
            } catch (final Exception e) {
                if (!autoMembers.isEmpty() && vpnService.isDone()) {
                    // The prepared foreground VPN service keeps ownership while Auto
                    // retries DNS/backend failures. No handshake is reported here.
                    currentTunnel = tunnel; currentConfig = null; currentTunnelHandle = -1;
                    tunnel.onStateChange(State.UP);
                } else {
                    if (originalTunnel != null && originalConfig != null)
                        setStateInternal(originalTunnel, originalConfig, State.UP);
                    throw e;
                }
            } finally { replacing = false; }
            if (!autoMembers.isEmpty()) startAutomatic(tunnel, autoMembers);
        } else if (state == State.DOWN && tunnel == currentTunnel) {
            setStateInternal(tunnel, null, State.DOWN);
        }
        return getState(tunnel);
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state)
            throws Exception {
        // Drain every candidate before Builder.establish can change routes, not
        // merely before the native engine starts. Unknown active state disables
        // comparisons; it must not disable an otherwise valid manual profile.
        invalidateHourly();
        final long ticket = r013PrimaryBegin();
        if (ticket == 0) throw new IllegalStateException("VPN transition is busy");
        try { setStateInternalGuarded(tunnel, config, state, ticket); }
        finally { r013PrimaryEnd(ticket); }
    }

    private void setStateInternalGuarded(final Tunnel tunnel, @Nullable final Config config, final State state,
                                         final long ticket) throws Exception {
        connectionRevision++;
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        if (state == State.UP) {
            if (config == null)
                throw new BackendException(Reason.TUNNEL_MISSING_CONFIG);

            if (VpnService.prepare(context) != null)
                throw new BackendException(Reason.VPN_NOT_AUTHORIZED);

            final VpnService service;
            if (!vpnService.isDone()) {
                Log.d(TAG, "Requesting to start VpnService");
                context.startService(new Intent(context, VpnService.class));
            }

            try {
                service = vpnService.get(2, TimeUnit.SECONDS);
            } catch (final TimeoutException e) {
                final Exception be = new BackendException(Reason.UNABLE_TO_START_VPN);
                be.initCause(e);
                throw be;
            }
            service.setOwner(this);
            activeService = service;

            if (currentTunnelHandle != -1) {
                Log.w(TAG, "Tunnel already up");
                return;
            }


            dnsRetry: for (int i = 0; i < DNS_RESOLUTION_RETRIES; ++i) {
                // Pre-resolve IPs so they're cached when building the userspace string
                for (final Peer peer : config.getPeers()) {
                    final InetEndpoint ep = peer.getEndpoint().orElse(null);
                    if (ep == null)
                        continue;
                    if (ep.getResolved().orElse(null) == null) {
                        if (i < DNS_RESOLUTION_RETRIES - 1) {
                            Log.w(TAG, "DNS host \"" + ep.getHost() + "\" failed to resolve; trying again");
                            Thread.sleep(1000);
                            continue dnsRetry;
                        } else
                            throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, ep.getHost());
                    }
                }
                break;
            }

            // Build config
            final String goConfig = config.toAwgUserspaceString();

            // Create the vpn tunnel with android API
            final VpnService.Builder builder = service.getBuilder();
            builder.setSession(tunnel.getName());

            for (final String excludedApplication : config.getInterface().getExcludedApplications())
                builder.addDisallowedApplication(excludedApplication);

            for (final String includedApplication : config.getInterface().getIncludedApplications())
                builder.addAllowedApplication(includedApplication);

            for (final InetNetwork addr : config.getInterface().getAddresses())
                builder.addAddress(addr.getAddress(), addr.getMask());

            for (final InetAddress addr : config.getInterface().getDnsServers())
                builder.addDnsServer(addr.getHostAddress());

            for (final String dnsSearchDomain : config.getInterface().getDnsSearchDomains())
                builder.addSearchDomain(dnsSearchDomain);

            boolean sawDefaultRoute = false;
            for (final Peer peer : config.getPeers()) {
                for (final InetNetwork addr : peer.getAllowedIps()) {
                    if (addr.getMask() == 0)
                        sawDefaultRoute = true;
                    builder.addRoute(addr.getAddress(), addr.getMask());
                }
            }

            // "Kill-switch" semantics
            if (!(sawDefaultRoute && config.getPeers().size() == 1)) {
                builder.allowFamily(OsConstants.AF_INET);
                builder.allowFamily(OsConstants.AF_INET6);
            }

            builder.setMtu(config.getInterface().getMtu().orElse(1280));

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                builder.setMetered(false);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                service.setUnderlyingNetworks(null);

            builder.setBlocking(true);
            try (final ParcelFileDescriptor tun = builder.establish()) {
                if (tun == null)
                    throw new BackendException(Reason.TUN_CREATION_ERROR);
                Log.d(TAG, "Go backend " + awgVersion());
                currentTunnelHandle = awgTurnOnGuarded(ticket, tunnel.getName(), tun.detachFd(), goConfig);
            }
            if (currentTunnelHandle < 0)
                throw new BackendException(Reason.GO_ACTIVATION_ERROR_CODE, currentTunnelHandle);

            currentTunnel = tunnel;
            currentConfig = config;

            service.protect(awgGetSocketV4(currentTunnelHandle));
            service.protect(awgGetSocketV6(currentTunnelHandle));

            launchStatusJob();
        } else {
            if (currentTunnelHandle == -1) {
                currentTunnel = null; currentConfig = null;
                if (!replacing) stopVpnService();
                return;
            }
            stopStatusJob();
            int handleToClose = currentTunnelHandle;
            if (awgTurnOffGuarded(ticket, handleToClose) != 0)
                throw new IllegalStateException("VPN transition expired");
            currentTunnel = null;
            currentTunnelHandle = -1;
            currentConfig = null;
            if (!replacing) stopVpnService();
        }

        tunnel.onStateChange(state);
    }

    /**
     * Callback for {@link GoBackend} that is invoked when {@link VpnService} is started by the
     * system's Always-On VPN mode.
     */
    public interface AlwaysOnCallback {
        void alwaysOnTriggered();
    }

    // TODO: When we finally drop API 21 and move to API 24, delete this and replace with the ordinary CompletableFuture.
    private static final class GhettoCompletableFuture<V> {
        private final LinkedBlockingQueue<V> completion = new LinkedBlockingQueue<>(1);
        private final FutureTask<V> result = new FutureTask<>(completion::peek);

        public boolean complete(final V value) {
            final boolean offered = completion.offer(value);
            if (offered)
                result.run();
            return offered;
        }

        public V get() throws ExecutionException, InterruptedException {
            return result.get();
        }

        public V get(final long timeout, final TimeUnit unit) throws ExecutionException, InterruptedException, TimeoutException {
            return result.get(timeout, unit);
        }

        public boolean isDone() {
            return !completion.isEmpty();
        }

        public GhettoCompletableFuture<V> newIncompleteFuture() {
            return new GhettoCompletableFuture<>();
        }
    }

    /**
     * {@link android.net.VpnService} implementation for {@link GoBackend}
     */
    public static class VpnService extends android.net.VpnService {
        @Nullable private GoBackend owner;

        public Builder getBuilder() {
            return new Builder();
        }

        @Override
        public void onCreate() {
            super.onCreate();
            NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (Build.VERSION.SDK_INT >= 26) manager.createNotificationChannel(new NotificationChannel("r013-vpn", "VPN-подключение", NotificationManager.IMPORTANCE_LOW));
            Intent launch = getPackageManager().getLaunchIntentForPackage(getPackageName());
            Notification.Builder builder = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, "r013-vpn") : new Notification.Builder(this);
            builder.setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("VPN013")
                .setContentText("VPN-служба работает · откройте приложение для управления")
                .setOngoing(true).setCategory(Notification.CATEGORY_SERVICE);
            if (launch != null) builder.setContentIntent(PendingIntent.getActivity(this, 0, launch, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
            if (Build.VERSION.SDK_INT >= 34) startForeground(1301, builder.build(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
            else startForeground(1301, builder.build());
            vpnService.complete(this);
        }

        @Override
        public void onDestroy() {
            final GoBackend backend = owner;
            if (backend != null) {
                // DNS/startup may still hold the backend lock. Never block Android's
                // main service thread, and never close a newer service's tunnel.
                new Thread(() -> {
                    synchronized (backend) {
                        if (backend.activeService != this) return;
                        backend.cancelAutomatic();
                        backend.stopStatusJob();
                        final Tunnel tunnel = backend.currentTunnel;
                        final long ticket = r013PrimaryBegin();
                        if (ticket == 0) return; // Never close beneath a live candidate.
                        try {
                            if (backend.currentTunnelHandle != -1 && awgTurnOffGuarded(ticket, backend.currentTunnelHandle) != 0) return;
                        } finally { r013PrimaryEnd(ticket); }
                        backend.currentTunnel = null;
                        backend.currentTunnelHandle = -1;
                        backend.currentConfig = null;
                        backend.activeService = null;
                        backend.connectionRevision++;
                        if (tunnel != null) tunnel.onStateChange(State.DOWN);
                    }
                }, "R013-VPN-Close").start();
            }
            try { if (vpnService.get(0, TimeUnit.NANOSECONDS) == this) vpnService = vpnService.newIncompleteFuture(); }
            catch (Exception ignored) { }
            super.onDestroy();
        }

        @Override
        public void onRevoke() {
            if (owner != null && owner.activeService == this) owner.cancelAutomatic();
            stopSelf();
            super.onRevoke();
        }

        @Override
        public int onStartCommand(@Nullable final Intent intent, final int flags, final int startId) {
            vpnService.complete(this);
            if (intent == null || intent.getComponent() == null || !intent.getComponent().getPackageName().equals(getPackageName())) {
                Log.d(TAG, "Service started by Always-on VPN feature");
                if (alwaysOnCallback != null)
                    alwaysOnCallback.alwaysOnTriggered();
            }
            return super.onStartCommand(intent, flags, startId);
        }

        public void setOwner(final GoBackend owner) {
            this.owner = owner;
        }
    }
}
