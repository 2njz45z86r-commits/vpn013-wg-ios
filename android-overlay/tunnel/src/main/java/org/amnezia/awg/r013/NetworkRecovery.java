// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013;

/** Physical-network notifications only; validation is never VPN traffic proof. */
public final class NetworkRecovery<N, T> {
    public record Change<T>(T from, T to, long revision) { }
    private final T offline;
    private N network;
    private T type;
    private boolean observed;
    private boolean validated;
    private long revision;

    public NetworkRecovery(T offline) { this.offline = offline; type = offline; }

    public synchronized Change<T> capabilities(N next, T nextType, boolean ready) {
        if (next == null || nextType == null || nextType.equals(offline))
            throw new IllegalArgumentException("Invalid physical network");
        T previous = type;
        boolean changed = !next.equals(network) || !nextType.equals(type);
        boolean recovered = ready && !validated;
        boolean first = !observed;
        if (changed || ready != validated) revision++;
        observed = true; network = next; type = nextType; validated = ready;
        // First discovery does not disturb a VPN already starting. Following
        // onLost, however, a validated network must request socket recovery.
        return !first && ready && (changed || recovered) ? new Change<>(previous, type, revision) : null;
    }

    public synchronized Change<T> lost(N lost) {
        if (network == null || !network.equals(lost)) return null;
        T previous = type;
        network = null; type = offline; validated = false; revision++;
        return new Change<>(previous, offline, revision);
    }

    public synchronized boolean isCurrent(Change<T> change) { return change.revision() == revision; }
    public synchronized T type() { return type; }
    public synchronized boolean connected() { return validated && network != null; }
    public synchronized void reset() {
        network = null; type = offline; observed = false; validated = false; revision++;
    }
}
