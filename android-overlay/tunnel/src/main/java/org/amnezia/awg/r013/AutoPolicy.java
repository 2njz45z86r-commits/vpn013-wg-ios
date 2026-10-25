// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013;

import java.util.HashSet;
import java.util.Set;

/** Pure decisions; backend ownership serializes health and measured selection. */
public final class AutoPolicy {
    public static final double MAXIMUM_LATENCY_MS = 1200;
    public enum Action { STAY, SWITCH, WAIT, STOPPED }
    public static final class Decision {
        public final Action action;
        public final int index;
        public final int waitSeconds;
        private Decision(Action action, int index, int waitSeconds) {
            this.action = action; this.index = index; this.waitSeconds = waitSeconds;
        }
    }
    private final int count;
    private int current;
    private int failures;
    private final Set<Integer> visited = new HashSet<>();
    private boolean running = true;

    public AutoPolicy(int count, int initialIndex) {
        if (count < 1 || count > 30 || initialIndex < 0 || initialIndex >= count)
            throw new IllegalArgumentException("Invalid Auto membership");
        this.count = count; current = initialIndex; visited.add(current);
    }
    public int current() { return current; }
    /** Owner must serialize this with record and the actual backend transition. */
    public void selectMeasuredCandidate(int index) {
        if (!running || index < 0 || index >= count) throw new IllegalStateException("Invalid measured selection");
        current = index; failures = 0; visited.clear(); visited.add(current);
    }
    public void stop() { running = false; }
    private Decision decision(Action action, int wait) { return new Decision(action, current, wait); }
    public Decision record(boolean healthy, boolean networkAvailable, Double latencyMs) {
        if (!running) return decision(Action.STOPPED, 0);
        if (!networkAvailable) { failures = 0; return decision(Action.WAIT, 15); }
        if (healthy && latencyMs != null && !latencyMs.isNaN() && !latencyMs.isInfinite()
                && latencyMs > MAXIMUM_LATENCY_MS) {
            failures = 0; return rotate();
        }
        if (healthy) { failures = 0; visited.clear(); visited.add(current); return decision(Action.STAY, 0); }
        if (++failures < 2) return decision(Action.WAIT, 5);
        failures = 0; return rotate();
    }
    private Decision rotate() {
        if (visited.size() == count) {
            visited.clear(); visited.add(current); return decision(Action.WAIT, 60);
        }
        for (int offset = 1; offset < count; offset++) {
            int next = (current + offset) % count;
            if (!visited.contains(next)) {
                current = next; visited.add(next); return decision(Action.SWITCH, 0);
            }
        }
        return decision(Action.WAIT, 60);
    }
}
