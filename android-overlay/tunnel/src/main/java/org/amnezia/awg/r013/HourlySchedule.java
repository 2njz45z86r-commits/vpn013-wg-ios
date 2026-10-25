// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013;

/** Monotonic elapsed times supplied by the service; no wall clock or UI timer. */
public final class HourlySchedule {
    public static final long INITIAL_DELAY_MS = 30_000;
    public static final long INTERVAL_MS = 3_600_000;
    private long next;
    public HourlySchedule(long now) { next = now + INITIAL_DELAY_MS; }
    public long remaining(long now) { return Math.max(0, next - now); }
    public boolean take(long now) {
        if (now < next) return false;
        next = now + INTERVAL_MS; // No catch-up storm after sleep or lost network.
        return true;
    }
}
