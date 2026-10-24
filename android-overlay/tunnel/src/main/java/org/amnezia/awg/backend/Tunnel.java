/*
 * Copyright © 2017-2023 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package org.amnezia.awg.backend;

import org.amnezia.awg.util.NonNullForAll;

import java.util.regex.Pattern;

/**
 * Represents an AmneziaWG tunnel.
 */

@NonNullForAll
public interface Tunnel {
    int NAME_MAX_LENGTH = 64;
    Pattern NAME_PATTERN = Pattern.compile("[\\p{L}\\p{N} _=+.()·-]{1,64}");

    static boolean isNameInvalid(final CharSequence name) {
        return !NAME_PATTERN.matcher(name).matches();
    }

    /**
     * Get the name of the tunnel, which should always pass the !isNameInvalid test.
     *
     * @return The name of the tunnel.
     */
    String getName();

    /**
     * React to a change in state of the tunnel. Should only be directly called by Backend.
     *
     * @param newState The new state of the tunnel.
     */
    void onStateChange(State newState);

    /**
     * Enum class to represent all possible states of a {@link Tunnel}.
     */
    enum State {
        DOWN,
        TOGGLE,
        UP;

        /**
         * Get the state of a {@link Tunnel}
         *
         * @param running boolean indicating if the tunnel is running.
         * @return State of the tunnel based on whether or not it is running.
         */
        public static State of(final boolean running) {
            return running ? UP : DOWN;
        }
    }
}
