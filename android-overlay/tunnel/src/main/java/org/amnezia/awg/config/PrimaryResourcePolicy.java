// SPDX-License-Identifier: MIT
package org.amnezia.awg.config;

import java.util.regex.Pattern;

/** Resource budget for primary AmneziaWG handshake construction. */
public final class PrimaryResourcePolicy {
    private static final int MAX_JUNK_COUNT = 64, MAX_PACKET_BYTES = 4096;
    private static final long MAX_JUNK_TOTAL = 256L * 1024, MAX_INITIAL_TOTAL = 20L * 1024;
    private static final Pattern FIELDS = Pattern.compile("\\s+", Pattern.UNICODE_CHARACTER_CLASS);
    private PrimaryResourcePolicy() {}
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Недопустимые параметры ресурсов AmneziaWG"); }
    public static void validate(int count, int min, int max, int[] padding, String[] initial) {
        if (count < 0 || count > MAX_JUNK_COUNT || min < 0 || min > MAX_PACKET_BYTES || max < 0 || max > MAX_PACKET_BYTES ||
            (count > 0 && min > max) || (long) count * max > MAX_JUNK_TOTAL) throw invalid();
        if (padding == null || padding.length != 4 || initial == null || initial.length != 5) throw invalid();
        for (int n : padding) if (n < 0 || n > MAX_PACKET_BYTES) throw invalid();
        long total = 0;
        for (String spec : initial) {
            int length = initialLength(spec);
            if (length > MAX_PACKET_BYTES) throw invalid();
            total += length;
            if (total > MAX_INITIAL_TOTAL) throw invalid();
        }
    }
    private static int initialLength(String spec) {
        if (spec == null || spec.isEmpty()) return 0;
        int pos = 0; long size = 0;
        while (true) {
            int start = spec.indexOf('<', pos);
            if (start < 0) break;
            int end = spec.indexOf('>', start + 1);
            if (end < 0) throw invalid();
            String tag = spec.substring(start + 1, end);
            String[] fields = FIELDS.split(tag, 0);
            int first = 0; while (first < fields.length && fields[first].isEmpty()) first++;
            if (first == fields.length) throw invalid();
            String kind = fields[first];
            String value = first + 1 < fields.length ? fields[first + 1] : "";
            long add;
            switch (kind) {
                case "r": case "rc": case "rd": case "dz":
                    if (!value.matches("[+-]?[0-9]+")) throw invalid();
                    try { add = Long.parseLong(value); } catch (NumberFormatException e) { throw invalid(); }
                    if (add < 0 || add > MAX_PACKET_BYTES) throw invalid();
                    break;
                case "t": add = 4; break;
                case "d": case "ds": add = 0; break;
                case "b":
                    if (value.startsWith("0x")) value = value.substring(2);
                    if (value.isEmpty() || value.length() > 2 * MAX_PACKET_BYTES || (value.length() & 1) != 0 || !value.matches("[0-9A-Fa-f]+")) throw invalid();
                    add = value.length() / 2; break;
                default: throw invalid();
            }
            size += add;
            if (size > MAX_PACKET_BYTES) throw invalid();
            pos = end + 1;
        }
        return (int) size;
    }
}
