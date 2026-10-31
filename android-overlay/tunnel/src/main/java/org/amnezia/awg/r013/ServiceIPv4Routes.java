// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Canonical IPv4 CIDR union/complement, with bounded input and output. */
public final class ServiceIPv4Routes {
    private static final long END = 1L << 32;
    private static final int LIMIT = 16384;
    private ServiceIPv4Routes() {}
    private static long[] parse(String cidr) {
        String[] pair = cidr.split("/", -1);
        if (pair.length != 2 || !pair[1].matches("0|[1-9][0-9]?")) throw new IllegalArgumentException("Invalid IPv4 prefix");
        int bits = Integer.parseInt(pair[1]);
        if (bits > 32) throw new IllegalArgumentException("Invalid IPv4 prefix");
        String[] octets = pair[0].split("\\.", -1);
        if (octets.length != 4) throw new IllegalArgumentException("Invalid IPv4 address");
        long address = 0;
        for (String part : octets) {
            if (!part.matches("0|[1-9][0-9]{0,2}")) throw new IllegalArgumentException("Invalid IPv4 address");
            int n = Integer.parseInt(part);
            if (n > 255) throw new IllegalArgumentException("Invalid IPv4 address");
            address = (address << 8) | n;
        }
        long size = 1L << (32 - bits);
        if ((address & (size - 1)) != 0) throw new IllegalArgumentException("Non-canonical IPv4 prefix");
        return new long[] {address, address + size};
    }
    private static List<long[]> ranges(List<String> cidrs) {
        if (cidrs.size() > LIMIT) throw new IllegalArgumentException("Too many IPv4 prefixes");
        List<long[]> source = new ArrayList<>();
        for (String value : cidrs) source.add(parse(value));
        source.sort(Comparator.comparingLong(a -> a[0]));
        List<long[]> union = new ArrayList<>();
        for (long[] next : source) {
            if (union.isEmpty() || union.get(union.size() - 1)[1] < next[0]) union.add(next);
            else union.get(union.size() - 1)[1] = Math.max(union.get(union.size() - 1)[1], next[1]);
        }
        return union;
    }
    public static List<String> calculate(List<String> cidrs, boolean complement) {
        List<long[]> union = ranges(cidrs);
        if (complement) {
            List<long[]> inverse = new ArrayList<>(); long cursor = 0;
            for (long[] range : union) { if (cursor < range[0]) inverse.add(new long[]{cursor, range[0]}); cursor = range[1]; }
            if (cursor < END) inverse.add(new long[]{cursor, END});
            union = inverse;
        }
        return encode(union);
    }
    public static List<String> subtract(List<String> cidrs, List<String> exclusions) {
        List<long[]> source = ranges(cidrs), remove = ranges(exclusions), result = new ArrayList<>();
        int index = 0;
        for (long[] range : source) {
            long cursor = range[0];
            while (index < remove.size() && remove.get(index)[1] <= cursor) index++;
            int j = index;
            while (j < remove.size() && remove.get(j)[0] < range[1]) {
                long[] cut = remove.get(j++);
                if (cut[0] > cursor) result.add(new long[]{cursor, Math.min(cut[0], range[1])});
                cursor = Math.max(cursor, cut[1]);
                if (cursor >= range[1]) break;
            }
            if (cursor < range[1]) result.add(new long[]{cursor, range[1]});
        }
        return encode(result);
    }
    private static List<String> encode(List<long[]> union) {
        List<String> result = new ArrayList<>();
        for (long[] range : union) {
            long cursor = range[0];
            while (cursor < range[1]) {
                long alignment = cursor == 0 ? END : Long.lowestOneBit(cursor);
                long size = Math.min(alignment, Long.highestOneBit(range[1] - cursor));
                int bits = 32 - Long.numberOfTrailingZeros(size);
                result.add(((cursor >>> 24) & 255) + "." + ((cursor >>> 16) & 255) + "." + ((cursor >>> 8) & 255) + "." + (cursor & 255) + "/" + bits);
                if (result.size() > LIMIT) throw new IllegalArgumentException("Too many resulting IPv4 routes");
                cursor += size;
            }
        }
        return result;
    }
}

