import java.util.*;
import org.amnezia.awg.r013.ServiceIPv4Routes;
public final class ServiceIPv4RoutesPropertyTest {
    static boolean contains(List<String> prefixes, long value) {
        for (String prefix : prefixes) {
            String[] split = prefix.split("/"); String[] octets = split[0].split("\\.");
            long start = 0; for (String part : octets) start = (start << 8) | Integer.parseInt(part);
            long size = 1L << (32 - Integer.parseInt(split[1]));
            if (value >= start && value < start + size) return true;
        }
        return false;
    }
    public static void main(String[] args) {
        Random random = new Random(13013);
        for (int trial = 0; trial < 200; trial++) {
            List<String> input = new ArrayList<>();
            for (int i = 0; i < 40; i++) {
                int last = random.nextInt(256), bits = 24 + random.nextInt(9);
                int aligned = (last >> (32-bits)) << (32-bits);
                input.add("10.1.2." + aligned + "/" + bits);
            }
            List<String> union = ServiceIPv4Routes.calculate(input, false);
            List<String> inverse = ServiceIPv4Routes.calculate(input, true);
            int dns1 = random.nextInt(256), dns2 = random.nextInt(256);
            List<String> withoutDns = ServiceIPv4Routes.subtract(input, Arrays.asList("10.1.2." + dns1 + "/32", "10.1.2." + dns2 + "/32"));
            for (int i = 0; i < 256; i++) {
                long value = (10L << 24) | (1L << 16) | (2L << 8) | i;
                boolean expected = contains(input, value);
                if (contains(union, value) != expected || contains(inverse, value) == expected) throw new AssertionError("coverage mismatch");
                if (contains(withoutDns, value) != (expected && i != dns1 && i != dns2)) throw new AssertionError("DNS exception mismatch");
            }
            if (!contains(inverse, 0) || !contains(inverse, 0xffffffffL)) throw new AssertionError("boundary mismatch");
        }
        System.out.println("ServiceIPv4RoutesPropertyTest PASS: 200 deterministic cases, 51200 address checks");
    }
}
