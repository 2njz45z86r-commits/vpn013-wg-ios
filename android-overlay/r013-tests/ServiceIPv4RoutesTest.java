import java.util.*;
import org.amnezia.awg.r013.ServiceIPv4Routes;
public final class ServiceIPv4RoutesTest {
    private static void eq(List<String> expected, List<String> actual) { if (!expected.equals(actual)) throw new AssertionError(actual); }
    private static void invalid(String value) { try { ServiceIPv4Routes.calculate(List.of(value), false); throw new AssertionError(value); } catch (IllegalArgumentException expected) {} }
    public static void main(String[] args) {
        eq(List.of("0.0.0.0/0"), ServiceIPv4Routes.calculate(List.of(), true));
        eq(List.of(), ServiceIPv4Routes.calculate(List.of("0.0.0.0/0"), true));
        eq(List.of("0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/4", "240.0.0.0/5", "248.0.0.0/6", "252.0.0.0/7", "254.0.0.0/8", "255.0.0.0/9", "255.128.0.0/10", "255.192.0.0/11", "255.224.0.0/12", "255.240.0.0/13", "255.248.0.0/14", "255.252.0.0/15", "255.254.0.0/16", "255.255.0.0/17", "255.255.128.0/18", "255.255.192.0/19", "255.255.224.0/20", "255.255.240.0/21", "255.255.248.0/22", "255.255.252.0/23", "255.255.254.0/24", "255.255.255.0/25", "255.255.255.128/26", "255.255.255.192/27", "255.255.255.224/28", "255.255.255.240/29", "255.255.255.248/30", "255.255.255.252/31", "255.255.255.254/32"), ServiceIPv4Routes.calculate(List.of("255.255.255.255/32"), true));
        eq(List.of("10.0.0.0/23"), ServiceIPv4Routes.calculate(List.of("10.0.1.0/24", "10.0.0.0/24", "10.0.0.0/25"), false));
        eq(List.of("10.0.0.0/25", "10.0.0.128/26", "10.0.0.192/27", "10.0.0.224/28", "10.0.0.240/29", "10.0.0.248/30", "10.0.0.252/31", "10.0.0.255/32"), ServiceIPv4Routes.subtract(List.of("10.0.0.0/24"), List.of("10.0.0.254/32")));
        invalid("1.2.3.4/24"); invalid("01.0.0.0/8"); invalid("256.0.0.0/8"); invalid("0.0.0.0/33");
        try { ServiceIPv4Routes.calculate(Collections.nCopies(16385, "10.0.0.0/8"), false); throw new AssertionError("input cap"); } catch (IllegalArgumentException expected) { }
        List<String> sparse = new ArrayList<>();
        for (int i = 0; i < 8192; i++) sparse.add("10." + (i / 256) + "." + (i % 256) + ".0/32");
        try { ServiceIPv4Routes.calculate(sparse, true); throw new AssertionError("output cap"); } catch (IllegalArgumentException expected) { }
        System.out.println("ServiceIPv4RoutesTest PASS");
    }
}

