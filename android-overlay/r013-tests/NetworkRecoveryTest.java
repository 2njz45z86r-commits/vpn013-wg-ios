import org.amnezia.awg.r013.NetworkRecovery;

/** Production event decisions, without sockets, Android or customer profiles. */
public final class NetworkRecoveryTest {
    private enum Type { NONE, WIFI, CELLULAR }
    private static int checks;
    private static void expect(boolean value, String reason) {
        checks++; if (!value) throw new AssertionError(reason);
    }
    public static void main(String[] args) {
        NetworkRecovery<Integer, Type> state = new NetworkRecovery<>(Type.NONE);
        expect(state.capabilities(1, Type.WIFI, true) == null, "Initial discovery must not restart VPN");
        expect(state.connected(), "Initial validated physical network recorded");
        expect(state.capabilities(1, Type.WIFI, true) == null, "Repeated capabilities do not reconnect");
        var loss = state.lost(1);
        expect(loss != null && loss.from() == Type.WIFI && loss.to() == Type.NONE, "Loss reported");
        expect(!state.connected(), "Loss clears validation");
        var returned = state.capabilities(1, Type.WIFI, true);
        expect(returned != null && returned.from() == Type.NONE && returned.to() == Type.WIFI,
            "REGRESSION: same Wi-Fi returning after loss must request recovery");
        expect(!state.isCurrent(loss) && state.isCurrent(returned), "Superseded queued loss cannot win");
        expect(state.lost(99) == null && state.connected(), "Loss of unrelated network ignored");
        expect(state.capabilities(1, Type.WIFI, false) == null && !state.connected(), "Validation loss recorded");
        var revalidated = state.capabilities(1, Type.WIFI, true);
        expect(revalidated != null && revalidated.to() == Type.WIFI,
            "REGRESSION: same network validation false then true requests recovery");
        expect(state.capabilities(1, Type.WIFI, true) == null, "Validation restoration emits once");
        var mobile = state.capabilities(2, Type.CELLULAR, true);
        expect(mobile != null && mobile.from() == Type.WIFI && mobile.to() == Type.CELLULAR,
            "Direct validated handover preserved");
        expect(state.lost(1) == null && state.connected(), "Old Wi-Fi loss cannot erase new cellular network");
        state.lost(2);
        expect(state.capabilities(3, Type.WIFI, false) == null, "Unvalidated return waits");
        expect(!state.connected(), "Unvalidated return is not internet proof");
        var delayed = state.capabilities(3, Type.WIFI, true);
        expect(delayed != null, "Delayed validation eventually recovers");
        state.reset();
        expect(!state.isCurrent(delayed) && !state.connected() && state.type() == Type.NONE,
            "Unbind invalidates pending callbacks");
        expect(state.capabilities(4, Type.CELLULAR, true) == null, "Rebind starts with non-disruptive discovery");
        for (int i = 0; i < 1000; i++) {
            var down = state.lost(i == 0 ? 4 : i + 9);
            expect(down != null, "Repeated real loss recorded");
            var up = state.capabilities(i + 10, Type.WIFI, true);
            expect(up != null && state.isCurrent(up) && !state.isCurrent(down), "Every return recovers once");
            expect(state.capabilities(i + 10, Type.WIFI, true) == null, "No recovery storm");
        }
        System.out.println("Android physical network recovery checks passed: " + checks);
    }
}
