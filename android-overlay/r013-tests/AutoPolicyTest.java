import org.amnezia.awg.r013.AutoPolicy;

/** No Android SDK, server or customer configuration is used in this test. */
public final class AutoPolicyTest {
    private static int checks;
    private static void expect(boolean ok, String reason) { checks++; if (!ok) throw new AssertionError(reason); }
    public static void main(String[] args) {
        for (int count = 1; count <= 30; count++) for (int initial = 0; initial < count; initial++) {
            AutoPolicy policy = new AutoPolicy(count, initial);
            expect(policy.current() == initial, "Initial server retained");
            AutoPolicy.Decision first = policy.record(false, true, null);
            expect(first.action == AutoPolicy.Action.WAIT && first.waitSeconds == 5 && policy.current() == initial,
                    "First failed attempt cannot skip server");
            AutoPolicy.Decision second = policy.record(false, true, null);
            expect(count == 1 ? second.action == AutoPolicy.Action.WAIT && second.waitSeconds == 60
                            : second.action == AutoPolicy.Action.SWITCH && policy.current() == (initial + 1) % count,
                    "Second failure rotates or waits without a reserve");
            policy.record(true, true, 1200.0);
            int before = policy.current();
            AutoPolicy.Decision slow = policy.record(true, true, 1200.1);
            expect(count == 1 ? slow.action == AutoPolicy.Action.WAIT
                            : slow.action == AutoPolicy.Action.SWITCH && policy.current() != before,
                    "Latency threshold is strictly above 1200ms");
            policy.stop();
            for (int i = 0; i < 30; i++)
                expect(policy.record(false, true, null).action == AutoPolicy.Action.STOPPED,
                        "Explicit stop can never reconnect");
            AutoPolicy offline = new AutoPolicy(count, initial);
            for (int i = 0; i < 30; i++) {
                AutoPolicy.Decision decision = offline.record(false, false, null);
                expect(decision.action == AutoPolicy.Action.WAIT && decision.waitSeconds == 15 && offline.current() == initial,
                        "Loss of physical network is not a failed server attempt");
            }
            expect(offline.record(false, true, null).waitSeconds == 5, "Offline state does not consume an attempt");
            AutoPolicy exhausted = new AutoPolicy(count, initial);
            for (int i = 0; i < count; i++) {
                expect(exhausted.record(false, true, null).waitSeconds == 5, "Exactly two attempts per member");
                AutoPolicy.Decision decision = exhausted.record(false, true, null);
                expect(i + 1 == count ? decision.action == AutoPolicy.Action.WAIT && decision.waitSeconds == 60
                                    : decision.action == AutoPolicy.Action.SWITCH,
                        "Exhausted roster backs off; no tight reconnect loop");
            }
        }
        System.out.println("Android Auto policy checks passed: " + checks);
    }
}
