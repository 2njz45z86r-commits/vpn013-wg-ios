import org.amnezia.awg.r013.HourlySchedule;
import org.amnezia.awg.r013.AutoPolicy;

public final class HourlyScheduleTest {
    private static int checks;
    private static void expect(boolean good) { checks++; if (!good) throw new AssertionError("Schedule/choice invariant failed at " + checks); }
    public static void main(String[] args) {
        HourlySchedule schedule = new HourlySchedule(100_000);
        expect(schedule.remaining(100_000) == 30_000);
        expect(!schedule.take(129_999)); expect(schedule.take(130_000));
        expect(!schedule.take(130_000)); expect(schedule.remaining(130_000) == 300_000);
        expect(!schedule.take(429_999)); expect(schedule.take(430_000));
        expect(schedule.take(30_000_000)); expect(!schedule.take(30_000_000));
        expect(schedule.remaining(30_000_000) == 300_000);
        for (int count = 1; count <= 30; count++) for (int index = 0; index < count; index++) {
            AutoPolicy policy = new AutoPolicy(count,0);
            policy.record(false,true,null); // Selection resets the first failure.
            policy.selectMeasuredCandidate(index);
            expect(policy.current() == index);
            AutoPolicy.Decision first = policy.record(false,true,null);
            expect(first.action == AutoPolicy.Action.WAIT && first.waitSeconds == 5 && policy.current() == index);
            policy.stop();
            try { policy.selectMeasuredCandidate(index); throw new AssertionError("Stopped policy switched"); }
            catch (IllegalStateException expected) { checks++; }
        }
        System.out.println("Android hourly schedule/selection checks passed: " + checks);
    }
}
