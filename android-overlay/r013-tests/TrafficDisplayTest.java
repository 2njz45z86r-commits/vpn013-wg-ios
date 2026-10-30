import org.amnezia.awg.r013.TrafficDisplay;

public final class TrafficDisplayTest {
    private static int checks;
    private static void check(boolean value) {checks++;if(!value)throw new AssertionError("traffic case "+checks);}
    public static void main(String[] args) {
        double[] input={0,1,125,1250,125000,250000,2500000,125000000,125000000000.0,124987.5,124993.75,Double.NaN,Double.POSITIVE_INFINITY,-1};
        String[] expected={"0 бит/с","8 бит/с","1 Кбит/с","10 Кбит/с","1 Мбит/с","2 Мбит/с","20 Мбит/с","1 Гбит/с","1 Тбит/с","999,9 Кбит/с","1 Мбит/с","—","—","—"};
        for(int i=0;i<input.length;i++)check(TrafficDisplay.speed(input[i]).equals(expected[i]));
        long[] volumes={0,999,1000,1500,999950,1000000,2500000,1000000000,Long.MAX_VALUE};
        String[] amounts={"0 Б","999 Б","1 КБ","1,5 КБ","1 МБ","1 МБ","2,5 МБ","1 ГБ","9,2 ЭБ"};
        for(int i=0;i<volumes.length;i++)check(TrafficDisplay.amount(volumes[i]).equals(amounts[i]));
        check(TrafficDisplay.amount(null).equals("—"));check(TrafficDisplay.amount(-1L).equals("—"));
        TrafficDisplay.Sampler sampler=new TrafficDisplay.Sampler();
        check(sampler.sample("a",0,0L,0L)==null);
        TrafficDisplay.Rate rate=sampler.sample("a",2,500000L,125000L);
        check(rate!=null && TrafficDisplay.speed(rate.received).equals("2 Мбит/с") && TrafficDisplay.speed(rate.sent).equals("500 Кбит/с"));
        check(sampler.sample("a",2.1,510000L,126000L)==rate);
        rate=sampler.sample("a",4,500000L,125000L);check(rate!=null && TrafficDisplay.speed(rate.received).equals("0 бит/с"));
        check(sampler.sample("a",6,1000L,1000L)==null);
        check(sampler.sample("b",8,5000000L,5000000L)==null);
        check(sampler.sample("b",40,6000000L,6000000L)==null);
        check(sampler.sample("b",41,null,null)==null);
        check(sampler.sample("b",42,6000000L,6000000L)==null);
        check(sampler.sample("b",41,7000000L,7000000L)==null);
        System.out.println("TrafficDisplayTest: "+checks+" checks passed");
    }
}
