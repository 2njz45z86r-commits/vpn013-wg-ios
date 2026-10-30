// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013;

import java.util.Locale;

/** Presentation-only decimal rates; never changes VPN state or packet routing. */
public final class TrafficDisplay {
    private TrafficDisplay() { }
    public static String amount(Long bytes) {
        return bytes == null ? "—" : compact(bytes.doubleValue(), new String[]{"Б","КБ","МБ","ГБ","ТБ","ПБ","ЭБ"});
    }
    public static String speed(Double bytesPerSecond) {
        return bytesPerSecond == null ? "—" : compact(bytesPerSecond * 8,
                new String[]{"бит/с","Кбит/с","Мбит/с","Гбит/с","Тбит/с","Пбит/с","Эбит/с","Збит/с","Ибит/с"});
    }
    private static String compact(double input, String[] units) {
        if (!Double.isFinite(input) || input < 0) return "—";
        double value=input; int index=0;
        while(value>=1000 && index+1<units.length) { value/=1000; index++; }
        value=Math.round(value*10)/10.0;
        if(value>=1000 && index+1<units.length) { value/=1000; index++; }
        String text=String.format(Locale.ROOT,"%.1f",value);
        if(text.endsWith(".0")) text=text.substring(0,text.length()-2);
        return text.replace('.',',')+" "+units[index];
    }
    public static final class Rate {
        public final double received,sent;
        Rate(double received,double sent) { this.received=received; this.sent=sent; }
    }
    public static final class Sampler {
        private String identity;
        private double time;
        private long received,sent;
        private Rate latest;
        public void reset() { identity=null; latest=null; }
        public Rate sample(String nextIdentity,double now,Long rx,Long tx) {
            if(nextIdentity==null || nextIdentity.isEmpty() || !Double.isFinite(now) || now<0 || rx==null || tx==null || rx<0 || tx<0) { reset(); return null; }
            boolean valid=nextIdentity.equals(identity) && rx>=received && tx>=sent && now>time && now-time<=30;
            if(valid && now-time<0.25) return latest;
            Rate result=valid ? new Rate((double)(rx-received)/(now-time),(double)(tx-sent)/(now-time)) : null;
            identity=nextIdentity; time=now; received=rx; sent=tx; latest=result; return result;
        }
    }
}
