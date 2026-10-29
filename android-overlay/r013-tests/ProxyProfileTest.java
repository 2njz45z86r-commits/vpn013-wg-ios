// SPDX-License-Identifier: MIT
import org.amnezia.awg.r013.ProxyProfile;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class ProxyProfileTest {
    private static int checks;
    private static final String ROOT="vless://00000000-0000-4000-8000-000000000001@example.org:443?security=tls";
    private static void check(boolean value) { checks++; if(!value) throw new AssertionError("case "+checks); }
    private static void rejects(String text) {
        try { ProxyProfile.parseList(text,ProxyProfile.Section.HAPP); throw new AssertionError("accepted invalid input"); }
        catch(IllegalArgumentException expected) { check(!expected.getMessage().contains("00000000") && !expected.getMessage().contains("vless://")); }
    }
    public static void main(String[] args) {
        for(ProxyProfile.Section section:ProxyProfile.Section.values()) {
            for(String type:new String[]{"tcp","ws","grpc","xhttp"}) {
                ProxyProfile p=ProxyProfile.parse(ROOT+"&type="+type+"#Name%20%2B",section);
                check(p.section==section && p.transport.equals(type) && p.name.equals("Name +"));
                check(p.host.equals("example.org") && p.serverName.equals("example.org") && p.port==443);
                check(!p.toString().contains(p.userId));
            }
        }
        String key=Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]);
        ProxyProfile reality=ProxyProfile.parse(ROOT.replace("tls","reality")+"&pbk="+key+"&sid=ab01&flow=xtls-rprx-vision",ProxyProfile.Section.INCY);
        check(reality.options.get("pbk").equals(key));
        check(ProxyProfile.parse(ROOT.replace("example.org","[2001:db8::1]"),ProxyProfile.Section.HAPP).host.equals("2001:db8::1"));
        String roster=ROOT+"#First\n"+ROOT+"#Second\n"+ROOT+"#First";
        check(ProxyProfile.parseList(roster,ProxyProfile.Section.BLACKTEMPLE).size()==2);
        check(ProxyProfile.parseList(Base64.getEncoder().encodeToString(roster.getBytes(StandardCharsets.UTF_8)),ProxyProfile.Section.HAPP).size()==2);
        check(ProxyProfile.parse(ROOT+"&type=xhttp&x_padding_bytes=100-200",ProxyProfile.Section.INCY).options.get("x_padding_bytes").equals("100-200"));
        for(String pad:new String[]{"-1","2-1","01","65537","1-65537","1-2-3"}) rejects(ROOT+"&type=xhttp&x_padding_bytes="+pad);
        rejects(ROOT+"&type=tcp&x_padding_bytes=10");
        String large=Base64.getEncoder().encodeToString(roster.getBytes(StandardCharsets.UTF_8))+" ".repeat(1_048_577);
        for(ProxyProfile.Section section:ProxyProfile.Section.values())
            check(ProxyProfile.parseList(large,section).size()==2);
        for(String tail:new String[]{"&allowInsecure=1","&security=reality","&type=udp","&flow=unknown","&fp=unknown",
                "&type=ws&flow=xtls-rprx-vision","&type=xhttp&mode=unknown","&type=grpc&mode=packet-up","&alpn=bad",
                "&sid=a","&path=%0D%0AHeader","&sni=bad_host","&host=example.org%3A443","&extra=%7B%7D","&unknown=1",
                "&type=grpc&authority=bad_host","&serviceName=ignored","&path=ignored"}) rejects(ROOT+tail);
        rejects(ROOT+"#%FF"); rejects(ROOT+"#%C0%AF");
        for(String input:new String[]{"", "not a config",ROOT.replace(":443",":0"), ROOT.replace(":443",":65536"),
                ROOT.replace("example.org","-bad.org"),ROOT.replace("example.org","example..org"),
                ROOT.replace("security=tls","security=none"),ROOT.replace("security=tls","security=reality&pbk=bad"),
                ROOT+"\ninvalid",ROOT.replace("00000000-0000-4000-8000-000000000001","1-1-1-1-1"),
                ROOT.replace("example.org","[fe80::1%25wlan0]"),"A".repeat(8_388_609),
                Base64.getEncoder().encodeToString(new byte[]{(byte)0xff})}) rejects(input);
        StringBuilder many=new StringBuilder(); for(int i=0;i<101;i++) many.append(ROOT).append('#').append(i).append('\n');
        rejects(many.toString());
        try { reality.options.put("fp","bad"); throw new AssertionError(); }
        catch(UnsupportedOperationException expected) { check(true); }
        System.out.println("ProxyProfileTest: "+checks+" checks passed");
    }
}
