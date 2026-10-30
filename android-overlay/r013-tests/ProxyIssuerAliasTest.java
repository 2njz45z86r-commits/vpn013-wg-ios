// SPDX-License-Identifier: MIT
import org.amnezia.awg.r013.ProxyProfile;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/** Issuer interoperability without accepting unchecked JSON or weakening TLS. */
public final class ProxyIssuerAliasTest {
    private static int checks;
    private static final String ROOT="vless://00000000-0000-4000-8000-000000000001@example.org:443?security=tls";
    private static void check(boolean value) { checks++; if(!value) throw new AssertionError("issuer case "+checks); }
    private static void rejects(String text, ProxyProfile.Section section) {
        try { ProxyProfile.parseList(text,section); throw new AssertionError("accepted unsafe issuer input"); }
        catch(IllegalArgumentException expected) {
            check(!expected.getMessage().contains("00000000") && !expected.getMessage().contains("vless://"));
        }
    }
    public static void main(String[] args) {
        for(ProxyProfile.Section section:ProxyProfile.Section.values()) {
            for(String alias:new String[]{"raw","RAW","splithttp","SPLITHTTP"}) {
                String kind=alias.equalsIgnoreCase("raw") ? "tcp" : "xhttp";
                String text=ROOT+"&type="+alias+"&support-x25519mlkem768=true&allowInsecure=0&insecure=false&skipTLSVerify=FALSE";
                ProxyProfile p=ProxyProfile.parse(text,section);
                check(p.transport.equals(kind) && p.security.equals("tls") && p.options.get("type").equals(kind));
                check(!p.options.containsKey("allowInsecure") && !p.options.containsKey("support-x25519mlkem768"));
                check(ProxyProfile.parseList(Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)),section).size()==1);
            }
            check(ProxyProfile.parse(ROOT+"&type=raw&headerType=none",section).transport.equals("tcp"));
            check(ProxyProfile.parse(ROOT.replace("security=tls","security=TLS"),section).security.equals("tls"));
            for(String flag:new String[]{"allowInsecure","insecure","skipTLSVerify"})
                for(String unsafe:new String[]{"1","true","TRUE","", "yes"}) rejects(ROOT+"&"+flag+"="+unsafe,section);
            for(String tail:new String[]{"&type=raw&headerType=http","&type=ws&headerType=none",
                    "&support-x25519mlkem768=2","&type=raw&type=tcp","&allowInsecure=false&allowInsecure=0",
                    "&type=xhttp&extra=%7B%7D","&type=raw&unknown=1"}) rejects(ROOT+tail,section);
            // A malformed final row still rejects the entire update atomically.
            rejects(ROOT+"&type=raw\n"+ROOT+"&type=splithttp&allowInsecure=true",section);
        }
        System.out.println("ProxyIssuerAliasTest: "+checks+" checks passed");
    }
}
