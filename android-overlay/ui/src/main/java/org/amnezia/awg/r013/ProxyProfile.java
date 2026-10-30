// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013;

import java.net.URI;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Typed import only: no supplied listeners, executable JSON or unchecked TLS options. */
public final class ProxyProfile {
    public enum Section { HAPP, INCY, BLACKTEMPLE }
    public final Section section;
    public final String name, host, userId, transport, security, serverName;
    public final int port;
    public final Map<String, String> options;
    private static final Set<String> ALLOWED = Set.of("type", "security", "encryption", "sni", "fp", "pbk", "sid",
            "flow", "path", "host", "serviceName", "mode", "alpn", "authority", "spx", "pqv", "x_padding_bytes",
            "headerType", "allowInsecure", "insecure", "skipTLSVerify", "support-x25519mlkem768");

    private ProxyProfile(Section section, String name, String host, int port, String userId,
                         String transport, String security, String serverName, Map<String,String> options) {
        this.section=section; this.name=name; this.host=host; this.port=port; this.userId=userId;
        this.transport=transport; this.security=security; this.serverName=serverName;
        this.options=Collections.unmodifiableMap(new LinkedHashMap<>(options));
    }
    private static IllegalArgumentException invalid() {
        // Deliberately never include an input URI, UUID or subscription token in errors.
        return new IllegalArgumentException("Конфигурация VLESS повреждена или содержит неподдерживаемые параметры");
    }
    private static String clean(String value, int max) {
        if(value.getBytes(StandardCharsets.UTF_8).length>max || value.codePoints().anyMatch(c -> c<32 || c==127)) throw invalid();
        return value;
    }
    private static String decode(String value) {
        try {
            ByteArrayOutputStream bytes=new ByteArrayOutputStream();
            for(int i=0;i<value.length();) {
                if(value.charAt(i)=='%') {
                    if(i+2>=value.length()) throw invalid();
                    int high=Character.digit(value.charAt(i+1),16), low=Character.digit(value.charAt(i+2),16);
                    if(high<0 || low<0) throw invalid();
                    bytes.write((high<<4)|low); i+=3;
                } else {
                    int cp=value.codePointAt(i);
                    byte[] encoded=new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8);
                    bytes.write(encoded,0,encoded.length);
                    i+=Character.charCount(cp);
                }
            }
            return clean(StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes.toByteArray())).toString(),4096);
        } catch(IllegalArgumentException | CharacterCodingException error) { throw invalid(); }
    }
    private static String host(String value) {
        clean(value,253);
        if(value.startsWith("[") && value.endsWith("]")) value=value.substring(1,value.length()-1);
        // URI validates numeric IPv6 without DNS. Zone IDs cannot cross physical networks.
        if(value.contains(":")) {
            if(value.contains("%")) throw invalid();
            try { if(new URI("https://["+value+"]/").getHost()==null) throw invalid(); }
            catch(Exception error) { throw invalid(); }
        } else {
            if(value.isEmpty()) throw invalid();
            for(String label:value.split("\\.",-1))
                if(!label.matches("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")) throw invalid();
        }
        return value.toLowerCase(Locale.ROOT);
    }
    public static ProxyProfile parse(String input, Section section) {
        Objects.requireNonNull(section);
        if(input==null || input.getBytes(StandardCharsets.UTF_8).length>65536) throw invalid();
        try {
            URI uri=new URI(input.trim());
            if(!"vless".equalsIgnoreCase(uri.getScheme()) || uri.getHost()==null ||
                    (uri.getRawPath()!=null && !uri.getRawPath().isEmpty()) || uri.getPort()<1 || uri.getPort()>65535) throw invalid();
            String user=decode(Objects.requireNonNull(uri.getRawUserInfo()));
            if(!user.matches("[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")) throw invalid();
            user=UUID.fromString(user).toString();
            Map<String,String> q=new LinkedHashMap<>();
            if(uri.getRawQuery()!=null) for(String item:uri.getRawQuery().split("&",-1)) {
                String[] pair=item.split("=",2);
                if(pair.length!=2) throw invalid();
                String key=decode(pair[0]), value=decode(pair[1]);
                if(!ALLOWED.contains(key) || q.putIfAbsent(key,value)!=null) throw invalid();
            }
            String transport=q.getOrDefault("type","tcp").toLowerCase(Locale.ROOT);
            if(transport.equals("raw")) transport="tcp";
            if(transport.equals("splithttp")) transport="xhttp";
            String security=q.getOrDefault("security","tls").toLowerCase(Locale.ROOT);
            if(!Set.of("tcp","ws","grpc","xhttp").contains(transport) || !Set.of("tls","reality").contains(security) ||
                    !"none".equals(q.getOrDefault("encryption","none"))) throw invalid();
            // Issuer aliases describe the same supported transport. TLS remains
            // verified by the typed configuration builder; unsafe flags never pass.
            for(String flag:List.of("allowInsecure","insecure","skipTLSVerify"))
                if(q.containsKey(flag) && !Set.of("0","false").contains(q.get(flag).toLowerCase(Locale.ROOT))) throw invalid();
            if(q.containsKey("support-x25519mlkem768") &&
                    !Set.of("0","1","false","true").contains(q.get("support-x25519mlkem768").toLowerCase(Locale.ROOT))) throw invalid();
            if(q.containsKey("headerType") && (!transport.equals("tcp") || !q.get("headerType").equals("none"))) throw invalid();
            q.put("type",transport); q.put("security",security);
            // Capability hints do not select a cipher or bypass certificate checks.
            for(String flag:List.of("headerType","allowInsecure","insecure","skipTLSVerify","support-x25519mlkem768")) q.remove(flag);
            String endpoint=host(uri.getHost()), sni=host(q.getOrDefault("sni",endpoint));
            String flow=q.getOrDefault("flow", "");
            if(!Set.of("", "xtls-rprx-vision").contains(flow) || (!flow.isEmpty() && !transport.equals("tcp"))) throw invalid();
            if(!Set.of("", "chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized")
                    .contains(q.getOrDefault("fp",""))) throw invalid();
            if(security.equals("reality")) {
                byte[] key=Base64.getUrlDecoder().decode(q.getOrDefault("pbk",""));
                if(key.length!=32 || !q.getOrDefault("sid","").matches("(?:[0-9a-fA-F]{2}){0,8}")) throw invalid();
            } else if(q.containsKey("pbk") || q.containsKey("sid") || q.containsKey("pqv") || q.containsKey("spx")) throw invalid();
            if(q.containsKey("host") && !q.get("host").isEmpty()) host(q.get("host"));
            if(q.containsKey("authority") && !q.get("authority").isEmpty()) host(q.get("authority"));
            if(!transport.equals("grpc") && (q.containsKey("serviceName") || q.containsKey("authority"))) throw invalid();
            if(!Set.of("ws","xhttp").contains(transport) && (q.containsKey("path") || q.containsKey("host"))) throw invalid();
            if(q.containsKey("x_padding_bytes")) {
                if(!transport.equals("xhttp")) throw invalid();
                String padding=q.get("x_padding_bytes");
                if(!padding.matches("(?:0|[1-9][0-9]{0,4})(?:-(?:0|[1-9][0-9]{0,4}))?")) throw invalid();
                String[] bounds=padding.split("-",-1);
                int first=Integer.parseInt(bounds[0]), last=Integer.parseInt(bounds[bounds.length-1]);
                if(first>last || last>65536 || (first==0 && last!=0)) throw invalid();
            }
            clean(q.getOrDefault("path",""),2048); clean(q.getOrDefault("serviceName",""),256);
            clean(q.getOrDefault("authority",""),253);
            String mode=q.getOrDefault("mode","");
            if(transport.equals("xhttp") && !Set.of("","auto","packet-up","stream-up","stream-one").contains(mode)) throw invalid();
            if(transport.equals("grpc") && !Set.of("","gun","multi").contains(mode)) throw invalid();
            if(!transport.equals("grpc") && !transport.equals("xhttp") && !mode.isEmpty()) throw invalid();
            if(q.containsKey("alpn")) for(String alpn:q.get("alpn").split(",",-1))
                if(!Set.of("h2","http/1.1","h3").contains(alpn)) throw invalid();
            String name=uri.getRawFragment()==null ? section.name() : decode(uri.getRawFragment());
            if(name.isBlank()) name=section.name();
            clean(name,128);
            return new ProxyProfile(section,name,endpoint,uri.getPort(),user,transport,security,sni,q);
        } catch(Exception error) { throw invalid(); }
    }
    /** Parse atomically. One bad row never silently replaces a complete saved roster. */
    public static List<ProxyProfile> parseList(String input, Section section) {
        if(input==null || input.getBytes(StandardCharsets.UTF_8).length>8_388_608) throw invalid();
        String text=input.trim();
        if(!text.regionMatches(true,0,"vless://",0,8) && !rosterMetadata(text)) {
            try {
                String compact=text.replaceAll("[\\r\\n\\t ]", "");
                byte[] bytes;
                try { bytes=Base64.getDecoder().decode(compact); }
                catch(IllegalArgumentException error) { bytes=Base64.getUrlDecoder().decode(compact); }
                text=StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            } catch(IllegalArgumentException | CharacterCodingException error) { throw invalid(); }
        }
        LinkedHashMap<String,ProxyProfile> profiles=new LinkedHashMap<>();
        int rows=0;
        for(String row:text.split("\\R")) {
            if(row.isBlank()) continue;
            if(++rows>300) throw invalid();
            if(rosterMetadata(row.trim())) {
                if(row.length()>2048 || row.chars().anyMatch(c -> c<32 || c==127)) throw invalid();
                continue;
            }
            ProxyProfile profile=parse(row,section);
            profiles.putIfAbsent(row.trim(),profile);
            if(profiles.size()>100) throw invalid();
        }
        if(profiles.isEmpty()) throw invalid();
        return List.copyOf(profiles.values());
    }
    private static boolean rosterMetadata(String row) {
        return row.startsWith("#profile-title:") || row.startsWith("#subscription-userinfo:") ||
               row.startsWith("#support-url:") || row.startsWith("#profile-web-page-url:");
    }
    @Override public String toString() { return "ProxyProfile["+section+", private]"; }
}
