// SPDX-License-Identifier: MIT
import org.amnezia.awg.r013.ArchiveReader;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;

public final class ArchiveReaderTest {
    static int checks;
    static void check(boolean value) { checks++; if (!value) throw new AssertionError("Archive invariant failed"); }
    static byte[] zip(Map<String,String> files) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream out = new ZipOutputStream(bytes)) {
            for (var entry : files.entrySet()) { out.putNextEntry(new ZipEntry(entry.getKey())); out.write(entry.getValue().getBytes(StandardCharsets.UTF_8)); out.closeEntry(); }
        }
        return bytes.toByteArray();
    }
    static void refused(Map<String,String> files) throws Exception {
        try { ArchiveReader.read(zip(files)); throw new AssertionError("Unsafe archive accepted"); } catch (IOException expected) { checks++; }
    }
    public static void main(String[] args) throws Exception {
        for (int count = 1; count <= 30; count++) {
            for (boolean reverse : new boolean[]{false,true}) {
                Map<String,String> files = new LinkedHashMap<>();
                for (int n = 0; n < count; n++) {
                    String name = "Server"+n+".conf";
                    if (reverse) { files.put("Android/"+name, "android-"+n); files.put("iPhone/"+name, "iphone-"+n); }
                    else { files.put("iPhone/"+name, "iphone-"+n); files.put("Android/"+name, "android-"+n); }
                }
                files.put("README.txt", "not a configuration");
                var result = ArchiveReader.read(zip(files)); check(result.profiles().size() == count);
                for (var item : result.profiles()) check(item.text().startsWith("android-"));
            }
        }
        refused(Map.of("../escape.conf","x")); refused(Map.of("/escape.conf","x"));
        refused(Map.of("A.conf","a","folder/A.conf","b"));
        refused(Map.of("A.conf","x".repeat(65537)));
        refused(Map.of("README.txt","none"));
        Map<String,String> many = new LinkedHashMap<>(); for (int n = 0; n < 257; n++) many.put("t"+n+".txt","x"); refused(many);
        refused(Map.of("A.conf","a","VPN013-Access.json","{}","sub/VPN013-Access.json","{}"));
        check(ArchiveReader.read(zip(Map.of("Дом.conf","ordinary"))).profiles().get(0).name().equals("Дом"));
        check(ArchiveReader.subscription(zip(Map.of("Android/Подписка.txt", "https://example.invalid/sub/example\n", "iPhone/Подписка.txt", "https://example.invalid/sub/example\n", "README.txt", "instructions"))).equals("https://example.invalid/sub/example"));
        check("INCY".equals(ArchiveReader.ownerSection(zip(Map.of("Android/Инструкция.txt","Профиль · INCY · Android\n", "iPhone/Инструкция.txt","Профиль · INCY · iPhone\n")))));
        check(ArchiveReader.ownerSection(zip(Map.of("Android/Инструкция.txt","Профиль · INCY · Android\n", "iPhone/Инструкция.txt","Профиль · Happ · iPhone\n"))) == null);
        check(ArchiveReader.ownerSection(zip(Map.of("README.txt","no label"))) == null);
        for (Map<String,String> files : List.of(Map.of("Android/Подписка.txt","a","iPhone/Подписка.txt","b"), Map.of("../Подписка.txt","a"), Map.of("README.txt","none"))) {
            try { ArchiveReader.subscription(zip(files)); throw new AssertionError("Unsafe subscription accepted"); } catch (IOException expected) { checks++; }
        }
        try { ArchiveReader.bounded(new ByteArrayInputStream(new byte[9]),8); throw new AssertionError(); } catch (IOException expected) { checks++; }
        System.out.println("Android archive checks passed: " + checks);
    }
}
