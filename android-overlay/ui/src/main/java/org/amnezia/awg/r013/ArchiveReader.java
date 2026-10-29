// SPDX-License-Identifier: MIT
package org.amnezia.awg.r013;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.*;

/** In-memory bounded ZIP reader; never extracts paths to the filesystem. */
public final class ArchiveReader {
    public record Item(String name, String text) { }
    public record Bundle(List<Item> profiles, String accessDocument) { }
    private record Candidate(Item item, int priority) { }
    public static byte[] bounded(InputStream in, int maximum) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(); byte[] buffer = new byte[8192];
        for (int count; (count = in.read(buffer)) != -1;) {
            if (out.size() + count > maximum) throw new IOException("Файл превышает допустимый размер");
            out.write(buffer, 0, count);
        }
        return out.toByteArray();
    }
    /** Owner ZIPs contain matching platform copies. Never extract archive paths. */
    public static String subscription(byte[] archive) throws IOException {
        if (archive.length > 8_388_608) throw new IOException("Архив слишком велик");
        String found = null; int count = 0, total = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive), StandardCharsets.UTF_8)) {
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null;) {
                if (++count > 256) throw new IOException("В архиве слишком много файлов");
                String path = entry.getName().replace('\\', '/');
                if (path.length() > 512 || path.startsWith("/") || Arrays.asList(path.split("/")).contains("..")) throw new IOException("Недопустимое имя файла");
                if (entry.isDirectory()) continue;
                byte[] data = bounded(zip, 1_048_576); total += data.length;
                if (total > 4_194_304) throw new IOException("Распакованный архив слишком велик");
                if (!path.substring(path.lastIndexOf('/') + 1).equals("Подписка.txt")) continue;
                String value;
                try { value = StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(data)).toString().trim(); }
                catch (java.nio.charset.CharacterCodingException e) { throw new IOException("Некорректный текст", e); }
                if (found != null && !found.equals(value)) throw new IOException("В архиве разные подписки");
                found = value;
            }
        }
        if (found == null || found.isEmpty()) throw new IOException("В архиве нет подписки");
        return found;
    }
    /** Identify only owner archives with consistent explicit platform labels. */
    public static String ownerSection(byte[] archive) throws IOException {
        if (archive.length > 8_388_608) throw new IOException("Архив слишком велик");
        String section = null; int count = 0, total = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive), StandardCharsets.UTF_8)) {
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null;) {
                if (++count > 256) throw new IOException("В архиве слишком много файлов");
                String path = entry.getName().replace('\\', '/');
                if (path.length() > 512 || path.startsWith("/") || Arrays.asList(path.split("/")).contains("..")) throw new IOException("Недопустимое имя файла");
                if (entry.isDirectory()) continue;
                byte[] data = bounded(zip, 1_048_576); total += data.length;
                if (total > 4_194_304) throw new IOException("Распакованный архив слишком велик");
                if (!path.substring(path.lastIndexOf('/') + 1).equals("Инструкция.txt")) continue;
                String text;
                try { text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(data)).toString(); }
                catch (java.nio.charset.CharacterCodingException e) { return null; }
                String[] parts = text.split("\\R",2)[0].split(" · ");
                if (parts.length < 3 || !Set.of("Android", "iPhone", "Windows").contains(parts[parts.length-1])) return null;
                String label = parts[parts.length-2].toUpperCase(Locale.ROOT);
                if (!Set.of("HAPP", "INCY", "BLACKTEMPLE", "AMNEZIAWG").contains(label)) return null;
                if (section != null && !section.equals(label)) return null;
                section = label;
            }
        }
        return section;
    }
    public static Bundle read(byte[] archive) throws IOException {
        if (archive.length > 8_388_608) throw new IOException("Архив слишком велик");
        Map<String, Candidate> selected = new LinkedHashMap<>();
        String access = null; int count = 0, total = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive), StandardCharsets.UTF_8)) {
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null;) {
                if (++count > 256) throw new IOException("В архиве слишком много файлов");
                String path = entry.getName().replace('\\', '/');
                if (path.length() > 512 || path.startsWith("/") || Arrays.asList(path.split("/")).contains(".."))
                    throw new IOException("Недопустимое имя файла в архиве");
                if (entry.isDirectory()) continue;
                String lower = path.toLowerCase(Locale.ROOT);
                String base = path.substring(path.lastIndexOf('/') + 1);
                boolean manifest = base.equalsIgnoreCase("VPN013-Access.json");
                boolean conf = lower.endsWith(".conf") && !lower.startsWith("__macosx/");
                byte[] bytes = bounded(zip, manifest ? 1_048_576 : conf ? 65_536 : 1_048_576);
                total += bytes.length;
                if (total > 4_194_304) throw new IOException("Распакованный архив слишком велик");
                if (manifest) {
                    if (access != null) throw new IOException("В архиве два документа заявки");
                    access = new String(bytes, StandardCharsets.UTF_8); continue;
                }
                if (!conf) continue;
                String name = base.substring(0, base.length() - 5);
                if (name.trim().isEmpty() || name.length() > 128) throw new IOException("Недопустимое имя профиля");
                String key = name.toLowerCase(Locale.ROOT);
                int priority = Arrays.asList(lower.split("/")).contains("android") ? 2 :
                    Arrays.asList(lower.split("/")).contains("iphone") || Arrays.asList(lower.split("/")).contains("ios") ? 0 : 1;
                Candidate existing = selected.get(key);
                if (existing != null && existing.priority == priority) throw new IOException("Повторяющееся имя профиля в архиве");
                if (existing == null || priority > existing.priority)
                    selected.put(key, new Candidate(new Item(name, new String(bytes, StandardCharsets.UTF_8)), priority));
            }
        }
        if (selected.isEmpty()) throw new IOException("В архиве нет конфигураций .conf");
        if (selected.size() > 300) throw new IOException("Слишком много конфигураций");
        return new Bundle(selected.values().stream().map(Candidate::item).collect(java.util.stream.Collectors.toList()), access);
    }
}
