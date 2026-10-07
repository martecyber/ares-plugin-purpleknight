package com.martecyber.plugins.purpleknight;

import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.parsers.ScannerParserUtils;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Parser for PurpleKnight's "Indicators results" CSV export — the one with a row per indicator
 * ({@code ShortName, Name, Status, Severity, Category, Description, Result message, ...}).
 * The per-indicator CSVs PurpleKnight also writes (affected objects, one file per indicator)
 * carry no indicator id inside the file, so they can't be matched back to an indicator here —
 * the HTML report embeds those objects and is the complete source.
 */
@Component
public class PurpleKnightCSVParser implements ImportParser {

    @Override public String getToolId() { return "purpleknight"; }
    @Override public String getFormatId() { return "csv"; }
    @Override public String getDisplayName() { return "PurpleKnight CSV (Indicators results)"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".csv"}; }

    @Override
    public boolean validate(byte[] content) {
        List<String[]> rows = ScannerParserUtils.parseCsv(firstBytes(content));
        if (rows.isEmpty()) return false;
        Map<String, Integer> idx = indexHeaders(rows.get(0));
        return idx.containsKey("shortname") && idx.containsKey("status") && idx.containsKey("severity");
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        List<String[]> rows = ScannerParserUtils.parseCsv(content);
        if (rows.isEmpty()) return result;
        Map<String, Integer> idx = indexHeaders(rows.get(0));

        String forest = null;
        int notRun = 0;
        for (String[] cols : rows.subList(1, rows.size())) {
            String status = get(cols, idx, "status");
            if (forest == null) forest = PurpleKnightSupport.forestFromReportName(get(cols, idx, "result"));
            if (PurpleKnightSupport.isFailedToRun(status)) { notRun++; continue; }
            if (!PurpleKnightSupport.isFinding(status)) continue;

            String name = get(cols, idx, "name");
            String shortName = get(cols, idx, "shortname");
            if (name == null && shortName == null) continue;

            Map<String, List<String>> frameworks = new LinkedHashMap<>();
            for (Map.Entry<String, Integer> h : idx.entrySet()) {
                String key = h.getKey();
                int us = key.lastIndexOf('_');
                if (us <= 0 || !key.substring(us + 1).chars().allMatch(Character::isDigit)) continue;
                String tag = get(cols, idx, key);
                if (tag != null) frameworks.computeIfAbsent(frameworkName(rows.get(0)[h.getValue()]), k -> new ArrayList<>()).add(tag);
            }

            int count = 0;
            try { String n = get(cols, idx, "number of results"); if (n != null) count = Integer.parseInt(n.trim()); }
            catch (NumberFormatException ignored) { /* leave 0 */ }

            result.addDetection(PurpleKnightSupport.toDetection(new PurpleKnightSupport.Indicator(
                shortName, name, get(cols, idx, "severity"), status, get(cols, idx, "category"),
                get(cols, idx, "score"), null,
                PurpleKnightSupport.htmlToMarkdown(get(cols, idx, "description")),
                PurpleKnightSupport.htmlToMarkdown(get(cols, idx, "likelihood of compromise")),
                get(cols, idx, "result message"),
                PurpleKnightSupport.htmlToMarkdown(get(cols, idx, "remediation")),
                frameworks, List.of(), count), forest));
        }

        if (notRun > 0) result.addWarning(notRun + " indicator(s) failed to run in PurpleKnight and were skipped.");
        if (result.getDetections().isEmpty()) {
            result.addWarning("No indicators of exposure/compromise found (status \"IOE Found\"/\"IOC Found\").");
        } else {
            PurpleKnightSupport.addDirectory(result, forest);
        }
        return result;
    }

    /** Column header minus its trailing "_N" index: "MITRE ATT&amp;CK_2" -> "MITRE ATT&amp;CK". */
    private static String frameworkName(String header) {
        int us = header.lastIndexOf('_');
        return us > 0 ? header.substring(0, us).trim() : header.trim();
    }

    /** Headers are the first record only — enough to recognise the file without tokenizing
     *  megabytes of rows twice. A header row can't contain quoted newlines. */
    private static byte[] firstBytes(byte[] content) {
        int end = 0;
        while (end < content.length && content[end] != '\n') end++;
        return java.util.Arrays.copyOf(content, Math.min(end + 1, content.length));
    }

    private static Map<String, Integer> indexHeaders(String[] headers) {
        Map<String, Integer> idx = new LinkedHashMap<>();
        for (int i = 0; i < headers.length; i++) {
            String h = headers[i];
            if (i == 0 && h.startsWith("﻿")) h = h.substring(1); // UTF-8 BOM from Excel-style exports
            idx.put(h.trim().toLowerCase(Locale.ROOT), i);
        }
        return idx;
    }

    private static String get(String[] cols, Map<String, Integer> idx, String key) {
        Integer i = idx.get(key);
        if (i == null || i >= cols.length) return null;
        String v = cols[i].trim();
        return v.isEmpty() ? null : v;
    }
}
