package com.martecyber.plugins.purpleknight;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for PurpleKnight HTML report.
 * Extracts failed indicators from the AD assessment report.
 */
@Component
public class PurpleKnightHTMLParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    // Match indicator rows: look for patterns with risk/severity text
    private static final Pattern INDICATOR_BLOCK = Pattern.compile(
        "<tr[^>]*>.*?</tr>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern TD_PATTERN = Pattern.compile(
        "<td[^>]*>(.*?)</td>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_TAG = Pattern.compile("<[^>]+>");
    private static final Pattern SEVERITY_SECTION = Pattern.compile(
        "(?:Tier\\s*[0-3]|Critical|High|Medium|Low)", Pattern.CASE_INSENSITIVE);

    @Override public String getToolId() { return "purpleknight"; }
    @Override public String getFormatId() { return "html"; }
    @Override public String getDisplayName() { return "PurpleKnight HTML"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".html", ".htm"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8).toLowerCase();
        return s.contains("purpleknight") || (s.contains("active directory") && s.contains("indicator"));
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        String html = new String(content, StandardCharsets.UTF_8);

        // Extract table rows
        Matcher rowMatcher = INDICATOR_BLOCK.matcher(html);
        while (rowMatcher.find()) {
            String row = rowMatcher.group();
            List<String> cells = extractCells(row);
            if (cells.size() < 2) continue;

            // Try to identify rows that look like indicator data
            // Common PK format: [Category] [Indicator Name] [Status] [Severity]
            String possibleStatus = cells.stream()
                .filter(c -> c.equalsIgnoreCase("fail") || c.equalsIgnoreCase("failed") ||
                             c.equalsIgnoreCase("at risk") || c.equalsIgnoreCase("exposed"))
                .findFirst().orElse(null);

            if (possibleStatus == null) continue; // Only failed indicators

            String name = findName(cells);
            if (name == null || name.length() < 5) continue;

            String severity = cells.stream()
                .filter(c -> SEVERITY_SECTION.matcher(c).matches())
                .findFirst().map(this::mapSeverity).orElse("medium");

            String templateId = "pk-" + name.toLowerCase().replaceAll("[^a-z0-9]+", "-");
            if (templateId.length() > 200) templateId = templateId.substring(0, 200);

            String raw;
            try { raw = MAPPER.writeValueAsString(Map.of("cells", cells)); }
            catch (Exception e) { raw = "{}"; }

            result.addDetection(new ParsedDetection(name, severity,
                "Status: " + possibleStatus, null, templateId, raw));
        }

        if (result.getDetections().isEmpty()) {
            result.addWarning("No failed indicators found. Verify the HTML report format.");
        }

        return result;
    }

    private List<String> extractCells(String row) {
        List<String> cells = new ArrayList<>();
        Matcher m = TD_PATTERN.matcher(row);
        while (m.find()) {
            String text = HTML_TAG.matcher(m.group(1)).replaceAll("").trim();
            if (!text.isEmpty()) cells.add(text);
        }
        return cells;
    }

    private String findName(List<String> cells) {
        // The name is typically the longest cell that is not a status or severity word
        return cells.stream()
            .filter(c -> c.length() > 10 && !SEVERITY_SECTION.matcher(c).matches()
                && !c.equalsIgnoreCase("fail") && !c.equalsIgnoreCase("failed")
                && !c.equalsIgnoreCase("pass") && !c.equalsIgnoreCase("at risk"))
            .max(Comparator.comparingInt(String::length))
            .orElse(null);
    }

    private String mapSeverity(String s) {
        if (s == null) return "medium";
        String lower = s.toLowerCase();
        if (lower.contains("critical") || lower.contains("tier 0")) return "critical";
        if (lower.contains("high") || lower.contains("tier 1")) return "high";
        if (lower.contains("medium") || lower.contains("tier 2")) return "medium";
        if (lower.contains("low") || lower.contains("tier 3")) return "low";
        return "medium";
    }
}
