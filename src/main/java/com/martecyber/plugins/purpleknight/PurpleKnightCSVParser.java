package com.martecyber.plugins.purpleknight;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Parser for PurpleKnight CSV export.
 * Typical columns: Category, Indicator Name, Status, Score, Severity, Description, Remediation
 */
@Component
public class PurpleKnightCSVParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override public String getToolId() { return "purpleknight"; }
    @Override public String getFormatId() { return "csv"; }
    @Override public String getDisplayName() { return "PurpleKnight CSV"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".csv"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8).toLowerCase();
        return (s.contains("indicator") || s.contains("purpleknight")) &&
               (s.contains("severity") || s.contains("category"));
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(content), StandardCharsets.UTF_8))) {
            String headerLine = br.readLine();
            if (headerLine == null) return result;
            String[] headers = parseCsvLine(headerLine);
            Map<String, Integer> colIndex = indexHeaders(headers);

            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] cols = parseCsvLine(line);

                String category = get(cols, colIndex, "category");
                String name = get(cols, colIndex, "indicator name");
                if (name == null) name = get(cols, colIndex, "indicator");
                if (name == null) name = get(cols, colIndex, "name");
                String status = get(cols, colIndex, "status");
                String severity = get(cols, colIndex, "severity");
                String description = get(cols, colIndex, "description");
                String remediation = get(cols, colIndex, "remediation");

                // Only import failed/at-risk indicators
                if (status != null && (status.equalsIgnoreCase("pass") || status.equalsIgnoreCase("ok"))) continue;
                if (name == null) continue;

                String sev = mapSeverity(severity);
                StringBuilder desc = new StringBuilder();
                if (category != null) desc.append("Category: ").append(category).append("\n");
                if (status != null) desc.append("Status: ").append(status).append("\n");
                if (description != null && !description.isBlank()) desc.append("\n").append(description);
                if (remediation != null && !remediation.isBlank()) desc.append("\n\nRemediation: ").append(remediation);

                String templateId = "pk-" + name.toLowerCase().replaceAll("[^a-z0-9]+", "-");
                if (templateId.length() > 200) templateId = templateId.substring(0, 200);

                String raw;
                try {
                    Map<String, Object> rawMap = new LinkedHashMap<>();
                    for (Map.Entry<String, Integer> h : colIndex.entrySet()) {
                        if (h.getValue() < cols.length) rawMap.put(h.getKey(), cols[h.getValue()]);
                    }
                    raw = MAPPER.writeValueAsString(rawMap);
                } catch (Exception e) { raw = "{}"; }

                result.addDetection(new ParsedDetection(name, sev, desc.toString().trim(), null, templateId, raw));
            }
        }
        // PurpleKnight scans Active Directory — emit a placeholder directory asset
        // so that detections can be associated. Analysts should update the identifier
        // to match the actual AD domain (e.g., corp.local).
        result.addAsset(new ParsedAsset("ad-directory", AssetType.DIRECTORY,
            Map.of("source", "purpleknight")));
        result.getDetections().stream()
            .filter(d -> d.getAssetIdentifier() == null)
            .forEach(d -> d.setAssetIdentifier("ad-directory"));
        return result;
    }

    private String mapSeverity(String s) {
        if (s == null) return "medium";
        return switch (s.toLowerCase()) {
            case "critical", "tier 0" -> "critical";
            case "high", "tier 1" -> "high";
            case "medium", "tier 2" -> "medium";
            case "low", "tier 3" -> "low";
            default -> "medium";
        };
    }

    private Map<String, Integer> indexHeaders(String[] headers) {
        Map<String, Integer> idx = new LinkedHashMap<>();
        for (int i = 0; i < headers.length; i++) idx.put(headers[i].trim().toLowerCase(), i);
        return idx;
    }

    private String get(String[] cols, Map<String, Integer> idx, String key) {
        Integer i = idx.get(key);
        if (i == null || i >= cols.length) return null;
        String v = cols[i].trim();
        return v.isEmpty() ? null : v;
    }

    private String[] parseCsvLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') { current.append('"'); i++; }
                else inQuotes = !inQuotes;
            } else if (c == ',' && !inQuotes) {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        fields.add(current.toString());
        return fields.toArray(new String[0]);
    }
}
