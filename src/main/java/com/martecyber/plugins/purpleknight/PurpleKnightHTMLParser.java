package com.martecyber.plugins.purpleknight;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.imports.ImportParser;
import com.martecyber.ares.imports.ParseResult;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for PurpleKnight's single-file HTML report. The page is a bundled web app, not a
 * table: every indicator's result is embedded as JSON in an inline script, one assignment per
 * indicator ({@code window["Category_1"]["<uuid>"] = {...};}), next to a {@code
 * window.reportJSON} summary holding the forest name. Both are read as JSON — nothing here
 * depends on the report's visual layout.
 */
@Component
public class PurpleKnightHTMLParser implements ImportParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern INDICATOR_ASSIGNMENT =
        Pattern.compile("window\\[\"Category_\\d+\"\\]\\[\"[0-9a-fA-F-]{36}\"\\]\\s*=\\s*");
    private static final String REPORT_JSON = "window.reportJSON";

    @Override public String getToolId() { return "purpleknight"; }
    @Override public String getFormatId() { return "html"; }
    @Override public String getDisplayName() { return "PurpleKnight HTML report"; }
    @Override public String[] getSupportedExtensions() { return new String[]{".html", ".htm"}; }

    @Override
    public boolean validate(byte[] content) {
        String s = new String(content, StandardCharsets.UTF_8);
        return s.contains(REPORT_JSON) && INDICATOR_ASSIGNMENT.matcher(s).find();
    }

    @Override
    public ParseResult parse(byte[] content) throws Exception {
        ParseResult result = new ParseResult();
        char[] text = new String(content, StandardCharsets.UTF_8).toCharArray();
        String html = new String(text);

        JsonNode summary = readSummary(text, html);
        String forest = readForest(summary, html);
        Map<Integer, String> categories = readCategories(summary);
        int notRun = 0;
        Matcher m = INDICATOR_ASSIGNMENT.matcher(html);
        while (m.find()) {
            JsonNode node = readJsonAt(text, m.end());
            if (node == null) { result.addWarning("Skipped an indicator block that is not valid JSON."); continue; }
            JsonNode ri = node.path("ResIndicator");
            JsonNode exec = node.path("ExecutionResult");

            if (ri.path("IsFailedToRun").asBoolean(false)) { notRun++; continue; }
            // ExposureType is "IOE"/"IOC" only for indicators that found something.
            String exposure = ri.path("ExposureType").asText("None");
            if (!"IOE".equalsIgnoreCase(exposure) && !"IOC".equalsIgnoreCase(exposure)) continue;

            List<String> objects = new ArrayList<>();
            for (JsonNode obj : node.path("IndicatorReportObjects")) objects.add(describeObject(obj));

            Map<String, List<String>> frameworks = new LinkedHashMap<>();
            for (JsonNode fw : ri.path("SecurityFrameworks")) {
                List<String> tags = new ArrayList<>();
                fw.path("Tags").forEach(t -> tags.add(t.asText()));
                if (!tags.isEmpty()) frameworks.put(fw.path("Name").asText(), tags);
            }

            result.addDetection(PurpleKnightSupport.toDetection(new PurpleKnightSupport.Indicator(
                text(ri, "ShortName"), text(ri, "Name"), text(ri, "Severity"), exposure,
                categories.get(ri.path("CategoryID").asInt(0)), text(exec, "Score"), text(ri, "Grade"),
                PurpleKnightSupport.htmlToMarkdown(text(ri, "Description")),
                PurpleKnightSupport.htmlToMarkdown(text(ri, "LikelihoodOfCompromise")),
                text(exec, "ResultMessage"),
                PurpleKnightSupport.htmlToMarkdown(text(exec, "Remediation")),
                frameworks, objects, node.path("TotalResultsCount").asInt(objects.size())), forest));
        }

        if (notRun > 0) result.addWarning(notRun + " indicator(s) failed to run in PurpleKnight and were skipped.");
        if (result.getDetections().isEmpty()) {
            result.addWarning("No indicators of exposure/compromise found in this report.");
        } else {
            PurpleKnightSupport.addDirectory(result, forest);
        }
        return result;
    }

    /** The {@code window.reportJSON} summary object, or null if absent/unreadable. */
    private static JsonNode readSummary(char[] text, String html) {
        int at = html.indexOf(REPORT_JSON);
        int brace = at >= 0 ? html.indexOf('{', at) : -1;
        return brace >= 0 ? readJsonAt(text, brace) : null;
    }

    private static String readForest(JsonNode summary, String html) {
        if (summary != null) {
            String forest = summary.path("reportResultsList").path(0).path("ForestName").asText(null);
            if (forest != null && !forest.isBlank()) return forest;
            String fromName = PurpleKnightSupport.forestFromReportName(summary.path("ReportName").asText(null));
            if (fromName != null) return fromName;
        }
        return PurpleKnightSupport.forestFromReportName(html.length() > 20_000 ? html.substring(0, 20_000) : html);
    }

    /** Category id -> name, from the report's own {@code GeneralConfig.Categories}. */
    private static Map<Integer, String> readCategories(JsonNode summary) {
        Map<Integer, String> names = new LinkedHashMap<>();
        if (summary != null) {
            for (JsonNode c : summary.path("GeneralConfig").path("Categories")) {
                names.put(c.path("ID").asInt(), c.path("Name").asText());
            }
        }
        return names;
    }

    /** Reads exactly one JSON value starting at {@code offset} and ignores whatever follows
     *  (the trailing {@code ;} and the next assignment) — without copying the 4 MB page. */
    private static JsonNode readJsonAt(char[] text, int offset) {
        try (JsonParser p = MAPPER.getFactory().createParser(text, offset, text.length - offset)) {
            return MAPPER.readTree(p);
        } catch (Exception e) {
            return null;
        }
    }

    /** One affected object arrives as a list of {@code "Key: value"} strings (or, defensively,
     *  a plain string / object) — rendered on one line. */
    private static String describeObject(JsonNode obj) {
        if (obj.isArray()) {
            List<String> parts = new ArrayList<>();
            obj.forEach(v -> { if (!"Ignored: False".equals(v.asText())) parts.add(v.asText()); });
            return String.join(" | ", parts);
        }
        if (obj.isObject()) {
            List<String> parts = new ArrayList<>();
            obj.fields().forEachRemaining(e -> parts.add(e.getKey() + ": " + e.getValue().asText()));
            return String.join(" | ", parts);
        }
        return obj.asText();
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.path(field);
        if (v.isMissingNode() || v.isNull()) return null;
        String s = v.asText();
        return s.isBlank() ? null : s;
    }
}
