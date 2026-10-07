package com.martecyber.plugins.purpleknight;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedAsset;
import com.martecyber.ares.imports.ParsedDetection;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Everything the CSV and HTML parsers share: one indicator's data, how it turns into a
 *  detection, severity/status mapping, and HTML-to-Markdown cleanup of PurpleKnight's prose. */
final class PurpleKnightSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    static final String FALLBACK_DIRECTORY = "ad-directory";
    /** Affected objects listed inline in a detection's description — the rest stay in raw data. */
    private static final int MAX_LISTED_OBJECTS = 50;
    private static final int MAX_RAW_OBJECTS = 500;

    private PurpleKnightSupport() {}

    /** One indicator's result, whichever export it came from. Absent fields are null/empty. */
    record Indicator(String shortName, String name, String severity, String status, String category,
                     String score, String grade, String description, String likelihood,
                     String resultMessage, String remediation, Map<String, List<String>> frameworks,
                     List<String> objects, int resultCount) {}

    /** Only indicators of exposure/compromise are findings. "Pass", "Not relevant", "Not
     *  selected" and "Failed to run" are not — the last one is reported as a warning instead.
     *  The legacy words are kept for older exports that used a plain fail/at-risk status. */
    static boolean isFinding(String status) {
        if (status == null) return false;
        String s = status.trim().toLowerCase(Locale.ROOT);
        return s.equals("ioe found") || s.equals("ioc found") || s.equals("ioefound") || s.equals("iocfound")
            || s.equals("ioe") || s.equals("ioc")
            || s.equals("fail") || s.equals("failed") || s.equals("at risk") || s.equals("exposed");
    }

    static boolean isFailedToRun(String status) {
        if (status == null) return false;
        String s = status.trim().toLowerCase(Locale.ROOT);
        return s.equals("failed to run") || s.equals("error");
    }

    static String mapSeverity(String s) {
        if (s == null) return "medium";
        return switch (s.trim().toLowerCase(Locale.ROOT)) {
            case "critical", "tier 0" -> "critical";
            case "high", "tier 1" -> "high";
            case "medium", "tier 2" -> "medium";
            case "low", "tier 3" -> "low";
            case "informational", "info", "information" -> "info";
            default -> "medium";
        };
    }

    /** Forest name PurpleKnight embeds in every export's file names, e.g.
     *  {@code Security_Assessment_Report_corp.local_2026_10_06_13_42_27_(SI000056)}. */
    private static final Pattern FOREST_IN_NAME =
        Pattern.compile("Security_Assessment_Report_(.+?)_\\d{4}_\\d{2}_\\d{2}_\\d{2}_\\d{2}_\\d{2}");

    static String forestFromReportName(String text) {
        if (text == null) return null;
        Matcher m = FOREST_IN_NAME.matcher(text);
        return m.find() ? m.group(1) : null;
    }

    static void addDirectory(ParseResult result, String forest) {
        result.addAsset(new ParsedAsset(directoryId(forest), AssetType.DIRECTORY,
            Map.of("source", "purpleknight")));
    }

    static String directoryId(String forest) {
        return forest == null || forest.isBlank() ? FALLBACK_DIRECTORY : forest.trim().toLowerCase(Locale.ROOT);
    }

    static ParsedDetection toDetection(Indicator ind, String forest) {
        String title = ind.name() != null ? ind.name() : ind.shortName();
        String templateId = ind.shortName() != null
            ? "pk-" + ind.shortName().toLowerCase(Locale.ROOT)
            : "pk-" + title.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-");
        if (templateId.length() > 200) templateId = templateId.substring(0, 200);

        StringBuilder d = new StringBuilder();
        if (ind.resultMessage() != null) d.append("**Result:** ").append(ind.resultMessage()).append("\n\n");
        StringBuilder meta = new StringBuilder();
        if (ind.shortName() != null) meta.append(ind.shortName());
        if (ind.category() != null) meta.append(meta.length() > 0 ? " · " : "").append(ind.category());
        if (ind.score() != null) meta.append(meta.length() > 0 ? " · " : "").append("score ").append(ind.score());
        if (ind.grade() != null) meta.append(" (").append(ind.grade()).append(")");
        if (meta.length() > 0) d.append(meta).append("\n\n");
        appendSection(d, null, ind.description());
        appendSection(d, "Likelihood of compromise", ind.likelihood());
        appendSection(d, "Remediation", ind.remediation());
        if (!ind.frameworks().isEmpty()) {
            d.append("**Security frameworks:**\n");
            ind.frameworks().forEach((name, tags) ->
                d.append("- ").append(name).append(": ").append(String.join(", ", tags)).append("\n"));
            d.append("\n");
        }
        if (!ind.objects().isEmpty()) {
            d.append("**Affected objects (").append(Math.max(ind.resultCount(), ind.objects().size())).append("):**\n");
            ind.objects().stream().limit(MAX_LISTED_OBJECTS).forEach(o -> d.append("- ").append(o).append("\n"));
            if (ind.objects().size() > MAX_LISTED_OBJECTS) {
                d.append("- … and ").append(ind.objects().size() - MAX_LISTED_OBJECTS).append(" more (see raw data)\n");
            }
        }

        Map<String, Object> raw = new LinkedHashMap<>();
        raw.put("shortName", ind.shortName());
        raw.put("status", ind.status());
        raw.put("category", ind.category());
        raw.put("score", ind.score());
        raw.put("grade", ind.grade());
        raw.put("resultMessage", ind.resultMessage());
        raw.put("frameworks", ind.frameworks());
        raw.put("objects", ind.objects().size() > MAX_RAW_OBJECTS
            ? ind.objects().subList(0, MAX_RAW_OBJECTS) : ind.objects());
        raw.put("resultCount", ind.resultCount());
        String rawJson;
        try { rawJson = MAPPER.writeValueAsString(raw); } catch (Exception e) { rawJson = "{}"; }

        return new ParsedDetection(title, mapSeverity(ind.severity()), d.toString().trim(),
            directoryId(forest), templateId, rawJson);
    }

    private static void appendSection(StringBuilder d, String heading, String body) {
        if (body == null || body.isBlank()) return;
        if (heading != null) d.append("**").append(heading).append(":** ");
        d.append(body.trim()).append("\n\n");
    }

    // ── HTML → Markdown ────────────────────────────────────────────────────────

    private static final Pattern LINK = Pattern.compile(
        "<a\\s[^>]*?href=\"([^\"]*)\"[^>]*>(.*?)</a>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern TAG = Pattern.compile("<[^>]+>");

    /** PurpleKnight's descriptions/remediations are small HTML fragments (p, ul/ol/li, b, code,
     *  a, br). Ares renders Markdown, so these are converted rather than stored as raw markup. */
    static String htmlToMarkdown(String html) {
        if (html == null) return null;
        String s = html.replace("\r", "");
        s = LINK.matcher(s).replaceAll(m -> Matcher.quoteReplacement("[" + TAG.matcher(m.group(2)).replaceAll("") + "](" + m.group(1) + ")"));
        s = s.replaceAll("(?i)<br\\s*/?>", "\n")
             .replaceAll("(?i)</p>|</div>|</ul>|</ol>", "\n\n")
             .replaceAll("(?i)<li[^>]*>", "\n- ")
             .replaceAll("(?i)</?(b|strong)>", "**")
             .replaceAll("(?i)</?code>", "`");
        s = TAG.matcher(s).replaceAll("");
        s = s.replace("&nbsp;", " ").replace("&lt;", "<").replace("&gt;", ">")
             .replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&");
        s = s.replaceAll("[ \\t]+\\n", "\n").replaceAll("\\n{3,}", "\n\n").trim();
        return s.isEmpty() ? null : s;
    }
}
