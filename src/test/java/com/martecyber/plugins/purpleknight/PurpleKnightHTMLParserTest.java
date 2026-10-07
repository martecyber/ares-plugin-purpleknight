package com.martecyber.plugins.purpleknight;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link PurpleKnightHTMLParser} against the shape of the real single-file report: the
 *  page is a bundled web app that embeds {@code window.reportJSON} plus one {@code
 *  window["Category_N"]["uuid"] = {...};} assignment per indicator — not an HTML table. */
class PurpleKnightHTMLParserTest {

    private final PurpleKnightHTMLParser parser = new PurpleKnightHTMLParser();

    private static String indicator(int category, String uuid, String shortName, String name, String exposure,
                                    boolean failedToRun, String severity, String objects) {
        return "window[\"Category_" + category + "\"][\"" + uuid + "\"] = {\n"
            + "  \"ResIndicator\": {\n"
            + "    \"State\": \"Completed\", \"Grade\": \"DMinus\", \"ExposureType\": \"" + exposure + "\",\n"
            + "    \"IsFailedToRun\": " + failedToRun + ", \"UUID\": \"" + uuid + "\", \"CategoryID\": " + category + ",\n"
            + "    \"ShortName\": \"" + shortName + "\", \"Name\": \"" + name + "\",\n"
            + "    \"Description\": \"<p>Checks <b>something</b> &amp; more.</p><ul><li>one</li><li>two</li></ul>\",\n"
            + "    \"Severity\": \"" + severity + "\",\n"
            + "    \"LikelihoodOfCompromise\": \"<p>Likely.</p>\",\n"
            + "    \"SecurityFrameworks\": [{\"Name\": \"MITRE ATT&CK\", \"Tags\": [\"Execution\", \"Lateral Movement\"]}]\n"
            + "  },\n"
            + "  \"ExecutionResult\": {\"Status\": \"Failed\", \"Score\": 46, \"ResultMessage\": \"Found 2 DCs.\",\n"
            + "    \"Remediation\": \"<p>Disable the <code>Spooler</code> service.</p>\"},\n"
            + "  \"IndicatorReportObjects\": " + objects + ",\n"
            + "  \"TotalResultsCount\": 2\n"
            + "}; \n";
    }

    private static String page(String... indicators) {
        return "<!DOCTYPE html><html><head>\n<script>\n window.reportJSON = {\n"
            + "  \"IndicatorsFiles\": [\"Category_1_Indicator_x.js\"],\n"
            + "  \"reportResultsList\": [{\"ForestName\": \"corp.example\"}],\n"
            + "  \"GeneralConfig\": {\"Categories\": [{\"ID\": 1, \"Name\": \"AD Delegation\"}, {\"ID\": 3, \"Name\": \"Domain Controllers\"}]},\n"
            + "  \"ReportName\": \"Security_Assessment_Report_06_10_2026_13_42_27\"\n"
            + "};\n</script>\n<script type=\"module\">var x=1;</script>\n"
            + "<script>\n window.reportJSON.GeneralConfig.Categories.map((c) => \"Category_\" + c.ID).forEach((n) => { window[n] = { } });"
            + String.join("", indicators) + "\n</script></head><body></body></html>";
    }

    private ParseResult parse(String html) throws Exception {
        return parser.parse(html.getBytes(StandardCharsets.UTF_8));
    }

    private static final String SPOOLER = indicator(3, "11111111-1111-1111-1111-111111111111", "SI000077",
        "Spooler remotely accessible", "IOE", false, "Critical",
        "[[\"HostName: DC01.corp.example\", \"Result: Spooler running\"], [\"HostName: DC02.corp.example\", \"Result: Spooler running\"]]");
    private static final String PASSING = indicator(1, "22222222-2222-2222-2222-222222222222", "SI000106",
        "Passing check", "None", false, "High", "null");
    private static final String BROKEN = indicator(1, "33333333-3333-3333-3333-333333333333", "SI000200",
        "Could not run", "None", true, "High", "null");

    @Test
    void validateRecognisesTheEmbeddedReportAndRejectsOtherHtml() {
        assertTrue(parser.validate(page(SPOOLER).getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("<html><body><table><tr><td>x</td></tr></table></body></html>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void onlyIndicatorsThatFoundSomethingBecomeDetections() throws Exception {
        ParseResult r = parse(page(PASSING, SPOOLER, BROKEN));

        assertEquals(1, r.getDetections().size());
        ParsedDetection d = r.getDetections().get(0);
        assertEquals("Spooler remotely accessible", d.getTitle());
        assertEquals("critical", d.getSeverity());
        assertEquals("pk-si000077", d.getSourceTemplateId());
        assertTrue(r.getWarnings().stream().anyMatch(w -> w.contains("failed to run")));
    }

    @Test
    void detectionsLandOnTheDirectoryNamedAfterTheForest() throws Exception {
        ParseResult r = parse(page(SPOOLER));

        assertEquals("corp.example", r.getDetections().get(0).getAssetIdentifier());
        assertTrue(r.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DIRECTORY) && a.getIdentifier().equals("corp.example")));
    }

    @Test
    void descriptionCarriesResultRemediationFrameworksAndAffectedObjectsAsMarkdown() throws Exception {
        String desc = parse(page(SPOOLER)).getDetections().get(0).getDescription();

        assertTrue(desc.contains("**Result:** Found 2 DCs."));
        assertTrue(desc.contains("Domain Controllers"), "category name comes from the report's own GeneralConfig");
        assertTrue(desc.contains("**something** & more."), "bold + entity decoded");
        assertTrue(desc.contains("- one") && desc.contains("- two"), "list items become Markdown bullets");
        assertTrue(desc.contains("Disable the `Spooler` service."));
        assertTrue(desc.contains("MITRE ATT&CK: Execution, Lateral Movement"));
        assertTrue(desc.contains("- HostName: DC01.corp.example | Result: Spooler running"));
        assertFalse(desc.contains("<p>") || desc.contains("<li>"));
    }

    @Test
    void aReportWithNothingToReportWarnsInsteadOfFailing() throws Exception {
        ParseResult r = parse(page(PASSING));
        assertTrue(r.getDetections().isEmpty());
        assertFalse(r.getWarnings().isEmpty());
    }

    @Test
    void aMalformedIndicatorBlockIsSkippedWithoutLosingTheRest() throws Exception {
        String bad = "window[\"Category_1\"][\"44444444-4444-4444-4444-444444444444\"] = {not json}; \n";
        ParseResult r = parse(page(bad, SPOOLER));
        assertEquals(1, r.getDetections().size());
        assertTrue(r.getWarnings().stream().anyMatch(w -> w.contains("not valid JSON")));
    }
}
