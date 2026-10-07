package com.martecyber.plugins.purpleknight;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link PurpleKnightCSVParser} against the real "Indicators results" export shape:
 *  only "IOE Found"/"IOC Found" rows become detections, a quoted field may span lines, a UTF-8
 *  BOM is tolerated, the forest name comes from the Result column, and "Informational" is info. */
class PurpleKnightCSVParserTest {

    private static final String HEADER = "\"ShortName\",\"Name\",\"SI version\",\"Target\",\"Status\",\"Runtime\",\"Score\","
        + "\"Severity\",\"Weight\",\"Category\",\"MITRE ATT&CK_1\",\"MITRE ATT&CK_2\",\"ANSSI_1\",\"Description\","
        + "\"Likelihood of compromise\",\"Result message\",\"Number of results\",\"Result\",\"Remediation\"\r\n";

    private final PurpleKnightCSVParser parser = new PurpleKnightCSVParser();

    private static String row(String shortName, String name, String status, String severity, String desc, String objectsName) {
        return "\"" + shortName + "\",\"" + name + "\",\"1.0\",\"AD\",\"" + status + "\",\"00:00:01:00\",\"80\",\""
            + severity + "\",\"5\",\"Account Security\",\"Credential Access\",\"\",\"vuln1_x\",\"" + desc + "\",\"<p>Likely.</p>\","
            + "\"Found 2 objects.\",\"2\",\"Security_Assessment_Report_corp.example_2026_10_06_13_42_27_(" + objectsName + ")\","
            + "\"<p>Fix it.</p>\"\r\n";
    }

    private ParseResult parse(String csv) throws Exception {
        return parser.parse(csv.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRecognisesTheIndicatorsResultsHeaderOnly() {
        assertTrue(parser.validate((HEADER + row("SI000001", "A", "Pass", "High", "d", "SI000001")).getBytes(StandardCharsets.UTF_8)));
        assertTrue(parser.validate(("﻿" + HEADER).getBytes(StandardCharsets.UTF_8)));
        // The per-indicator affected-objects CSVs and the summary CSV are not indicator results.
        assertFalse(parser.validate("\"HostName\",\"ObjectGUID\",\"Result\",\"Ignored\"\r\n".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("\"Tool version\",\"5.1\"\r\n".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void onlyExposureFoundRowsBecomeDetections() throws Exception {
        String csv = HEADER
            + row("SI000001", "Fine check", "Pass", "High", "d", "SI000001")
            + row("SI000002", "Not applicable", "Not Relevant", "High", "d", "SI000002")
            + row("SI000003", "Not selected", "Not Selected", "High", "d", "SI000003")
            + row("SI000004", "Could not run", "Failed to Run", "High", "d", "SI000004")
            + row("SI000005", "Exposed thing", "IOE Found", "Critical", "d", "SI000005");
        ParseResult r = parse(csv);

        assertEquals(1, r.getDetections().size());
        ParsedDetection d = r.getDetections().get(0);
        assertEquals("Exposed thing", d.getTitle());
        assertEquals("critical", d.getSeverity());
        assertEquals("pk-si000005", d.getSourceTemplateId());
        assertTrue(r.getWarnings().stream().anyMatch(w -> w.contains("failed to run")));
    }

    @Test
    void detectionLandsOnTheDirectoryNamedAfterTheForestInTheResultColumn() throws Exception {
        ParseResult r = parse(HEADER + row("SI000005", "Exposed thing", "IOE Found", "High", "d", "SI000005"));

        assertEquals("corp.example", r.getDetections().get(0).getAssetIdentifier());
        assertTrue(r.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DIRECTORY) && a.getIdentifier().equals("corp.example")));
    }

    @Test
    void quotedFieldsMayContainNewlinesAndCommasWithoutShiftingColumns() throws Exception {
        String csv = HEADER + row("SI000005", "Exposed thing",
            "IOE Found", "High", "<p>First line,\nsecond line with a comma, and \"\"quotes\"\".</p>", "SI000005");
        ParsedDetection d = parse(csv).getDetections().get(0);

        assertEquals("high", d.getSeverity());
        assertTrue(d.getDescription().contains("second line with a comma"));
        assertTrue(d.getDescription().contains("Fix it."), "columns after the multi-line field must still line up");
        assertFalse(d.getDescription().contains("<p>"), "HTML is converted to Markdown");
    }

    @Test
    void informationalIsInfoAndBomOnTheFirstHeaderIsTolerated() throws Exception {
        String csv = "﻿" + HEADER + row("SI000005", "Exposed thing", "IOE Found", "Informational", "d", "SI000005");
        assertEquals("info", parse(csv).getDetections().get(0).getSeverity());
    }

    @Test
    void frameworkColumnsAreGroupedIntoTheDescription() throws Exception {
        ParsedDetection d = parse(HEADER + row("SI000005", "Exposed thing", "IOE Found", "High", "d", "SI000005")).getDetections().get(0);
        assertTrue(d.getDescription().contains("MITRE ATT&CK: Credential Access"));
        assertTrue(d.getDescription().contains("ANSSI: vuln1_x"));
    }

    @Test
    void emptyContentProducesNothingAndDoesNotThrow() throws Exception {
        assertTrue(parse("").getDetections().isEmpty());
    }
}
