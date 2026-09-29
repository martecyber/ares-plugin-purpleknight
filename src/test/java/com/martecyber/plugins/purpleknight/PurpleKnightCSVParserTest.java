package com.martecyber.plugins.purpleknight;

import com.martecyber.ares.assets.AssetType;
import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link PurpleKnightCSVParser}: pass/OK-status rows being skipped, header-driven column
 *  lookup (order-independent, case-insensitive), severity/tier mapping, and the placeholder
 *  "ad-directory" asset every detection gets backfilled onto. */
class PurpleKnightCSVParserTest {

    private final PurpleKnightCSVParser parser = new PurpleKnightCSVParser();

    private ParseResult parse(String csv) throws Exception {
        return parser.parse(csv.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresIndicatorOrProductNamePlusSeverityOrCategory() {
        assertTrue(parser.validate("Category,Indicator Name,Status,Severity\n".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("A,B,C\n".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void passAndOkStatusIndicatorsAreSkipped() throws Exception {
        String csv = "Category,Indicator Name,Status,Severity,Description,Remediation\n"
            + "AD,Some check,Pass,Medium,desc,rem\n"
            + "AD,Another check,ok,Low,desc,rem\n";
        assertTrue(parse(csv).getDetections().isEmpty());
    }

    @Test
    void failedIndicatorBecomesADetectionOnThePlaceholderDirectoryAsset() throws Exception {
        String csv = "Category,Indicator Name,Status,Severity,Description,Remediation\n"
            + "Trust Relationships,Weak Kerberos encryption,Fail,High,Uses RC4,Disable RC4\n";
        ParseResult result = parse(csv);

        assertTrue(result.getAssets().stream().anyMatch(a -> a.getType().equals(AssetType.DIRECTORY) && a.getIdentifier().equals("ad-directory")));
        ParsedDetection d = result.getDetections().get(0);
        assertEquals("Weak Kerberos encryption", d.getTitle());
        assertEquals("high", d.getSeverity());
        assertEquals("ad-directory", d.getAssetIdentifier());
        assertTrue(d.getDescription().contains("Category: Trust Relationships"));
        assertTrue(d.getDescription().contains("Status: Fail"));
        assertTrue(d.getDescription().contains("Uses RC4"));
        assertTrue(d.getDescription().contains("Remediation: Disable RC4"));
    }

    @Test
    void tierLabelsMapToTheSameSeverityAsTheirWordEquivalent() throws Exception {
        String csv = "Indicator,Status,Severity\n"
            + "Check A,Fail,Tier 0\n"
            + "Check B,Fail,Tier 2\n";
        var detections = parse(csv).getDetections();
        assertEquals("critical", detections.get(0).getSeverity());
        assertEquals("medium", detections.get(1).getSeverity());
    }

    @Test
    void missingSeverityDefaultsToMedium() throws Exception {
        String csv = "Indicator,Status\nCheck A,Fail\n";
        assertEquals("medium", parse(csv).getDetections().get(0).getSeverity());
    }

    @Test
    void columnLookupIsCaseInsensitiveAndOrderIndependent() throws Exception {
        // Same data, header columns in a different order than the "typical" layout the parser
        // documents — proves lookup is genuinely by name, not by fixed position.
        String csv = "STATUS,severity,Indicator Name\nFail,High,Weak password policy\n";
        ParsedDetection d = parse(csv).getDetections().get(0);
        assertEquals("Weak password policy", d.getTitle());
        assertEquals("high", d.getSeverity());
    }

    @Test
    void rowWithoutAnIndicatorNameIsSkipped() throws Exception {
        String csv = "Category,Status,Severity\nAD,Fail,High\n";
        assertTrue(parse(csv).getDetections().isEmpty());
    }

    @Test
    void emptyContentProducesNoDetectionsAndNoException() throws Exception {
        assertDoesNotThrow(() -> assertTrue(parse("").getDetections().isEmpty()));
    }
}
