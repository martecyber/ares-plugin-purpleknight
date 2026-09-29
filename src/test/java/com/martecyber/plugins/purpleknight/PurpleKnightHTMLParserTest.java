package com.martecyber.plugins.purpleknight;

import com.martecyber.ares.imports.ParseResult;
import com.martecyber.ares.imports.ParsedDetection;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/** Covers {@link PurpleKnightHTMLParser}'s heuristic table-row extraction: only rows containing
 *  a recognized fail/at-risk status word become detections, the longest non-status/non-severity
 *  cell is taken as the indicator name, and rows/cells that don't look like indicator data are
 *  silently ignored rather than failing the parse. */
class PurpleKnightHTMLParserTest {

    private final PurpleKnightHTMLParser parser = new PurpleKnightHTMLParser();

    private ParseResult parse(String html) throws Exception {
        return parser.parse(html.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validateRequiresPurpleknightOrActiveDirectoryPlusIndicator() {
        assertTrue(parser.validate("<html>PurpleKnight Report</html>".getBytes(StandardCharsets.UTF_8)));
        assertTrue(parser.validate("<html>Active Directory Indicator results</html>".getBytes(StandardCharsets.UTF_8)));
        assertFalse(parser.validate("<html>Some other report</html>".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void extractsAFailedIndicatorRowWithItsSeverity() throws Exception {
        String html = "<table><tr>"
            + "<td>Trust Relationships</td>"
            + "<td>Weak Kerberos Encryption Types Allowed</td>"
            + "<td>Fail</td>"
            + "<td>High</td>"
            + "</tr></table>";
        ParseResult result = parse(html);

        assertEquals(1, result.getDetections().size());
        ParsedDetection d = result.getDetections().get(0);
        assertEquals("Weak Kerberos Encryption Types Allowed", d.getTitle());
        assertEquals("high", d.getSeverity());
        assertEquals("Status: Fail", d.getDescription());
        assertNull(d.getAssetIdentifier());
    }

    @Test
    void rowsWithoutARecognizedFailStatusWordAreIgnored() throws Exception {
        String html = "<table><tr>"
            + "<td>Trust Relationships</td>"
            + "<td>Some passing indicator name</td>"
            + "<td>Pass</td>"
            + "<td>High</td>"
            + "</tr></table>";
        assertTrue(parse(html).getDetections().isEmpty());
    }

    @Test
    void statusMatchIsCaseInsensitiveAndAcceptsAtRiskAndExposed() throws Exception {
        String html = "<table>"
            + "<tr><td>Cat</td><td>Indicator name one</td><td>FAILED</td><td>Low</td></tr>"
            + "<tr><td>Cat</td><td>Indicator name two</td><td>At Risk</td><td>Low</td></tr>"
            + "<tr><td>Cat</td><td>Indicator name three</td><td>exposed</td><td>Low</td></tr>"
            + "</table>";
        assertEquals(3, parse(html).getDetections().size());
    }

    @Test
    void htmlTagsInsideCellsAreStrippedFromTheExtractedText() throws Exception {
        String html = "<table><tr>"
            + "<td>Cat</td><td><b>Weak</b> <span>password policy detected</span></td>"
            + "<td>Fail</td><td>Medium</td>"
            + "</tr></table>";
        assertEquals("Weak password policy detected", parse(html).getDetections().get(0).getTitle());
    }

    @Test
    void missingSeverityCellDefaultsToMedium() throws Exception {
        String html = "<table><tr><td>Cat</td><td>Some failing indicator</td><td>Fail</td></tr></table>";
        assertEquals("medium", parse(html).getDetections().get(0).getSeverity());
    }

    @Test
    void reportWithNoMatchingRowsProducesAWarningInsteadOfAnEmptySilentResult() throws Exception {
        ParseResult result = parse("<html>PurpleKnight report with no table rows at all</html>");
        assertTrue(result.getDetections().isEmpty());
        assertFalse(result.getWarnings().isEmpty());
    }
}
