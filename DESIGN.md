# UN Extractor Architecture & Design

This document explains the architecture, design decisions, and limitations of the `un-extractor` tool.

## Overview

UN Extractor is a tool for parsing United Nations General Assembly meeting records from PDF documents converted to XML. It extracts structured data (session info, agenda items, speaker statements) and outputs JSON.

## Data Flow

```
PDF File
  ↓
pdftohtml -xml
  ↓
XML File (pdftoxml.xml)
  ↓
un-extractor
  ↓
JSON Report
```

## Architecture

### 1. Input Format: XML from pdftohtml

PDFs are converted using `pdftohtml -xml`, which:
- Preserves document layout via position attributes (`left`, `top`, `width`, `height`)
- Marks text formatting (bold `<b>`, italic `<i>`) as XML tags
- Maintains page structure with `<page>` and `<text>` elements

Example XML structure:
```xml
<document>
  <page number="1">
    <text top="100" left="90" width="200" height="14">
      <b>Session Name</b>
    </text>
  </page>
</document>
```

### 2. Extraction Strategy

The `Extractor` class uses a multi-stage extraction process:

#### Stage 1: Header Extraction (Session Info)
- Uses XPath with EXSLT regex to find session name
- Locates text elements containing "session" keyword
- Extracts meeting number from following bold elements
- Extracts meeting date from subsequent text

**Key Challenge:** Session info may be formatted inconsistently across different document variations.

#### Stage 2: Agenda Item Detection
Identifies agenda items by matching bold text against the regex pattern:
```
\s*Items? \d+ of the provisional agenda\.\s* |
Agenda items? \d+ |
Address by ...
```

For each agenda item:
- Extracts item number(s) from the marker text
- Builds item title from following text elements
- Recursively processes speaker statements

#### Stage 3: Speaker Statement Extraction
For each agenda item:
1. Iterates through following `<b>` (bold) text elements
2. Checks left margin position to identify speaker statements
3. Matches speaker name against regex pattern:
   ```
   <b>(?P<name>.*?)</b> (\((?P<state>.*?)\))? (<i>spoke in (?P<language>.*?)</i>)?:
   ```
4. If pattern matches: extracts name, state, language
5. If pattern doesn't match: uses raw text as speaker name
6. Extracts following paragraphs from speaker statement

#### Stage 4: Paragraph Extraction
For each speaker statement:
- Collects consecutive text elements at left margin (positions 90, 52)
- Breaks paragraphs on empty lines or indent changes
- Handles quoted/indented paragraphs separately
- Continues across page boundaries when needed

### 3. Layout Heuristics

The extractor relies on document layout conventions with hard-coded margins:

| Constant | Value | Purpose |
|----------|-------|---------|
| `MARGIN_LEFT` | 126 | Normal paragraph left margin |
| `MARGIN_LEFT2` | 504 | Alternative left margin |
| `MARGIN_TOP` | 135 | Page header skip threshold |
| `MARGIN_BOTTOM` | 1080 | Page footer skip threshold |

**Note:** These values are specific to UN document formatting. Different document layouts may require adjustment.

### 4. Fallback: Regex Scanner

The `RegexScanner` class provides pattern matching for test scenarios and fallback detection. It identifies structural tokens like:
- Agenda items (`Agenda items? \d+`)
- Votes taken (`A recorded vote was taken`)
- Decisions (`It was so decided`)
- Meeting events (`The meeting was called to order at`)

## Data Structure

### Report (Output)

```python
Report = namedtuple("Report", ["header", "items"])

Report(
    header={
        "session_name": "Seventieth session",
        "meeting_number": "50",
        "meeting_date": "Wednesday, 30 September 2015, 10 a.m."
    },
    items=[
        {
            "header": {
                "title": "Agenda item title...",
                "items": [
                    {"item_nb": "45", "continued": False},
                    {"item_nb": "29", "continued": True}
                ]
            },
            "statements": [
                {
                    "speaker": {
                        "name": "Mr. Smith",
                        "state": "United States",
                        "language": "English"
                    },
                    "paragraphs": ["First paragraph...", "Second paragraph..."]
                },
                ...
            ]
        },
        ...
    ]
)
```

## Key Limitations

### 1. Layout Dependency
The extractor depends heavily on document layout conventions. Changes in PDF formatting can cause parsing failures:
- Wrong margins → misclassified statements
- Different bold usage → unrecognized speakers
- Layout variations → missed content

### 2. Fragility
- Hard-coded margin values only work for standard UN documents
- Speaker name detection relies on specific regex patterns
- Missing fallbacks for non-standard formatting

### 3. PDF Quality Issues
- Poor OCR quality → corrupted text
- Scanned documents → layout detection failures
- Color PDFs converted → formatting information loss

### 4. Language & Scripts
- Some UN documents use non-Latin scripts
- Code point handling may differ by system
- Text normalization needed for consistent output

## Design Trade-offs

### Why XPath over Simpler Parsing?
- **Pro:** Structured queries resistant to whitespace variations
- **Con:** Requires EXSLT regex support (handled via lxml)
- **Decision:** Chosen for reliability over complexity

### Why Not Use Text File Input?
- **Pro:** Simpler format, no XML parsing needed
- **Con:** Layout indicators lost, fragile regex matching needed
- **Decision:** XML preserves structure necessary for reliable extraction

### Why Hard-Coded Margins?
- **Pro:** Simple, fast layout analysis
- **Con:** Not portable to different document formats
- **Alternative:** Dynamic margin detection via distribution analysis
- **Decision:** Current approach simpler; future enhancement possible

## Extending the Extractor

### Adding Support for New Document Variants

1. **Update Layout Margins:** Adjust `MARGIN_*` constants if needed
2. **Extend Agenda Pattern:** Add new regex patterns for agenda item detection
3. **Enhance Speaker Matching:** Modify speaker name regex for edge cases
4. **Add Validation Rules:** Extend `is_report_ok()` for new formats

### Improving Robustness

1. **Dynamic Margin Detection:** Analyze text position distribution to find margins
2. **Fallback Strategies:** Implement text-based parsing when XML fails
3. **Error Recovery:** Continue extraction even when parts fail
4. **Format Detection:** Auto-detect document type and adjust extraction

## Testing Strategy

The test suite includes:
- **Unit Tests:** Individual function behavior
- **Integration Tests:** End-to-end extraction on sample documents
- **Regex Tests:** Token scanner pattern matching

Test data in `tests/data/`:
- `N0553261.xml/.json` - Working example with full extraction
- `N0637121.xml/.json` - Alternative format example
- `minimal.xml` - Minimal structure for edge cases

## Future Improvements

1. Support for multiple input formats (text, PDF directly)
2. Dynamic layout detection instead of hard-coded margins
3. Language-aware text normalization
4. Parallel processing for batch document extraction
5. Incremental extraction and caching
6. Better error messages with document coordinates
