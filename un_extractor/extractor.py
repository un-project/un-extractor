"""Extractor module for parsing UN General Assembly records.

This module provides tools to parse XML files converted from PDF documents
containing United Nations General Assembly meeting records. It extracts
structured data including session information, agenda items, speaker statements,
and related metadata, converting them to JSON format.

The extraction process uses:
- XPath queries for structured XML data extraction
- Regular expressions for fallback pattern matching and text cleaning
- Layout-based heuristics (margins and positioning) to identify document sections

Note: The original code was designed for UN plaintext dumps and relies on
hard-coded page margins and XPath queries, making it inherently brittle.
It works best with XML converted from PDFs using pdftohtml.
"""

import collections
import json
import logging
import lxml.etree
import re
from typing import Iterator, List

logger = logging.getLogger("un-extractor")

# Prefer rich for colourful, readable logs; fallback gracefully if unavailable.
# we configure a basic formatter because RichHandler only formats the message
# part by default.
try:
    from rich.logging import RichHandler

    logging.basicConfig(
        level="DEBUG",
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )
except ImportError:  # pragma: no cover - optional dependency
    # fall back to plain logging
    logging.basicConfig(level="DEBUG")

Report = collections.namedtuple("Report", ["header", "items"])

MARGIN_TOP = 135
MARGIN_BOTTOM = 1080
MARGIN_LEFT = 126
MARGIN_LEFT2 = 504


def parse_votes(text: str) -> List[str]:
    """Split a comma‑separated vote list and normalise whitespace.

    Example::

        >>> parse_votes("yes, no, abstain")
        ['yes', 'no', 'abstain']
    """
    votes = [" ".join(v.split()) for v in text.strip().split(",") if len(v.strip()) > 0]
    return votes


def xpath_regex(
    element: lxml.etree._Element, expression: str
) -> Iterator[lxml.etree._Element]:
    """Helper generator which runs an XPath expression including regular
    expressions.

    The EXSLT namespace is required for ``re:match``.

    The namespace URL is ``http://exslt.org/regular-expressions``.
    """
    for elem in element.xpath(
        expression, namespaces={"re": "http://exslt.org/regular-expressions"}
    ):
        yield elem


def read_paragraphs(elem, paragraphs, paragraph="", quoted=False):
    """Extract paragraph text from speaker statements in the XML.

    Processes text elements following a speaker marker, building paragraphs
    based on layout conventions (left margin positioning and spacing).
    Continues recursively across multiple pages if needed.

    Args:
        elem: Current `<text>` element to start processing from
        paragraphs: List to append extracted paragraph strings to
        paragraph: Accumulated paragraph text (used for recursion)
        quoted: Whether current text is in a quoted section
    """
    parent_elem = elem

    # initialize paragraph with first words after ":"
    if len(paragraph) == 0:
        paragraph = elem.xpath("string()")
        paragraph = paragraph[paragraph.find(":") + 1 : -1].strip()

    # parse the whole page until a <b> element is found
    for elem in xpath_regex(parent_elem, ".//following-sibling::text"):
        elem_top = int(elem.get("top"))
        elem_left = int(elem.get("left"))

        # ignore text in header and footer
        if elem_top < MARGIN_TOP or elem_top > MARGIN_BOTTOM:
            continue

        # if <b> element is found, save current paragraph and return
        if elem.find("b") is not None:
            if len(paragraph.strip()) > 0:
                logger.info("\t\tnew paragraph")
                logger.debug("\t\t%s" % paragraph.strip())
                paragraphs.append(paragraph.strip())
            return

        # skip empty element
        if elem.text is None or len(elem.text.strip()) == 0:
            continue

        # check whether a new paragraph is found
        if not quoted and (
            elem_left == MARGIN_LEFT or elem_left == MARGIN_LEFT2 or elem.text[0] == " "
        ):
            if len(paragraph.strip()) > 0:
                logger.info("\t\tnew paragraph")
                logger.debug("\t\t%s" % paragraph.strip())
                paragraphs.append(paragraph.strip())
            paragraph = elem.text.strip()
        elif elem_left == 162:
            # found a new quoted paragraph
            quoted = True
            if len(paragraph.strip()) > 0:
                logger.info("\t\tnew paragraph")
                logger.debug("\t\t%s" % paragraph.strip())
                paragraphs.append(paragraph.strip())
            paragraph = elem.text.strip()
        else:
            # same paragraph
            paragraph = " ".join([paragraph, elem.text.strip()])

    # move to the next page if any
    next_page = parent_elem.getparent().getnext()
    if next_page is not None:
        read_paragraphs(next_page.find("text"), paragraphs, paragraph, quoted)
    else:
        # last page, save current paragraph
        if len(paragraph.strip()) > 0:
            logger.info("\t\tnew paragraph")
            logger.debug("\t\t%s" % paragraph.strip())
            paragraphs.append(paragraph.strip())


def read_statements(elem, statements):
    """Extract speaker statements from the given element and its siblings.

    Processes text elements following an agenda item, identifying speaker
    statements and extracting their paragraphs. Handles both simple and
    split speaker names across multiple XML elements.

    Args:
        elem: Starting <b> element to process
        statements: List to append statement dictionaries to
    """
    parent_text = elem.getparent()

    elems = xpath_regex(parent_text, ".//following-sibling::text/b")
    while elem is not None:
        elem_left = int(elem.getparent().get("left"))
        if elem_left != MARGIN_LEFT and elem_left != MARGIN_LEFT2:
            elem_top = int(elem.getparent().get("top"))
            if elem_top < MARGIN_TOP or elem_top > MARGIN_BOTTOM:
                # skip page header
                try:
                    elem = next(elems)
                except StopIteration:
                    elem = None
                continue
            # found new agenda item
            return
        logger.info("\tnew speaker")
        logger.debug("\t%s" % elem.text.strip())
        match = re.search(
            r"""<b>(?P<name>.*?)\ ?<\/b>
            (\ *\((?P<state>.*?([\r\n].*?)??.*?)\))??
            (\ *\(?<i>spoke\ in\ (?P<language>.*?)<\/i>\))??:""",
            lxml.etree.tostring(elem.getparent()).decode("utf-8"),
            flags=re.UNICODE | re.VERBOSE,
        )
        if match is not None:
            statement = {
                "speaker": {
                    "name": match.group("name"),
                    "language": match.group("language"),
                    "state": match.group("state"),
                },
                "paragraphs": [],
            }
        else:
            statement = {
                "speaker": {"name": elem.text.strip(), "language": None, "state": None},
                "paragraphs": [],
            }
        read_paragraphs(elem.getparent(), statement["paragraphs"])
        statements.append(statement)
        try:
            elem = next(elems)
        except StopIteration:
            elem = None

    # move to the next page if any
    next_page = parent_text.getparent().getnext()
    while next_page is not None:
        next_b = next_page.find(".//b")
        if next_b is not None:
            read_statements(next_b, statements)
            break
        else:
            next_page = next_page.getnext()


class RegexScanner:
    """Lightweight, regexp-based tokenizer for UN document pattern matching.

    This scanner is used primarily for testing and fallback detection.
    It maintains a fixed set of regular expressions for identifying key
    structural elements in UN General Assembly records.

    The scanner yields ``(token, match)`` tuples in document order,
    allowing flexible processing of patterns as they appear in the text.

    Attributes:
        patterns: List of (pattern_string, token_name) tuples
        compiled patterns: Pre-compiled regex objects for performance

    Methods:
        scan_with_holes: Generate matching tokens across text with gaps
    """

    def __init__(self):
        # ordered by priority (earlier patterns are checked first during search)
        patterns = [
            (r"<b>Agenda items? \d+", "agenda_item"),
            (r"<b>Statement by the President</b>", "president_statement"),
            (r"<b>Programme of work</b>", "programme_of_work"),
            (r"<b>The (?:Acting )?President\b", "president_speaker"),
            (r"<i>A recorded vote was taken\.", "vote_open"),
            (r"<i>A vote was taken by secret ballot\.", "secret_vote_open"),
            (r"<i>In favour</i>:", "in_favour_open"),
            (r"<i>Against</i>:", "against_open"),
            (r"<i>Abstaining</i>:", "abstaining_open"),
            (
                r"<i>The amendment was rejected by .* votes to .*?,",
                "amendment_rejected",
            ),
            (r"<i>Draft resolution .* was adopted", "draft_resolution_adopted"),
            (r"<i>Draft resolution .* was rejected", "draft_resolution_rejected"),
            (r"<i>Draft decision .* was adopted", "draft_decision_adopted"),
            (r"<i>Draft decision .* was rejected", "draft_decision_rejected"),
            (r"<i>It was so decided", "decided"),
            (r"The meeting was adjourned at", "meeting_end"),
            (r"The meeting was called to order at", "meeting_begin"),
            (r"The meeting was suspended at", "meeting_suspended"),
        ]
        # compile regexes once, ignoring case and allowing DOT to match newlines
        self.patterns = [
            (token, re.compile(pat, re.IGNORECASE | re.UNICODE))
            for pat, token in patterns
        ]

    def scan_with_holes(self, text):
        """Yield `(token, match)` pairs for every substring that matches a
        known token pattern.  Matches are returned in left-to-right order.
        """
        matches = []
        for token, pat in self.patterns:
            for m in pat.finditer(text):
                matches.append((m.start(), token, m))
        for _, token, m in sorted(matches, key=lambda t: t[0]):
            yield token, m


class Extractor:
    """Main class responsible for parsing UN General Assembly XML records.

    Parses XML files converted from PDF documents containing United Nations
    General Assembly meeting records, extracting structured meeting information
    including session details, agenda items, and speaker statements.

    The extraction process uses a combination of:
    - XPath queries with EXSLT regex support for structured data
    - Regular expression pattern matching for fallback text extraction
    - Layout-based heuristics (positioning margins) to identify sections

    Attributes:
        scanner (RegexScanner): Fallback pattern matcher for token detection

    Public Methods:
        get_report(infile): Parse XML and return extracted Report
        is_report_ok(report): Validate extracted report structure
        validate(infile): Check XML validity for extraction

    Note:
        The class is inherently brittle due to reliance on document layout
        conventions. Best results with XML from pdftohtml -xml conversion.
    """

    ITEM_LOOKUP = 1
    ITEM_TITLE_LOOKUP = 2
    STATEMENT_LOOKUP = 3
    IN_FAVOUR_LOOKUP = 4
    AGAINST_LOOKUP = 5
    ABSTAINING_LOOKUP = 6

    SESSION_NAME_LINE = 5
    MEETING_NUMBER_LINE = 6
    MEETING_DATE_LINE = 8

    def __init__(self):
        self.state = self.ITEM_LOOKUP
        # legacy test helper
        self.scanner = RegexScanner()

    def is_report_ok(self, report: Report) -> bool:
        """Validate extracted report structure and content.

        Performs lightweight validation checking that:
        - Header contains required fields (session_name, meeting_number, meeting_date)
        - Report contains at least one agenda item
        - Header values match expected formats

        Args:
            report (Report): Named tuple with 'header' and 'items' fields

        Returns:
            bool: True if report structure is valid, False otherwise
        """
        if not report.header:
            logger.error("header is empty!")
            return False
        if not report.items:
            logger.error("report does not contain any item!")
            return False
        if "session_name" not in report.header:
            logger.error("header does not contain a 'session_name' item!")
            return False
        if "meeting_number" not in report.header:
            logger.error("header does not contain a 'meeting_number' item!")
            return False
        if "meeting_date" not in report.header:
            logger.error("header does not contain a 'meeting_date' item!")
            return False
        if not re.match(r"[\w-]+\ session", report.header["session_name"]):
            logger.error(
                "invalid value for 'session_name': %s", report.header["session_name"]
            )
            return False
        if not re.match(r"\d+", report.header["meeting_number"]):
            logger.error(
                "invalid value for 'meeting_number': %s",
                report.header["meeting_number"],
            )
            return False
        try:
            from dateutil.parser import parse  # type: ignore

            parse(report.header["meeting_date"])
        except ValueError as err:
            logger.error(
                "invalid value for 'meeting_date': '%s' (%s)",
                report.header["meeting_date"],
                format(err),
            )
            return False
        return True

    def validate(self, infile) -> bool:
        """Validate that the XML file has a valid structure for UN records.

        Returns:
            bool: True if the XML is valid for extraction, False otherwise.
        """
        try:
            xml = lxml.etree.parse(infile)
            logger.debug("XML parsed successfully")
        except lxml.etree.XMLSyntaxError as e:
            logger.error(f"XML syntax error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to parse XML: {e}")
            return False

        # Check for required elements
        has_session = list(
            xpath_regex(xml, r"(//text[re:match(text(),'\s*.* session\s*')])[1]")
        )
        if not has_session:
            logger.error("No session information found in document")
            return False

        # Check for agenda items
        agenda_re = (
            r"//text/b[re:match(text(),"
            r"'(\s*Items? \d+ of the provisional agenda\.\s*|"
            r"Agenda items? \d+|Address by .*)')]"
        )
        has_agenda = list(xpath_regex(xml, agenda_re))
        if not has_agenda:
            logger.warning("No agenda items found in document")

        logger.info("XML structure validation passed")
        return True

    def get_report(self, infile) -> Report:
        """Parse an XML file and extract UN General Assembly meeting report.

        Reads an XML document (typically converted from PDF using pdftohtml),
        extracts session information, agenda items, and speaker statements,
        returning a structured Report containing all extracted data.

        The extraction process:
        1. Parses XML and validates basic structure
        2. Extracts meeting header (session, number, date)
        3. Identifies and processes agenda items
        4. For each agenda item, extracts speaker statements and content
        5. Returns validated Report or raises ValueError on failure

        Args:
            infile: File-like object or path containing XML data

        Returns:
            Report: Named tuple with 'header' dict and 'items' list

        Raises:
            ValueError: If XML is invalid or required data cannot be extracted

        Example:
            >>> extractor = Extractor()
            >>> with open('meeting.xml') as f:
            ...     report = extractor.get_report(f)
            >>> print(report.header['meeting_number'])
        """
        report = Report(header={}, items=[])
        try:
            xml = lxml.etree.parse(infile)
        except lxml.etree.XMLSyntaxError as e:
            raise ValueError(f"Invalid XML syntax: {e}") from e
        except Exception as e:
            raise ValueError(f"Failed to parse XML file: {e}") from e

        item = {}
        # ``vote`` and ``statement`` variables were pre-declared in the
        # original code but never used; leave them out to satisfy linters.

        # find session name
        # look for the first text element containing the word "session" (case
        # insensitive); XPath needs the EXSLT regular-expression namespace
        try:
            header = next(
                xpath_regex(xml, r"(//text[re:match(text(),'\s*.* session\s*')])[1]")
            )
        except StopIteration:
            raise ValueError(
                "Could not find session information. Please ensure the XML was "
                "converted from a valid UN General Assembly record using pdftohtml."
            ) from None

        if header is not None:
            logger.info("session_name: %s" % header.text.strip())
            report.header["session_name"] = header.text.strip()

            # find meeting number
            try:
                # XPath pattern to find meeting number from following siblings
                meeting_number_pattern = (
                    r"(.//following-sibling::text/b[re:match(text(),"
                    r"'\s*\d+\s*')])[1]"
                )
                meeting_number = next(xpath_regex(header, meeting_number_pattern))
            except StopIteration:
                logger.warning("Could not find meeting number")
                meeting_number = None
            if meeting_number is not None:
                logger.info("meeting_number: %s" % meeting_number.text.strip())
                report.header["meeting_number"] = meeting_number.text.strip()

                # find meeting date
                try:
                    meeting_date = next(
                        xpath_regex(
                            meeting_number.getparent(),
                            "(.//following-sibling::text)[2]",
                        )
                    )
                except StopIteration:
                    logger.warning("Could not find meeting date")
                    meeting_date = None

                if meeting_date is not None and meeting_date.text is not None:
                    meeting_date = re.sub(
                        r"(\d.*?)\.(\d.*?)", r"\1:\2", meeting_date.text.strip()
                    )
                    logger.info("meeting_date: %s" % meeting_date)
                    report.header["meeting_date"] = meeting_date

        # find agenda items
        # the regular expression used to detect agenda items is long, so
        # construct it separately for readability and to avoid exceeding the
        # 88-character line limit enforced by flake8/black.
        agenda_re = (
            r"//text/b[re:match(text(),"
            r"'(\s*Items? \d+ of the provisional agenda\.\s*|"
            r"Agenda items? \d+|Address by .*)')]"
        )
        for agenda_item in xpath_regex(xml, agenda_re):
            logger.info("new agenda item")
            items = []

            # Extract item numbers and continued status from agenda marker text
            agenda_text = agenda_item.text
            # Also check following sibling text elements for continued indicator
            parent_elem = agenda_item.getparent()
            next_sibling = parent_elem.getnext()
            is_continued = False
            if next_sibling is not None:
                next_text = next_sibling.xpath("string()")
                if "continued" in next_text.lower():
                    is_continued = True

            # Extract item numbers from agenda text
            for iterator in re.finditer(
                r"(?P<item_nb>\d+)",
                agenda_text,
                flags=re.UNICODE,
            ):
                items.append(
                    {
                        "item_nb": iterator.group("item_nb"),
                        "continued": is_continued,
                    }
                )
            item = {"header": {"title": "", "items": items}, "statements": []}
            report.items.append(item)

            # find item titles
            parent_top = 0
            # write "Address by..."
            if agenda_item.text.startswith("Address by"):
                item["header"]["title"] += agenda_item.text  # type: ignore[index]

            # Skip the closing parenthesis ')' if it appears as a separate element
            # immediately after the agenda item marker
            first_title_elem = True
            for elem in xpath_regex(
                agenda_item.getparent(), ".//following-sibling::text/b"
            ):
                elem_left = int(elem.getparent().get("left"))
                elem_top = int(elem.getparent().get("top"))

                # Skip standalone closing parenthesis or continued marker
                elem_text = elem.text or ""
                if first_title_elem and elem_text.strip() in (")", "continued"):
                    first_title_elem = False
                    continue
                first_title_elem = False

                if (
                    elem_left == MARGIN_LEFT or elem_left == MARGIN_LEFT2
                ) and elem_top - parent_top > 18:
                    # found statement
                    logger.debug(item["header"]["title"])  # type: ignore[index]
                    read_statements(elem, item["statements"])  # type: ignore[index]
                    break
                item["header"]["title"] += elem.text  # type: ignore[index]
                parent_top = elem_top
                title_value = item["header"]["title"].strip()  # type: ignore[index]
                item["header"]["title"] = title_value  # type: ignore[index]
        return report

    def extract(self, infile, outfile) -> None:
        infile_name = getattr(infile, "name", "<input>")
        logger.info("extract report from '%s'" % infile_name)
        report = self.get_report(infile)

        logger.info("check if report is ok")
        if not self.is_report_ok(report):
            # validation errors are already logged inside is_report_ok
            raise ValueError("extracted report failed validation")

        outfile_name = getattr(outfile, "name", "<output>")
        logger.info("save report to '%s'" % outfile_name)
        json.dump(report._asdict(), outfile, indent=4)
