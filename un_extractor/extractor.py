"""This is the extractor module.

This module parses XML files to extract a report in JSON format.
"""

import collections
import json
import logging
import lxml.etree
import re
import sys

logger = logging.getLogger("un-extractor")

# Initialize coloredlogs
import coloredlogs

coloredlogs.install(level="DEBUG")

Report = collections.namedtuple("Report", ["header", "items"])

MARGIN_TOP = 135
MARGIN_BOTTOM = 1080
MARGIN_LEFT = 126
MARGIN_LEFT2 = 504


def parse_votes(text):
    votes = [" ".join(v.split()) for v in text.strip().split(",") if len(v.strip()) > 0]
    return votes


def xpath_regex(element, expression):
    for elem in element.xpath(
        expression, namespaces={"re": "http://exslt.org/regular-expressions"}
    ):
        yield elem


def read_paragraphs(elem, paragraphs, paragraph="", quoted=False):
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


class Extractor:
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

    def is_report_ok(self, report):
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
            from dateutil.parser import parse

            parse(report.header["meeting_date"])
        except ValueError as err:
            logger.error(
                "invalid value for 'meeting_date': '%s' (%s)",
                report.header["meeting_date"],
                format(err),
            )
            return False
        return True

    def get_report(self, infile):
        report = Report(header={}, items=[])
        xml = lxml.etree.parse(infile)
        item = {}
        vote = {}
        statement = {}

        # find session name
        header = next(
            xpath_regex(xml, "(//text[re:match(text()," "'\s*.* session\s*')])[1]")
        )
        if header is not None:
            logger.info("session_name: %s" % header.text.strip())
            report.header["session_name"] = header.text.strip()

            # find meeting number
            meeting_number = next(
                xpath_regex(
                    header,
                    "(.//following-sibling::text/b[re:match(text(),"
                    "'\s*\d+\s*')])[1]",
                )
            )
            if meeting_number is not None:
                logger.info("meeting_number: %s" % meeting_number.text.strip())
                report.header["meeting_number"] = meeting_number.text.strip()

            # find meeting date
            meeting_date = next(
                xpath_regex(
                    meeting_number.getparent(), "(.//following-sibling::text)[2]"
                )
            )
            if meeting_date is not None and meeting_date.text is not None:
                meeting_date = re.sub(
                    r"(\d.*?)\.(\d.*?)", r"\1:\2", meeting_date.text.strip()
                )
                logger.info("meeting_date: %s" % meeting_date)
                report.header["meeting_date"] = meeting_date

        # find agenda items
        for agenda_item in xpath_regex(
            xml,
            "//text/b[re:match(text(),"
            "'(\s*Items? \d+ of the provisional agenda.\s*|Agenda items? \d+|Address by .*)')]",
        ):
            logger.info("new agenda item")
            items = []
            for iterator in re.finditer(
                r"""(?P<item_nb>\d+)
                    \ ?(<\/b>\ ?)?(?P<continued>
                    \(<i>continued<\/i>\))?""",
                agenda_item.text,
                flags=re.UNICODE | re.VERBOSE,
            ):
                items.append(
                    {
                        "item_nb": iterator.group("item_nb"),
                        "continued": True
                        if iterator.group("continued") is not None
                        else False,
                    }
                )
            item = {"header": {"title": "", "items": items}, "statements": []}
            report.items.append(item)

            # find item titles
            parent_top = 0
            # write "Address by..."
            if agenda_item.text.startswith("Address by"):
                item["header"]["title"] += agenda_item.text
            for elem in xpath_regex(
                agenda_item.getparent(), ".//following-sibling::text/b"
            ):
                elem_left = int(elem.getparent().get("left"))
                elem_top = int(elem.getparent().get("top"))
                if (
                    elem_left == MARGIN_LEFT or elem_left == MARGIN_LEFT2
                ) and elem_top - parent_top > 18:
                    # found statement
                    logger.debug(item["header"]["title"])
                    read_statements(elem, item["statements"])
                    break
                item["header"]["title"] += elem.text
                parent_top = elem_top
            item["header"]["title"] = item["header"]["title"].strip()
        return report

    def extract(self, infile, outfile):
        logger.info("extract report from '%s'" % infile.name)
        report = self.get_report(infile)

        logger.info("check if report is ok")
        self.is_report_ok(report)

        logger.info("save report to '%s'" % outfile.name)
        json.dump(report._asdict(), outfile, indent=4)
