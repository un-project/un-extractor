"""This is the extractor module.

This module parses XML files to extract a report in JSON format.
"""

from __future__ import print_function

import collections
import json
import logging
import lxml.etree
import re
import sys

from un_extractor.re_scan import Scanner

logger = logging.getLogger('un-extractor')

# Initialize coloredlogs
import coloredlogs
coloredlogs.install(level='DEBUG')

Report = collections.namedtuple('Report', ['header', 'items'])

def parse_votes(text):
    votes = [' '.join(v.split()) for v in text.strip().split(',')
             if len(v.strip()) > 0]
    return votes

def xpath_regex(element, expression):
    for elem in element.xpath(expression,
                              namespaces=
                              {"re": "http://exslt.org/regular-expressions"}):
        yield elem

def read_paragraphs(elem, paragraphs, paragraph='', quoted=False):
    parent_elem = elem
    if len(paragraph) == 0:
        paragraph = elem.xpath("string()")
        paragraph = paragraph[paragraph.find(':') + 1:-1].strip()
    for elem in xpath_regex(parent_elem, ".//following-sibling::text"):
        elem_top = int(elem.get("top"))
        elem_left = int(elem.get("left"))
        if elem_top < 135 or elem_top > 1082:
            continue;
        if elem.find("b") is not None:
            if len(paragraph.strip()) > 0:
                logger.info('\t\tnew paragraph')
                logger.debug('\t\t%s' % paragraph.strip())
                paragraphs.append(paragraph.strip())
                quoted = False
            return
        if elem.text is None or len(elem.text.strip()) == 0:
            continue
        if not quoted and (elem_left == 126 or elem_left == 504 or
                           elem.text[0] == ' '):
            if len(paragraph.strip()) > 0:
                logger.info('\t\tnew paragraph')
                logger.debug('\t\t%s' % paragraph.strip())
                paragraphs.append(paragraph.strip())
            paragraph = elem.text.strip()
        elif elem_left == 162:
            quoted = True
            if len(paragraph.strip()) > 0:
                logger.info('\t\tnew paragraph')
                logger.debug('\t\t%s' % paragraph.strip())
                paragraphs.append(paragraph.strip())
            paragraph = elem.text.strip()
        else:
            paragraph = ' '.join([paragraph, elem.text.strip()])

    # move to next page with list of bold text
    next_page = parent_elem.getparent().getnext()
    if next_page is not None:
        read_paragraphs(next_page.find("text"), paragraphs, paragraph,
                             quoted)
    else:
        if len(paragraph.strip()) > 0:
            logger.info('\t\tnew paragraph')
            logger.debug('\t\t%s' % paragraph.strip())
            paragraphs.append(paragraph.strip())

def read_statements(elem, statements):
    parent_text = elem.getparent()
    elems = xpath_regex(parent_text, ".//following-sibling::text/b")
    while elem is not None:
        elem_left = int(elem.getparent().get("left"))
        if elem_left != 126 and elem_left != 504:
            elem_top = int(elem.getparent().get("top"))
            if elem_top < 135 or elem_top > 1082:
                # skip page header
                try:
                    elem = elems.next()
                except StopIteration:
                    elem = None
                continue
            # found new agenda item
            return
        logger.info('\tnew speaker')
        logger.debug('\t%s' % elem.text.strip())
        match = re.search(
            r"""<b>(?P<name>.*?)\ ?<\/b>
            (\ *\((?P<state>.*?([\r\n].*?)??.*?)\))??
            (\ *\(?<i>spoke\ in\ (?P<language>.*?)<\/i>\))??:""",
            lxml.etree.tostring(elem.getparent()),
            flags=re.UNICODE|re.VERBOSE)
        if match is not None:
            statement = {'speaker': {'name': match.group('name'),
                                     'language': match.group('language'),
                                     'state': match.group('state')},
                         'paragraphs':[]}
        else:
            statement = {'speaker': {'name': elem.text.strip(),
                                     'language': None,
                                     'state': None},
                         'paragraphs':[]}
        read_paragraphs(elem.getparent(), statement['paragraphs'])
        statements.append(statement)
        try:
            elem = elems.next()
        except StopIteration:
            elem = None
    # move to next page with list of bold text
    next_page = parent_text.getparent().getnext()
    while next_page is not None:
        next_b = next_page.find('.//b')
        if next_b is not None:
            read_statements(next_b, statements)
            break
        else:
            next_page = next_page.getnext()

class Extractor(object):
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
        if 'session_name' not in report.header:
            logger.error("header does not contain a 'session_name' item!")
            return False
        if 'meeting_number' not in report.header:
            logger.error("header does not contain a 'meeting_number' item!")
            return False
        if 'meeting_date' not in report.header:
            logger.error("header does not contain a 'meeting_date' item!")
            return False
        if not re.match(r'[\w-]+\ session', report.header['session_name']):
            logger.error("invalid value for 'session_name': %s",
                         report.header['session_name'])
            return False
        if not re.match(r'\d+', report.header['meeting_number']):
            logger.error("invalid value for 'meeting_number': %s",
                         report.header['meeting_number'])
            return False
        try:
            from dateutil.parser import parse
            parse(report.header['meeting_date'])
        except ValueError as err:
            logger.error("invalid value for 'meeting_date': '%s' (%s)",
                         report.header['meeting_date'], format(err))
            return False
        return True

    def get_report(self, infile):
        report = Report(header={}, items=[])
        xml = lxml.etree.parse(infile)
        item = {}
        vote = {}
        statement = {}

        # find session name
        header = xpath_regex(xml, "(//text[re:match(text(),"
                                  "'\s*.* session\s*')])[1]").next()
        if header is not None:
            logger.info('session_name: %s' % header.text.strip())
            report.header['session_name'] = header.text.strip()

            # find meeting number
            meeting_number = xpath_regex(
                header, "(.//following-sibling::text/b[re:match(text(),"
                           "'\s*\d+\s*')])[1]").next()
            if meeting_number is not None:
                logger.info('meeting_number: %s' % meeting_number.text.strip())
                report.header['meeting_number'] = meeting_number.text.strip()

            # find meeting date
            meeting_date = xpath_regex(
                meeting_number.getparent(),
                "(.//following-sibling::text)[2]").next()
            if meeting_date is not None:
                logger.info('meeting_date: %s' % meeting_date.text.strip())
                report.header['meeting_date'] = meeting_date.text.strip()

        # find agenda items
        for agenda_item in xpath_regex(xml, "//text/b[re:match(text(),"
            "'(\s*Items? \d+ of the provisional agenda.\s*|Agenda items? \d+)')]"):
            logger.info('new agenda item')
            items = []
            for iterator in re.finditer(
                    r"""(?P<item_nb>\d+)
                    \ ?(<\/b>\ ?)?(?P<continued>
                    \(<i>continued<\/i>\))?""",
                    agenda_item.text, flags=re.UNICODE|re.VERBOSE):
                items.append({
                    'item_nb': iterator.group('item_nb'),
                    'continued': True if iterator.group('continued')\
                            is not None else False})
            item = {'header': {'title': '', 'items': items},
                    'statements':[]}
            report.items.append(item)

            # find item titles
            parent_top = 0
            for elem in xpath_regex(agenda_item.getparent(),
                                    ".//following-sibling::text/b"):
                elem_left = int(elem.getparent().get("left"))
                elem_top = int(elem.getparent().get("top"))
                if (elem_left == 126 or elem_left == 504) and\
                    elem_top - parent_top > 18:
                    # found statement
                    logger.debug(item['header']['title'])
                    read_statements(elem, item['statements'])
                    break
                item['header']['title'] += elem.text
                parent_top = elem_top
            item['header']['title'] = item['header']['title'].strip()
        return report
        #for token, match in self.scanner.scan_with_holes(input_text):
        #    if token is None:
        #        if self.state == self.IN_FAVOUR_LOOKUP:
        #            vote['in_favour'] = parse_votes(match)
        #            self.state = self.STATEMENT_LOOKUP
        #        elif self.state == self.AGAINST_LOOKUP:
        #            vote['against'] = parse_votes(match)
        #            self.state = self.STATEMENT_LOOKUP
        #        elif self.state == self.ABSTAINING_LOOKUP:
        #            vote['abstaining'] = parse_votes(match)
        #            self.state = self.STATEMENT_LOOKUP
        #        elif self.state == self.STATEMENT_LOOKUP:
        #            statement['paragraphs'] += match.strip().split('\n')
        #    else:
        #        if token == 'president':
        #            logger.info('new token: PRESIDENT')
        #            report.header['president'] = match.groupdict()
        #        elif token == 'agenda_item':
        #            logger.info('new token: AGENDA ITEM')
        #            items = []
        #            logger.info(match.group(0))
        #            for iterator in re.finditer(
        #                    r"""(?P<item_nb>\d+)
        #                    \ ?(<\/b>\ ?)?(?P<continued>
        #                    \(<i>continued<\/i>\))?""",
        #                    match.group(0), flags=re.UNICODE|re.VERBOSE):
        #                items.append({
        #                    'item_nb': iterator.group('item_nb'),
        #                    'continued': True if iterator.group('continued')\
        #                            is not None else False})
        #            item = {'header': {'title': '', 'items': items},
        #                    'statements':[]}
        #            report.items.append(item)
        #            self.state = self.ITEM_TITLE_LOOKUP
        #        elif token == 'president_statement':
        #            logger.info('new token: PRESIDENT STATEMENT')
        #            item = {'header': {'title': 'Statement by the President'},
        #                    'statements':[]}
        #            report.items.append(item)
        #            self.state = self.ITEM_TITLE_LOOKUP
        #        elif token == 'programme_of_work':
        #            logger.info('new token: PROGRAMME OF WORK')
        #            item = {'header': {'title': 'Programme of work'},
        #                    'statements':[]}
        #            report.items.append(item)
        #            self.state = self.ITEM_TITLE_LOOKUP
        #        elif token == 'vote_open':
        #            logger.info('new token: VOTE OPEN')
        #            vote = {'in_favour':[], 'against':[], 'abstaining':[]}
        #            item['statements'].append({'vote': vote})
        #            self.state = self.ITEM_LOOKUP
        #        elif token == 'secret_vote_open':
        #            logger.info('new token: SECRET VOTE OPEN')
        #            #TODO: implement this
        #        elif token == 'in_favour_open':
        #            logger.info('new token: IN FAVOUR OPEN')
        #            self.state = self.IN_FAVOUR_LOOKUP
        #        elif token == 'against_open':
        #            logger.info('new token: AGAINST OPEN')
        #            self.state = self.AGAINST_LOOKUP
        #        elif token == 'abstaining_open':
        #            logger.info('new token: ABSTAINING OPEN')
        #            self.state = self.ABSTAINING_LOOKUP
        #        elif token == 'speaker':
        #            logger.info('new token: SPEAKER')
        #            self.state = self.STATEMENT_LOOKUP
        #            statement = {'speaker': match.groupdict(), 'paragraphs':[]}
        #            if not item:
        #                item = {'statements':[]}
        #                report.items.append(item)
        #            item['statements'].append(statement)
        #        elif token == 'president_speaker':
        #            logger.info('new token: PRESIDENT SPEAKER')
        #            self.state = self.STATEMENT_LOOKUP
        #            statement = {'speaker': match.groupdict(), 'paragraphs':[]}
        #            if not item:
        #                item = {'statements':[]}
        #                report.items.append(item)
        #            item['statements'].append(statement)
        #        elif token == 'draft_resolution_adopted':
        #            logger.info('new token: DRAFT RESOLUTION ADOPTED: %s',
        #                        match.groupdict())
        #            self.state = self.ITEM_LOOKUP
        #            item['statements'].append({'header': match.groupdict(),
        #                                       'adopted': True})
        #            #item = None
        #        elif token == 'draft_resolution_rejected':
        #            logger.info('new token: DRAFT RESOLUTION REJECTED')
        #            self.state = self.ITEM_LOOKUP
        #            if not item:
        #                item = {'statements':[]}
        #                report.items.append(item)
        #            item['statements'].append({'header': match.groupdict(),
        #                                       'adopted': False})
        #            #item = None
        #        elif token == 'draft_decision_adopted':
        #            logger.info('new token: DRAFT DECISION ADOPTED: %s',
        #                        match.groupdict())
        #            self.state = self.ITEM_LOOKUP
        #            item['statements'].append({'header': match.groupdict(),
        #                                       'adopted': True})
        #            #item = None
        #        elif token == 'draft_decision_rejected':
        #            logger.info('new token: DRAFT DECISION REJECTED')
        #            self.state = self.ITEM_LOOKUP
        #            if not item:
        #                item = {'statements':[]}
        #                report.items.append(item)
        #            item['statements'].append({'header': match.groupdict(),
        #                                       'adopted': False})
        #            #item = None
        #        elif token == 'amendment_adopted':
        #            logger.info('new token: AMENDMENT ADOPTED: %s',
        #                        match.groupdict())
        #            self.state = self.ITEM_LOOKUP
        #            item['statements'].append({'header': match.groupdict(),
        #                                       'adopted': True})
        #            #item = None
        #        elif token == 'amendment_rejected':
        #            logger.info('new token: AMENDMENT REJECTED')
        #            self.state = self.ITEM_LOOKUP
        #            if not item:
        #                item = {'statements':[]}
        #                report.items.append(item)
        #            item['statements'].append({'header': match.groupdict(),
        #                                       'adopted': False})
        #            #item = None
        #        elif token == 'decided':
        #            logger.info('new token: IT WAS SO DECIDED')
        #            self.state = self.ITEM_LOOKUP
        #            if not item:
        #                item = {'statements':[]}
        #                report.items.append(item)
        #            item['statements'].append({'header': match.groupdict(),
        #                                       'decided': True})
        #            #item = None
        #        elif token == 'meeting_begin':
        #            logger.info('new token: MEETING BEGIN')
        #        elif token == 'meeting_suspended':
        #            logger.info('new token: MEETING SUSPENDED')
        #        elif token == 'meeting_end':
        #            logger.info('new token: MEETING END')
        #            if match.groupdict()['decided']:
        #                item['statements'].append({'header': match.groupdict(),
        #                                           'decided': True})
        #            return report

    def extract(self, infile, outfile):
        logger.info("extract report from '%s'" % infile.name)
        report = self.get_report(infile)

        logger.info("check if report is ok")
        self.is_report_ok(report)

        logger.info("save report to '%s'" % outfile.name)
        json.dump(report._asdict(), outfile, indent=4)
