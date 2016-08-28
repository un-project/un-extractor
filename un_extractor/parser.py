from __future__ import print_function
from re_scan import Scanner
import collections
import re
import json

Report = collections.namedtuple('Report', ['header', 'items'])

def parse_votes(text):
    votes = [' '.join(v.split()) for v in text.strip().split(',') if len(v.strip()) > 0]
    return votes

class Parser(object):
    ITEM_LOOKUP = 1
    ITEM_TITLE_LOOKUP = 2
    STATEMENT_LOOKUP = 3
    IN_FAVOUR_LOOKUP = 4
    AGAINST_LOOKUP = 5
    ABSTAINING_LOOKUP = 6

    SESSION_NAME_LINE = 4
    MEETING_DATE_LINE = 7

    def __init__(self):
        self.line_rules = [
            r'<text( [a-z]+?="\d+")*><b>\d+\/\d+ ?<\/b><\/text>',
            r'<text( [a-z]+?="\d+")*>\d{2}-\d{5}<b> [\d]+\/[\d]+ ?<\/b><\/text>',
            r'<text( [a-z]+?="\d+")*>\d{2}-\d{5}<\/text>',
            r'<text( [a-z]+?="\d+")*><b>[A-Z]\/\d{2}\/PV\.\d{1,3} \d{2}\/\d{2}\/\d{4}<\/b><\/text>',
            r'<text( [a-z]+?="\d+")*><b>\d{2}\/\d{2}\/\d{4} [A-Z]\/\d{2}\/PV\.\d{1,3}<\/b><\/text>',
            r'<text( [a-z]+?="\d+")*><b>[A-Z]\/\d{2}\/PV\.\d{1,3}<\/b><\/text>',
            r'<text( [a-z]+?="\d+")*>\d+-\d+ [A-Z]?<\/text>',
            r'<text( [a-z]+?="\d+")*>(<i>)*(<b>)* +(<\/b>)*(<\/i>)*<\/text>',
            r'^<image ',
            r'^<page number',
            r'^\s*<fontspec',
            r'^<\/page>',
            r'^<pdf2xml',
            r'^<\/pdf2xml>$',
            r'^<\?xml',
            r'<!DOCTYPE',
            r'^$',
        ]
        self.word_rules = [
            (r'<text.*font="\d+">', r''),
            (r'<\/text>', r''),
            (r' +', r' '),
            (r'-\n', r'-')
        ]
        self.string_rules = [
            (r' +\n ', ' '),
            (r'(\w) <\/i>\n<i>', r'\1 '),
            (r'(\w) <\/b>\n<b>(?!Agenda)', r'\1 '),
            (r'<\/i><i>', r''),
            (r'<\/b><b>', r''),
            (r'<i> <\/i>', r' '),
            (r'<b> <\/b>', r' ')
        ]

        self.line_patterns = list(map(lambda x: re.compile(x, flags=re.UNICODE), self.line_rules))
        self.word_patterns = list(map(lambda x: (re.compile(x[0], flags=re.UNICODE), x[1]), self.word_rules))
        self.string_patterns = list(map(lambda x: (re.compile(x[0], flags=re.UNICODE), x[1]), self.string_rules))
        self.scanner = Scanner([
            ('vote_open', r'(<i>)? ?A record(ed| of) vote was taken\.? ?(<\/i>)?\.?'),
            ('secret_vote_open', r'(<i>)? ?A vote was taken by secret ballot\.? ?(<\/i>)?\.?'),
            ('in_favour_open', r'<i>In favour:?<\/i>:?'),
            ('against_open', r'<i>Against:?<\/i>:?'),
            ('abstaining_open', r'<i>Abstaining:?<\/i>:?'),
            ('programme_of_work', r'<b>Programme of work<\/b>'),
            ('president', r'<i>President:?<\/i>:?\n(?P<name>\w+\. [\w ]+)( \.)+( |\n)\((?P<state>[\w ]+)\)'),
            ('agenda_item', r'<b>Agenda items? \d+.*<\/b> ?(\(?<i>\(?continued\)?<\/i>\)?)?'),
            #('agenda_item', r'<b>(Agenda items? \d+|Items? \d+ of the provisional agenda).*<\/b>(\(<i>continued<\/i>\))?'),
            ('president_statement', r'<b>Statement by the President<\/b>?'),
            ('president_speaker', r'<b>(?P<name>The (Acting )?President) ?:?<\/b>( ?\(<i>[i|I]nterpretation|[s|S]poke(<\/i>\n<i>)? ?(from|in ?)?(<\/i>\n<i>)?(?P<language>.*?)<\/i>\))??:?'),
            ('speaker', r'<b>(?P<name>.*?) ?<\/b>( ?\((?P<state>.*?([\r\n].*?)??.*?)\))??( ?\(<i>spoke ?(in ?)?(<\/i>\n<i>(in )?)?(?P<language>.*?)<\/i>\))??:'),
            ('draft_resolution_adopted', r'<i>Draft resolution (?P<draft_resolution_name>[A-Z]+(\/\d+\/)?.*?) was adopted.*<\/i>'),
            ('draft_resolution_rejected', r'<i>Draft resolution (?P<draft_resolution_name>[A-Z]+(\/\d+\/)?.*?) was rejected.*<\/i>'),
            ('draft_decision_adopted', r'<i>Draft decision (?P<draft_decision_name>[A-Z]+(\/\d+\/)?.*?) was adopted.*<\/i>'),
            ('draft_decision_rejected', r'<i>Draft decision (?P<draft_decision_name>[A-Z]+(\/\d+\/)?.*?) was rejected.*<\/i>'),
            ('amendment_adopted', r'<i>The amendment was adopted.*<\/i>'),
            ('amendment_rejected', r'<i>The (oral )?amendment was rejected.*<\/i>'),
            ('decided', r'<i>It was so decided\.? ?<\/i>\.?'),
            ('meeting_begin', r'(<i>.*)?(<b>.*)??The(<\/i>)? (<i>)?meeting was called to order at?((<\/i> <i>)| )(noon|\d{1,2}(<\/i>)?((\.|:) ?(<i>)?\d{2}(\.)?)? ?(noon|[a|p](<\/i>)?(\.)?(<i>)?m)?)(<\/i>)?\.? ?(<\/b>)?(<\/i>)?'),
            ('meeting_end', r'(<i>.*)?(<b>.*)?(.*escorted.*)?(?P<decided>It was so decided. )? ?The(<\/i>)? (<i>)?meeting (was )?(rose|adjourned|called to order)( at)?((<\/i> <i>)| )(noon|\d{1,2}(<\/i>)?((\.|:) ?(<i>)?\d{2}(\.)?)? ?(noon|[a|p](<\/i>)?(\.)?(<i>)?m)?)(<\/i>)?\.? ?(<\/b>)?(<\/i>)?'),
            ('meeting_suspended', r'.*meeting was suspended.*'),
            #('meeting_suspended', r'(<i>.*)?(<b>.*)?The(<\/i>)? (<i>)?meeting was suspended( at)?((<\/i> <i>)| )(noon|\d{1,2}(<\/i>)?((\.|:) ?(<i>)?\d{2}(\.)?)? ?(noon|[a|p](<\/i>)?(\.)?(<i>)?m)?)(<\/i>)?\.? ?(<\/b>)?(<\/i>)?'),
        ])

    def keep_line(self, line):
        for pattern in self.line_patterns:
            if pattern.match(line):
                #print(line)
                return False
        return True

    def clean_line(self, line):
        for pattern, repl in self.word_patterns:
            line = pattern.sub(repl, line)
        return line

    def clean_string(self, string):
        for pattern, repl in self.string_patterns:
            string = pattern.sub(repl, string)
        return string

    def get_lines(self, infile):
        lines = collections.deque()
        header_found = False
        for line in infile:
            if header_found is False and re.match('<text .*?>United Nations<\/text>', line):
                header_found = True
                header = [self.clean_line(line)]
                for count, line in enumerate(infile):
                    if re.match('<text .*?>asdf<\/text>', line):
                        continue
                    header.append(self.clean_line(line))
                    if count == 11:
                        break
                lines.extendleft(reversed(header))
            elif self.keep_line(line):
                lines.append(self.clean_line(line))
        return lines

    def get_report(self, infile):
        report = Report(header={}, items=[])
        self.state = self.ITEM_LOOKUP
        lines = self.get_lines(infile)
        input_text = ''.join(lines)
        input_text = self.clean_string(input_text)
        open('out.xml', 'w').write(input_text)
        report.header['session_name'] = lines[self.SESSION_NAME_LINE]
        report.header['meeting_date'] = lines[self.MEETING_DATE_LINE]
        item = None
        for token, match in self.scanner.scan_with_holes(input_text):
            if token is None:
                if self.state == self.IN_FAVOUR_LOOKUP:
                    vote['in_favour'] = parse_votes(match)
                    self.state = self.STATEMENT_LOOKUP
                elif self.state == self.AGAINST_LOOKUP:
                    vote['against'] = parse_votes(match)
                    self.state = self.STATEMENT_LOOKUP
                elif self.state == self.ABSTAINING_LOOKUP:
                    vote['abstaining'] = parse_votes(match)
                    self.state = self.STATEMENT_LOOKUP
                elif self.state == self.ITEM_TITLE_LOOKUP:
                    item['header']['title'] += match.strip().replace('</b>', '').replace('<b>', '')
                elif self.state == self.STATEMENT_LOOKUP:
                    statement['paragraphs'] += match.strip().split('\n')
            else:
                if token == 'president':
                    print('FOUND PRESIDENT')
                    report.header['president'] = match.groupdict()
                elif token == 'agenda_item':
                    print('NEW AGENDA ITEM')
                    items = []
                    for m in re.finditer(r'(?P<item_nb>\d+) ?(<\/b> ?)?(?P<continued>\(<i>continued<\/i>\))?', match.group(0)):
                        items.append({'type': None, 'item_nb': m.group('item_nb'), 'continued': True if m.group('continued') is not None else False})
                    item = {'header': {'title': '', 'items': items}, 'statements':[]}
                    report.items.append(item)
                    self.state = self.ITEM_TITLE_LOOKUP
                elif token == 'president_statement':
                    print('PRESIDENT STATEMENT')
                    item = {'header': {'title': 'Statement by the President'}, 'statements':[]}
                    report.items.append(item)
                    self.state = self.ITEM_TITLE_LOOKUP
                elif token == 'programme_of_work':
                    print('PROGRAMME OF WORK')
                    item = {'header': {'title': 'Programme of work'},
                            'statements':[]}
                    report.items.append(item)
                    self.state = self.ITEM_TITLE_LOOKUP
                elif token == 'vote_open':
                    print('VOTE OPEN')
                    vote = {'in_favour':[], 'against':[], 'abstaining':[]}
                    item['statements'].append({'vote': vote})
                    self.state = self.ITEM_LOOKUP
                elif token == 'secret_vote_open':
                    print('SECRET VOTE OPEN')
                    #TODO: implement this
                elif token == 'in_favour_open':
                    print('IN FAVOUR OPEN')
                    self.state = self.IN_FAVOUR_LOOKUP
                elif token == 'against_open':
                    print('AGAINST OPEN')
                    self.state = self.AGAINST_LOOKUP
                elif token == 'abstaining_open':
                    print('ABSTAINING OPEN')
                    self.state = self.ABSTAINING_LOOKUP
                elif token == 'speaker':
                    print('NEW SPEAKER')
                    self.state = self.STATEMENT_LOOKUP
                    statement = { 'speaker': match.groupdict() , 'paragraphs':[] }
                    if item is None:
                        item = {'statements':[]}
                        report.items.append(item)
                    item['statements'].append(statement)
                elif token == 'president_speaker':
                    print('NEW PRESIDENT SPEAKER')
                    self.state = self.STATEMENT_LOOKUP
                    statement = { 'speaker': match.groupdict() , 'paragraphs':[] }
                    if item is None:
                        item = {'statements':[]}
                        report.items.append(item)
                    item['statements'].append(statement)
                elif token == 'draft_resolution_adopted':
                    print('DRAFT RESOLUTION ADOPTED:', match.groupdict())
                    self.state = self.ITEM_LOOKUP
                    item['statements'].append({'header': match.groupdict(), 'adopted': True})
                    #item = None
                elif token == 'draft_resolution_rejected':
                    print('DRAFT RESOLUTION REJECTED')
                    self.state = self.ITEM_LOOKUP
                    if item is None:
                        item = {'statements':[]}
                        report.items.append(item)
                    item['statements'].append({'header': match.groupdict(), 'adopted': False})
                    #item = None
                elif token == 'draft_decision_adopted':
                    print('DRAFT DECISION ADOPTED:', match.groupdict())
                    self.state = self.ITEM_LOOKUP
                    item['statements'].append({'header': match.groupdict(), 'adopted': True})
                    #item = None
                elif token == 'draft_decision_rejected':
                    print('DRAFT DECISION REJECTED')
                    self.state = self.ITEM_LOOKUP
                    if item is None:
                        item = {'statements':[]}
                        report.items.append(item)
                    item['statements'].append({'header': match.groupdict(), 'adopted': False})
                    #item = None
                elif token == 'amendment_adopted':
                    print('AMENDMENT ADOPTED:', match.groupdict())
                    self.state = self.ITEM_LOOKUP
                    item['statements'].append({'header': match.groupdict(), 'adopted': True})
                    #item = None
                elif token == 'amendment_rejected':
                    print('AMENDMENT REJECTED')
                    self.state = self.ITEM_LOOKUP
                    if item is None:
                        item = {'statements':[]}
                        report.items.append(item)
                    item['statements'].append({'header': match.groupdict(), 'adopted': False})
                    #item = None
                elif token == 'decided':
                    print('IT WAS SO DECIDED')
                    self.state = self.ITEM_LOOKUP
                    if item is None:
                        item = {'statements':[]}
                        report.items.append(item)
                    item['statements'].append({'header': match.groupdict(), 'decided': True})
                    #item = None
                elif token == 'meeting_begin':
                    print('BEGIN')
                elif token == 'meeting_suspended':
                    print('SUSPENDED')
                elif token == 'meeting_end':
                    print('END')
                    if match.groupdict()['decided']:
                        item['statements'].append({'header': match.groupdict(), 'decided': True})
                    return report

    def parse_xml(self, args):
        report = self.get_report(args.infile)
        json.dump(report._asdict(), args.outfile, indent=4)
