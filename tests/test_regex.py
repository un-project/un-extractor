"""This is the test module.

This module tests the extractor against different strings.
"""

import unittest
from un_extractor.extractor import Extractor


class TestRegex(unittest.TestCase):

    def setUp(self):
        self.extractor = Extractor()

    def scan_extract(self, line):
        for token, match in self.extractor.scanner.scan_with_holes(line):
            return token, match

    def check_extract(self, line, expected_token):
        token, _ = self.scan_extract(line)
        self.assertEqual(expected_token, token)

    def test_regex(self):
        self.check_extract("<b>Agenda item 1</b>(<i>continued</i>)",
                           "agenda_item")
        self.check_extract("<b>Agenda item 14</b><i>(continued)</i>",
                           "agenda_item")
        self.check_extract("<b>Agenda item 7</b> (<i>continued</i>)",
                           "agenda_item")
        self.check_extract("<b>Agenda items 13 and 115</b>", "agenda_item")
        self.check_extract("<b>Statement by the President</b>",
                           "president_statement")
        self.check_extract("<b>Programme of work</b>", "programme_of_work")
        self.check_extract("<b>The President</b>:", "president_speaker")
        self.check_extract("<b>The Acting President </b><i>(spoke in French)"
                           "</i>:<b>  </b>", "president_speaker")
        self.check_extract("<b>The Acting President </b><i>(spoke in French)"
                           "</i>:<b>  </b>", "president_speaker")
        self.check_extract("<b>The President </b><i>(interpretation from "
                           "French)</i>:<b>  </b>", "president_speaker")
        self.check_extract("<i>A recorded vote was taken.</i>", "vote_open")
        self.check_extract("<i>A vote was taken by secret ballot.</i>",
                           "secret_vote_open")
        self.check_extract("<i>In favour</i>:", "in_favour_open")
        self.check_extract("<i>Against</i>:", "against_open")
        self.check_extract("<i>Abstaining</i>:", "abstaining_open")
        self.check_extract("<i>The amendment was rejected by 83 votes to 80, "
                           "</i>:", "amendment_rejected")
        self.check_extract("<i>Draft resolution A/70/L.1 was adopted </i>",
                           "draft_resolution_adopted")
        self.check_extract("<i>Draft resolution C was rejected by 54 votes to "
                           "45,</i>", "draft_resolution_rejected")
        self.check_extract("<i>Draft decision XIX was adopted</i>",
                           "draft_decision_adopted")
        self.check_extract("<i>Draft decision XIX was rejected</i>",
                           "draft_decision_rejected")
        self.check_extract("<i>It was so decided</i>", "decided")
        self.check_extract("<i>The meeting was adjourned at 1 p.m. </i>",
                           "meeting_end")
        self.check_extract("The meeting was called to order at 10.45 a.m.",
                           "meeting_begin")
        self.check_extract("<i><b>The meeting was called to order at 10.10 a.m."
                           "</b></i>", "meeting_begin")
        self.check_extract("<i><b>The meeting was called to order at 10:20.</b>"
                           "</i>", "meeting_begin")
        self.check_extract("<i><b>The meeting was called to order at 10.35 a.m"
                           "</b></i><b>.</b>", "meeting_begin")
        self.check_extract("<i><b>The meeting was called to order at 10.40 a.m"
                           "</b></i>.", "meeting_begin")
        self.check_extract("<i><b>The meeting was called to order at 11 a.m</b>"
                           "</i>.", "meeting_begin")
        self.check_extract("<i><b>  </b>The meeting was called to order at 9.10"
                           " a.m. </i>", "meeting_begin")
        self.check_extract("The meeting was called to order at 10.05 a.m."
                           "</item>", "meeting_begin")
        self.check_extract("The meeting was suspended at 6.20 p.m. and resumed "
                           "at 11.30 a.m. on", "meeting_suspended")
        self.check_extract("The meeting was called to order at 6.20 p.m."
                           "</item>", "meeting_begin")
        self.check_extract("The meeting was called to order at 10.45 a.m.",
                           "meeting_begin")

if __name__ == '__main__':
    unittest.main()

#my_regex = re.compile("<this is where the magic (doesn't)? happen(s)?>")
#
#@pytest.mark.parametrize('test_str', [
#    "an easy test that I'm sure will pass",
#    "a few things that may trip me up",
#    "a really pathological, contrived example",
#    "something from the real world?",
#])
#def test_my_regex(test_str):
#     assert my_regex.match(test_str) is not None
