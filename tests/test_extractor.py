"""Additional unit tests for un_extractor.

These exercises verify small helper functions and the public API of
:class:`Extractor`.  We deliberately avoid relying on external XML files so
that the test suite remains self-contained.
"""

import unittest
from un_extractor.extractor import Extractor, parse_votes, Report


class TestHelpers(unittest.TestCase):
    def test_parse_votes_basic(self):
        self.assertEqual(parse_votes("A, B, C"), ["A", "B", "C"])
        self.assertEqual(parse_votes("  yes,  no "), ["yes", "no"])
        # empty or whitespace-only entries are ignored
        self.assertEqual(parse_votes("alpha,,  ,beta"), ["alpha", "beta"])


class TestExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = Extractor()

    def make_header(self, **kwargs):
        h = {
            "session_name": "Tenth session",
            "meeting_number": "1",
            "meeting_date": "2020-02-01",
        }
        h.update(kwargs)
        return h

    def test_is_report_ok_valid(self):
        report = Report(header=self.make_header(), items=[{"foo": "bar"}])
        self.assertTrue(self.extractor.is_report_ok(report))

    def test_extract_raises_on_invalid_report(self):
        # create a fake file-like object; StringIO doesn't have a ``name`` attribute
        # so the extractor should handle it gracefully as part of the error path.
        bad_report = Report(header={}, items=[])
        self.extractor.get_report = lambda infile: bad_report  # type: ignore
        from io import StringIO

        with self.assertRaises(ValueError):
            self.extractor.extract(StringIO(""), StringIO(""))

    def test_is_report_ok_missing_fields(self):
        report = Report(header={}, items=[])
        self.assertFalse(self.extractor.is_report_ok(report))

        report = Report(header=self.make_header(session_name=""), items=[{}])
        self.assertFalse(self.extractor.is_report_ok(report))

    def test_is_report_ok_invalid_values(self):
        h = self.make_header(session_name="not a session")
        report = Report(header=h, items=[{}])
        self.assertFalse(self.extractor.is_report_ok(report))

        h = self.make_header(meeting_number="abc")
        report = Report(header=h, items=[{}])
        self.assertFalse(self.extractor.is_report_ok(report))

        h = self.make_header(meeting_date="not a date")
        report = Report(header=h, items=[{}])
        self.assertFalse(self.extractor.is_report_ok(report))

    def test_get_report_minimal(self):
        # exercise the parsing logic using a tiny XML snippet stored in the
        # repository
        from pathlib import Path

        xml_path = Path(__file__).parent / "data" / "minimal.xml"
        with xml_path.open() as f:
            report = self.extractor.get_report(f)
        self.assertEqual(report.header.get("session_name"), "10th session")
        self.assertEqual(report.header.get("meeting_number"), "5")
        self.assertTrue(report.items)


class TestPackageExports(unittest.TestCase):
    def test___all__contains_core_symbols(self):
        import un_extractor as pkg

        self.assertIn("Extractor", pkg.__all__)
        self.assertIn("__version__", pkg.__all__)


# more thorough integration tests could be added when a small sample XML file is
# committed to the repository; at present we keep the suite lightweight.


if __name__ == "__main__":
    unittest.main()
