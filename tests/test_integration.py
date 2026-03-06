"""Integration tests exercising the extractor on a real recording.

The sample XML/JSON pair under ``tests/data`` is intentionally small enough
to version in the repository; these tests ensure that behaviour remains
stable as the code evolves.
"""

import json
import unittest
from pathlib import Path

from un_extractor.extractor import Extractor


class TestIntegration(unittest.TestCase):
    def test_sample_recording(self):
        data_dir = Path(__file__).parent / "data"
        xml_path = data_dir / "N0553261.xml"
        json_path = data_dir / "N0553261.json"

        extractor = Extractor()
        with xml_path.open() as xf:
            report = extractor.get_report(xf)
        # turn extracted report into plain dict for comparison
        extracted = report._asdict()

        with json_path.open() as jf:
            expected = json.load(jf)

        # structural equality; order within lists and dicts matters in this
        # release since the extractor is deterministic
        self.assertEqual(expected, extracted)
