"""Integration tests: run the full pipeline on each sample PDF and compare
against stored golden fixtures.

To regenerate fixtures after an intentional change:

    python - <<'EOF'
    import json, logging
    from pathlib import Path
    from src.pipeline.process_pdf import process_pdf
    logging.disable(logging.CRITICAL)
    for pdf in sorted(Path("data/raw_pdfs").rglob("*.pdf")):
        r = process_pdf(pdf)
        summary = {
            "symbol": r.symbol, "session": r.session,
            "meeting_number": r.meeting_number,
            "date": r.date.isoformat() if r.date else None,
            "location": r.location,
            "president_name": r.president.name if r.president else None,
            "total_speeches": sum(len(i.speeches) for i in r.items),
            "total_resolutions": sum(len(i.resolutions) for i in r.items),
            "total_stage_directions": sum(len(i.stage_directions) for i in r.items),
            "items": [
                {"position": item.position, "item_type": item.item_type,
                 "agenda_number": item.agenda_number,
                 "speech_count": len(item.speeches),
                 "resolution_count": len(item.resolutions),
                 "resolutions": [
                     {"draft_symbol": res.draft_symbol, "vote_type": res.vote_type,
                      "yes_count": res.yes_count, "no_count": res.no_count,
                      "abstain_count": res.abstain_count}
                     for res in item.resolutions]}
                for item in r.items],
        }
        Path(f"tests/fixtures/{pdf.stem}.json").write_text(
            json.dumps(summary, indent=2)
        )
        print(f"Regenerated {pdf.stem}.json")
    EOF
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from src.pipeline.process_pdf import process_pdf

# Suppress pipeline validation warnings during tests.
logging.disable(logging.WARNING)

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_PDFS_DIR = Path(__file__).parent.parent / "data" / "raw_pdfs"

_SAMPLE_PDFS = sorted(_PDFS_DIR.rglob("*.pdf")) if _PDFS_DIR.exists() else []


def _summarise(pdf_path: Path) -> dict:
    r = process_pdf(pdf_path)
    return {
        "symbol": r.symbol,
        "session": r.session,
        "meeting_number": r.meeting_number,
        "date": r.date.isoformat() if r.date else None,
        "location": r.location,
        "president_name": r.president.name if r.president else None,
        "total_speeches": sum(len(i.speeches) for i in r.items),
        "total_resolutions": sum(len(i.resolutions) for i in r.items),
        "total_stage_directions": sum(len(i.stage_directions) for i in r.items),
        "items": [
            {
                "position": item.position,
                "item_type": item.item_type,
                "agenda_number": item.agenda_number,
                "speech_count": len(item.speeches),
                "resolution_count": len(item.resolutions),
                "resolutions": [
                    {
                        "draft_symbol": res.draft_symbol,
                        "vote_type": res.vote_type,
                        "yes_count": res.yes_count,
                        "no_count": res.no_count,
                        "abstain_count": res.abstain_count,
                    }
                    for res in item.resolutions
                ],
            }
            for item in r.items
        ],
    }


@pytest.mark.parametrize("pdf_path", _SAMPLE_PDFS, ids=lambda p: p.stem)
def test_pipeline_matches_golden_fixture(pdf_path: Path) -> None:
    """Pipeline output must match the stored golden fixture."""
    fixture_path = _FIXTURES_DIR / f"{pdf_path.stem}.json"
    if not fixture_path.exists():
        pytest.skip(
            f"No fixture for {pdf_path.stem} — run the regeneration snippet above"
        )

    expected = json.loads(fixture_path.read_text())
    actual = _summarise(pdf_path)

    assert actual == expected, (
        f"Pipeline output for {pdf_path.name} differs from golden fixture.\n"
        "If the change is intentional, regenerate fixtures using the snippet"
        " in this file's docstring."
    )
