"""Semantic extraction via the Claude API.

Uses ``claude-sonnet-4-6`` at temperature 0 to handle tasks that are
ambiguous or too varied for rule-based extraction:
  - Country name normalisation
  - Resolution title extraction
  - Agenda title normalisation
  - Group / bloc affiliation detection

All calls enforce JSON-only output.  A ``SemanticExtractor`` instance is
stateless and safe to share across threads.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from src.llm.prompts import (
    EXTRACT_GROUP_AFFILIATION_SYSTEM,
    EXTRACT_GROUP_AFFILIATION_USER,
    EXTRACT_RESOLUTION_TITLE_SYSTEM,
    EXTRACT_RESOLUTION_TITLE_USER,
    NORMALISE_AGENDA_TITLE_SYSTEM,
    NORMALISE_AGENDA_TITLE_USER,
    NORMALISE_COUNTRIES_SYSTEM,
    NORMALISE_COUNTRIES_USER,
)

log = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 1024
_TEMPERATURE = 0.0


class SemanticExtractor:
    """Wrapper around the Anthropic client for structured semantic extraction."""

    def __init__(self, api_key: str | None = None) -> None:
        """Create a new extractor.

        Parameters
        ----------
        api_key:
            Anthropic API key.  Falls back to ``ANTHROPIC_API_KEY`` env var.
        """
        self._client = anthropic.Anthropic(api_key=api_key)

    def _call(self, system: str, user: str) -> dict[str, Any]:
        """Make one API call and return the parsed JSON response.

        Raises ``ValueError`` if the response is not valid JSON.
        """
        message = self._client.messages.create(
            model=_MODEL,
            max_tokens=_MAX_TOKENS,
            temperature=_TEMPERATURE,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        raw: str = message.content[0].text.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        try:
            result: dict[str, Any] = json.loads(raw)
            return result
        except json.JSONDecodeError as exc:
            log.error("LLM response is not valid JSON: %s", raw[:200])
            raise ValueError(f"LLM returned non-JSON: {raw[:100]}") from exc

    # -----------------------------------------------------------------------
    # Public methods
    # -----------------------------------------------------------------------

    def normalise_countries(self, names: list[str]) -> dict[str, str | None]:
        """Normalise *names* to official UN Member State names.

        Returns a dict mapping each original name to its normalised form
        (or ``None`` if unrecognised).
        """
        if not names:
            return {}
        user = NORMALISE_COUNTRIES_USER.format(
            names_json=json.dumps(names, ensure_ascii=False)
        )
        result = self._call(NORMALISE_COUNTRIES_SYSTEM, user)
        normalised: dict[str, str | None] = result.get("normalized", {})
        return normalised

    def extract_resolution_title(self, symbol: str, context: str) -> str | None:
        """Return the title of a resolution given surrounding context text."""
        user = EXTRACT_RESOLUTION_TITLE_USER.format(
            symbol=symbol, context=context[:2000]
        )
        result = self._call(EXTRACT_RESOLUTION_TITLE_SYSTEM, user)
        return result.get("title")

    def normalise_agenda_title(
        self, raw_text: str
    ) -> dict[str, str | int | bool | None]:
        """Return cleaned agenda item fields from *raw_text*."""
        user = NORMALISE_AGENDA_TITLE_USER.format(raw_text=raw_text[:1000])
        return self._call(NORMALISE_AGENDA_TITLE_SYSTEM, user)

    def extract_group_affiliation(self, speech_opening: str) -> str | None:
        """Return the group name a delegate speaks on behalf of, or ``None``."""
        user = EXTRACT_GROUP_AFFILIATION_USER.format(text=speech_opening[:500])
        result = self._call(EXTRACT_GROUP_AFFILIATION_SYSTEM, user)
        return result.get("on_behalf_of")
