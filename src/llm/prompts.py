"""Prompt templates for Claude API semantic extraction calls.

All prompts instruct the model to return JSON only (no prose).
Temperature must be set to 0 at call time.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Country normalisation
# ---------------------------------------------------------------------------

NORMALISE_COUNTRIES_SYSTEM = """\
You are a data normalisation assistant for United Nations documents.
Your task is to convert country names as they appear in UN vote records
into their official UN Member State names.

Rules:
- Return the exact official UN name (e.g. "United States of America",
  not "USA" or "United States").
- If a name is already in official form, return it unchanged.
- If a name cannot be matched to any UN Member State, return null.
- Always respond with a JSON object only, no prose.
"""

NORMALISE_COUNTRIES_USER = """\
Convert the following country names to their official UN Member State names.

Input names:
{names_json}

Respond with this JSON structure:
{{
  "normalized": {{
    "<original name>": "<official UN name or null>",
    ...
  }}
}}
"""

# ---------------------------------------------------------------------------
# Resolution title extraction
# ---------------------------------------------------------------------------

EXTRACT_RESOLUTION_TITLE_SYSTEM = """\
You are extracting data from United Nations General Assembly verbatim records.
Your task is to identify the title of a draft resolution given the surrounding
document context.

Rules:
- The title is usually a bold heading near the draft resolution symbol.
- Return the title as a plain string.
- If you cannot determine the title with confidence, return null.
- Always respond with a JSON object only, no prose.
"""

EXTRACT_RESOLUTION_TITLE_USER = """\
Document context (text surrounding the resolution symbol {symbol}):

{context}

Respond with:
{{
  "title": "<resolution title or null>"
}}
"""

# ---------------------------------------------------------------------------
# Agenda item title normalisation
# ---------------------------------------------------------------------------

NORMALISE_AGENDA_TITLE_SYSTEM = """\
You are processing United Nations General Assembly agenda items.
Your task is to extract a clean, normalised title for an agenda item
given the raw text from the verbatim record.

Rules:
- Remove "(continued)" suffixes.
- Remove sub-item labels like "(a)", "(b)" from the title.
- Keep the full official title text.
- Always respond with a JSON object only, no prose.
"""

NORMALISE_AGENDA_TITLE_USER = """\
Raw agenda item text:

{raw_text}

Respond with:
{{
  "number": <integer or null>,
  "sub_item": "<letter or null>",
  "continued": <true or false>,
  "title": "<clean title>"
}}
"""

# ---------------------------------------------------------------------------
# Speaker group affiliation
# ---------------------------------------------------------------------------

EXTRACT_GROUP_AFFILIATION_SYSTEM = """\
You are extracting data from United Nations verbatim records.
Your task is to identify whether a delegate is speaking on behalf of a
named group or bloc, given the opening paragraph of their speech.

Rules:
- Groups include: African Group, Group of 77, Non-Aligned Movement (NAM),
  European Union, Group of Western European and Other States, etc.
- Return the group name as it appears in the text, or null if not present.
- Always respond with a JSON object only, no prose.
"""

EXTRACT_GROUP_AFFILIATION_USER = """\
Opening paragraph of speech:

{text}

Respond with:
{{
  "on_behalf_of": "<group name or null>"
}}
"""
