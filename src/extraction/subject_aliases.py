"""Normalise raw DHL subject strings to canonical UNBIS scheme names.

The DHL CSVs carry pipe-separated subject strings such as::

    "UNRWA--ACTIVITIES|PALESTINE QUESTION|MIDDLE EAST SITUATION"

``normalize_subject`` reduces these to one of the 18 canonical UNBIS
scheme names (e.g. ``"POLITICAL AND LEGAL QUESTIONS"``) by:

1. Trying ``classify_unbis()`` from ``unbis_subjects.py`` (7,245 UNBIS
   preferred labels) — covers ~82 % of tag occurrences.
2. Trying ``_ALIASES`` — a curated dict for common DHL compound tags,
   acronyms, and UN entity names that do not appear verbatim in the
   UNBIS label list.
3. Applying lightweight prefix/suffix rules for the remaining systematic
   patterns (``UN.``, ``UN `` operations, country ``SITUATION`` entries).

Returns the first matching scheme name, or ``None`` if no tag matches.

UNBIS scheme names (canonical set)
-----------------------------------
  01  POLITICAL AND LEGAL QUESTIONS
  02  ECONOMIC DEVELOPMENT AND DEVELOPMENT FINANCE
  03  NATURAL RESOURCES AND THE ENVIRONMENT
  04  AGRICULTURE, FORESTRY AND FISHING
  05  INDUSTRY
  06  TRANSPORT AND COMMUNICATIONS
  07  INTERNATIONAL TRADE
  08  POPULATION
  09  HUMAN SETTLEMENTS
  10  HEALTH
  11  EDUCATION
  12  EMPLOYMENT
  13  HUMANITARIAN AID AND RELIEF
  14  SOCIAL CONDITIONS AND EQUITY
  15  CULTURE
  16  SCIENCE AND TECHNOLOGY
  17  GEOGRAPHICAL DESCRIPTORS
  18  ORGANIZATIONAL QUESTIONS
"""

from __future__ import annotations

from src.extraction.unbis_subjects import classify_unbis

# Shorthand for frequently used scheme names
_POL = "POLITICAL AND LEGAL QUESTIONS"
_ECO = "ECONOMIC DEVELOPMENT AND DEVELOPMENT FINANCE"
_ENV = "NATURAL RESOURCES AND THE ENVIRONMENT"
_HUM = "HUMANITARIAN AID AND RELIEF"
_SOC = "SOCIAL CONDITIONS AND EQUITY"
_SCI = "SCIENCE AND TECHNOLOGY"
_ORG = "ORGANIZATIONAL QUESTIONS"

# ---------------------------------------------------------------------------
# Curated aliases
#
# Keys are uppercase DHL base tags (the part before ``--``).
# The ``normalize_subject`` function first strips the ``--suffix`` before
# looking up in this dict, so entries need not repeat every compound form.
# ---------------------------------------------------------------------------

_ALIASES: dict[str, str] = {
    # --- Palestine / Middle East -----------------------------------------
    "UNRWA": _POL,
    "UNIFIL": _POL,
    "UN INTERIM FORCE IN LEBANON": _POL,
    "MIDDLE EAST--NUCLEAR PROLIFERATION": _POL,
    # --- Nuclear / arms control ------------------------------------------
    "IAEA": _POL,
    "CONVENTIONAL ARMS": _POL,
    "WEAPONS": _POL,
    "SOUTHERN HEMISPHERE": _POL,  # nuclear-weapon-free zones
    "NUCLEAR DISARMAMENT NEGOTIATIONS": _POL,
    "NUCLEAR TEST BANS": _POL,
    "PREPARATORY COMMISSION FOR THE COMPREHENSIVE NUCLEAR-TEST-BAN "
    "TREATY ORGANIZATION": _POL,
    "ORGANISATION FOR THE PROHIBITION OF CHEMICAL WEAPONS": _POL,
    "AUTONOMOUS WEAPONS": _POL,
    # --- Peace & security ------------------------------------------------
    "COLLECTIVE SECURITY": _POL,
    "COLLECTIVE SECURITY TREATY ORGANIZATION": _POL,
    "ARMED CONFLICTS PREVENTION": _POL,
    "COLLECTIVE MEASURES": _POL,
    "PEACE AND SECURITY": _POL,
    "SPECIAL POLITICAL MISSIONS": _POL,
    "KAMPUCHEA SITUATION": _POL,
    "RIGHT OF PEOPLES TO PEACE": _POL,
    # --- International legal / sanctions ---------------------------------
    "INTERNATIONAL TRIBUNAL": _POL,
    "ECONOMIC SANCTIONS": _POL,
    "MULTILATERAL TREATIES": _POL,
    "POLICY OF STATE TERRORISM": _POL,
    "AU/UN HYBRID OPERATION IN DARFUR": _POL,
    "CHAGOS ARCHIPELAGO": _POL,
    "KOSOVO": _POL,
    # --- Country situations (not matched by UNBIS) -----------------------
    "AZERBAIJAN SITUATION": _POL,
    "GUINEA-BISSAU SITUATION": _POL,
    "TIMOR-LESTE SITUATION": _POL,
    # --- Intergovernmental organisations (relations with UN) -------------
    "LEAGUE OF ARAB STATES": _POL,
    "ORGANIZATION FOR SECURITY AND COOPERATION IN EUROPE": _POL,
    "ORGANIZATION FOR DEMOCRACY AND ECONOMIC DEVELOPMENT - GUAM": _POL,
    "SHANGHAI COOPERATION ORGANIZATION": _POL,
    "ORGANISATION OF ISLAMIC COOPERATION": _POL,
    "ECONOMIC COOPERATION ORGANIZATION": _POL,
    "CENTRAL EUROPEAN INITIATIVE": _POL,
    "PACIFIC ISLANDS FORUM": _POL,
    "INTER-PARLIAMENTARY UNION": _POL,
    "AFRICAN UNION": _POL,
    "OAU": _POL,
    "COUNCIL OF EUROPE": _POL,
    "INTERNATIONAL ORGANIZATION OF LA FRANCOPHONIE": _POL,
    "ASSOCIATION OF SOUTHEAST ASIAN NATIONS": _POL,
    "GREAT LAKES REGION (AFRICA)": _POL,
    "CENTRAL ASIAN": _POL,
    # --- Development & economics -----------------------------------------
    "NEW INTERNATIONAL ECONOMIC ORDER": _ECO,
    "AGENDA 21": _ENV,  # Rio Earth Summit / sustainable development
    "2030 AGENDA": _ECO,
    "MILLENNIUM SUMMIT": _ECO,
    "DEVELOPMENT COOPERATION": _ECO,
    # --- Environment -----------------------------------------------------
    "STRADDLING FISH STOCKS": _ENV,
    "MEDITERRANEAN-DEAD SEA CANAL PROJECT": _ENV,
    # --- Humanitarian ----------------------------------------------------
    "EMERGENCY ASSISTANCE": _HUM,
    "NEW INTERNATIONAL HUMANITARIAN ORDER": _HUM,
    "INTERNATIONAL HUMANITARIAN FACT-FINDING COMMISSION": _HUM,
    # --- Social / human rights -------------------------------------------
    "NATIONAL INSTITUTIONS": _SOC,  # national human rights institutions
    "CLONING OF HUMAN BEINGS": _SOC,
    # --- Science & technology --------------------------------------------
    "NATURE": _SCI,
    # --- UN organisational (bodies, admin, budget) -----------------------
    "UNITAR": _ORG,
    "UN CONFERENCES": _ORG,
    "UN SYSTEM": _ORG,
    "UN CHARTER": _ORG,
}


# ---------------------------------------------------------------------------
# Prefix / suffix rules applied when neither classify_unbis nor _ALIASES match
# ---------------------------------------------------------------------------


def _classify_by_rule(base: str) -> str | None:
    """Apply systematic pattern rules to an uppercase DHL base tag."""
    # UN. prefix → UN bodies (committees, councils, secretariat) → ORG
    if base.startswith("UN.") or base.startswith("UN "):
        # UN operational missions/forces → political
        _mission_kw = (
            "FORCE",
            "MISSION",
            "OPERATION",
            "OBSERVER",
            "INTERIM",
            "TRANSITION",
            "STABILIZATION",
            "ASSISTANCE",
            "PEACEKEEPING",
            "MULTIDIMENSIONAL",
            "HYBRID",
            "PREVENTIVE",
            "ADVANCE",
            "CONFIDENCE",
            "PROTECTION",
            "DISENGAGEMENT",
            "TRUCE",
            "COMMISSIONER",
            "TRIBUNAL",
            "RESIDUAL MECHANISM",
        )
        if any(kw in base for kw in _mission_kw):
            return _POL
        return _ORG
    # UN-- prefix (UN--BUDGET (YYYY), UN--MEMBERS, UN--ADMINISTRATION …)
    if base.startswith("UN--") or base.startswith("UN -"):
        return _ORG
    # Country / region SITUATION → political
    if base.endswith("SITUATION"):
        return _POL
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize_subject(subjects: str) -> str | None:
    """Return the canonical UNBIS scheme name for a DHL subjects string.

    ``subjects`` is a raw pipe-separated DHL subjects string
    (e.g. ``"UNRWA--ACTIVITIES|PALESTINE QUESTION"``).  Returns the UNBIS
    scheme name of the first tag that can be classified, or ``None`` if no
    tag matches any of the three lookup layers.

    The lookup order per tag is:
    1. ``classify_unbis()`` — direct UNBIS label match (7,245 terms).
    2. ``_ALIASES`` — curated DHL-specific entries.
    3. ``_classify_by_rule()`` — prefix/suffix heuristics for UN entities
       and country situation entries.
    """
    if not subjects:
        return None
    for raw_tag in subjects.split("|"):
        tag = raw_tag.strip().upper()
        if not tag:
            continue

        # Layer 1: UNBIS direct lookup (handles '--' stripping & plurals)
        result = classify_unbis(tag)
        if result:
            return result

        # Layer 2 & 3: aliases and rules (try full tag, then base before --)
        for candidate in _alias_candidates(tag):
            if candidate in _ALIASES:
                return _ALIASES[candidate]
            rule_result = _classify_by_rule(candidate)
            if rule_result:
                return rule_result

    return None


def _alias_candidates(tag: str) -> list[str]:
    """Return lookup candidates for a DHL tag: full tag and base before --."""
    base = tag.split("--")[0].strip()
    seen: set[str] = set()
    result = []
    for v in (tag, base):
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result
