"""Map raw DHL subject tags to a small set of canonical resolution categories.

Usage
-----
    from src.extraction.vote_categories import classify_subjects
    category = classify_subjects("PALESTINE QUESTION|UNRWA--ACTIVITIES")
    # → "The Palestinian conflict"

The DHL CSVs carry pipe-separated subject strings (438 distinct GA values,
195 SC values).  ``classify_subjects`` reduces these to one of the canonical
categories below by scanning each subject tag against priority-ordered keyword
lists (uppercase substring match).  The first matching category wins.  If no
keyword matches, ``"Uncategorized"`` is returned.

Categories (in priority order)
-------------------------------
  The Palestinian conflict
  Nuclear weapons and nuclear material
  Arms control and disarmament
  Human rights
  Colonialism
  (Economic) development
  Peace and security
  Terrorism
  Environment
  Refugees and humanitarian assistance
  Women's rights
  UN administration
  Uncategorized
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Category definitions  (priority order — first match wins)
# Each tuple: (canonical_category_name, [uppercase substring keywords])
# A subject tag matches a category if ANY keyword is a substring of the tag.
# ---------------------------------------------------------------------------

_CATEGORIES: list[tuple[str, list[str]]] = [
    (
        "The Palestinian conflict",
        [
            "PALESTINE",
            "TERRITORIES OCCUPIED BY ISRAEL",
            "UNRWA",
            "PALESTINIANS",
            "MIDDLE EAST SITUATION",
            "MIDDLE EAST--NUCLEAR",  # nuclear-weapon-free zone for the Middle East
        ],
    ),
    (
        "Nuclear weapons and nuclear material",
        [
            "NUCLEAR",
            "FISSIONABLE MATERIALS",
            "IAEA",
            "COMPREHENSIVE NUCLEAR-TEST-BAN",
        ],
    ),
    (
        "Arms control and disarmament",
        [
            "DISARMAMENT",
            "ARMS RACE",
            "ARMS TRANSFER",
            "CHEMICAL WEAPON",
            "BIOLOGICAL WARFARE",
            "CONVENTIONAL WEAPON",
            "CONVENTIONAL ARMS",
            "LANDMINE",
            "CLUSTER MUNITION",
            "SMALL ARMS",
            "AUTONOMOUS WEAPON",
            "WEAPONS OF MASS DESTRUCTION",
            "ANTI-MISSILE",
            "BALLISTIC MISSILE",
            "DEPLETED URANIUM",
            "MILITARY BUDGET",
            "MILITARY EXPENDITURE",
            "STOCKPILE MANAGEMENT",
            "OUTER SPACE--ARMS",
            "OUTER SPACE--CONFIDENCE",
            "WEAPONS--OUTER SPACE",
            "EXPLOSIVES",
            "MINE CLEARANCE",
            "DUAL-USE TECHNOLOGY",
            "VERIFICATION",
            "MULTILATERALISM--DISARMAMENT",
            "INDIAN OCEAN--ZONES OF PEACE",
            "SOUTH ATLANTIC OCEAN REGION--ZONES OF PEACE",
            "ZONES OF PEACE",
        ],
    ),
    (
        "Human rights",
        [
            "HUMAN RIGHTS",
            "RACIAL DISCRIMINATION",
            "TORTURE",
            "CAPITAL PUNISHMENT",
            "SUMMARY EXECUTION",
            "INDIGENOUS PEOPLES",
            "MINORITIES",
            "TRAFFICKING IN PERSONS",
            "RIGHTS OF THE CHILD",
            "PERSONS WITH DISABILITIES",
            "RELIGIOUS INTOLERANCE",
            "DEMOCRACY",
            "GLOBALIZATION--HUMAN RIGHTS",
            "SCIENCE AND TECHNOLOGY--HUMAN RIGHTS",
            "CHILDREN IN ARMED CONFLICTS",
            "CIVILIAN PERSONS--ARMED CONFLICTS",
            "WOMEN--DISCRIMINATION",
            "RIGHT TO PEACE",
            "RIGHT OF PEOPLES TO PEACE",
            "RIGHT OF ASSEMBLY",
        ],
    ),
    (
        "Colonialism",
        [
            "COLONIALISM",
            "DECOLONIZATION",
            "NON-SELF-GOVERNING TERRITORIES",
            "COLONIAL COUNTRIES",
            "SELF-DETERMINATION OF PEOPLES",
            "APARTHEID",
            "SOUTH AFRICA--",
            "NAMIBIA",
            "WESTERN SAHARA",
            "FALKLAND ISLANDS",
            "EAST TIMOR QUESTION",
            "COMORIAN ISLAND",
            "NATIONAL LIBERATION MOVEMENTS",
            "NON-NUCLEAR-WEAPON STATES--SECURITY",  # sovereignty / equal security
        ],
    ),
    (
        "(Economic) development",
        [
            "ECONOMIC DEVELOPMENT",
            "ECONOMIC COOPERATION",
            "DEVELOPMENT FINANCE",
            "DEVELOPMENT COOPERATION",
            "DEVELOPMENT TRENDS",
            "DEVELOPMENT EDUCATION",
            "DEVELOPMENT--INTERNATIONAL",
            "NEW INTERNATIONAL ECONOMIC ORDER",
            "LEAST DEVELOPED COUNTRIES",
            "LANDLOCKED DEVELOPING COUNTRIES",
            "SMALL ISLAND DEVELOPING STATES",
            "DEVELOPING COUNTRIES",
            "FOOD SECURITY",
            "SUSTAINABLE DEVELOPMENT",
            "POVERTY",
            "SOCIAL DEVELOPMENT",
            "COMMODITIES",
            "EXTERNAL DEBT",
            "FINANCIAL FLOWS",
            "FINANCIAL INCLUSION",
            "INTERNATIONAL TRADE",
            "INDUSTRIAL DEVELOPMENT",
            "SCIENCE AND TECHNOLOGY--DEVELOPMENT",
            "RIGHT TO DEVELOPMENT",
            "ECONOMIC ASSISTANCE",
            "ECONOMIC RIGHTS",
            "HUNGER",
            "HEALTH",
            "2030 AGENDA",
            "AGENDA 21",
            "MILLENNIUM SUMMIT",
            "RURAL POVERTY",
            "RIGHT TO FOOD",
            "RIGHT TO DRINKING WATER",
            "INVESTMENT PROMOTION",
            "GLOBALIZATION--INTERDEPENDENCE",
            "GLOBALIZATION--UN",
            "SOCIAL CONDITIONS",
            "HUMAN SETTLEMENTS",
            "SCIENCE AND TECHNOLOGY--DEVELOPMENT",
            "CULTURE--DEVELOPMENT",
        ],
    ),
    (
        "Peace and security",
        [
            "PEACEKEEPING",
            "PEACEBUILDING",
            "PEACE AND SECURITY",
            "COLLECTIVE SECURITY",
            "ARMED CONFLICTS PREVENTION",
            "SPECIAL POLITICAL MISSIONS",
            "UN MISSION",
            "UN OPERATION",
            "UN FORCE",
            "UN INTERIM FORCE",
            "UN OBSERVER",
            "UN ADVANCE MISSION",
            "UN ANGOLA",
            "UN AOUZOU",
            "UN ASSISTANCE MISSION",
            "UN CIVILIAN POLICE",
            "UN CONFIDENCE RESTORATION",
            "UN DISENGAGEMENT",
            "UN INTEGRATED",
            "UN INTERIM ADMINISTRATION",
            "UN INTERIM SECURITY",
            "UN IRAN-IRAQ",
            "UN IRAQ-KUWAIT",
            "UN PREVENTIVE",
            "UN PROTECTION FORCE",
            "UN STABILIZATION",
            "UN SUPPORT MISSION",
            "UN TRANSITION",
            "UN TRANSITIONAL",
            "UN TRUCE",
            "IMPLEMENTATION FORCE",
            "STABILIZATION FORCE",
            "KFOR",
            "SITUATION",
            "RESPONSIBILITY TO PROTECT",
            "DISPUTE SETTLEMENT",
            "INTERNATIONAL SECURITY",
            "FORCE IN INTERNATIONAL RELATIONS",
            "PEACE--CONVENTIONAL",
            "COLLECTIVE SECURITY TREATY",
            "REGIONAL SECURITY",
            "POLITICAL CONDITIONS",
            "UN HYBRID OPERATION",
            "UN MULTIDIMENSIONAL",
            "UN POLITICAL MISSION",
            "INTERNATIONAL TRIBUNAL",
            "SPECIAL COURT",
            "INTERNATIONAL RESIDUAL MECHANISM",
            "SANCTIONS",
            "PEACE--INTERNATIONAL",
            "ECONOMIC SANCTIONS",
            "UNIFIL",
            "CHILDREN IN ARMED CONFLICTS",
            "CIVILIAN PERSONS--ARMED CONFLICTS",
            "PEACE",
            "UN. INTERNATIONAL COURT OF JUSTICE",
            "CYPRUS QUESTION",
            "ANGOLA--SOUTH AFRICA",
            "UN. ECONOMIC AND SOCIAL COUNCIL--REPORTS",
            "ORGANIZATION FOR SECURITY AND COOPERATION IN EUROPE",
            "ERITREA--ETHIOPIA",
            "IRAN (ISLAMIC REPUBLIC OF)--IRAQ",
            "IRAQ--KUWAIT",
            "CHAD--",
            "ARMENIA--AZERBAIJAN",
        ],
    ),
    (
        "Terrorism",
        [
            "TERRORISM",
            "COUNTER-TERRORISM",
            "HOSTAGE",
            "ATTACKS ON AIRCRAFT",
            "AIRCRAFT INCIDENT",
            "RADIOACTIVE MATERIALS--TERRORISM",
        ],
    ),
    (
        "Environment",
        [
            "ENVIRONMENT",
            "CLIMATE",
            "BIOLOGICAL DIVERSITY",
            "DESERTIFICATION",
            "SUSTAINABLE ENERGY",
            "COASTAL ZONE",
            "MARINE ECOSYSTEMS",
            "DRIFT-NET FISHING",
            "STRADDLING FISH STOCKS",
            "LAW OF THE SEA",
            "OUTER SPACE--PEACEFUL USES",
            "ANTARCTICA",
            "MOUNTAIN AREAS",
            "DISASTER PREVENTION",
            "NUCLEAR ACCIDENTS--CHORNOBYL",
        ],
    ),
    (
        "Refugees and humanitarian assistance",
        [
            "REFUGEE",
            "DISPLACED PERSONS",
            "DISASTER RELIEF",
            "EMERGENCY ASSISTANCE",
            "HUMANITARIAN ASSISTANCE",
            "FREEDOM OF MOVEMENT--FAMILY",
            "MIGRATION",
            "MIGRANTS",
        ],
    ),
    (
        "Women's rights",
        [
            "WOMEN'S ADVANCEMENT",
            "WOMEN--DISCRIMINATION",
            "WOMEN--INTERNATIONAL",
            "WOMEN IN ARMED",
            "RURAL WOMEN",
            "WOMEN MIGRANT",
        ],
    ),
    (
        "UN administration",
        [
            "UN--BUDGET",
            "UN--FINANCING",
            "UN--ORGANIZATIONAL REFORM",
            "UN--MEMBERS",
            "UN--ADMINISTRATION",
            "UN--HUMAN RESOURCES",
            "UN--PROGRAMME PLANNING",
            "UN--FINANCIAL",
            "UN--ANNIVERSARIES",
            "UN SYSTEM--",
            "COORDINATION WITHIN UN SYSTEM",
            "MULTILINGUALISM--UN",
            "UN. SECRETARIAT",
            "UN. SECRETARY-GENERAL",
            "CONFERENCE AND MEETING SERVICES",
            "UNITAR",
            "UN CONFERENCES",
            "UN CHARTER",
            "UN. COMMITTEE ON RELATIONS WITH THE HOST COUNTRY",
            "UN. CONFERENCE ON DISARMAMENT",
            "UN. DISARMAMENT COMMISSION",
            "UN. INTERNATIONAL LAW COMMISSION",
            "UN. GENERAL ASSEMBLY",
            "UN--RESOLUTIONS",
            "UN RESOLUTIONS",
        ],
    ),
]


def classify_subjects(subjects: str) -> str:
    """Return the canonical category for a pipe-separated DHL subjects string.

    Scans each subject tag against priority-ordered keyword lists (uppercase
    substring match).  Returns the first matching category name, or ``"Uncategorized"``
    if none match.
    """
    if not subjects:
        return "Uncategorized"
    tags = [t.strip().upper() for t in subjects.split("|") if t.strip()]
    for category, keywords in _CATEGORIES:
        for tag in tags:
            for kw in keywords:
                if kw in tag:
                    return category
    return "Uncategorized"
