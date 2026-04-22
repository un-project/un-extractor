#!/usr/bin/env python3
"""Extend UN ideal points for years beyond the published Voeten/BSV dataset.

Two modes
---------
Default (no ``--extend``)
    Re-estimates ideal points for *all* years using a cross-sectional 2PL IRT
    per year.  Stored with ``source = 'computed_irt'``.  Useful for
    development and for validating the model against Voeten's published values.

``--extend``
    Estimates only years that do *not* already have a ``voeten_bsv2017`` row
    in the database (i.e. sessions after Voeten's last data year).  For each
    new year the optimizer is warm-started from the previous year's rescaled
    ideal points (Voeten values are shifted so USA = 0 before use as θ₀),
    giving smoother cross-year trajectories than a cold start.
    Stored with ``source = 'computed_irt'``.

    Run ``scripts/import_voeten_ideal_points.py`` *before* this script when
    using ``--extend``.

Model
-----
Cross-sectional two-parameter logistic (2PL) IRT per year:

    P(y_ij = Yes) = Φ(α_j · θ_i − β_j)

where Φ is the standard normal CDF, θ_i is the country ideal point (positive
= more aligned with USA), α_j the vote discrimination, β_j the difficulty.

Identification: θ_USA = 0 in all years.  Abstentions and absences are treated
as missing.  Only resolutions with ≥ 10 Yes/No votes are included.

Standard errors come from the diagonal of the Fisher information matrix.

Note on scale
-------------
Our cross-sectional estimates place the USA at 0 by construction, whereas
Voeten's published values place the USA at ~+2.5 (world mean ≈ 0).  These are
*not* directly comparable on the y-axis; do not mix them in the same plot.
Use the ``source`` column to filter.

Reference
---------
Bailey, M. A., Strezhnev, A., & Voeten, E. (2017).
Estimating dynamic state preferences from United Nations voting data.
Journal of Conflict Resolution, 61(2), 430–456.
https://doi.org/10.1177/0022002715595700

Usage
-----
    python scripts/compute_ideal_points.py
    python scripts/compute_ideal_points.py --db postgresql://...
    python scripts/compute_ideal_points.py --extend           # new years only
    python scripts/compute_ideal_points.py --year 2024        # single year
    python scripts/compute_ideal_points.py --dry-run
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import numpy as np
    from scipy.optimize import minimize
    from scipy.stats import norm as _norm
except ImportError:
    print(
        "ERROR: numpy and scipy are required.\n"
        "Install with:  pip install numpy scipy",
        file=sys.stderr,
    )
    sys.exit(1)

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_DEFAULT_CSV = Path(__file__).resolve().parents[1] / "data" / "undl" / "ga_voting.csv"

# IRT hyper-parameters
_MIN_VOTES_PER_RES = 10
_MIN_RES_PER_YEAR = 5
_MIN_COUNTRIES = 20
_REGULARISATION = 0.1
_GTOL = 1e-4
_MAXITER = 500


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS country_ideal_points (
                id          SERIAL PRIMARY KEY,
                country_id  INTEGER REFERENCES countries(id) ON DELETE CASCADE,
                iso3        VARCHAR(3) NOT NULL,
                year        INTEGER NOT NULL,
                ideal_point DOUBLE PRECISION NOT NULL,
                se          DOUBLE PRECISION,
                source      VARCHAR(32) NOT NULL DEFAULT 'computed_irt',
                UNIQUE (iso3, year)
            )
            """
        )
    )
    session.execute(
        text(
            """
            ALTER TABLE country_ideal_points
            ADD COLUMN IF NOT EXISTS source VARCHAR(32) NOT NULL DEFAULT 'computed_irt'
            """
        )
    )
    for idx_sql in [
        "CREATE INDEX IF NOT EXISTS ix_cip_country ON country_ideal_points (country_id)",
        "CREATE INDEX IF NOT EXISTS ix_cip_year ON country_ideal_points (year)",
        "CREATE INDEX IF NOT EXISTS ix_cip_source ON country_ideal_points (source)",
    ]:
        session.execute(text(idx_sql))
    session.commit()
    log.info("country_ideal_points schema ready.")


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def _load_votes(csv_path: Path) -> dict[int, dict[str, dict[str, int]]]:
    """Return {year: {iso3: {undl_id: vote}}} where vote ∈ {1, 0}.

    Abstentions and absences are excluded (treated as missing).
    """
    all_votes: dict[int, dict[str, dict[str, int]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            v = row.get("ms_vote", "").strip()
            if v not in ("Y", "N"):
                continue
            year_str = (row.get("date") or "")[:4]
            if not year_str.isdigit():
                continue
            year = int(year_str)
            iso3 = row.get("ms_code", "").strip().upper()
            undl_id = row.get("undl_id", "").strip()
            if iso3 and undl_id:
                all_votes[year][iso3][undl_id] = 1 if v == "Y" else 0
    return all_votes


# ---------------------------------------------------------------------------
# Warm-start helpers
# ---------------------------------------------------------------------------


def _get_voeten_last_year(session: Session) -> int | None:
    """Return the highest year covered by voeten_bsv2017 rows, or None."""
    row = session.execute(
        text(
            "SELECT max(year) FROM country_ideal_points "
            "WHERE source = 'voeten_bsv2017'"
        )
    ).fetchone()
    return row[0] if row and row[0] is not None else None


def _get_warm_start(session: Session, year: int) -> dict[str, float]:
    """Return {iso3: theta} for the given year, rescaled to USA = 0.

    Used to initialise the optimiser for the first extension year from
    Voeten's published values, and for subsequent extension years from the
    previous year's computed_irt results.
    """
    rows = session.execute(
        text(
            "SELECT iso3, ideal_point FROM country_ideal_points WHERE year = :y"
            " ORDER BY source DESC"  # voeten_bsv2017 > computed_irt (alphabetic)
        ),
        {"y": year},
    ).fetchall()
    if not rows:
        return {}
    ip_map = {iso3.upper(): ip for iso3, ip in rows}
    usa_shift = ip_map.get("USA", 0.0)
    return {iso3: ip - usa_shift for iso3, ip in ip_map.items()}


# ---------------------------------------------------------------------------
# IRT estimation (one year)
# ---------------------------------------------------------------------------


def _estimate_year(
    year_votes: dict[str, dict[str, int]],
    warm_start: dict[str, float] | None = None,
) -> tuple[list[str], np.ndarray, np.ndarray] | None:
    """Estimate ideal points for a single year.

    Returns (countries, ideal_points, standard_errors) or None if
    insufficient data.  Positive values indicate alignment with the USA
    reference point (θ_USA = 0 by construction).

    Parameters
    ----------
    warm_start:
        Optional {iso3: theta} mapping (USA=0 scale) to use as the starting
        point for the optimizer instead of zeros.  Countries not present in
        the mapping start at 0.
    """
    countries = sorted(year_votes.keys())
    resolutions = sorted({r for cv in year_votes.values() for r in cv})
    n_c, n_r = len(countries), len(resolutions)

    if n_c < _MIN_COUNTRIES or n_r < _MIN_RES_PER_YEAR:
        return None

    V = np.full((n_c, n_r), np.nan)
    c_idx = {c: i for i, c in enumerate(countries)}
    r_idx = {r: j for j, r in enumerate(resolutions)}
    for c, rv in year_votes.items():
        for r, v in rv.items():
            V[c_idx[c], r_idx[r]] = float(v)

    n_observed = np.sum(~np.isnan(V), axis=0)
    keep = n_observed >= _MIN_VOTES_PER_RES
    V = V[:, keep]
    n_r = V.shape[1]
    if n_r < _MIN_RES_PER_YEAR:
        return None

    obs = ~np.isnan(V)
    y = np.where(obs, V, 0.0)

    usa_idx = countries.index("USA") if "USA" in countries else None
    free_idx = np.array(
        [i for i in range(n_c) if i != usa_idx], dtype=int
    )
    n_free = len(free_idx)

    def neg_ll_grad(params: np.ndarray) -> tuple[float, np.ndarray]:
        theta_free = params[:n_free]
        alpha = params[n_free : n_free + n_r]
        beta = params[n_free + n_r :]

        theta = np.zeros(n_c)
        theta[free_idx] = theta_free

        eta = alpha[None, :] * theta[:, None] - beta[None, :]
        phi = _norm.pdf(eta)
        Phi = np.clip(_norm.cdf(eta), 1e-9, 1.0 - 1e-9)

        r = obs * phi * (y / Phi - (1.0 - y) / (1.0 - Phi))

        ll = (
            np.sum(obs * (y * np.log(Phi) + (1.0 - y) * np.log(1.0 - Phi)))
            - _REGULARISATION * np.sum(theta_free ** 2)
        )

        g_theta_all = np.sum(r * alpha[None, :], axis=1)
        g_theta = g_theta_all[free_idx] - 2.0 * _REGULARISATION * theta_free
        g_alpha = np.sum(r * theta[:, None], axis=0)
        g_beta = -np.sum(r, axis=0)
        grad = np.concatenate([g_theta, g_alpha, g_beta])
        return -ll, -grad

    # Initialise theta from warm_start (rescaled to USA=0) when available
    x0 = np.zeros(n_free + 2 * n_r)
    x0[n_free : n_free + n_r] = 1.0  # discrimination = 1
    if warm_start:
        free_countries = [countries[i] for i in free_idx]
        for k, c in enumerate(free_countries):
            if c in warm_start:
                x0[k] = warm_start[c]

    result = minimize(
        neg_ll_grad,
        x0,
        method="L-BFGS-B",
        jac=True,
        options={"maxiter": _MAXITER, "gtol": _GTOL},
    )
    if not result.success:
        log.debug("L-BFGS-B did not fully converge: %s", result.message)

    theta_free = result.x[:n_free]
    alpha = result.x[n_free : n_free + n_r]
    beta = result.x[n_free + n_r :]

    theta = np.zeros(n_c)
    theta[free_idx] = theta_free

    eta = alpha[None, :] * theta[:, None] - beta[None, :]
    phi = _norm.pdf(eta)
    Phi = np.clip(_norm.cdf(eta), 1e-9, 1.0 - 1e-9)
    info = np.sum(obs * alpha[None, :] ** 2 * phi ** 2 / (Phi * (1.0 - Phi)), axis=1)
    safe_info = np.where(info > 0.0, info, 1.0)  # avoid sqrt(0) before np.where selects
    se = np.where(info > 0.0, 1.0 / np.sqrt(safe_info), np.nan)

    # Flip: positive = agrees with USA
    return countries, -theta, se


# ---------------------------------------------------------------------------
# Country ID index
# ---------------------------------------------------------------------------


def _build_iso3_to_country_id(session: Session) -> dict[str, int]:
    rows = session.execute(
        text("SELECT iso3, id FROM countries WHERE iso3 IS NOT NULL")
    ).fetchall()
    return {iso3.upper(): cid for iso3, cid in rows}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def compute_ideal_points(
    db_url: str | None = None,
    csv_path: Path | None = None,
    extend: bool = False,
    dry_run: bool = False,
    only_year: int | None = None,
) -> None:
    """Estimate ideal points and write to country_ideal_points.

    Parameters
    ----------
    extend:
        When True, estimate only years after the last voeten_bsv2017 year,
        using the previous year's ideal points as a warm start.
    """
    if csv_path is None:
        csv_path = _DEFAULT_CSV

    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_schema(session)

    log.info("Loading vote data from %s …", csv_path)
    all_votes = _load_votes(csv_path)

    years = sorted(all_votes.keys())
    if only_year is not None:
        years = [y for y in years if y == only_year]

    # --extend: restrict to years after the last Voeten year
    voeten_last_year: int | None = None
    if extend:
        with get_session(engine) as session:
            voeten_last_year = _get_voeten_last_year(session)
        if voeten_last_year is None:
            log.warning(
                "--extend specified but no voeten_bsv2017 rows found in DB. "
                "Run import_voeten_ideal_points.py first.  "
                "Falling back to full estimation."
            )
        else:
            years = [y for y in years if y > voeten_last_year]
            log.info(
                "Voeten data covers up to %d; extending for %d year(s): %s",
                voeten_last_year,
                len(years),
                years,
            )

    if not years:
        log.info("No years to estimate — nothing to do.")
        return

    log.info("Estimating ideal points for %d year(s).", len(years))

    with get_session(engine) as session:
        iso3_to_country = _build_iso3_to_country_id(session)

    total_rows = 0
    prev_theta: dict[str, float] = {}  # warm start for next year

    with get_session(engine) as session:
        for year in years:
            # Build warm start: either from previous year's DB rows (first
            # extension year) or from the previous iteration's estimates.
            if extend and not prev_theta and voeten_last_year is not None:
                warm_start = _get_warm_start(session, voeten_last_year)
                log.debug(
                    "Year %d: warm-starting from %d voeten year-%d values.",
                    year, len(warm_start), voeten_last_year,
                )
            else:
                warm_start = prev_theta or None

            result = _estimate_year(all_votes[year], warm_start=warm_start)
            if result is None:
                log.warning("Year %d: insufficient data — skipped.", year)
                continue

            countries, theta, se = result
            log.info("Year %d: %d countries estimated.", year, len(countries))

            # Store this year's estimates as warm start for next year
            prev_theta = {
                iso3: float(theta[i])
                for i, iso3 in enumerate(countries)
            }

            if not dry_run:
                for i, iso3 in enumerate(countries):
                    ip = float(theta[i])
                    se_val = None if np.isnan(se[i]) else float(se[i])
                    country_id = iso3_to_country.get(iso3.upper())

                    session.execute(
                        text(
                            """
                            INSERT INTO country_ideal_points
                                (country_id, iso3, year, ideal_point, se, source)
                            VALUES (:cid, :iso3, :year, :ip, :se, 'computed_irt')
                            ON CONFLICT (iso3, year) DO UPDATE
                                SET ideal_point = EXCLUDED.ideal_point,
                                    se          = EXCLUDED.se,
                                    source      = EXCLUDED.source,
                                    country_id  = EXCLUDED.country_id
                            """
                        ),
                        {
                            "cid": country_id,
                            "iso3": iso3,
                            "year": year,
                            "ip": ip,
                            "se": se_val,
                        },
                    )
                    total_rows += 1
                session.flush()

        if not dry_run:
            log.info("Committed %d country-year ideal point rows.", total_rows)
        else:
            log.info("Dry run: would write %d rows (not committed).", total_rows)


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Estimate UN ideal points (cross-sectional 2PL IRT) "
            "and store in country_ideal_points."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--csv",
        default=None,
        help="Path to ga_voting.csv (default: data/undl/ga_voting.csv)",
    )
    p.add_argument(
        "--extend",
        action="store_true",
        help=(
            "Only estimate years beyond the last voeten_bsv2017 year in the DB. "
            "Requires import_voeten_ideal_points.py to have been run first."
        ),
    )
    p.add_argument(
        "--year",
        type=int,
        default=None,
        metavar="YYYY",
        help="Estimate only this year (overrides --extend year filtering)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Estimate but do not write to the database",
    )
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    compute_ideal_points(
        db_url=args.db,
        csv_path=Path(args.csv) if args.csv else None,
        extend=args.extend,
        dry_run=args.dry_run,
        only_year=args.year,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
