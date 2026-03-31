#!/usr/bin/env python3
"""Estimate UN country ideal points from GA recorded votes (Bailey-Strezhnev-Voeten).

Implements a cross-sectional two-parameter logistic (2PL) IRT model for each
GA session year, placing every country on a latent policy dimension anchored at
the United States (θ_USA = 0 in all years, positive = more aligned with USA).

Model
-----
For country i, vote j in year t:

    P(y_ij = Yes) = Φ(α_j · θ_i − β_j)

where Φ is the standard normal CDF, θ_i is the country ideal point,
α_j is the vote discrimination parameter, and β_j is the vote difficulty.

Identification
--------------
- θ_USA = 0 in all years (USA as reference, "Western liberal" pole).
- L2 regularisation (λ = 0.1) on free θ parameters to stabilise estimation.

Abstentions and absences are treated as missing (not used in likelihood).
Only resolutions with ≥ 10 Yes/No votes are included.

Standard errors are computed from the diagonal of the Fisher information
matrix at the optimum:  SE_i = 1 / sqrt(Σ_j α_j² φ(η_ij)² / [p_ij(1-p_ij)]).

Output
------
Writes to ``country_ideal_points (country_id, iso3, year, ideal_point, se)``,
one row per (country, year) with at least one classifiable vote.

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
    python scripts/compute_ideal_points.py --csv data/undl/ga_voting.csv
    python scripts/compute_ideal_points.py --year 2010
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
_MIN_VOTES_PER_RES = 10   # minimum Y+N votes for a resolution to be included
_MIN_RES_PER_YEAR = 5     # minimum resolutions to attempt estimation
_MIN_COUNTRIES = 20       # minimum countries to attempt estimation
_REGULARISATION = 0.1     # L2 penalty on ideal points (not USA anchor)
_GTOL = 1e-4              # gradient norm convergence tolerance
_MAXITER = 500            # L-BFGS-B max iterations


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
                UNIQUE (iso3, year)
            )
            """
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_cip_country "
            "ON country_ideal_points (country_id)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_cip_year "
            "ON country_ideal_points (year)"
        )
    )
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
# IRT estimation (one year)
# ---------------------------------------------------------------------------


def _estimate_year(
    year_votes: dict[str, dict[str, int]],
) -> tuple[list[str], np.ndarray, np.ndarray] | None:
    """Estimate ideal points for a single year.

    Returns (countries, ideal_points, standard_errors) or None if
    insufficient data.  ``ideal_points`` is signed so that positive values
    indicate alignment with the USA reference point.
    """
    countries = sorted(year_votes.keys())
    resolutions = sorted({r for cv in year_votes.values() for r in cv})
    n_c, n_r = len(countries), len(resolutions)

    if n_c < _MIN_COUNTRIES or n_r < _MIN_RES_PER_YEAR:
        return None

    # Vote matrix: (n_c, n_r), NaN = missing
    V = np.full((n_c, n_r), np.nan)
    c_idx = {c: i for i, c in enumerate(countries)}
    r_idx = {r: j for j, r in enumerate(resolutions)}
    for c, rv in year_votes.items():
        for r, v in rv.items():
            V[c_idx[c], r_idx[r]] = float(v)

    # Drop resolutions with fewer than _MIN_VOTES_PER_RES Y/N votes
    n_observed = np.sum(~np.isnan(V), axis=0)
    keep = n_observed >= _MIN_VOTES_PER_RES
    V = V[:, keep]
    n_r = V.shape[1]
    if n_r < _MIN_RES_PER_YEAR:
        return None

    obs = ~np.isnan(V)           # (n_c, n_r) boolean mask
    y = np.where(obs, V, 0.0)    # NaN → 0 (masked by obs in LL)

    # USA fixed at θ=0 for identification
    usa_idx = countries.index("USA") if "USA" in countries else None
    free_idx = np.array(
        [i for i in range(n_c) if i != usa_idx], dtype=int
    )
    n_free = len(free_idx)

    def neg_ll_grad(params: np.ndarray) -> tuple[float, np.ndarray]:
        theta_free = params[:n_free]
        alpha = params[n_free:n_free + n_r]
        beta = params[n_free + n_r:]

        theta = np.zeros(n_c)
        theta[free_idx] = theta_free

        eta = alpha[None, :] * theta[:, None] - beta[None, :]  # (n_c, n_r)
        phi = _norm.pdf(eta)
        Phi = np.clip(_norm.cdf(eta), 1e-9, 1.0 - 1e-9)

        # Score contribution per observation
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

    x0 = np.zeros(n_free + 2 * n_r)
    x0[n_free : n_free + n_r] = 1.0  # initialise discrimination = 1

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

    # Fisher information SE: SE_i = 1 / sqrt(Σ_j α_j² φ² / [p(1-p)])
    eta = alpha[None, :] * theta[:, None] - beta[None, :]
    phi = _norm.pdf(eta)
    Phi = np.clip(_norm.cdf(eta), 1e-9, 1.0 - 1e-9)
    info = np.sum(obs * alpha[None, :] ** 2 * phi ** 2 / (Phi * (1.0 - Phi)), axis=1)
    se = np.where(info > 0.0, 1.0 / np.sqrt(info), np.nan)

    # Sign convention: positive = agrees with USA (flip raw θ)
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
    dry_run: bool = False,
    only_year: int | None = None,
) -> None:
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
    log.info("Estimating ideal points for %d year(s).", len(years))

    with get_session(engine) as session:
        iso3_to_country = _build_iso3_to_country_id(session)

        total_rows = 0
        for year in years:
            result = _estimate_year(all_votes[year])
            if result is None:
                log.warning("Year %d: insufficient data — skipped.", year)
                continue

            countries, theta, se = result
            log.info(
                "Year %d: %d countries estimated.",
                year,
                len(countries),
            )

            if not dry_run:
                for i, iso3 in enumerate(countries):
                    ip = float(theta[i])
                    se_val = None if np.isnan(se[i]) else float(se[i])
                    country_id = iso3_to_country.get(iso3.upper())

                    session.execute(
                        text(
                            """
                            INSERT INTO country_ideal_points
                                (country_id, iso3, year, ideal_point, se)
                            VALUES (:cid, :iso3, :year, :ip, :se)
                            ON CONFLICT (iso3, year) DO UPDATE
                                SET ideal_point = EXCLUDED.ideal_point,
                                    se = EXCLUDED.se,
                                    country_id = EXCLUDED.country_id
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
            log.info(
                "Dry run: would write %d rows (not committed).",
                sum(
                    len(_estimate_year(all_votes[y])[0])
                    for y in years
                    if _estimate_year(all_votes[y]) is not None
                ),
            )


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Estimate UN country ideal points (Bailey-Strezhnev-Voeten 2PL IRT) "
            "from GA recorded votes and store in country_ideal_points."
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
        "--year",
        type=int,
        default=None,
        metavar="YYYY",
        help="Estimate only this year",
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
        dry_run=args.dry_run,
        only_year=args.year,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
