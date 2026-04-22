#!/usr/bin/env python3
"""Full dynamic Bayesian IRT ideal points (Bailey–Strezhnev–Voeten 2017).

Implements the ordinal-probit Gibbs sampler from:

    Bailey, M. A., Strezhnev, A., & Voeten, E. (2017).
    Estimating Dynamic State Preferences from United Nations Voting Data.
    Journal of Conflict Resolution, 61(2), 430–456.
    https://doi.org/10.1177/0022002715595700

Original R/Rcpp source:
    https://github.com/erikvoeten/United-Nations-General-Assembly-Votes-and-Ideal-Points

Model
-----
For each (country i, session t, resolution j) observation with vote y ∈ {1,2,3}:

    Z_ij  ~ N(β_j · θ_it, 1)            latent utility
    y = 1  iff Z < γ₁ⱼ                  Yes
    y = 2  iff γ₁ⱼ ≤ Z < γ₂ⱼ           Abstain
    y = 3  iff Z ≥ γ₂ⱼ                  No

Vote polarity: positive θ means the country aligns with the US/Western bloc
(which typically votes No on most GA resolutions).

Dynamic prior (random walk):
    θ_it ~ N(θ_i,t-1,  SV_it · Smooth · σ²_θ)

where SV_it (SmoothVector) = n_it / (n_it + n_i,t-1) controls how much weight
the prior gets relative to the likelihood.  Larger SmoothVector → weaker prior
(more responsive to current data).

Gibbs sampler steps (per iteration):
    1. θ  — conjugate Gaussian posterior (closed-form update)
    2. γ  — Metropolis–Hastings with truncated-normal random walk
    3. Z  — truncated-normal draw (Albert & Chib data augmentation)
    4. β  — conjugate Gaussian posterior (closed-form update)

Scale identification: after step 1, θ is rescaled to mean = 0, std = 1.
Polarity is anchored by starting values (USA = +3, Russia = −2).

Output
------
Writes to ``country_ideal_points (iso3, year, ideal_point, se, source)``
with ``source = 'bsv2017_mcmc'``.  ``ideal_point`` is the posterior mean,
``se`` is the posterior standard deviation (across thinned samples).

Usage
-----
    python scripts/compute_ideal_points_mcmc.py --db postgresql://...
    python scripts/compute_ideal_points_mcmc.py --n-iter 5000 --n-burn 1000 --thin 10
    python scripts/compute_ideal_points_mcmc.py --dry-run --verbose
"""

from __future__ import annotations

import argparse
import csv
import logging
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import numpy as np
    from scipy.stats import norm as _norm
except ImportError:
    print("ERROR: numpy and scipy are required.\n"
          "Install with:  pip install numpy scipy", file=sys.stderr)
    sys.exit(1)

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_DEFAULT_CSV = Path(__file__).resolve().parents[1] / "data" / "undl" / "ga_voting.csv"

# ── Hyperparameters (matching BSV defaults) ──────────────────────────────────
_SMOOTH          = 0.5    # prior weight relative to likelihood
_S2_THETA_PRIOR  = 1.0   # variance of theta prior
_S2_BETA_PRIOR   = 1.0   # variance of beta prior
_BETA_PRIOR      = 0.0   # mean of beta prior
_SIGMA_MH        = 0.2 / 3  # M-H proposal std for gamma
_THETA_CLAMP     = 5.0   # hard min/max on theta before rescaling
_Z_CLAMP         = 9.0   # hard min/max on latent Z
_GAMMA_BOUNDS    = 7.0   # truncation bounds for gamma proposals
_MIN_VOTES_PER_RES = 5   # minimum distinct votes to include a resolution

# COW codes for polarity anchor (must agree: USA positive, Russia negative)
_ISO3_USA    = "USA"
_ISO3_RUSSIA = "RUS"


# ── Schema ────────────────────────────────────────────────────────────────────

def _ensure_schema(session: Session) -> None:
    session.execute(text("""
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
    """))
    session.execute(text("""
        ALTER TABLE country_ideal_points
        ADD COLUMN IF NOT EXISTS source VARCHAR(32) NOT NULL DEFAULT 'computed_irt'
    """))
    for sql in [
        "CREATE INDEX IF NOT EXISTS ix_cip_country ON country_ideal_points (country_id)",
        "CREATE INDEX IF NOT EXISTS ix_cip_year    ON country_ideal_points (year)",
        "CREATE INDEX IF NOT EXISTS ix_cip_source  ON country_ideal_points (source)",
    ]:
        session.execute(text(sql))
    session.commit()
    log.info("country_ideal_points schema ready.")


# ── Data loading ─────────────────────────────────────────────────────────────

def _load_votes_ordinal(csv_path: Path) -> dict:
    """Load GA votes as ordinal 1=Yes / 2=Abstain / 3=No.

    Returns a dict with arrays and index structures used by the sampler.
    """
    _VOTE_MAP = {"Y": 1, "A": 2, "N": 3}

    # raw records
    raw: list[tuple[str, int, str, int]] = []  # (iso3, session, undl_id, vote)
    with csv_path.open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            v_raw = row.get("ms_vote", "").strip()
            if v_raw not in _VOTE_MAP:
                continue
            session_raw = row.get("session", "").strip()
            if not session_raw.isdigit():
                continue
            session = int(session_raw)
            if session == 19:   # only 1 vote in this session — excluded in BSV
                continue
            iso3 = row.get("ms_code", "").strip().upper()
            undl_id = row.get("undl_id", "").strip()
            if iso3 and undl_id:
                raw.append((iso3, session, undl_id, _VOTE_MAP[v_raw]))

    log.info("Loaded %d raw ordinal observations.", len(raw))

    # Build resolution vote tallies to filter unanimous / sparse votes
    res_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for _, _, uid, v in raw:
        res_counts[uid][v - 1] += 1

    # Keep resolutions with at least 2 distinct vote outcomes AND >= _MIN_VOTES_PER_RES
    keep_res: set[str] = set()
    for uid, cnts in res_counts.items():
        n_yes, n_abs, n_no = cnts
        n_total = n_yes + n_abs + n_no
        if n_total < _MIN_VOTES_PER_RES:
            continue
        if n_yes == n_total or n_abs == n_total or n_no == n_total:
            continue  # unanimous
        keep_res.add(uid)

    raw = [(iso3, sess, uid, v) for iso3, sess, uid, v in raw if uid in keep_res]
    log.info("After filtering: %d observations, %d resolutions.", len(raw), len(keep_res))

    # Sort by resolution then country-session (matches BSV AllData sort)
    raw.sort(key=lambda r: (r[2], r[0], r[1]))

    # Build index structures
    res_list  = sorted(keep_res)
    res_idx   = {uid: j for j, uid in enumerate(res_list)}
    TT = len(res_list)

    # country-session list
    cs_set  = sorted({(iso3, sess) for iso3, sess, _, _ in raw})
    cs_list = cs_set  # list of (iso3, session)
    cs_idx  = {cs: i for i, cs in enumerate(cs_list)}
    NN = len(cs_list)

    ObsN = len(raw)
    y_obs          = np.empty(ObsN, dtype=np.int8)
    theta_obs_idx  = np.empty(ObsN, dtype=np.int32)
    beta_obs_idx   = np.empty(ObsN, dtype=np.int32)

    for k, (iso3, sess, uid, v) in enumerate(raw):
        y_obs[k]         = v
        theta_obs_idx[k] = cs_idx[(iso3, sess)]
        beta_obs_idx[k]  = res_idx[uid]

    VoteN = np.bincount(beta_obs_idx, minlength=TT).astype(np.int32)
    IndN  = np.bincount(theta_obs_idx, minlength=NN).astype(np.int32)

    return dict(
        y_obs=y_obs,
        theta_obs_idx=theta_obs_idx,
        beta_obs_idx=beta_obs_idx,
        cs_list=cs_list,       # list of (iso3, session)
        res_list=res_list,     # list of undl_id strings
        NN=NN, TT=TT, ObsN=ObsN,
        VoteN=VoteN, IndN=IndN,
    )


# ── Preprocessing ─────────────────────────────────────────────────────────────

def _compute_smooth_vector(cs_list: list, IndN: np.ndarray) -> np.ndarray:
    """Compute SmoothVector for each country-session.

    SV_it = n_it / (n_it + n_{i, prev})
    where prev is the previous session with data for country i.
    For the first session, n_prev = number of votes in the next session.
    """
    NN = len(cs_list)
    # Build {(iso3, session): index}
    cs_idx = {cs: i for i, cs in enumerate(cs_list)}

    # Group sessions per country
    country_sessions: dict[str, list[int]] = defaultdict(list)
    for iso3, sess in cs_list:
        country_sessions[iso3].append(sess)
    for iso3 in country_sessions:
        country_sessions[iso3].sort()

    smooth = np.ones(NN)

    for iso3, sessions in country_sessions.items():
        sess_set = set(sessions)
        for t_idx, sess in enumerate(sessions):
            ii = cs_idx[(iso3, sess)]
            n_curr = IndN[ii]

            # Previous session with data
            if t_idx > 0:
                prev_sess = sessions[t_idx - 1]
                n_prev = IndN[cs_idx[(iso3, prev_sess)]]
                smooth[ii] = n_curr / (n_curr + n_prev)
            elif t_idx == 0 and len(sessions) > 1:
                # First session: use next session's vote count
                next_sess = sessions[1]
                n_next = IndN[cs_idx[(iso3, next_sess)]]
                smooth[ii] = n_curr / (n_curr + n_next)
            # else: only one session for this country → smooth stays 1.0

    return smooth


def _build_lag_indices(
    cs_list: list,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Precompute lag/next indices for each country-session.

    Returns
    -------
    prev_cs_idx : (NN,) int32, index of (country, most_recent_prev_session)
                  or -1 if no previous session exists.
    next_cs_idx : (NN,) int32, index of (country, next_session)
                  or -1 if no next session exists (used only for first sessions).
    is_first    : (NN,) bool, True for the first session of each country.
    """
    cs_idx = {cs: i for i, cs in enumerate(cs_list)}
    NN = len(cs_list)

    country_sessions: dict[str, list[int]] = defaultdict(list)
    for iso3, sess in cs_list:
        country_sessions[iso3].append(sess)
    for iso3 in country_sessions:
        country_sessions[iso3].sort()

    prev_cs_idx = np.full(NN, -1, dtype=np.int32)
    next_cs_idx = np.full(NN, -1, dtype=np.int32)
    is_first    = np.zeros(NN, dtype=bool)

    for iso3, sessions in country_sessions.items():
        for t_idx, sess in enumerate(sessions):
            ii = cs_idx[(iso3, sess)]
            if t_idx == 0:
                is_first[ii] = True
                if len(sessions) > 1:
                    next_cs_idx[ii] = cs_idx[(iso3, sessions[1])]
            if t_idx > 0:
                prev_cs_idx[ii] = cs_idx[(iso3, sessions[t_idx - 1])]

    return prev_cs_idx, next_cs_idx, is_first


# ── Initialisation ────────────────────────────────────────────────────────────

def _init_gamma(
    y_obs: np.ndarray,
    beta_obs_idx: np.ndarray,
    VoteN: np.ndarray,
    TT: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Initialise cutpoints from empirical vote fractions (matching BSV gStart)."""
    n_yes = np.bincount(beta_obs_idx, weights=(y_obs == 1).astype(float), minlength=TT)
    n_abs = np.bincount(beta_obs_idx, weights=(y_obs == 2).astype(float), minlength=TT)
    frac_yes = n_yes / np.maximum(VoteN, 1)
    frac_abs = n_abs / np.maximum(VoteN, 1)
    gamma1 = -1.0 + 2.0 * frac_yes
    gamma2 = -1.0 + 2.0 * (frac_yes + frac_abs)
    gamma1 = np.clip(gamma1, -_GAMMA_BOUNDS + 0.1, _GAMMA_BOUNDS - 0.1)
    gamma2 = np.clip(gamma2, gamma1 + 1e-3, _GAMMA_BOUNDS - 0.1)
    return gamma1, gamma2


def _init_beta(
    y_obs: np.ndarray,
    beta_obs_idx: np.ndarray,
    theta_obs_idx: np.ndarray,
    cs_list: list,
    TT: int,
) -> np.ndarray:
    """Initialise beta from US vs Russia vote polarity (matching BSV Beta init).

    beta = +1 when US voted No (3) and Russia voted Yes (1) → positive discrimination
    beta = −1 when US voted Yes (1) and Russia voted No (3) → negative discrimination
    beta =  0 when both voted the same or both absent
    """
    cs_idx = {cs: i for i, cs in enumerate(cs_list)}

    # Build per-resolution vote maps {ii → v} for US and Russia
    usa_sessions   = {sess: cs_idx[(iso3, sess)]
                      for iso3, sess in cs_list if iso3 == _ISO3_USA}
    russia_sessions = {sess: cs_idx[(iso3, sess)]
                       for iso3, sess in cs_list if iso3 == _ISO3_RUSSIA}

    usa_vote_by_res    = np.full(TT, 0, dtype=np.int8)
    russia_vote_by_res = np.full(TT, 0, dtype=np.int8)
    for k in range(len(y_obs)):
        cs_i = theta_obs_idx[k]
        iso3, sess = cs_list[cs_i]
        res_j = beta_obs_idx[k]
        if iso3 == _ISO3_USA:
            usa_vote_by_res[res_j] = y_obs[k]
        elif iso3 == _ISO3_RUSSIA:
            russia_vote_by_res[res_j] = y_obs[k]

    beta = np.zeros(TT, dtype=np.float64)
    beta[usa_vote_by_res > russia_vote_by_res]  =  1.0  # US more No than Russia
    beta[usa_vote_by_res < russia_vote_by_res]  = -1.0  # US more Yes than Russia
    return beta


def _init_theta(cs_list: list, NN: int) -> np.ndarray:
    """Initialise theta with US = +3, Russia = −2, others = 0 (matching BSV)."""
    theta = np.zeros(NN)
    for i, (iso3, _) in enumerate(cs_list):
        if iso3 == _ISO3_USA:
            theta[i] = 3.0
        elif iso3 == _ISO3_RUSSIA:
            theta[i] = -2.0
    return theta


# ── Gibbs sampler ─────────────────────────────────────────────────────────────

def _run_gibbs(
    data: dict,
    smooth_vec: np.ndarray,
    prev_cs_idx: np.ndarray,
    next_cs_idx: np.ndarray,
    is_first: np.ndarray,
    n_iter: int,
    n_burn: int,
    thin: int,
    rng: np.random.Generator,
    print_every: int = 100,
) -> tuple[np.ndarray, np.ndarray]:
    """Run the BSV Gibbs sampler.

    Returns
    -------
    theta_mean : (NN,) posterior mean of ideal points across thinned samples
    theta_sd   : (NN,) posterior standard deviation
    """
    y_obs         = data["y_obs"]
    theta_obs_idx = data["theta_obs_idx"]
    beta_obs_idx  = data["beta_obs_idx"]
    cs_list       = data["cs_list"]
    NN, TT, ObsN  = data["NN"], data["TT"], data["ObsN"]
    IndN          = data["IndN"]
    VoteN         = data["VoteN"]

    # ── Initialise parameters ──────────────────────────────────────────────
    theta   = _init_theta(cs_list, NN)
    beta    = _init_beta(y_obs, beta_obs_idx, theta_obs_idx, cs_list, TT)
    gamma1, gamma2 = _init_gamma(y_obs, beta_obs_idx, VoteN, TT)

    # Latent Z: sample from TN(0, 1, glo, ghi) given initial gammas
    gamma1_obs = gamma1[beta_obs_idx]
    gamma2_obs = gamma2[beta_obs_idx]
    glo = np.where(y_obs == 1, -99.0, np.where(y_obs == 2, gamma1_obs, gamma2_obs))
    ghi = np.where(y_obs == 1, gamma1_obs, np.where(y_obs == 2, gamma2_obs, 99.0))
    U   = rng.uniform(size=ObsN)
    pa, pb = _norm.cdf(glo), _norm.cdf(ghi)
    Z   = np.clip(_norm.ppf(pa + U * (pb - pa)), -_Z_CLAMP, _Z_CLAMP)

    # theta_mean is the posterior mean (unrescaled) used as next-iter lag prior
    theta_mean = theta.copy()

    # prior variance for each country-session
    prior_var  = smooth_vec * _SMOOTH * _S2_THETA_PRIOR   # (NN,)
    prior_prec = 1.0 / prior_var                           # (NN,)

    n_store   = n_iter // thin
    theta_store = np.empty((n_store, NN))
    store_ptr   = 0
    total_iters = n_iter + n_burn
    t0 = time.time()

    for kk in range(1, total_iters + 1):

        # ── Lag theta prior (random-walk mean for this iteration) ──────────
        lag_theta = np.zeros(NN)

        # Most countries: use previous session's posterior mean
        mask = prev_cs_idx >= 0
        lag_theta[mask] = theta_mean[prev_cs_idx[mask]]

        # First session of each country: use the next session (BSV behaviour)
        mask_first = is_first & (next_cs_idx >= 0)
        lag_theta[mask_first] = theta_mean[next_cs_idx[mask_first]]

        # ── Step 1: Sample θ (conjugate Gaussian posterior) ───────────────
        beta_obs = beta[beta_obs_idx]

        lik_prec      = np.bincount(theta_obs_idx, weights=beta_obs ** 2, minlength=NN)
        lik_mean_num  = np.bincount(theta_obs_idx, weights=beta_obs * Z,  minlength=NN)

        post_prec  = lik_prec + prior_prec
        var_theta  = 1.0 / post_prec
        theta_mean = var_theta * (lik_mean_num + lag_theta * prior_prec)

        theta = rng.normal(theta_mean, np.sqrt(var_theta))
        theta = np.clip(theta, -_THETA_CLAMP, _THETA_CLAMP)

        # Scale identification: mean = 0, std = 1
        mu_t, sd_t = theta.mean(), theta.std()
        if sd_t > 1e-9:
            theta = (theta - mu_t) / sd_t

        # Expand rescaled theta to observation level
        theta_obs = theta[theta_obs_idx]
        beta_obs  = beta[beta_obs_idx]   # unchanged
        mu_obs    = beta_obs * theta_obs  # (ObsN,)

        # ── Step 2: Update γ₁, γ₂ via Metropolis–Hastings ────────────────
        # Proposal: truncated normal random walk
        u1 = rng.uniform(size=TT)
        cdf_g2 = _norm.cdf((gamma2 - gamma1) / _SIGMA_MH)
        cdf_lo = _norm.cdf((-_GAMMA_BOUNDS - gamma1) / _SIGMA_MH)
        cand_g1 = gamma1 + _SIGMA_MH * _norm.ppf(u1 * cdf_g2 + cdf_lo * (1.0 - u1))

        u2 = rng.uniform(size=TT)
        cdf_hi  = _norm.cdf((_GAMMA_BOUNDS - gamma2) / _SIGMA_MH)
        cdf_cg1 = _norm.cdf((cand_g1 - gamma2) / _SIGMA_MH)
        cand_g2 = gamma2 + _SIGMA_MH * _norm.ppf(u2 * cdf_hi + cdf_cg1 * (1.0 - u2))

        # Likelihood per observation under current and candidate gammas
        cg1_obs = cand_g1[beta_obs_idx]
        cg2_obs = cand_g2[beta_obs_idx]
        g1_obs  = gamma1[beta_obs_idx]
        g2_obs  = gamma2[beta_obs_idx]

        cur_lo = np.where(y_obs == 1, -99.0, np.where(y_obs == 2, g1_obs,  g2_obs))
        cur_hi = np.where(y_obs == 1, g1_obs,  np.where(y_obs == 2, g2_obs,  99.0))
        can_lo = np.where(y_obs == 1, -99.0, np.where(y_obs == 2, cg1_obs, cg2_obs))
        can_hi = np.where(y_obs == 1, cg1_obs, np.where(y_obs == 2, cg2_obs, 99.0))

        cur_lik = np.clip(_norm.cdf(cur_hi - mu_obs) - _norm.cdf(cur_lo - mu_obs), 1e-12, None)
        can_lik = np.clip(_norm.cdf(can_hi - mu_obs) - _norm.cdf(can_lo - mu_obs), 1e-12, None)

        log_lr  = np.log(can_lik) - np.log(cur_lik)
        log_lr_res = np.bincount(beta_obs_idx, weights=log_lr, minlength=TT)

        # Hastings correction for asymmetric truncated-normal proposals
        log_h = (
            np.log(_norm.sf((cand_g1 - gamma2) / _SIGMA_MH) + 1e-300)
            - np.log(_norm.sf((gamma1 - cand_g2) / _SIGMA_MH) + 1e-300)
        )
        log_accept = log_lr_res + log_h
        accept = rng.uniform(size=TT) < np.exp(np.clip(log_accept, -50.0, 0.0))
        gamma1 = np.where(accept, cand_g1, gamma1)
        gamma2 = np.where(accept, cand_g2, gamma2)

        # Refresh per-obs gamma after update
        g1_obs = gamma1[beta_obs_idx]
        g2_obs = gamma2[beta_obs_idx]

        # ── Step 3: Sample Z (truncated normal) ───────────────────────────
        glo = np.where(y_obs == 1, -99.0, np.where(y_obs == 2, g1_obs, g2_obs))
        ghi = np.where(y_obs == 1, g1_obs, np.where(y_obs == 2, g2_obs, 99.0))
        a, b = glo - mu_obs, ghi - mu_obs
        pa, pb = _norm.cdf(a), _norm.cdf(b)
        U = rng.uniform(size=ObsN)
        Z = mu_obs + _norm.ppf(pa + U * (pb - pa))
        Z = np.clip(Z, -_Z_CLAMP, _Z_CLAMP)

        # ── Step 4: Sample β (conjugate Gaussian posterior) ───────────────
        lik_prec_b    = np.bincount(beta_obs_idx, weights=theta_obs ** 2, minlength=TT)
        lik_mean_num_b = np.bincount(beta_obs_idx, weights=theta_obs * Z, minlength=TT)
        post_prec_b   = lik_prec_b + 1.0 / _S2_BETA_PRIOR
        var_beta      = 1.0 / post_prec_b
        beta_mean_b   = var_beta * (lik_mean_num_b + _BETA_PRIOR / _S2_BETA_PRIOR)
        beta = rng.normal(beta_mean_b, np.sqrt(var_beta))

        # ── Store posterior samples (post burn-in, thinned) ───────────────
        if kk > n_burn and (kk - n_burn) % thin == 0:
            theta_store[store_ptr] = theta
            store_ptr += 1

        if kk % print_every == 0:
            elapsed = time.time() - t0
            phase = "burn-in" if kk <= n_burn else "sampling"
            log.info("iter %5d/%d  (%s)  %.1fs elapsed", kk, total_iters, phase, elapsed)

    log.info("Sampler finished. %d posterior samples stored.", store_ptr)
    theta_post_mean = theta_store[:store_ptr].mean(axis=0)
    theta_post_sd   = theta_store[:store_ptr].std(axis=0)
    return theta_post_mean, theta_post_sd


# ── DB helpers ────────────────────────────────────────────────────────────────

def _build_iso3_to_country_id(session: Session) -> dict[str, int]:
    rows = session.execute(
        text("SELECT iso3, id FROM countries WHERE iso3 IS NOT NULL")
    ).fetchall()
    return {iso3.upper(): cid for iso3, cid in rows}


# ── Main ──────────────────────────────────────────────────────────────────────

def compute_ideal_points_mcmc(
    db_url: str | None = None,
    csv_path: Path | None = None,
    n_iter: int = 5000,
    n_burn: int = 1000,
    thin: int = 10,
    seed: int = 42,
    dry_run: bool = False,
    print_every: int = 100,
) -> None:
    """Run the BSV Gibbs sampler and write results to country_ideal_points."""
    if csv_path is None:
        csv_path = _DEFAULT_CSV

    engine = get_engine(db_url)
    create_schema(engine)
    with get_session(engine) as session:
        _ensure_schema(session)

    log.info("Loading votes from %s …", csv_path)
    data = _load_votes_ordinal(csv_path)
    cs_list = data["cs_list"]
    NN, TT  = data["NN"], data["TT"]
    log.info("Data: %d country-sessions (NN), %d resolutions (TT), %d obs.",
             NN, TT, data["ObsN"])

    log.info("Computing SmoothVector …")
    smooth_vec = _compute_smooth_vector(cs_list, data["IndN"])

    log.info("Building lag indices …")
    prev_cs_idx, next_cs_idx, is_first = _build_lag_indices(cs_list)

    rng = np.random.default_rng(seed)

    log.info("Starting Gibbs sampler: %d burn-in + %d sampling, thin=%d …",
             n_burn, n_iter, thin)
    theta_mean, theta_sd = _run_gibbs(
        data=data,
        smooth_vec=smooth_vec,
        prev_cs_idx=prev_cs_idx,
        next_cs_idx=next_cs_idx,
        is_first=is_first,
        n_iter=n_iter,
        n_burn=n_burn,
        thin=thin,
        rng=rng,
        print_every=print_every,
    )

    if dry_run:
        log.info("Dry run — skipping DB write.")
        # Print a quick sanity check
        usa_rows = [(cs, theta_mean[i], theta_sd[i])
                    for i, cs in enumerate(cs_list) if cs[0] == "USA"]
        usa_rows.sort(key=lambda x: x[0][1])
        log.info("USA ideal points (first/last 3):")
        for cs, ip, sd in usa_rows[:3] + usa_rows[-3:]:
            log.info("  session %d  ip=%.3f  sd=%.3f", cs[1], ip, sd)
        return

    with get_session(engine) as session:
        iso3_to_cid = _build_iso3_to_country_id(session)

    rows_written = 0
    with get_session(engine) as session:
        for i, (iso3, sess) in enumerate(cs_list):
            year = sess + 1945
            ip   = float(theta_mean[i])
            sd   = float(theta_sd[i])
            cid  = iso3_to_cid.get(iso3.upper())

            session.execute(text("""
                INSERT INTO country_ideal_points
                    (country_id, iso3, year, ideal_point, se, source)
                VALUES (:cid, :iso3, :year, :ip, :se, 'bsv2017_mcmc')
                ON CONFLICT (iso3, year) DO UPDATE
                    SET ideal_point = EXCLUDED.ideal_point,
                        se          = EXCLUDED.se,
                        source      = EXCLUDED.source,
                        country_id  = EXCLUDED.country_id
            """), {"cid": cid, "iso3": iso3, "year": year, "ip": ip, "se": sd})
            rows_written += 1

        session.commit()

    log.info("Wrote %d country-year ideal point rows (source=bsv2017_mcmc).", rows_written)

    with get_session(engine) as session:
        stats = session.execute(text("""
            SELECT min(year), max(year), count(*), count(DISTINCT iso3)
            FROM country_ideal_points WHERE source = 'bsv2017_mcmc'
        """)).fetchone()
        log.info("DB totals (bsv2017_mcmc): years %s–%s | %s rows | %s countries", *stats)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Full dynamic Bayesian IRT ideal points (BSV 2017 Gibbs sampler).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None,
                   help="Database URL (overrides DATABASE_URL)")
    p.add_argument("--csv", default=None,
                   help="Path to ga_voting.csv")
    p.add_argument("--n-iter", type=int, default=5000,
                   help="Post-burn-in sampling iterations")
    p.add_argument("--n-burn", type=int, default=1000,
                   help="Burn-in iterations (discarded)")
    p.add_argument("--thin", type=int, default=10,
                   help="Thinning interval (store every Nth sample)")
    p.add_argument("--seed", type=int, default=42,
                   help="Random seed for reproducibility")
    p.add_argument("--print-every", type=int, default=100,
                   help="Log progress every N iterations")
    p.add_argument("--dry-run", action="store_true",
                   help="Run sampler but do not write to DB")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    compute_ideal_points_mcmc(
        db_url=args.db,
        csv_path=Path(args.csv) if args.csv else None,
        n_iter=args.n_iter,
        n_burn=args.n_burn,
        thin=args.thin,
        seed=args.seed,
        dry_run=args.dry_run,
        print_every=args.print_every,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
