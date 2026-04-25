#!/usr/bin/env python3
"""Train a vote-prediction classifier and flag anomalous country votes.

Trains a gradient-boosting classifier (HistGradientBoostingClassifier) to
predict a country's vote (yes / no / abstain) on a GA resolution, then scores
every historical vote with an anomaly score.  Results land in
``vote_predictions``.

Features
--------
All features are pre-vote information (available before the vote is cast):

  ideal_point     – country's ideal point for the vote year (continuous)
  issue_me        – Palestinian conflict (Voeten coding, bool / NULL)
  issue_nu        – Nuclear weapons (bool / NULL)
  issue_co        – Colonialism (bool / NULL)
  issue_hr        – Human rights (bool / NULL)
  issue_ec        – Economic development (bool / NULL)
  issue_di        – Arms control / disarmament (bool / NULL)
  important_vote  – Voeten "important vote" flag (bool / NULL)
  year            – calendar year of the vote (int)
  n_sponsors      – number of co-sponsors (int)
  us_sponsored    – USA is a co-sponsor (bool)
  ru_sponsored    – Russia / USSR is a co-sponsor (bool)
  cn_sponsored    – China / PRC is a co-sponsor (bool)

NULLs are passed as NaN; HistGradientBoostingClassifier handles them natively.

Scope
-----
Only GA recorded votes with a vote position of yes / no / abstain are
included.  SC votes are excluded (far fewer, structurally different).

Anomaly score
-------------
  anomaly_score = 1 - P(actual_vote)

A score near 1.0 means the model assigned near-zero probability to what the
country actually did — i.e. the vote was very surprising.  ``is_anomaly`` is
set when ``anomaly_score >= --anomaly-threshold`` (default 0.70).

Output table: ``vote_predictions``
-----------------------------------
  country_vote_id  INTEGER  UNIQUE FK → country_votes.id
  p_yes            FLOAT
  p_no             FLOAT
  p_abstain        FLOAT
  predicted        VARCHAR(10)   most likely class
  anomaly_score    FLOAT         1 - P(actual)
  is_anomaly       BOOLEAN
  model_year       INTEGER       last training year
  created_at       DATE

Safe to re-run: uses ``ON CONFLICT (country_vote_id) DO UPDATE``.

Usage
-----
    python scripts/compute_vote_predictions.py --db postgresql://...
    python scripts/compute_vote_predictions.py --eval          # print metrics
    python scripts/compute_vote_predictions.py --year 2023     # single year
    python scripts/compute_vote_predictions.py --anomaly-threshold 0.80
    python scripts/compute_vote_predictions.py --dry-run
    python scripts/compute_vote_predictions.py --verbose
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

_DEFAULT_ANOMALY_THRESHOLD = 0.70
_CLASSES = ["yes", "no", "abstain"]

# ISO3 codes used for sponsor-feature look-ups.
# Russia: "RUS"; USSR (pre-1991) was also "SUN" in some datasets.
_US_ISO3 = {"USA"}
_RU_ISO3 = {"RUS", "SUN"}
_CN_ISO3 = {"CHN"}

# Minimum training samples for the classifier to be meaningful
_MIN_TRAIN_ROWS = 500


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(text("""
            CREATE TABLE IF NOT EXISTS vote_predictions (
                id               SERIAL  PRIMARY KEY,
                country_vote_id  INTEGER NOT NULL UNIQUE
                                 REFERENCES country_votes(id) ON DELETE CASCADE,
                p_yes            FLOAT   NOT NULL,
                p_no             FLOAT   NOT NULL,
                p_abstain        FLOAT   NOT NULL,
                predicted        VARCHAR(10) NOT NULL,
                anomaly_score    FLOAT   NOT NULL,
                is_anomaly       BOOLEAN NOT NULL,
                model_year       INTEGER NOT NULL,
                created_at       DATE    NOT NULL
            )
            """))
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_vp_country_vote "
            "ON vote_predictions (country_vote_id)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_vp_is_anomaly "
            "ON vote_predictions (is_anomaly) WHERE is_anomaly"
        )
    )
    session.commit()


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

_FEATURE_QUERY = """
SELECT
    cv.id                     AS country_vote_id,
    cv.vote_position          AS actual,
    EXTRACT(YEAR FROM d.date)::int AS year,
    cip.ideal_point           AS ideal_point,
    r.issue_me,
    r.issue_nu,
    r.issue_co,
    r.issue_hr,
    r.issue_ec,
    r.issue_di,
    r.important_vote,
    COALESCE(sp.n_sponsors, 0)           AS n_sponsors,
    COALESCE(sp.us_sponsored,  FALSE)    AS us_sponsored,
    COALESCE(sp.ru_sponsored,  FALSE)    AS ru_sponsored,
    COALESCE(sp.cn_sponsored,  FALSE)    AS cn_sponsored
FROM country_votes cv
JOIN votes v         ON v.id  = cv.vote_id
JOIN documents d     ON d.id  = v.document_id
JOIN resolutions r   ON r.id  = v.resolution_id
LEFT JOIN country_ideal_points cip
    ON  cip.country_id = cv.country_id
    AND cip.year       = EXTRACT(YEAR FROM d.date)::int
LEFT JOIN (
    SELECT
        resolution_id,
        COUNT(*)                                    AS n_sponsors,
        BOOL_OR(c.iso3 IN ('USA'))                  AS us_sponsored,
        BOOL_OR(c.iso3 IN ('RUS','SUN'))            AS ru_sponsored,
        BOOL_OR(c.iso3 IN ('CHN'))                  AS cn_sponsored
    FROM resolution_sponsors rs
    LEFT JOIN countries c ON c.id = rs.country_id
    GROUP BY resolution_id
) sp ON sp.resolution_id = r.id
WHERE d.body           = 'GA'
  AND v.vote_type      = 'recorded'
  AND cv.vote_position IN ('yes', 'no', 'abstain')
  AND d.date IS NOT NULL
  {year_filter}
ORDER BY year, cv.id
"""

_FEATURE_COLS = [
    "ideal_point",
    "issue_me",
    "issue_nu",
    "issue_co",
    "issue_hr",
    "issue_ec",
    "issue_di",
    "important_vote",
    "year",
    "n_sponsors",
    "us_sponsored",
    "ru_sponsored",
    "cn_sponsored",
]


def _fetch_rows(session: Session, year: int | None = None) -> list[dict[str, Any]]:
    year_filter = f"AND EXTRACT(YEAR FROM d.date)::int = {year}" if year else ""
    sql = _FEATURE_QUERY.format(year_filter=year_filter)
    rows = session.execute(text(sql)).mappings().fetchall()
    return [dict(r) for r in rows]


def _rows_to_arrays(
    rows: list[dict[str, Any]],
) -> tuple[np.ndarray, np.ndarray, list[int]]:
    """Return (X, y_int, country_vote_ids)."""
    X_list = []
    y_list = []
    ids = []
    label_map = {"yes": 0, "no": 1, "abstain": 2}
    for r in rows:
        feats = []
        for col in _FEATURE_COLS:
            v = r[col]
            if v is None:
                feats.append(float("nan"))
            elif isinstance(v, bool):
                feats.append(float(v))
            else:
                feats.append(float(v))
        X_list.append(feats)
        y_list.append(label_map[r["actual"]])
        ids.append(r["country_vote_id"])
    return np.array(X_list, dtype=np.float64), np.array(y_list, dtype=np.int32), ids


# ---------------------------------------------------------------------------
# Model training and evaluation
# ---------------------------------------------------------------------------


def _train(X: np.ndarray, y: np.ndarray) -> Any:
    from sklearn.ensemble import HistGradientBoostingClassifier

    clf = HistGradientBoostingClassifier(
        max_iter=200,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X, y)
    return clf


def _evaluate(clf: Any, X: np.ndarray, y: np.ndarray) -> None:
    from sklearn.metrics import classification_report, confusion_matrix

    y_pred = clf.predict(X)
    log.info(
        "Classification report (test set):\n%s",
        classification_report(y, y_pred, target_names=_CLASSES),
    )
    log.info(
        "Confusion matrix (rows=actual, cols=predicted):\n%s",
        confusion_matrix(y, y_pred),
    )


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def run(
    session: Session,
    year: int | None = None,
    eval_split: bool = False,
    anomaly_threshold: float = _DEFAULT_ANOMALY_THRESHOLD,
    dry_run: bool = False,
) -> dict[str, int]:
    """Train, predict, write.  Returns {written, anomalies}."""
    _ensure_schema(session)

    log.info("Fetching feature rows …")
    all_rows = _fetch_rows(session)
    if not all_rows:
        log.warning("No rows found — is import_undl_votes.py complete?")
        return {"written": 0, "anomalies": 0}

    all_years = sorted({r["year"] for r in all_rows})
    max_year = max(all_years)
    log.info(
        "Loaded %d country-vote rows, years %d–%d",
        len(all_rows),
        min(all_years),
        max_year,
    )

    X_all, y_all, ids_all = _rows_to_arrays(all_rows)

    # Optional eval: train on first 80% of years, evaluate on last 20%
    if eval_split:
        cutoff = all_years[int(len(all_years) * 0.8)]
        mask_train = X_all[:, _FEATURE_COLS.index("year")] < cutoff
        mask_test = ~mask_train
        log.info(
            "Eval split: train on %d rows (<%d), test on %d rows (≥%d)",
            mask_train.sum(),
            cutoff,
            mask_test.sum(),
            cutoff,
        )
        clf = _train(X_all[mask_train], y_all[mask_train])
        _evaluate(clf, X_all[mask_test], y_all[mask_test])

    # Train on ALL data for production predictions
    log.info("Training on all %d rows …", len(all_rows))
    if len(all_rows) < _MIN_TRAIN_ROWS:
        log.error("Too few rows (%d) to train a meaningful model.", len(all_rows))
        return {"written": 0, "anomalies": 0}

    clf = _train(X_all, y_all)
    log.info("Training complete.")

    # Predict on target set (all or filtered year)
    if year is not None:
        target_rows = [r for r in all_rows if r["year"] == year]
        if not target_rows:
            log.warning("No rows for year %d", year)
            return {"written": 0, "anomalies": 0}
        X_pred, y_pred_true, ids_pred = _rows_to_arrays(target_rows)
    else:
        X_pred, y_pred_true, ids_pred = X_all, y_all, ids_all

    proba = clf.predict_proba(X_pred)  # shape (N, 3): yes/no/abstain
    # clf.classes_ may not be [0,1,2] in sorted order; align columns
    cls_idx = {c: i for i, c in enumerate(clf.classes_)}
    p_yes = proba[:, cls_idx[0]]
    p_no = proba[:, cls_idx[1]]
    p_abstain = proba[:, cls_idx[2]]

    label_map_inv = {0: "yes", 1: "no", 2: "abstain"}
    today = date.today()
    written = 0
    anomalies = 0

    log.info("Writing %d predictions …", len(ids_pred))
    batch: list[dict[str, Any]] = []
    for i, cv_id in enumerate(ids_pred):
        actual_int = int(y_pred_true[i])
        p_actual = float(proba[i, cls_idx[actual_int]])
        anomaly_score = round(1.0 - p_actual, 4)
        is_anomaly = anomaly_score >= anomaly_threshold
        predicted = label_map_inv[int(np.argmax(proba[i]))]

        batch.append(
            {
                "cv_id": cv_id,
                "p_yes": round(float(p_yes[i]), 4),
                "p_no": round(float(p_no[i]), 4),
                "p_abstain": round(float(p_abstain[i]), 4),
                "predicted": predicted,
                "anomaly_score": anomaly_score,
                "is_anomaly": is_anomaly,
                "model_year": max_year,
                "created_at": today,
            }
        )
        if is_anomaly:
            anomalies += 1

        if not dry_run and len(batch) >= 5000:
            _flush(session, batch)
            written += len(batch)
            batch = []

    if not dry_run and batch:
        _flush(session, batch)
        written += len(batch)
        session.commit()
    elif dry_run:
        written = len(ids_pred)

    log.info(
        "%s %d predictions (%d anomalies, threshold=%.2f)",
        "Would write" if dry_run else "Wrote",
        written,
        anomalies,
        anomaly_threshold,
    )
    return {"written": written, "anomalies": anomalies}


def _flush(session: Session, batch: list[dict[str, Any]]) -> None:
    session.execute(
        text("""
            INSERT INTO vote_predictions
                (country_vote_id, p_yes, p_no, p_abstain,
                 predicted, anomaly_score, is_anomaly, model_year, created_at)
            VALUES
                (:cv_id, :p_yes, :p_no, :p_abstain,
                 :predicted, :anomaly_score, :is_anomaly, :model_year, :created_at)
            ON CONFLICT (country_vote_id) DO UPDATE SET
                p_yes         = EXCLUDED.p_yes,
                p_no          = EXCLUDED.p_no,
                p_abstain     = EXCLUDED.p_abstain,
                predicted     = EXCLUDED.predicted,
                anomaly_score = EXCLUDED.anomaly_score,
                is_anomaly    = EXCLUDED.is_anomaly,
                model_year    = EXCLUDED.model_year,
                created_at    = EXCLUDED.created_at
            """),
        batch,
    )
    session.flush()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Train vote-prediction model and flag anomalous country votes.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--db", default=None, help="Database URL (overrides DATABASE_URL)")
    p.add_argument(
        "--year",
        type=int,
        default=None,
        help="Only write predictions for this year (model still trains on all data)",
    )
    p.add_argument(
        "--eval",
        action="store_true",
        default=False,
        help="Print classification metrics on an 80/20 time-split before production run",
    )
    p.add_argument(
        "--anomaly-threshold",
        type=float,
        default=_DEFAULT_ANOMALY_THRESHOLD,
        dest="anomaly_threshold",
        help="anomaly_score >= threshold → is_anomaly=True",
    )
    p.add_argument("--dry-run", action="store_true", default=False)
    p.add_argument("--verbose", action="store_true", default=False)
    return p


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    engine = get_engine(args.db)
    create_schema(engine)

    with get_session(engine) as session:
        run(
            session,
            year=args.year,
            eval_split=args.eval,
            anomaly_threshold=args.anomaly_threshold,
            dry_run=args.dry_run,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
