"""Unit tests for scripts/compute_vote_predictions.py."""
from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.compute_vote_predictions import (
    _FEATURE_COLS,
    _CLASSES,
    _DEFAULT_ANOMALY_THRESHOLD,
    _rows_to_arrays,
    _train,
)


def _make_row(
    cv_id: int = 1,
    actual: str = "yes",
    year: int = 2010,
    ideal_point: float | None = 0.5,
    issue_me: bool | None = None,
    us_sponsored: bool = False,
    n_sponsors: int = 5,
) -> dict:
    return {
        "country_vote_id": cv_id,
        "actual": actual,
        "year": year,
        "ideal_point": ideal_point,
        "issue_me": issue_me,
        "issue_nu": None,
        "issue_co": None,
        "issue_hr": None,
        "issue_ec": None,
        "issue_di": None,
        "important_vote": None,
        "n_sponsors": n_sponsors,
        "us_sponsored": us_sponsored,
        "ru_sponsored": False,
        "cn_sponsored": False,
    }


class TestRowsToArrays:
    def test_shape(self):
        rows = [_make_row(cv_id=i) for i in range(5)]
        X, y, ids = _rows_to_arrays(rows)
        assert X.shape == (5, len(_FEATURE_COLS))
        assert y.shape == (5,)
        assert len(ids) == 5

    def test_label_encoding(self):
        rows = [
            _make_row(actual="yes"),
            _make_row(actual="no"),
            _make_row(actual="abstain"),
        ]
        _, y, _ = _rows_to_arrays(rows)
        assert list(y) == [0, 1, 2]

    def test_ids_preserved(self):
        rows = [_make_row(cv_id=10), _make_row(cv_id=20), _make_row(cv_id=30)]
        _, _, ids = _rows_to_arrays(rows)
        assert ids == [10, 20, 30]

    def test_none_becomes_nan(self):
        row = _make_row(ideal_point=None, issue_me=None)
        X, _, _ = _rows_to_arrays([row])
        ideal_idx = _FEATURE_COLS.index("ideal_point")
        issue_idx = _FEATURE_COLS.index("issue_me")
        assert math.isnan(X[0, ideal_idx])
        assert math.isnan(X[0, issue_idx])

    def test_bool_feature_encoded_as_float(self):
        row = _make_row(us_sponsored=True)
        X, _, _ = _rows_to_arrays([row])
        idx = _FEATURE_COLS.index("us_sponsored")
        assert X[0, idx] == 1.0

    def test_float_feature_preserved(self):
        row = _make_row(ideal_point=0.75)
        X, _, _ = _rows_to_arrays([row])
        idx = _FEATURE_COLS.index("ideal_point")
        assert X[0, idx] == pytest.approx(0.75)

    def test_year_feature(self):
        row = _make_row(year=1992)
        X, _, _ = _rows_to_arrays([row])
        idx = _FEATURE_COLS.index("year")
        assert X[0, idx] == 1992.0


class TestTrain:
    """Smoke-test that the classifier trains and predicts 3 classes."""

    def _synthetic_data(self, n: int = 300) -> tuple[np.ndarray, np.ndarray]:
        rng = np.random.default_rng(0)
        # ideal_point is the main feature; higher → yes, lower → no, mid → abstain
        ip = rng.uniform(-2, 2, n)
        y = np.where(ip > 0.5, 0, np.where(ip < -0.5, 1, 2))
        X = rng.normal(0, 0.1, (n, len(_FEATURE_COLS)))
        X[:, _FEATURE_COLS.index("ideal_point")] = ip
        return X, y

    def test_trains_without_error(self):
        X, y = self._synthetic_data()
        clf = _train(X, y)
        assert clf is not None

    def test_predicts_three_classes(self):
        X, y = self._synthetic_data()
        clf = _train(X, y)
        proba = clf.predict_proba(X[:10])
        assert proba.shape == (10, 3)
        assert np.allclose(proba.sum(axis=1), 1.0, atol=1e-6)

    def test_handles_nan_features(self):
        X, y = self._synthetic_data()
        X[0, _FEATURE_COLS.index("issue_me")] = float("nan")
        clf = _train(X, y)
        # Should still predict without error
        clf.predict_proba(X[:1])

    def test_anomaly_score_range(self):
        X, y = self._synthetic_data(600)
        clf = _train(X[:400], y[:400])
        proba = clf.predict_proba(X[400:])
        for i in range(len(proba)):
            actual_int = int(y[400 + i])
            cls_idx = {c: j for j, c in enumerate(clf.classes_)}
            p_actual = proba[i, cls_idx[actual_int]]
            anomaly_score = 1.0 - p_actual
            assert 0.0 <= anomaly_score <= 1.0


class TestConstants:
    def test_classes_list(self):
        assert _CLASSES == ["yes", "no", "abstain"]

    def test_feature_cols_count(self):
        assert len(_FEATURE_COLS) == 13

    def test_anomaly_threshold_default(self):
        assert 0.0 < _DEFAULT_ANOMALY_THRESHOLD < 1.0
