#!/usr/bin/env python3
"""Fit a topic model over speech text and write results to the database.

Two backends are supported:

  lda (default)
    sklearn LatentDirichletAllocation on bag-of-words counts.
    Fast, reproducible, no extra dependencies.  Works best with long texts.

  bertopic
    BERTopic with sentence-transformers + UMAP + HDBSCAN.
    Higher-quality, semantically coherent topics.
    Requires:  pip install bertopic sentence-transformers

Schema created
--------------
  topics (id, topic_num, label, keywords, model, n_topics, created_at)
  speech_topics (speech_id, topic_id, weight)

Re-running the script with the same --model / --n-topics pair is safe: it
deletes and replaces the previous run's rows.

Usage
-----
    python scripts/compute_speech_topics.py --db postgresql://...
    python scripts/compute_speech_topics.py --n-topics 40 --body GA
    python scripts/compute_speech_topics.py --model bertopic --n-topics 30
    python scripts/compute_speech_topics.py --min-words 50 --top-k 12
    python scripts/compute_speech_topics.py --dry-run --verbose
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Any

import json
import os

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from src.db.database import create_schema, get_engine, get_session  # noqa: E402

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_N_TOPICS_DEFAULT = 50
_MIN_WORDS_DEFAULT = 30
_TOP_K_DEFAULT = 10
_WEIGHT_THRESHOLD = 0.10   # LDA: only store topics with probability ≥ this
_BATCH_SIZE = 2_000        # rows per INSERT batch
_UPSERT_SQL = text(
    "INSERT INTO speech_topics (speech_id, topic_id, weight) "
    "VALUES (:sid, :tid, :w) "
    "ON CONFLICT (speech_id, topic_id) "
    "DO UPDATE SET weight = EXCLUDED.weight"
)

# ---------------------------------------------------------------------------
# UN-specific stop words (layered on top of sklearn's English set)
# Words that appear in nearly every speech regardless of topic.
# ---------------------------------------------------------------------------

_UN_STOP_WORDS: frozenset[str] = frozenset(
    [
        # Titles / honorifics
        "mr", "mrs", "ms", "dr", "sir", "madam", "excellency",
        # Structural terms
        "president", "chair", "chairman", "chairwoman", "chairperson",
        "secretary", "general", "assembly", "council", "committee",
        "delegation", "delegations", "representative", "representatives",
        "speaker", "floor",
        # Meeting / document terms
        "meeting", "session", "agenda", "item", "document", "record",
        "resolution", "draft", "paragraph", "article", "annex",
        "amendment", "proposal", "text", "provisions",
        # Common procedural phrases (single words)
        "thank", "thanks", "noted", "note", "like", "also", "shall",
        "would", "could", "may", "must", "indeed", "furthermore",
        "therefore", "however", "regard", "regards", "concerning",
        # Very common UN nouns that span all topics
        "united", "nations", "international", "member", "state", "states",
        "country", "countries", "government", "governments",
        "organization", "organisations", "organizations",
        "community", "cooperation", "global", "world",
    ]
)

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def _ensure_schema(session: Session) -> None:
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS topics (
                id          SERIAL PRIMARY KEY,
                topic_num   INTEGER NOT NULL,
                label       TEXT NOT NULL,
                keywords    TEXT[] NOT NULL,
                model       VARCHAR(20) NOT NULL,
                n_topics    INTEGER NOT NULL,
                created_at  TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
                UNIQUE (topic_num, model, n_topics)
            )
            """
        )
    )
    session.execute(
        text(
            """
            CREATE TABLE IF NOT EXISTS speech_topics (
                id          SERIAL PRIMARY KEY,
                speech_id   INTEGER NOT NULL REFERENCES speeches(id) ON DELETE CASCADE,
                topic_id    INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
                weight      DOUBLE PRECISION NOT NULL,
                UNIQUE (speech_id, topic_id)
            )
            """
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_speech_topics_speech "
            "ON speech_topics (speech_id)"
        )
    )
    session.execute(
        text(
            "CREATE INDEX IF NOT EXISTS ix_speech_topics_topic "
            "ON speech_topics (topic_id)"
        )
    )
    session.commit()
    log.info("Schema ready.")


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def _load_speeches(
    session: Session,
    body: str | None,
    min_words: int,
) -> list[tuple[int, str]]:
    """Return [(speech_id, text)] from the speeches table.

    Filters out very short speeches (fewer than min_words whitespace-delimited
    tokens) and, if body is given, restricts to documents of that body.
    """
    if body:
        rows = session.execute(
            text(
                """
                SELECT s.id, s.text
                FROM speeches s
                JOIN documents d ON d.id = s.document_id
                WHERE d.body = :body
                  AND s.text IS NOT NULL
                  AND s.text <> ''
                ORDER BY s.id
                """
            ),
            {"body": body},
        ).fetchall()
    else:
        rows = session.execute(
            text(
                """
                SELECT id, text
                FROM speeches
                WHERE text IS NOT NULL AND text <> ''
                ORDER BY id
                """
            )
        ).fetchall()

    result = []
    for sid, txt in rows:
        if len(txt.split()) >= min_words:
            result.append((int(sid), txt))
    log.info(
        "Loaded %d speeches (body=%s, min_words=%d).",
        len(result),
        body or "all",
        min_words,
    )
    return result


# ---------------------------------------------------------------------------
# Text pre-processing
# ---------------------------------------------------------------------------

_JUNK_RE = re.compile(r"[^a-zA-Z\s]")


def _clean(text: str) -> str:
    """Lowercase, strip non-alpha characters, collapse whitespace."""
    return _JUNK_RE.sub(" ", text.lower()).strip()


# ---------------------------------------------------------------------------
# LDA backend
# ---------------------------------------------------------------------------


def _fit_lda(
    texts: list[str],
    n_topics: int,
    n_top_words: int,
) -> tuple[Any, Any, np.ndarray[Any, Any], list[list[str]]]:
    """Return (lda_model, vectorizer, doc_topic_matrix, keyword_lists)."""
    from sklearn.decomposition import LatentDirichletAllocation
    from sklearn.feature_extraction.text import CountVectorizer

    log.info("Vectorising %d documents …", len(texts))
    vec = CountVectorizer(
        min_df=5,
        max_df=0.90,
        stop_words=list(
            frozenset(CountVectorizer(stop_words="english").get_stop_words())
            | _UN_STOP_WORDS
        ),
        max_features=20_000,
        preprocessor=_clean,
    )
    X = vec.fit_transform(texts)
    log.info("Vocabulary: %d terms.", X.shape[1])

    log.info("Fitting LDA with %d topics …", n_topics)
    lda = LatentDirichletAllocation(
        n_components=n_topics,
        max_iter=20,
        learning_method="online",
        batch_size=512,
        random_state=42,
        n_jobs=1,
    )
    doc_topic = lda.fit_transform(X)
    log.info("LDA perplexity: %.1f", lda.perplexity(X))

    # Extract top keywords per topic
    vocab = np.array(vec.get_feature_names_out())
    keyword_lists: list[list[str]] = []
    for topic_vec in lda.components_:
        top_idx = topic_vec.argsort()[: -n_top_words - 1 : -1]
        keyword_lists.append(vocab[top_idx].tolist())

    return lda, vec, doc_topic, keyword_lists


# ---------------------------------------------------------------------------
# BERTopic backend (optional)
# ---------------------------------------------------------------------------


def _fit_bertopic(
    texts: list[str],
    n_topics: int,
    n_top_words: int,
) -> tuple[Any, list[int], list[float], list[list[str]]]:
    """Return (model, topic_assignments, probs, keyword_lists).

    topic_assignments[i] is the topic number for texts[i]; -1 = outlier.
    """
    try:
        from bertopic import BERTopic
    except ImportError:
        log.error(
            "BERTopic is not installed. "
            " Run: pip install bertopic sentence-transformers"
        )
        sys.exit(1)

    log.info("Fitting BERTopic (nr_topics=%d) over %d texts …", n_topics, len(texts))
    model = BERTopic(
        nr_topics=n_topics,
        top_n_words=n_top_words,
        calculate_probabilities=True,
        verbose=False,
    )
    assignments, probs_matrix = model.fit_transform(texts)

    # Collect keyword lists in topic_num order
    topic_info = model.get_topic_info()
    keyword_lists = []
    for _, row in topic_info.iterrows():
        topic_num = row["Topic"]
        kw_pairs = model.get_topic(topic_num) or []
        keyword_lists.append([w for w, _ in kw_pairs[:n_top_words]])

    # probs_matrix shape: (n_docs, n_topics); pull dominant probability
    probs: list[float]
    if probs_matrix is not None and hasattr(probs_matrix, "__len__"):
        probs = [float(row[t]) if t != -1 else 1.0
                 for row, t in zip(probs_matrix, assignments)]
    else:
        probs = [1.0] * len(assignments)

    return model, [int(t) for t in assignments], probs, keyword_lists


# ---------------------------------------------------------------------------
# LLM topic labelling
# ---------------------------------------------------------------------------


def _label_topics_with_llm(keyword_lists: list[list[str]]) -> list[str]:
    """Return a short human-readable phrase for each topic using Claude.

    Sends all topics in a single API call.  Falls back to the dot-joined
    keyword string if the API key is absent or the call fails.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        log.warning("ANTHROPIC_API_KEY not set — using keyword fallback for labels.")
        return [" · ".join(kws[:6]) for kws in keyword_lists]

    try:
        import anthropic
    except ImportError:
        log.warning("anthropic package not available — using keyword fallback.")
        return [" · ".join(kws[:6]) for kws in keyword_lists]

    topics_payload = [
        {"id": i, "keywords": kws[:10]} for i, kws in enumerate(keyword_lists)
    ]
    prompt = (
        "You are labelling topics from a topic model trained on UN speeches.\n"
        "For each topic below, return a concise noun phrase (2–5 words) that "
        "captures the theme — e.g. 'Nuclear disarmament', 'Humanitarian aid in conflict'.\n"
        "Return ONLY a JSON array of strings, one label per topic, in the same order.\n\n"
        f"{json.dumps(topics_payload, indent=2)}"
    )

    client = anthropic.Anthropic(api_key=api_key)
    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            temperature=0,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = re.sub(r"^```[a-z]*\n?", "", raw)
            raw = re.sub(r"\n?```$", "", raw)
        labels: list[str] = json.loads(raw)
        if len(labels) != len(keyword_lists):
            raise ValueError(
                f"Expected {len(keyword_lists)} labels, got {len(labels)}"
            )
        log.info("LLM labels generated for %d topics.", len(labels))
        return labels
    except Exception as exc:
        log.warning("LLM labelling failed (%s) — using keyword fallback.", exc)
        return [" · ".join(kws[:6]) for kws in keyword_lists]


# ---------------------------------------------------------------------------
# DB writes
# ---------------------------------------------------------------------------


def _clear_run(session: Session, model: str, n_topics: int) -> None:
    """Delete existing speech_topics and topics rows for this (model, n_topics) run."""
    # Delete speech_topics first (FK)
    session.execute(
        text(
            """
            DELETE FROM speech_topics
            WHERE topic_id IN (
                SELECT id FROM topics WHERE model = :m AND n_topics = :n
            )
            """
        ),
        {"m": model, "n": n_topics},
    )
    session.execute(
        text("DELETE FROM topics WHERE model = :m AND n_topics = :n"),
        {"m": model, "n": n_topics},
    )
    session.flush()
    log.info("Cleared previous %s n_topics=%d run.", model, n_topics)


def _write_topics(
    session: Session,
    keyword_lists: list[list[str]],
    labels: list[str],
    topic_nums: list[int],
    model: str,
    n_topics: int,
) -> dict[int, int]:
    """Insert topic rows; return {topic_num: topics.id}."""
    topic_num_to_id: dict[int, int] = {}
    for topic_num, keywords, label in zip(topic_nums, keyword_lists, labels):
        row = session.execute(
            text(
                """
                INSERT INTO topics (topic_num, label, keywords, model, n_topics)
                VALUES (:num, :label, :kw, :model, :ntopics)
                ON CONFLICT (topic_num, model, n_topics)
                DO UPDATE SET label = EXCLUDED.label, keywords = EXCLUDED.keywords
                RETURNING id
                """
            ),
            {
                "num": topic_num,
                "label": label,
                "kw": keywords,
                "model": model,
                "ntopics": n_topics,
            },
        ).fetchone()
        if row:
            topic_num_to_id[topic_num] = int(row[0])

    session.flush()
    log.info("Wrote %d topic rows.", len(topic_num_to_id))
    return topic_num_to_id


def _write_assignments_lda(
    session: Session,
    speech_ids: list[int],
    doc_topic: np.ndarray[Any, Any],
    topic_num_to_id: dict[int, int],
    threshold: float,
    dry_run: bool,
) -> int:
    """Insert speech_topics rows for LDA output (soft assignments).

    For each speech, stores all topics whose probability meets the threshold.
    """
    total = 0
    batch: list[dict[str, Any]] = []

    for i, sid in enumerate(speech_ids):
        row = doc_topic[i]
        for topic_num, weight in enumerate(row):
            if weight < threshold:
                continue
            tid = topic_num_to_id.get(topic_num)
            if tid is None:
                continue
            batch.append({"sid": sid, "tid": tid, "w": float(weight)})

            if len(batch) >= _BATCH_SIZE:
                if not dry_run:
                    session.execute(
                        _UPSERT_SQL,
                        batch,
                    )
                    session.flush()
                total += len(batch)
                batch = []

    if batch:
        if not dry_run:
            session.execute(
                _UPSERT_SQL,
                batch,
            )
            session.flush()
        total += len(batch)

    return total


def _write_assignments_bertopic(
    session: Session,
    speech_ids: list[int],
    assignments: list[int],
    probs: list[float],
    topic_num_to_id: dict[int, int],
    dry_run: bool,
) -> int:
    """Insert speech_topics rows for BERTopic output (hard assignments)."""
    total = 0
    batch: list[dict[str, Any]] = []

    for sid, topic_num, weight in zip(speech_ids, assignments, probs):
        if topic_num == -1:   # BERTopic outlier cluster
            continue
        tid = topic_num_to_id.get(topic_num)
        if tid is None:
            continue
        batch.append({"sid": sid, "tid": tid, "w": float(weight)})

        if len(batch) >= _BATCH_SIZE:
            if not dry_run:
                session.execute(_UPSERT_SQL, batch)
                session.flush()
            total += len(batch)
            batch = []

    if batch:
        if not dry_run:
            session.execute(
                _UPSERT_SQL,
                batch,
            )
            session.flush()
        total += len(batch)

    return total


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def compute_speech_topics(
    db_url: str | None = None,
    model_name: str = "lda",
    n_topics: int = _N_TOPICS_DEFAULT,
    min_words: int = _MIN_WORDS_DEFAULT,
    n_top_words: int = _TOP_K_DEFAULT,
    weight_threshold: float = _WEIGHT_THRESHOLD,
    body: str | None = None,
    dry_run: bool = False,
) -> None:
    engine = get_engine(db_url)
    create_schema(engine)

    with get_session(engine) as session:
        _ensure_schema(session)

    with get_session(engine) as session:
        pairs = _load_speeches(session, body, min_words)

    if not pairs:
        log.error("No speeches found — nothing to do.")
        return

    speech_ids = [sid for sid, _ in pairs]
    texts = [txt for _, txt in pairs]

    if model_name == "lda":
        _lda, _vec, doc_topic, keyword_lists = _fit_lda(texts, n_topics, n_top_words)
        topic_nums = list(range(n_topics))
        labels = _label_topics_with_llm(keyword_lists)

        with get_session(engine) as session:
            if not dry_run:
                _clear_run(session, model_name, n_topics)
            topic_num_to_id = _write_topics(
                session, keyword_lists, labels, topic_nums, model_name, n_topics
            )
            n_rows = _write_assignments_lda(
                session, speech_ids, doc_topic,
                topic_num_to_id, weight_threshold, dry_run,
            )
            if not dry_run:
                session.commit()

        # Print topic summary
        for i, (label, kws) in enumerate(zip(labels, keyword_lists)):
            log.info("  Topic %2d: %s  [%s]", i, label, " · ".join(kws[:6]))

    elif model_name == "bertopic":
        bt_model, assignments, probs, keyword_lists = _fit_bertopic(
            texts, n_topics, n_top_words
        )
        # BERTopic topic numbers can be non-contiguous (and include -1)
        unique_nums = sorted(set(assignments) - {-1})
        labels = _label_topics_with_llm(keyword_lists)

        with get_session(engine) as session:
            if not dry_run:
                _clear_run(session, model_name, n_topics)
            topic_num_to_id = _write_topics(
                session, keyword_lists, labels, unique_nums, model_name, n_topics
            )
            n_rows = _write_assignments_bertopic(
                session, speech_ids, assignments, probs, topic_num_to_id, dry_run
            )
            if not dry_run:
                session.commit()

    else:
        log.error("Unknown model %r — choose 'lda' or 'bertopic'.", model_name)
        return

    log.info(
        "%s %d speech_topics rows (%d speeches, %d topics).",
        "[dry-run] would write" if dry_run else "Wrote",
        n_rows,
        len(speech_ids),
        n_topics,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--db", default=None,
        help="PostgreSQL connection URL ($DATABASE_URL)",
    )
    p.add_argument(
        "--model", default="lda", choices=["lda", "bertopic"],
        help="Topic model backend (default: lda)",
    )
    p.add_argument(
        "--n-topics", type=int, default=_N_TOPICS_DEFAULT,
        help=f"Number of topics (default: {_N_TOPICS_DEFAULT})",
    )
    p.add_argument(
        "--min-words", type=int, default=_MIN_WORDS_DEFAULT,
        help=f"Minimum words per speech (default: {_MIN_WORDS_DEFAULT})",
    )
    p.add_argument(
        "--top-k", type=int, default=_TOP_K_DEFAULT,
        help=f"Top keywords per topic label (default: {_TOP_K_DEFAULT})",
    )
    p.add_argument(
        "--threshold", type=float, default=_WEIGHT_THRESHOLD,
        help=f"LDA: minimum topic weight to store (default: {_WEIGHT_THRESHOLD})",
    )
    p.add_argument(
        "--body", choices=["GA", "SC"], default=None,
        help="Restrict to speeches from this body (default: all)",
    )
    p.add_argument(
        "--dry-run", action="store_true", help="Fit model but do not write to DB"
    )
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    import os
    db_url = args.db or os.environ.get("DATABASE_URL")
    if not db_url:
        p.error("--db or $DATABASE_URL is required")

    compute_speech_topics(
        db_url=db_url,
        model_name=args.model,
        n_topics=args.n_topics,
        min_words=args.min_words,
        n_top_words=args.top_k,
        weight_threshold=args.threshold,
        body=args.body,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
