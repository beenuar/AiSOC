#!/usr/bin/env python3
"""Measure what semantic recall adds over the full-text search it sits beside.

Depth 9.2 (parity 6.5), the half that stops the rest being an assertion. The
parity item asks for "the accuracy delta"; this is the delta that can be
measured without a funded model, and the one that is actually about the thing
9.2 builds.

What is measured
----------------
Retrieval, not verdicts. Each probe is an analyst's question and the one
memory item that answers it. Two retrievers run over the same corpus:

``lexical``
    The baseline the knowledge base has always used: Postgres
    ``to_tsvector``/``plainto_tsquery`` ranking, reproduced here as an
    English-stemmed bag-of-words with ``ts_rank``-shaped scoring so the
    comparison needs no database. The reproduction is approximate and the
    report says so; what it has to be is *the same kind of retriever*, and a
    stemmed term-overlap ranker is exactly that.

``semantic``
    Cosine over embeddings from whichever backend this deployment has
    configured, through ``app.services.semantic_memory``.

Reported: recall@1, recall@3, recall@5 and mean reciprocal rank for each, the
delta, and the measured lexical overlap between each probe and its answer.

Why the overlap figure is published beside the scores
-----------------------------------------------------
A probe set written in the documents' own words would hand the lexical
baseline a score it could not earn on a real analyst's question, and the
delta would look small for a reason that has nothing to do with the
retriever. Publishing the overlap lets a reader check the probes really are
phrased differently rather than take the design note on trust.

Honest unavailability
---------------------
With no embedding backend the semantic rows read **"not measured"**, never
``0.000``. A reader who sees a zero concludes the retriever was graded and
failed. This is the same rule ``run_model_matrix.py`` follows for an
unfunded model row.

Usage:
    python3 scripts/score_memory_recall.py
    python3 scripts/score_memory_recall.py --json
    python3 scripts/score_memory_recall.py --self-test

Exit codes: 0 scored (or an announced skip), 1 the probe set is unusable.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

PROBES_REL = Path("services/api/tests/eval_data/memory_recall_probes_v1.json")

#: Rank positions reported. @1 is what a prompt with room for one runbook
#: gets; @5 is what a context bundle gets.
AT_K = (1, 3, 5)

#: Snowball-ish suffix stripping. Not a real stemmer: a dependency for a
#: scoring script is a dependency in every image that installs this service's
#: requirements, and the baseline only has to be the *same kind* of retriever
#: as Postgres's, not a bit-exact reimplementation of it. The report says so.
_SUFFIXES = ("ingly", "edly", "ing", "ed", "ly", "es", "s")

#: Postgres's english stop-word list, trimmed to the words these probes use.
#: Present so the baseline is not scored down for matching "the".
_STOPWORDS = frozenset(
    """a an and are as at be been before but by do does for from had has have how i if in into is it
    its of on onto or should so than that the their them then there these they this to was were what
    when where which who will with you your do not no any every""".split()
)

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9._/-]*")


def stem(word: str) -> str:
    for suffix in _SUFFIXES:
        if len(word) > len(suffix) + 2 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def tokens(text: str) -> list[str]:
    return [stem(w) for w in _WORD_RE.findall(text.lower()) if w not in _STOPWORDS and len(w) > 1]


def lexical_rank(query: str, corpus: list[dict[str, Any]]) -> list[str]:
    """Item ids ordered the way a ``ts_rank`` search would order them.

    ``ts_rank`` weights by term frequency and normalises by document length;
    this does the same with a cosine over term-frequency vectors, which has
    the property that matters for the comparison: a document only ranks if it
    *contains the words*, which is precisely what the baseline cannot do and
    the measurement is about.
    """
    q = Counter(tokens(query))
    if not q:
        return []
    scored: list[tuple[float, str]] = []
    for item in corpus:
        d = Counter(tokens(f"{item.get('title', '')} {item['content']}"))
        shared = set(q) & set(d)
        if not shared:
            continue
        dot = sum(q[t] * d[t] for t in shared)
        norm = math.sqrt(sum(v * v for v in q.values())) * math.sqrt(sum(v * v for v in d.values()))
        scored.append((dot / norm if norm else 0.0, item["id"]))
    scored.sort(key=lambda pair: (-pair[0], pair[1]))
    return [item_id for _, item_id in scored]


def overlap(query: str, item: dict[str, Any]) -> float:
    """Share of the probe's content words that appear in the answering item."""
    q = set(tokens(query))
    if not q:
        return 0.0
    d = set(tokens(f"{item.get('title', '')} {item['content']}"))
    return len(q & d) / len(q)


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


async def semantic_rank_all(probes: list[dict[str, Any]], corpus: list[dict[str, Any]]) -> dict[str, list[str]] | str:
    """Ranked item ids per probe, or a sentence saying why it could not run.

    Returns a string rather than raising so the caller can print
    "not measured" with the reason, which is the honest row.
    """
    sys.path.insert(0, str(repo_root() / "services" / "api"))
    try:
        from app.services.semantic_memory import EmbeddingsUnavailable, embed  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        return f"the API service could not be imported ({type(exc).__name__}: {exc})"

    doc_texts = [f"{item.get('title', '')}\n\n{item['content']}".strip() for item in corpus]
    try:
        doc_vectors, model = await embed(doc_texts)
        query_vectors, _ = await embed([p["query"] for p in probes])
    except EmbeddingsUnavailable as exc:
        return str(exc)
    except Exception as exc:  # noqa: BLE001
        return f"the embedding backend failed ({type(exc).__name__}: {exc})"

    out: dict[str, list[str]] = {}
    for index, probe in enumerate(probes):
        scored = [(_cosine(query_vectors[index], doc_vectors[j]), corpus[j]["id"]) for j in range(len(corpus))]
        scored.sort(key=lambda pair: (-pair[0], pair[1]))
        out[probe["id"]] = [item_id for _, item_id in scored]
    out["__model__"] = [model]
    return out


def score(ranked: dict[str, list[str]], probes: list[dict[str, Any]]) -> dict[str, Any]:
    hits = dict.fromkeys(AT_K, 0)
    reciprocal = 0.0
    misses: list[str] = []
    for probe in probes:
        order = ranked.get(probe["id"], [])
        try:
            position = order.index(probe["expected"]) + 1
        except ValueError:
            misses.append(probe["id"])
            continue
        reciprocal += 1.0 / position
        for k in AT_K:
            if position <= k:
                hits[k] += 1
    total = len(probes)
    return {
        **{f"recall_at_{k}": hits[k] / total for k in AT_K},
        "mrr": reciprocal / total,
        "probes": total,
        "not_retrieved_at_all": misses,
    }


def load_probes(root: Path) -> dict[str, Any]:
    return json.loads((root / PROBES_REL).read_text(encoding="utf-8"))


def _fmt(value: float) -> str:
    return f"{value:.3f}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    root = repo_root()
    try:
        data = load_probes(root)
    except (OSError, json.JSONDecodeError) as exc:
        # An unreadable probe set is a refusal with a sentence, not a
        # traceback: a scorer that cannot find its corpus must not look like
        # a crashed scorer that might have measured something.
        print(f"score_memory_recall: cannot read {PROBES_REL} ({exc}) — nothing to score", file=sys.stderr)
        return 1
    corpus = data["corpus"]
    probes = data["probes"]

    by_id = {item["id"]: item for item in corpus}
    unknown = [p["id"] for p in probes if p["expected"] not in by_id]
    if unknown:
        print(f"probe set names items that are not in the corpus: {unknown}", file=sys.stderr)
        return 1
    if len(probes) < 10:
        # Small-corpus refusal, the same reasoning `aisoc_benchmark.replay`
        # applies to headline accuracy: a rate over a handful of probes is
        # misleading in the direction that sells.
        print(f"only {len(probes)} probe(s); refusing to publish a rate", file=sys.stderr)
        return 1

    lexical = {p["id"]: lexical_rank(p["query"], corpus) for p in probes}
    lexical_score = score(lexical, probes)

    semantic_raw = asyncio.run(semantic_rank_all(probes, corpus))
    semantic_score: dict[str, Any] | None = None
    semantic_reason: str | None = None
    semantic_model: str | None = None
    if isinstance(semantic_raw, str):
        semantic_reason = semantic_raw
    else:
        semantic_model = (semantic_raw.pop("__model__", [""]) or [""])[0]
        semantic_score = score(semantic_raw, probes)

    overlaps = [overlap(p["query"], by_id[p["expected"]]) for p in probes]
    mean_overlap = sum(overlaps) / len(overlaps)

    result = {
        "probe_set": str(PROBES_REL),
        "is_synthetic": bool(data.get("is_synthetic")),
        "corpus_items": len(corpus),
        "probes": len(probes),
        "mean_lexical_overlap": mean_overlap,
        "lexical": lexical_score,
        "semantic": semantic_score,
        "semantic_model": semantic_model,
        "semantic_not_measured_because": semantic_reason,
    }

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print("Memory recall — lexical baseline against semantic recall")
    print(f"  probe set            {PROBES_REL} (synthetic: {result['is_synthetic']})")
    print(f"  corpus               {len(corpus)} items, {len(probes)} probes")
    print(f"  mean lexical overlap {_fmt(mean_overlap)}  (share of a probe's words present in its answer)")
    print()
    header = f"  {'metric':<18}{'lexical':>12}{'semantic':>14}{'delta':>12}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for key in [f"recall_at_{k}" for k in AT_K] + ["mrr"]:
        lex = lexical_score[key]
        if semantic_score is None:
            print(f"  {key:<18}{_fmt(lex):>12}{'not measured':>14}{'—':>12}")
        else:
            sem = semantic_score[key]
            print(f"  {key:<18}{_fmt(lex):>12}{_fmt(sem):>14}{sem - lex:>+12.3f}")
    print()
    if semantic_score is None:
        # Never `0.000`. A reader who sees a zero concludes the retriever was
        # graded and failed.
        print(f"  semantic recall NOT MEASURED: {semantic_reason}")
    else:
        print(f"  semantic backend model: {semantic_model}")
        if lexical_score["not_retrieved_at_all"]:
            print(f"  lexical returned nothing at all for: {', '.join(lexical_score['not_retrieved_at_all'])}")
        if semantic_score["not_retrieved_at_all"]:
            print(f"  semantic returned nothing at all for: {', '.join(semantic_score['not_retrieved_at_all'])}")
    print()
    print("  The lexical row reproduces Postgres ts_rank's *kind* of retrieval (stemmed term")
    print("  overlap, length-normalised), not its exact scoring. The comparison is between a")
    print("  retriever that needs the words and one that does not.")
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def _rule_self_test() -> list[tuple[str, bool]]:
    root = repo_root()
    data = load_probes(root)
    corpus = data["corpus"]
    probes = data["probes"]
    by_id = {item["id"]: item for item in corpus}

    perfect = {p["id"]: [p["expected"]] for p in probes}
    perfect_score = score(perfect, probes)
    empty_score = score({p["id"]: [] for p in probes}, probes)
    # Rank the right answer second everywhere.
    second = {p["id"]: ["m-backup-runbook" if p["expected"] != "m-backup-runbook" else "m-travel", p["expected"]] for p in probes}
    second_score = score(second, probes)

    return [
        ("every probe names an item in the corpus", all(p["expected"] in by_id for p in probes)),
        ("a perfect ranking scores 1.0 at every k", all(perfect_score[f"recall_at_{k}"] == 1.0 for k in AT_K)),
        (
            "an empty ranking scores 0.0, and names every miss",
            empty_score["mrr"] == 0.0 and len(empty_score["not_retrieved_at_all"]) == len(probes),
        ),
        (
            "the right answer in second place scores 0 at k=1 and 1 at k=3",
            second_score["recall_at_1"] == 0.0 and second_score["recall_at_3"] == 1.0,
        ),
        ("MRR for a second-place answer is 0.5", abs(second_score["mrr"] - 0.5) < 1e-9),
        (
            "the probes really are low-overlap with their answers (mean < 0.40)",
            (sum(overlap(p["query"], by_id[p["expected"]]) for p in probes) / len(probes)) < 0.40,
        ),
        (
            "the lexical baseline is a real retriever, not a stub: it finds at least one answer",
            any(p["expected"] in lexical_rank(p["query"], corpus)[:3] for p in probes),
        ),
    ]


if __name__ == "__main__":
    if SELF_TEST_FLAG in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, extra=_rule_self_test()))
    sys.exit(main())
