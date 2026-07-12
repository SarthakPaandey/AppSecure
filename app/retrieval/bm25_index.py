"""Production-oriented BM25 (Okapi) with inverted index.

Designed for hundreds–tens of thousands of finding documents:
  - inverted index (only candidate docs containing query terms are scored)
  - scan_id filtering without full rescan when possible
  - pure Python (no native deps) so deploy stays simple

Not a synonym pack — pure lexical ranking complementary to dense vectors.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable


_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9\-_/.+]*", re.I)

# Light IR stopwords (not vuln-specific). Keeps IDF mass on content terms.
_STOP = frozenset(
    """
    a an the and or but if then than that this these those is are was were be been being
    do does did can could should would will may might must
    of in on at to for from by with as into about over under after before
    which what when where who how why
    we you i they it our your their my
    any all some each every both few more most other such only same so too very
    not no just also
    """.split()
)


def tokenize(text: str) -> list[str]:
    """Normalize + tokenize for BM25 (lower, strip stop, keep technical tokens)."""
    toks = _TOKEN_RE.findall((text or "").lower())
    out: list[str] = []
    for t in toks:
        if t in _STOP:
            continue
        # normalize cwe-089 style
        if t.startswith("cwe") and t.replace("cwe", "").replace("-", "").isdigit():
            num = re.sub(r"\D", "", t)
            out.append(f"cwe-{num}")
            continue
        out.append(t)
    return out


@dataclass
class BM25Hit:
    doc_id: str
    score: float
    scan_id: str | None = None


@dataclass
class _DocStats:
    doc_id: str
    scan_id: str | None
    length: int
    tfs: dict[str, int]


class BM25Index:
    """Okapi BM25 over an inverted index (k1=1.5, b=0.75 by default)."""

    def __init__(self, *, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self._docs: dict[str, _DocStats] = {}
        self._inverted: dict[str, list[tuple[str, int]]] = defaultdict(list)
        self._df: dict[str, int] = {}
        self._avgdl: float = 0.0
        self._n: int = 0

    def __len__(self) -> int:
        return self._n

    def clear(self) -> None:
        self._docs.clear()
        self._inverted.clear()
        self._df.clear()
        self._avgdl = 0.0
        self._n = 0

    def build(
        self,
        documents: Iterable[tuple[str, str, str | None]],
    ) -> int:
        """Build index from (doc_id, text, scan_id) triples. Replaces previous index."""
        self.clear()
        total_len = 0
        term_doc_freq: dict[str, set[str]] = defaultdict(set)
        inverted_tf: dict[str, list[tuple[str, int]]] = defaultdict(list)

        for doc_id, text, scan_id in documents:
            tokens = tokenize(text)
            if not tokens:
                tokens = ["_empty"]
            tfs: dict[str, int] = defaultdict(int)
            for t in tokens:
                tfs[t] += 1
            length = len(tokens)
            total_len += length
            self._docs[doc_id] = _DocStats(
                doc_id=doc_id, scan_id=scan_id, length=length, tfs=dict(tfs)
            )
            for term, tf in tfs.items():
                inverted_tf[term].append((doc_id, tf))
                term_doc_freq[term].add(doc_id)

        self._n = len(self._docs)
        self._avgdl = (total_len / self._n) if self._n else 0.0
        self._df = {t: len(docs) for t, docs in term_doc_freq.items()}
        self._inverted = dict(inverted_tf)
        return self._n

    def _idf(self, term: str) -> float:
        """Okapi IDF with +1 smoothing (Robertson/Sparck Jones style)."""
        n = self._n or 1
        df = self._df.get(term, 0)
        # log(1 + (N - df + 0.5) / (df + 0.5))
        return math.log(1.0 + (n - df + 0.5) / (df + 0.5))

    def search(
        self,
        query: str,
        *,
        top_k: int = 20,
        scan_id: str | None = None,
        min_score: float = 0.0,
    ) -> list[BM25Hit]:
        if not self._n or not (query or "").strip():
            return []

        q_terms = tokenize(query)
        if not q_terms:
            return []

        # Candidate set = union of postings for query terms
        scores: dict[str, float] = defaultdict(float)
        for term in q_terms:
            postings = self._inverted.get(term)
            if not postings:
                continue
            idf = self._idf(term)
            for doc_id, tf in postings:
                doc = self._docs.get(doc_id)
                if not doc:
                    continue
                if scan_id and doc.scan_id and doc.scan_id != scan_id:
                    continue
                dl = doc.length or 1
                denom = tf + self.k1 * (1.0 - self.b + self.b * dl / (self._avgdl or 1.0))
                scores[doc_id] += idf * (tf * (self.k1 + 1.0) / denom)

        hits = [
            BM25Hit(
                doc_id=doc_id,
                score=score,
                scan_id=(self._docs[doc_id].scan_id if doc_id in self._docs else None),
            )
            for doc_id, score in scores.items()
            if score > min_score
        ]
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits[:top_k]


def reciprocal_rank_fusion(
    ranked_lists: list[list[str]],
    *,
    k: int = 60,
    weights: list[float] | None = None,
) -> list[tuple[str, float]]:
    """RRF fusion of multiple ranked id lists (industry-standard hybrid IR).

    score(d) = sum_i w_i / (k + rank_i(d))
    """
    if not ranked_lists:
        return []
    w = weights or [1.0] * len(ranked_lists)
    if len(w) != len(ranked_lists):
        w = [1.0] * len(ranked_lists)

    scores: dict[str, float] = defaultdict(float)
    for weight, ranking in zip(w, ranked_lists):
        for rank, doc_id in enumerate(ranking, start=1):
            if not doc_id:
                continue
            scores[doc_id] += weight * (1.0 / (k + rank))

    return sorted(scores.items(), key=lambda x: x[1], reverse=True)


@dataclass
class FindingsBM25Index:
    """BM25 facade over vulnerability findings (rebuild on ingest)."""

    index: BM25Index = field(default_factory=BM25Index)

    def rebuild_from_records(self, records: Iterable) -> int:
        """records: iterable of FindingRecord-like objects with to_embed_text()."""
        docs: list[tuple[str, str, str | None]] = []
        for rec in records:
            fid = getattr(rec, "finding_id", None) or getattr(rec, "id", None)
            if not fid:
                continue
            text = rec.to_embed_text() if hasattr(rec, "to_embed_text") else str(rec)
            scan = getattr(rec, "scan_id", None)
            docs.append((str(fid), text, scan))
        return self.index.build(docs)

    def search(
        self,
        query: str,
        *,
        top_k: int = 20,
        scan_id: str | None = None,
    ) -> list[BM25Hit]:
        return self.index.search(query, top_k=top_k, scan_id=scan_id)
