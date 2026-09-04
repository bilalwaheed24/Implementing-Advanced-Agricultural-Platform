"""Biosecurity sequence screening — seed-and-extend local alignment (FR-C1).

Method (ADR-008): a k-mer index over the hazard database provides seeds; each seed
is extended ungapped, and a banded Smith-Waterman local alignment around the seed
produces the reported identity, length and coordinates. This is the same principle
BLAST uses, implemented directly because the BLAST binary cannot be installed in
the target environment.

REAL IMPLEMENTATION (algorithm). DEMO data: the hazard database shipped with this
project contains synthetic motifs, not real pathogen sequences.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

ENGINE_VERSION = "screening-1.0.0"

K = 11                      # seed length
MATCH, MISMATCH, GAP = 2, -3, -5
MIN_SEED_HITS = 1
MAX_HITS_REPORTED = 25
MIN_REPORT_LENGTH = 30      # shorter alignments are chance matches, not evidence
BAND = 150                  # alignment window either side of a seed

VALID_NUCLEOTIDES = re.compile(r"^[ACGTUNRYKMSWBDHV]+$")

# Verdict thresholds (Security/GMO.md §3). Configuration, not magic numbers.
BLOCK_IDENTITY, BLOCK_LENGTH = 0.90, 60
FLAG_IDENTITY, FLAG_LENGTH = 0.75, 40

# Risk-based sensitivity: for the highest-severity agents the cost of a miss is far
# greater than the cost of a human review, so homology is flagged at a lower identity.
# Measured behaviour: a 200 bp construct at 18% divergence from a severity-5 motif
# aligns at ~74.5% identity, which the flat 75% threshold let through as CLEAR.
HIGH_SEVERITY = 4
HIGH_SEVERITY_FLAG_IDENTITY, HIGH_SEVERITY_FLAG_LENGTH = 0.70, 60


class SequenceError(ValueError):
    """The submitted sequence is not acceptable for screening."""


def normalize(sequence: str) -> str:
    """Strip FASTA headers/whitespace, upper-case, and map U->T."""
    lines = [ln.strip() for ln in sequence.splitlines() if not ln.startswith(">")]
    cleaned = "".join(lines).upper().replace(" ", "").replace("U", "T")
    return cleaned


def validate(sequence: str, max_length: int) -> str:
    cleaned = normalize(sequence)
    if not cleaned:
        raise SequenceError("Sequence is empty")
    if len(cleaned) > max_length:
        raise SequenceError(f"Sequence exceeds the maximum length of {max_length} bases")
    if len(cleaned) < K:
        raise SequenceError(f"Sequence must be at least {K} bases")
    if not VALID_NUCLEOTIDES.match(cleaned):
        raise SequenceError("Sequence contains characters outside the IUPAC nucleotide alphabet")
    return cleaned


def reverse_complement(sequence: str) -> str:
    table = str.maketrans("ACGTN", "TGCAN")
    return sequence.translate(table)[::-1]


@dataclass
class HazardRecord:
    id: str
    agent_name: str
    hazard_class: str
    severity: int
    sequence: str


@dataclass
class Hit:
    hazard_id: str
    agent_name: str
    hazard_class: str
    severity: int
    identity: float
    align_length: int
    score: float
    query_start: int
    query_end: int
    subject_start: int
    subject_end: int
    strand: str = "+"

    def as_dict(self) -> dict:
        return {
            "hazard_id": self.hazard_id, "agent_name": self.agent_name,
            "hazard_class": self.hazard_class, "severity": self.severity,
            "identity": round(self.identity, 4), "align_length": self.align_length,
            "score": round(self.score, 2), "query_start": self.query_start,
            "query_end": self.query_end, "subject_start": self.subject_start,
            "subject_end": self.subject_end, "strand": self.strand,
        }


@dataclass
class ScreeningResult:
    verdict: str
    max_identity: float
    hits: list[Hit] = field(default_factory=list)
    hazard_classes: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    engine_version: str = ENGINE_VERSION
    query_length: int = 0

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict, "max_identity": round(self.max_identity, 4),
            "hits": [h.as_dict() for h in self.hits], "hazard_classes": self.hazard_classes,
            "reasons": self.reasons, "engine_version": self.engine_version,
            "query_length": self.query_length,
        }


def build_index(hazards: Iterable[HazardRecord]) -> dict[str, list[tuple[str, int]]]:
    """k-mer index: kmer -> [(hazard_id, offset), ...]."""
    index: dict[str, list[tuple[str, int]]] = {}
    for hazard in hazards:
        seq = normalize(hazard.sequence)
        for i in range(len(seq) - K + 1):
            index.setdefault(seq[i:i + K], []).append((hazard.id, i))
    return index


def _smith_waterman(query: str, subject: str) -> tuple[int, int, int, int, int, int]:
    """Local alignment. Returns (score, matches, length, q_start, q_end, s_start).

    Linear gap penalty; the band is already applied by the caller slicing the inputs.
    """
    n, m = len(query), len(subject)
    if n == 0 or m == 0:
        return 0, 0, 0, 0, 0, 0
    previous = [0] * (m + 1)
    # Traceback via a compact pointer matrix; sequences here are windows (<= ~200 nt).
    pointers = [[0] * (m + 1) for _ in range(n + 1)]
    best, best_i, best_j = 0, 0, 0
    for i in range(1, n + 1):
        current = [0] * (m + 1)
        qi = query[i - 1]
        for j in range(1, m + 1):
            diagonal = previous[j - 1] + (MATCH if qi == subject[j - 1] else MISMATCH)
            up = previous[j] + GAP
            left = current[j - 1] + GAP
            value = max(0, diagonal, up, left)
            current[j] = value
            if value == 0:
                pointers[i][j] = 0
            elif value == diagonal:
                pointers[i][j] = 1
            elif value == up:
                pointers[i][j] = 2
            else:
                pointers[i][j] = 3
            if value > best:
                best, best_i, best_j = value, i, j
        previous = current

    matches = length = 0
    i, j = best_i, best_j
    while i > 0 and j > 0 and pointers[i][j] != 0:
        direction = pointers[i][j]
        if direction == 1:
            matches += query[i - 1] == subject[j - 1]
            length += 1
            i, j = i - 1, j - 1
        elif direction == 2:
            length += 1
            i -= 1
        else:
            length += 1
            j -= 1
    return best, matches, length, i, best_i, j


def _align_window(query: str, subject: str, q_off: int, s_off: int,
                  hazard: HazardRecord, strand: str) -> Hit | None:
    q_lo = max(0, q_off - BAND)
    q_hi = min(len(query), q_off + K + BAND)
    s_lo = max(0, s_off - BAND)
    s_hi = min(len(subject), s_off + K + BAND)
    score, matches, length, q_start, q_end, s_start = _smith_waterman(
        query[q_lo:q_hi], subject[s_lo:s_hi])
    if length == 0:
        return None
    return Hit(
        hazard_id=hazard.id, agent_name=hazard.agent_name, hazard_class=hazard.hazard_class,
        severity=hazard.severity, identity=matches / length, align_length=length, score=float(score),
        query_start=q_lo + q_start, query_end=q_lo + q_end,
        subject_start=s_lo + s_start, subject_end=s_lo + s_start + length, strand=strand,
    )


def screen(query: str, hazards: list[HazardRecord], max_length: int = 100_000) -> ScreeningResult:
    """Screen a query sequence against the hazard database."""
    cleaned = validate(query, max_length)
    index = build_index(hazards)
    hazard_by_id = {h.id: h for h in hazards}

    best_by_hazard: dict[str, Hit] = {}
    for strand, sequence in (("+", cleaned), ("-", reverse_complement(cleaned))):
        seeds: dict[tuple[str, int], int] = {}
        for i in range(len(sequence) - K + 1):
            for hazard_id, offset in index.get(sequence[i:i + K], ()):
                # Group seeds by diagonal so repeated k-mers do not re-align the same region.
                seeds.setdefault((hazard_id, offset - i), i)
        for (hazard_id, diagonal), q_off in seeds.items():
            hazard = hazard_by_id[hazard_id]
            subject = normalize(hazard.sequence)
            s_off = max(0, min(len(subject) - 1, diagonal + q_off))
            hit = _align_window(sequence, subject, q_off, s_off, hazard, strand)
            if hit is None:
                continue
            existing = best_by_hazard.get(hazard_id)
            if existing is None or hit.score > existing.score:
                best_by_hazard[hazard_id] = hit

    candidates = [h for h in best_by_hazard.values() if h.align_length >= MIN_REPORT_LENGTH]
    hits = sorted(candidates, key=lambda h: (-h.score, -h.identity))[:MAX_HITS_REPORTED]
    return _verdict(cleaned, hits)


def _verdict(query: str, hits: list[Hit]) -> ScreeningResult:
    reasons: list[str] = []
    verdict = "CLEAR"
    max_identity = max((h.identity for h in hits), default=0.0)

    def is_significant(hit: Hit) -> bool:
        """Does this hit warrant at least human review?"""
        if hit.identity >= FLAG_IDENTITY and hit.align_length >= FLAG_LENGTH:
            return True
        return (hit.severity >= HIGH_SEVERITY
                and hit.identity >= HIGH_SEVERITY_FLAG_IDENTITY
                and hit.align_length >= HIGH_SEVERITY_FLAG_LENGTH)

    for hit in hits:
        if hit.identity >= BLOCK_IDENTITY and hit.align_length >= BLOCK_LENGTH:
            verdict = "BLOCK"
            reasons.append(
                f"High-confidence homology to {hit.agent_name} ({hit.hazard_class}): "
                f"{hit.identity:.0%} identity over {hit.align_length} bases")
        elif is_significant(hit):
            if verdict != "BLOCK":
                verdict = "FLAG"
            threshold_note = ("" if hit.identity >= FLAG_IDENTITY else
                              f" (flagged at the reduced threshold for severity "
                              f"{hit.severity} agents)")
            reasons.append(
                f"Partial homology to {hit.agent_name} ({hit.hazard_class}): "
                f"{hit.identity:.0%} identity over {hit.align_length} bases{threshold_note}")

    # A severity-5 agent escalates the verdict by one level.
    significant = [h for h in hits if is_significant(h)]
    if significant and max(h.severity for h in significant) >= 5 and verdict == "FLAG":
        verdict = "BLOCK"
        reasons.append("Escalated to BLOCK: matched agent has the highest severity class (5)")

    if not reasons:
        reasons.append("No significant homology to any hazard sequence in the reference database")

    classes = sorted({h.hazard_class for h in significant})
    return ScreeningResult(verdict=verdict, max_identity=max_identity, hits=hits,
                           hazard_classes=classes, reasons=reasons, query_length=len(query))
