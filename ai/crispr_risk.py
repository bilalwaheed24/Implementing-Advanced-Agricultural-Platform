"""CRISPR gene-edit risk assessment and DURC monitoring (FR-C2, FR-C3).

Rules-first and fully explainable (ADR-012): every contribution to the score is
returned in `reasons`, because the output can block a research proposal and must
withstand challenge by the researcher and the regulator.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

MODEL_VERSION = "crispr-risk-1.0.0"

VALID_GUIDE = re.compile(r"^[ACGTU]{17,25}$")
VALID_PAM = re.compile(r"^[ACGTUNRYKMSWBDHV]{2,8}$")

EDIT_TYPE_WEIGHT = {
    "BASE_EDIT": 0.10,
    "KNOCKOUT": 0.20,
    "KNOCK_IN": 0.35,
    "PRIME_EDIT": 0.30,
    "MULTIPLEX": 0.55,
}

ORGANISM_CLASS_WEIGHT = {
    "CROP": 0.10,
    "MODEL_PLANT": 0.05,
    "PLANT_PATHOGEN": 0.70,
    "INSECT_VECTOR": 0.55,
    "SOIL_MICROBE": 0.30,
}

# Intent phrases that raise concern. Matched case-insensitively as substrings.
INTENT_WEIGHT = {
    "virulence": 0.85,
    "host range": 0.85,
    "host-range": 0.85,
    "toxin": 0.80,
    "pathogenicity": 0.80,
    "resistance to control": 0.75,
    "fungicide resistance": 0.70,
    "herbicide tolerance": 0.15,
    "drought tolerance": 0.05,
    "yield": 0.05,
    "nutrition": 0.05,
    "disease resistance": 0.10,
    "research": 0.10,
}

# Genes whose disruption has outsized ecological or safety consequence.
CRITICAL_TARGETS = {
    "avr": 0.7, "effector": 0.7, "toxin": 0.9, "virulence": 0.9,
    "resistance": 0.4, "sterility": 0.6, "gene drive": 1.0, "drive": 0.8,
}

# DURC concern matrix (GMO.md §5): (organism class, intent marker) -> outcome.
DURC_MATRIX = [
    ("PLANT_PATHOGEN", ("virulence", "pathogenicity", "host range", "host-range"), "BLOCK"),
    ("PLANT_PATHOGEN", ("toxin",), "BLOCK"),
    ("INSECT_VECTOR", ("gene drive", "drive", "sterility"), "BLOCK"),
    ("SOIL_MICROBE", ("toxin", "antibiotic"), "FLAG"),
    ("CROP", ("gene drive", "drive"), "FLAG"),
]

WEIGHTS = {"target": 0.25, "edit": 0.15, "off_target": 0.25, "organism": 0.20, "intent": 0.15}


class CrisprInputError(ValueError):
    """The submitted gene-edit proposal is not well formed."""


@dataclass
class CrisprResult:
    risk_score: float
    risk_level: str
    durc_flag: bool
    off_target_count: int
    off_targets: list[dict] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    model_version: str = MODEL_VERSION

    def as_dict(self) -> dict:
        return {
            "risk_score": round(self.risk_score, 4), "risk_level": self.risk_level,
            "durc_flag": self.durc_flag, "off_target_count": self.off_target_count,
            "off_targets": self.off_targets, "reasons": self.reasons,
            "model_version": self.model_version,
        }


def validate_guide(guide: str, pam: str) -> tuple[str, str]:
    guide_clean = guide.strip().upper().replace("U", "T")
    pam_clean = pam.strip().upper().replace("U", "T")
    if not VALID_GUIDE.match(guide_clean):
        raise CrisprInputError("Guide RNA must be 17-25 bases of A/C/G/T/U")
    if not VALID_PAM.match(pam_clean):
        raise CrisprInputError("PAM must be 2-8 IUPAC nucleotide characters")
    return guide_clean, pam_clean


def _pam_matches(window: str, pam: str) -> bool:
    """IUPAC-aware PAM match (N matches anything, R = A/G, Y = C/T ...)."""
    iupac = {"A": "A", "C": "C", "G": "G", "T": "T", "N": "ACGT", "R": "AG", "Y": "CT",
             "K": "GT", "M": "AC", "S": "CG", "W": "AT", "B": "CGT", "D": "AGT",
             "H": "ACT", "V": "ACG"}
    if len(window) != len(pam):
        return False
    return all(base in iupac.get(code, "") for base, code in zip(window, pam))


def scan_off_targets(guide: str, pam: str, reference: str, max_mismatches: int = 3,
                     limit: int = 50) -> list[dict]:
    """Seed-and-check scan for PAM-adjacent near-matches of the guide.

    Mismatches inside the 12-base seed region proximal to the PAM are weighted
    more heavily, which reflects Cas9 specificity.
    """
    reference = reference.upper().replace("U", "T")
    guide_length, pam_length = len(guide), len(pam)
    results: list[dict] = []
    for i in range(0, len(reference) - guide_length - pam_length + 1):
        window = reference[i:i + guide_length]
        pam_window = reference[i + guide_length:i + guide_length + pam_length]
        if not _pam_matches(pam_window, pam):
            continue
        mismatches = [j for j in range(guide_length) if window[j] != guide[j]]
        if len(mismatches) > max_mismatches:
            continue
        seed_mismatches = sum(1 for j in mismatches if j >= guide_length - 12)
        results.append({
            "position": i,
            "sequence": window,
            "pam": pam_window,
            "mismatches": len(mismatches),
            "seed_mismatches": seed_mismatches,
            "severity": "HIGH" if seed_mismatches == 0 and len(mismatches) <= 2 else "MODERATE",
        })
        if len(results) >= limit:
            break
    return results


def _target_criticality(target_gene: str) -> tuple[float, str | None]:
    lowered = target_gene.lower()
    best, marker = 0.0, None
    for keyword, weight in CRITICAL_TARGETS.items():
        if keyword in lowered and weight > best:
            best, marker = weight, keyword
    return best, marker


def _intent_weight(intent: str) -> tuple[float, str | None]:
    lowered = intent.lower()
    best, marker = 0.10, None
    for phrase, weight in INTENT_WEIGHT.items():
        if phrase in lowered and weight > best:
            best, marker = weight, phrase
    return best, marker


def check_durc(organism_class: str, intent: str, target_gene: str) -> tuple[bool, str, list[str]]:
    """Return (flagged, outcome, reasons)."""
    lowered = f"{intent} {target_gene}".lower()
    reasons: list[str] = []
    outcome = "CLEAR"
    for org, markers, verdict in DURC_MATRIX:
        if org != organism_class:
            continue
        for marker in markers:
            if marker in lowered:
                reasons.append(
                    f"Dual-use research of concern: {organism_class} combined with '{marker}'")
                if verdict == "BLOCK":
                    outcome = "BLOCK"
                elif outcome != "BLOCK":
                    outcome = "FLAG"
    return bool(reasons), outcome, reasons


def assess(target_gene: str, organism: str, organism_class: str, guide_rna: str, pam: str,
           edit_type: str, intent: str, reference: str = "") -> CrisprResult:
    guide, pam_clean = validate_guide(guide_rna, pam)
    edit = edit_type.upper()
    if edit not in EDIT_TYPE_WEIGHT:
        raise CrisprInputError(f"Unknown edit type {edit_type}; expected one of "
                               f"{sorted(EDIT_TYPE_WEIGHT)}")
    org_class = organism_class.upper()
    if org_class not in ORGANISM_CLASS_WEIGHT:
        raise CrisprInputError(f"Unknown organism class {organism_class}; expected one of "
                               f"{sorted(ORGANISM_CLASS_WEIGHT)}")

    reasons: list[str] = []
    off_targets = scan_off_targets(guide, pam_clean, reference) if reference else []
    high_risk_off = [o for o in off_targets if o["severity"] == "HIGH"]

    target_score, target_marker = _target_criticality(target_gene)
    if target_marker:
        reasons.append(f"Target gene '{target_gene}' matches the critical-target keyword "
                       f"'{target_marker}' (criticality {target_score:.2f})")

    edit_score = EDIT_TYPE_WEIGHT[edit]
    reasons.append(f"Edit type {edit} carries a base weight of {edit_score:.2f}")

    # Saturating function of off-target count; high-severity hits count double.
    weighted_off = len(off_targets) + len(high_risk_off)
    off_score = min(1.0, weighted_off / 8.0)
    if off_targets:
        reasons.append(f"{len(off_targets)} potential off-target site(s) found, "
                       f"{len(high_risk_off)} with seed-region identity")
    elif reference:
        reasons.append("No off-target sites found in the supplied reference")

    organism_score = ORGANISM_CLASS_WEIGHT[org_class]
    reasons.append(f"Organism class {org_class} carries a weight of {organism_score:.2f}")

    intent_score, intent_marker = _intent_weight(intent)
    if intent_marker:
        reasons.append(f"Stated intent matches '{intent_marker}' (weight {intent_score:.2f})")

    score = (WEIGHTS["target"] * target_score + WEIGHTS["edit"] * edit_score
             + WEIGHTS["off_target"] * off_score + WEIGHTS["organism"] * organism_score
             + WEIGHTS["intent"] * intent_score)

    durc_flag, durc_outcome, durc_reasons = check_durc(org_class, intent, target_gene)
    reasons.extend(durc_reasons)

    if durc_outcome == "BLOCK":
        score = max(score, 0.90)
        reasons.append("Score raised to the prohibited band by the dual-use concern matrix")
    elif durc_outcome == "FLAG":
        score = max(score, 0.62)

    score = round(min(1.0, score), 4)
    if score >= 0.85:
        level = "PROHIBITED"
    elif score >= 0.60:
        level = "HIGH"
    elif score >= 0.35:
        level = "MODERATE"
    else:
        level = "LOW"

    return CrisprResult(risk_score=score, risk_level=level, durc_flag=durc_flag,
                        off_target_count=len(off_targets), off_targets=off_targets[:10],
                        reasons=reasons)
