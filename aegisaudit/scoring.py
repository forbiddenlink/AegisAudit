from typing import List, Dict
from aegisaudit.models import Finding, Severity, ScanSummary

# Category Weights (Total 100)
# Updated for Phase 2: Broader coverage
CATEGORY_WEIGHTS = {
    "headers": 20.0,
    "cookies": 15.0,
    "https": 15.0,
    "dns": 15.0,  # New: SPF/DMARC/CAA
    "supply-chain": 15.0,  # New: JS Libs & SRI
    "tls": 10.0,  # New: Deep Crypto
    "csp": 5.0,
    "security.txt": 5.0,
}


def calculate_score(findings: List[Finding]) -> ScanSummary:
    """
    Calculate scoring based on weighted categories.
    Start with 100% per category, deduct based on severity.
    Then calculate weighted average.
    """

    # Track raw scores per category (0-100)
    category_scores: Dict[str, float] = {k: 100.0 for k in CATEGORY_WEIGHTS.keys()}

    # Severity Penalties
    penalties = {
        Severity.CRITICAL: 100.0,
        Severity.HIGH: 40.0,
        Severity.MEDIUM: 15.0,
        Severity.LOW: 5.0,
        Severity.INFO: 0.0,
    }

    counts = {s: 0 for s in Severity}

    for f in findings:
        counts[f.severity] += 1

        # Determine category from tags or fallback
        # We look for the first tag that matches a known category key
        cat = None
        for tag in f.tags:
            if tag in CATEGORY_WEIGHTS:
                cat = tag
                break

        # Deduct from that category (skip if no matching category)
        if cat is not None:
            deduction = penalties[f.severity]
            category_scores[cat] = max(0.0, category_scores[cat] - deduction)

    # Calculate Overall Weighted Score
    total_weight = 0.0
    weighted_sum = 0.0

    for cat, weight in CATEGORY_WEIGHTS.items():
        score = category_scores.get(cat, 100.0)
        weighted_sum += score * weight
        total_weight += weight

    overall = 0.0
    if total_weight > 0:
        overall = weighted_sum / total_weight

    return ScanSummary(
        counts_by_severity=counts, category_scores=category_scores, overall_score=overall
    )
