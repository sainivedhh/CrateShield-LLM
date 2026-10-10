"""Statistical power calculation script for CrateShield Benchmark v3 (Phase 3).

Calculates:
1. Paired sample size needed to detect a 0.15 difference in recall using McNemar's test
   (alpha=0.05 uncorrected and Holm-corrected alpha=0.01, power=0.80).
2. Paired sample size needed for equivalence test (TOST) with margin +/-0.10.
3. Achieved statistical power across candidate sample sizes.
"""
from __future__ import annotations

import math
from scipy import stats


def mcnemar_sample_size(delta: float, p_discordant: float, alpha: float = 0.05, power: float = 0.80) -> int:
    """Calculates paired sample size for McNemar test.
    
    delta: difference in proportions (p10 - p01)
    p_discordant: total discordant rate (p10 + p01)
    """
    z_alpha = stats.norm.ppf(1 - alpha / 2)
    z_beta = stats.norm.ppf(power)
    
    # Formula for asymptotic normal approximation for paired McNemar test
    # N = ((z_alpha * sqrt(p_discordant) + z_beta * sqrt(p_discordant - delta**2)) / delta)**2
    term1 = z_alpha * math.sqrt(p_discordant)
    term2_arg = max(0.0001, p_discordant - delta**2)
    term2 = z_beta * math.sqrt(term2_arg)
    n = ((term1 + term2) / delta) ** 2
    return math.ceil(n)


def tost_sample_size(margin: float, p_discordant: float, alpha: float = 0.05, power: float = 0.80) -> int:
    """Calculates sample size for Two One-Sided Tests (TOST) equivalence.
    
    margin: equivalence margin (+/- delta)
    p_discordant: variance parameter for paired binary difference
    """
    z_alpha = stats.norm.ppf(1 - alpha)
    z_beta = stats.norm.ppf(power)
    # Under true difference = 0: N = ((z_alpha + z_beta)**2 * p_discordant) / margin**2
    n = ((z_alpha + z_beta) ** 2 * p_discordant) / (margin ** 2)
    return math.ceil(n)


def compute_mcnemar_power(n: int, delta: float, p_discordant: float, alpha: float = 0.05) -> float:
    """Computes achieved power for McNemar test with sample size n."""
    z_alpha = stats.norm.ppf(1 - alpha / 2)
    term2_arg = max(0.0001, p_discordant - delta**2)
    numerator = math.sqrt(n) * delta - z_alpha * math.sqrt(p_discordant)
    z_beta = numerator / math.sqrt(term2_arg)
    return float(stats.norm.cdf(z_beta))


def generate_power_tables() -> str:
    lines = [
        "# Benchmark v3 Statistical Power Sizing Report",
        "",
        "## 1. McNemar's Test: Sample Size to Detect |delta| = 0.15 (Power = 0.80)",
        "",
        "| Discordance Rate (p_D) | Alpha = 0.05 (Uncorrected) | Alpha = 0.01 (Holm-corrected, 5 tests) |",
        "|---|---|---|",
    ]
    
    discordance_rates = [0.15, 0.20, 0.25, 0.30, 0.35]
    for pd in discordance_rates:
        n_uncorr = mcnemar_sample_size(0.15, pd, alpha=0.05, power=0.80)
        n_holm = mcnemar_sample_size(0.15, pd, alpha=0.01, power=0.80)
        lines.append(f"| {pd:.2f} | N = {n_uncorr} | N = {n_holm} |")
        
    lines.extend([
        "",
        "## 2. TOST Equivalence Test: Sample Size for Margin Delta = +/-0.10 (Alpha = 0.05, Power = 0.80)",
        "",
        "| Discordance Rate (p_D) | Required Pairs N |",
        "|---|---|",
    ])
    
    for pd in discordance_rates:
        n_tost = tost_sample_size(0.10, pd, alpha=0.05, power=0.80)
        lines.append(f"| {pd:.2f} | N = {n_tost} |")
        
    lines.extend([
        "",
        "## 3. Achieved Power Across Candidate Sample Sizes (|delta| = 0.15, p_D = 0.20)",
        "",
        "| Sample Size (Pairs N) | Alpha = 0.05 Power | Alpha = 0.01 (Holm) Power |",
        "|---|---|---|",
    ])
    
    candidate_ns = [40, 60, 80, 100, 120, 150]
    for n in candidate_ns:
        p_uncorr = compute_mcnemar_power(n, 0.15, 0.20, alpha=0.05)
        p_holm = compute_mcnemar_power(n, 0.15, 0.20, alpha=0.01)
        lines.append(f"| N = {n} | {p_uncorr:.1%} | {p_holm:.1%} |")
        
    lines.append("")
    report = "\n".join(lines)
    return report


if __name__ == "__main__":
    report = generate_power_tables()
    print(report)