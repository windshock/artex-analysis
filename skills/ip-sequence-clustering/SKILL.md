---
name: ip-sequence-clustering
description: Analyze ordered HTTP/network source-IP logs for repeating proxy-pool or automation patterns using Jaccard set similarity and Kendall rank correlation. Use for defensive incident response, threat hunting, proxy rotation triage, cyclic log analysis, and anomalous or cross-group IP identification. Accept ordered IP-per-line text, CSV, or TSV. Produce evidence-backed phase and round boundaries, pairwise similarity scores, anomalous IP candidates, and cautious non-attribution conclusions. Do not use for IP geolocation or actor identification.
---

# IP Sequence Clustering

Quantify repeating **source-IP composition and order** while keeping anomaly triage separate from attacker attribution. Use the bundled offline Python script for reproducible results; do not claim that heuristic phase boundaries are statistically proven or that an IP is an attacker based only on its frequency.

## Workflow

1. **Verify the input.** Prefer the original log export ordered by *request time*. For `.txt`, require one source IP per line. For CSV/TSV, identify a trustworthy `remote_addr`/source-IP column. Never silently trust `X-Forwarded-For` and never infer chronology from an alphabetically sorted IP list. Ask for a timestamp or original ordering if missing, and label the limitation if it cannot be supplied.
2. **Run the deterministic analyzer** (`python3` version 3.10+, no third-party dependencies):
   ```bash
   python3 scripts/analyze_ip_sequences.py requests.txt --out results
   # Or:
   python3 scripts/analyze_ip_sequences.py requests.csv --ip-column remote_addr --out results
   ```
   Run from the skill directory; for a different working directory, use the absolute path to `scripts/analyze_ip_sequences.py`.
3. **Inspect `report.md` AND `report.json`.** Check inferred phase boundaries, inferred repetition counts, minimum *pairwise* Jaccard and Kendall scores, number of shared IPs, exclusions, and warnings. Do not rely solely on overall summary rows.
4. **Review `anomalies.csv` and `memberships.csv`.** Keep high-frequency/interleaved candidates, cross-group addresses, and over-/under-represented IPs in separate categories. These are investigation leads, not malicious-IP convictions.
5. **Validate against independent logs.** Compare URI, HTTP method, request parameters, status, timestamps, User-Agent/JA4 (where available), authenticated session identifiers, log source, proxy headers, and duplicate-export artifacts. Compare against a benign baseline and a separate observation period before treating the pattern as evidence of a coordinated actor.
6. **Report with clear labels:** observed evidence, mathematically computed metrics, segmentation *heuristics*, competing explanations, and unresolved questions. Do not conflate three list traversals with three distinct tools, actors, or attack waves.

## Reproducible method

- **Phase split (heuristic):** Remove *from similarity calculations only* exceptional globally frequent IPs (auto-exclusion is conservative but not infallible). In the remaining event sequence, use abrupt increases in the rolling proportion of **globally first-seen IPs** to propose new IP-pool phases. This is *not* k-means or an actor clustering classifier. If pool membership does not change, novelty-based splitting may miss a new phase.
- **Cycle starts (heuristic):** Within each proposed phase, infer an expected repeat count from the modal per-IP appearance frequency, and locate candidate restarts where the rank of the first-occurrence IP order sharply resets near expected period boundaries.
- **Jaccard:** For candidate rounds with sets of distinct IPs A and B, use `|A intersection B| / |A union B|`. This measures membership, not order.
- **Kendall tau-a:** Project each round onto their **shared, distinct** IPs, preserving **first-occurrence order**. Count concordant and discordant pairs: `(C-D)/(C+D)`. No rank ties exist in this projected representation. This measures order agreement conditional on shared IPs; report the shared count. If fewer than 2 shared IPs, tau is undefined.
- **Threshold rule:** `validated_pattern` requires each pair of inferred rounds in a phase to satisfy Jaccard >= 0.80 and Kendall tau >= 0.85 (adjustable). The threshold indicates a pattern under chosen rules, **not a p-value or proof of attack**.
- **Outliers:** `EXCLUDED_DOMINANT` (high-frequency IP excluded from scoring only); `CROSS_GROUP_IP` (appears in more than one phase); `OVER_REPRESENTED`/`UNDER_REPRESENTED` (within-phase frequency differs from modal repetitions). The same IP may appear in multiple anomaly categories.

For algorithm limitations and examples, read `references/methodology.md` before publishing a scientific claim or revising thresholds.

## Options and outputs

```bash
# Apply known analyst-defined phase boundaries; do not label these automatic.
python3 scripts/analyze_ip_sequences.py requests.txt --segments 1-63,64-126 --out confirmed-boundaries

# Retain the high-frequency IP in similarity calculations, or exclude a known interleaved one.
python3 scripts/analyze_ip_sequences.py requests.txt --no-auto-exclude --out no-exclusion
python3 scripts/analyze_ip_sequences.py requests.txt --exclude-ip 192.0.2.200 --out explicit-exclusion

# Tune validation thresholds, without treating tuning as independent confirmation.
python3 scripts/analyze_ip_sequences.py requests.txt --min-jaccard 0.90 --min-kendall 0.95 --out strict
```

Produces `report.md` (narrative), `report.json` (full reproducibility), `anomalies.csv` (triage), and `memberships.csv` (every distinct IP, phase membership and count). Reuse `assets/demo_ip_sequence.txt` for a non-sensitive example. **Never publish private IP logs or organization-internal URLs without authorization.**

## Interpretation rules

- Use the phrase *"same or similar ordered IP pools were reused"*, not *"proved one attacker"*.
- Say *"candidate interleaved/high-frequency IP"*, not *"C2/orchestrator/verification server"* unless independently corroborated.
- Absence of overlap with a known IOC collection does not prove innocence or unrelatedness. Same /24, ISP, ASN, or country does not prove a shared operator.
- No timestamps means no rate, duration, concurrency, or session inference.
- If source IP comes from an untrusted forwarded header, identify the spoofing risk before any attribution.
- If log collection/export might duplicate records, flag repeated sequences as potentially artificial until verified.
- For a social post, describe this as **hypothesis generation plus numerical verification** rather than a fully validated unsupervised discovery system.