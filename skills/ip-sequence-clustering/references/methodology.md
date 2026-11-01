# Methodology and validity limits

## 1. Input and provenance

Use one event per line in chronological order. Distinguish the actual TCP peer/source IP from a potentially untrusted forwarded header. Do not infer event order from a sorted list. Record the source SHA-256, collection window and any filtered event types.

## 2. Candidate segmentation is a heuristic

A phase boundary is proposed when the rolling proportion of previously unseen IPs sharply rises after a low-novelty region. This may miss phase changes with overlapping pools and may flag arbitrary first-time bursts. Cycle boundaries are proposed near repeated-position resets using the modal source-IP frequency. These are algorithmic hypotheses, not ground truth.

## 3. Mathematical verification

**Jaccard similarity:** `J(A,B) = |A ∩ B| / |A ∪ B|`, where A and B are sets of distinct source IPs seen in candidate cycles. Range 0 to 1.

**Kendall tau-a:** Restrict each candidate cycle to IPs shared by both, retain their first-occurrence order, and count discordant pairs D among n shared IPs. Then `tau = 1 − 4D / (n(n−1))`. Range −1 to 1; undefined for fewer than two shared IPs. The shared-IP restriction means order similarity alone does not imply full-pool similarity.

Compute **both metrics** for every pair of candidate cycles. By default, the script calls a proposed pattern validated only when each pair reaches Jaccard ≥ 0.80 and Kendall tau ≥ 0.85. These are configurable operational thresholds, not p-values or empirically calibrated false-positive rates.

## 4. Triage categories

- `DOMINANT`: exceptionally frequent IP, provisionally excluded from similarity scoring; the event is not deleted from source data.
- `CROSS_PHASE`: appears in more than one proposed IP-pool phase.
- `FREQUENCY_DEVIATION`: frequency differs from the phase's modal per-IP count.

A shared IP can have multiple labels. Anomaly detection is not threat attribution.

## 5. Falsification and controls

Before asserting organized automation, verify timestamps, URL sequences, HTTP status, JA4/User-Agent where available, session behavior, reverse-proxy chain, and duplicate log ingestion. Compare authorized scanners, benign batch systems, user proxies and analytics exports as alternative causes. A human verification step, C2 server, or particular AI agent must be corroborated independently.

## 6. Reproducibility

The Python CLI produces `report.md`, `report.json`, `memberships.csv` and `anomalies.csv`. Use a synthetic demonstration dataset when sharing publicly. Do not expose private production IP logs in an open repository.
