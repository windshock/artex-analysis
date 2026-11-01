# Proxy IP Sequence Analysis: Jaccard Similarity and Kendall Tau

## Why combine these two measures?

Two request windows can contain the same IP addresses in entirely different orders. Jaccard measures shared **membership**; Kendall tau measures **relative ordering** among shared first-occurrence addresses.

- **Jaccard:** `J(A,B) = |A ∩ B| / |A ∪ B|`, where A and B are sets of *distinct source IPs* observed in candidate rounds. Order and frequency do not affect the score.
- **Kendall tau-a:** Restrict each round to IPs observed in **both** rounds, keep only their **first occurrence** and compare all shared IP pairs. `tau = (C-D)/(C+D)` for concordant/discordant pairs. With fewer than two shared IPs, tau is undefined.

These scores answer different questions. Strong Jaccard with weak Kendall implies the same addresses were reused in a changed order.

## Analysis pipeline

1. Preserve original event chronology. Never sort records by IP, silently deduplicate requests or accept untrusted `X-Forwarded-For` values as verified client addresses.
2. Identify exceptional high-frequency IPs and, where justified, omit them *from scoring only*. Preserve their events for analysis and reporting.
3. Use a **heuristic** rise in globally first-seen IP density to propose phase changes. Propose round restarts near expected cycle lengths when address appearance ranks reset.
4. Compute pairwise Jaccard and Kendall across all proposed rounds within each phase; disclose thresholds, counts of shared IPs, and the worst pairwise scores.
5. Flag dominant, cross-phase, over- and under-represented IPs as **triage candidates**, not proven malicious nodes.
6. Test alternate hypotheses with benign baselines, order-shuffled controls, duplicate-log checks and request-level context.

**Important:** Jaccard and Kendall **validate proposed rounds**. They do not automatically infer segmentation boundaries, actor identities, proxy ownership or the number of adversaries.

## Evidence and attribution limitations

- A shared `/24`, ASN, hosting provider or country does not imply a common actor.
- An interleaved high-frequency IP may be a checker, another scanner, a direct client or a logging artifact. HTTP request context is required to determine its role.
- Event order without timestamps provides no rate, duration or simultaneity information.
- Thresholds tuned on an incident are not an independent performance evaluation; validate on held-out data.

Implementation details, CLI usage and tests: [IP Sequence Clustering](../skills/ip-sequence-clustering/README.md).