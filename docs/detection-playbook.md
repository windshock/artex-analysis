# Sequence-Oriented Defensive Hunting Playbook

**Purpose:** Look beyond one IP, user agent, or URL. Reconstruct candidate relationships between requests, start with transparent rules, and introduce statistical or sequential models only when they improve discrimination against a benign baseline.

| Unit of analysis | Initial test | Advanced study |
| --- | --- | --- |
| Repeated proxy IP pool | Chronological IP list, Jaccard and Kendall comparison | Null simulations for fixed vs. rotating pools |
| Repeated JS GETs | Counts per `(trusted source/session, canonical path, time window)` | Inter-arrival distributions and resource-transition graphs |
| Error-followed retries | Related requests after 4xx/5xx | Conditional transitions, n-grams or Markov models |
| Follow-up validation | Narrow, focused requests after broad exploration | Session correlation, response-dependent actions and independent tool traces |
| Tool fingerprint changes | UA/TLS/JA4 or path-selection shifts within a task | Request-order and graph features combined with session context |

## Procedure

1. **Validate provenance:** Confirm the socket source IP, trusted forwarding headers, request ordering and absence of duplicated ingestion.
2. **Extract features:** JavaScript GET count per time window, return-to-path after errors, inter-request gaps, distinct IPs, Jaccard overlap and Kendall order agreement.
3. **Build controls:** Normal browsers, cache-disabled crawlers, health checks, CDN behavior and authorized scanners. Test on a different observation period.
4. **Link actions:** Require multiple independent clues—time, shared resource, request parameters (redacted), response and/or authenticated session—before describing a follow-up phase.
5. **Report conservatively:** Separate direct observations, calculated statistics, heuristic output and unsupported attribution. Human intervention and tool-side details require independent evidence.

## Rules likely to cause false positives

- Do not identify ARTEX solely by `User-Agent: norma/0.4`, `curl/*`, or another single header.
- Do not flag every repeated `.js` GET as malicious.
- Do not label a high-frequency IP as a C2 server, proxy broker or human verification node without supporting evidence.
- Do not describe remote HTML-to-Markdown conversion or local `grep` as directly visible in HTTP server logs.

**When is mathematics necessary?** Start with interpretable correlation rules for WebFetch-like retries. For repeated IP-pool composition and ordering, Jaccard and Kendall provide explicit, comparable measurements. For longer tool-use workflows, compare transition patterns, n-gram counts and temporal features against benign runs.