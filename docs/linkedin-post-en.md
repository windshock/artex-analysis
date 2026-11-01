# LinkedIn Research Summary (Draft)

**Even when an attacker uses an AI agent, their operational behavior can leave recognizable patterns.**

I recently explored two separate research tracks: controlled **ARTEX behavior experiments** and **rotating proxy-IP sequence analysis**. These are independent datasets; their similarity does not imply a shared threat actor or incident.

**1. Repeating proxy pools.** Rather than focusing only on the number of changing source IPs, I examined whether addresses were reused as an ordered list. I used **Jaccard similarity** to compare the membership of candidate IP rounds and **Kendall's tau** to measure the relative ordering of shared addresses. After proposing boundaries with separate heuristics, these statistics helped verify repetition and identify unusual, cross-group or overrepresented IPs for further investigation.

**2. ARTEX tool-use characteristics.** In controlled observations, WebFetch-like retrieval and HTML-to-Markdown workflows raised questions about errors and retries. JavaScript inspection through commands resembling `curl asset.js | grep pattern` can also produce repeated requests for the same asset. A web server sees these HTTP requests and their sequence—not the client's Markdown conversion or local `grep` process.

**3. Operator follow-up.** Automation does not eliminate the possibility that a human operator returns to inspect results, but HTTP logs alone cannot establish that a person, rather than another script, made the request. The useful task is correlating broad exploration, focused validation and subsequent actions while testing competing explanations.

The broader lesson: **Detect behavior across requests, not just fingerprints in individual requests.** Understand both the tools and the operational workflows surrounding them.

To make part of this approach reproducible, I packaged a small **IP Sequence Clustering** skill with Jaccard/Kendall verification, anomaly triage, tests and entirely synthetic data.

Project: https://github.com/windshock/artex-analysis

#ThreatHunting #ARTEX #AISecurity #BehavioralDetection #NetworkSecurity