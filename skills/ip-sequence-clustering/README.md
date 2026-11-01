# IP Sequence Clustering

A shareable ChatGPT Skill with a **fully offline, standard-library-only Python analyzer** for detecting repeated source-IP pools and examining anomalous IP behavior.

**Metrics:** Jaccard set similarity + Kendall tau on first-occurrence order of shared IPs. **Discovery:** transparent first-seen novelty and order-reset heuristics. These are deliberately separated; the two scores do not, by themselves, discover phase boundaries.

## Quick start

Requirements: Python 3.10+ (no packages or API keys required).

```bash
python3 scripts/analyze_ip_sequences.py assets/demo_ip_sequence.txt --out ./results
```

Run with your own data:

```bash
# One IP address per line, in chronological event order:
python3 scripts/analyze_ip_sequences.py ~/requests.txt --out ./results

# CSV/TSV, preserving the original row order:
python3 scripts/analyze_ip_sequences.py ~/access_log.csv --ip-column remote_addr --out ./results

# Analyst-provided phase boundaries (1-based inclusive):
python3 scripts/analyze_ip_sequences.py ~/requests.txt --segments 1-63,64-126 --out ./results
```

Outputs:
- `report.md`: phase and round interpretation with scores and caveats.
- `report.json`: full metrics, evidence counts and parameter settings.
- `anomalies.csv`: dominant, cross-phase, over-/under-represented IPs.
- `memberships.csv`: every IP and its phase memberships and total appearances.

## What it can and cannot say

- Finds **repetition in an ordered list of IP appearances**.
- Provides **investigative leads** where IP appearances do not follow common recurrence patterns.
- Does **not** prove one attacker, a rented proxy network, compromised endpoints, a C2 server, maliciousness, or the intent of any connection.
- Without original timestamps/request metadata, it cannot determine traffic rates or causality.
- With unordered exports, untrusted `X-Forwarded-For`, or repeated log exports, it may produce misleading results.

## Share and install

The included `SKILL.md` and `agents/openai.yaml` make this directory importable as a ChatGPT Skill. Upload the packaged `skill.zip` as a Skill in ChatGPT's Skills interface, or commit the folder to a public GitHub repository for others to reuse. The package contains **no real incident IPs**; the demo uses documentation-reserved IP ranges.

## Tests

```bash
python3 -m unittest discover -s scripts/tests -v
```

Technical details: [references/methodology.md](references/methodology.md).