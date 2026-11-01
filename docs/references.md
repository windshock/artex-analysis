# Public Sources and Evidence Scope

## Independent reporting on ARTEX and agentic intrusion tooling

The links below provide background on publicly described ARTEX-related activity. They are **not** evidence that the repository's separate WebFetch, JavaScript or proxy-pool observations originate from the same actor or incident.

- CrowdStrike, *Unknown Threat Actor Uses AI-Driven ARTEX to Target South Korean Finance* (2026-10-07): https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/
- AhnLab ASEC, *AI Autonomous Penetration Threats Through ARTEX* (original Korean article, 2026-10): https://asec.ahnlab.com/ko/95844/
- Microsoft Security, *AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise* (2026-10-21): https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/
- Google Threat Intelligence Group, *ARTEX and Friends: Enter Agentic Offensive Frameworks* (2026-10-30): https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks

Source titles, date details and availability should be checked independently before reusing them in an external publication.

## Separate evidence categories

| Category | What is included | Claim limitation |
| --- | --- | --- |
| Investigator-reported observations | Potential WebFetch processing errors, retries and repeated JS retrieval | Underlying raw traces are private; no universal tool defect is established |
| Reproducible public implementation | Synthetic IP sequences, tests, Jaccard/Kendall verification | Synthetic examples do not prove real-world attribution or detection performance |
| Hypotheses | Human follow-up after an agent run, or a distinct validation channel | Cannot be inferred from one high-frequency IP alone |
| External threat intelligence | Public accounts of ARTEX misuse | Not a matching campaign by association alone |

Unpublished source logs, tool configuration, versions, execution traces and collection timestamps remain necessary for independent validation of the investigator-reported observations.