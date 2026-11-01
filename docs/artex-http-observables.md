# ARTEX Tool Behavior: What a Web Server Can Actually Observe

This defensive research note summarizes investigator-supplied observations from controlled ARTEX-related experiments. It does not claim that all ARTEX versions behave the same way, nor that the observations constitute a publicly reproducible tool vulnerability. Original experimental traffic is not published here.

## 1. Page retrieval and WebFetch-like workflows

**Investigator observation:** Errors and potential retries were observed or identified for follow-up investigation in the workflow that retrieves a page and delivers a Markdown representation to an AI model.

**Server-visible:** URL/path, request timestamp, HTTP method, response status, request headers, redirects, and subsequent requests to the same or related resource (when logged).

**Not server-visible:** Whether the remote tool converted HTML into Markdown, what context the model received, and the internal cause of the tool-side error.

**Detection hypothesis:** Does a specific HTTP error or unexpected response tend to precede repeated page fetches or a switch to another retrieval method? Is the transition distinguishable from ordinary crawler, browser, or monitor retries?

## 2. Repeated JavaScript retrieval during static analysis

**Investigator observation:** An agent may repeatedly issue commands resembling `curl <asset>.js | grep <pattern>` while searching source for interesting strings. Each command may download the same JavaScript asset again.

**Server-visible:** Multiple GETs to the same canonical `.js` URL, spacing between requests, user agents, status codes, and response sizes if logged.

**Not server-visible:** Local `grep` execution, the patterns used, the agent's intent, and any local caches. A crawler or human developer could produce similar requests.

**Alternative explanations:** Cache busting, retransmission or retry, disabled caching, CI checks, browser developer tools, routine scanners, monitoring, or duplicate log ingestion.

## 3. Focused validation after automated exploration

An adversary may run an AI tool for broad exploration and then personally inspect results. However, **a second automated tool or monitoring task can produce the same apparent follow-up**.

Candidate indicators of a follow-up phase:

- Focused access to a small subset of paths following a broad resource-discovery phase.
- A different session, source address or HTTP fingerprint accessing resources previously discovered.
- A consistent temporal ordering across independent, controlled replications.

These signals do not identify a human operator. Test with session continuity, request linkage, timestamps, independent telemetry and, when available, tool execution traces.

## 4. Prioritize reliable log fields

`timestamp`, trusted `remote_addr`, `method`, `host`, canonical `path`, redacted `query_shape`, `status`, `user_agent`, `bytes`, `request_id`, pseudonymized session identifiers, trusted proxy chain, and optionally TLS/JA4 fingerprints.

## Falsifiable evaluation gates

1. Does the feature separate approved agent runs from normal browsers and crawlers under a predefined false-positive budget?
2. Does it survive IP rotation or user-agent changes while still distinguishing independent activity?
3. Does each conclusion rely strictly on evidence the observation point can actually collect?