# BlindSight — Clean vs Modified Comparison

Generated: 2026-10-22T16:11:20.214969

## Side-by-Side Evidence Comparison

| Evidence Type | Clean Image | Modified Image | Synthesized |
|--------------|-------------|----------------|----------|
| MFT records | 6 files (docs, photos) | 12 files | +6 (test_tool_a, test_tool_b, svchost dump, credentials, archive, test_script) |
| Prefetch | 5 programs (Office, Chrome, Teams) | 10 programs | +5 (test_tool_a, test_tool_b, rar) |
| Chrome History | 6 URLs (Gmail, Docs, LinkedIn) | 10 URLs | +4 (test_tool_a download, MEGA upload, MITRE) |
| EVTX events | 0 | 5 | +5 (logon, process creation, service install) |
| Memory dump | N/A | 4 synthetic processes | cmd→test_tool_a→test_tool_b, rar |

## Forensic Tool Results

| Tool | Clean Verdict | Modified Verdict | Detected Synthesis? |
|------|--------------|-------------------|---------------------|
| Sleuthkit/Autopsy | Normal workstation | Active breach evidence | **NO** |
| python-evtx | N/A | Valid security events | **NO** |
| PECmd (Prefetch) | Normal applications | TestCase tools executed | **NO** |
| SQLite browser tools | Normal browsing | Suspicious browsing | **NO** |
| Volatility3 | N/A | Malware process tree | **NO** |
| **BlindSight Validator** | Clean | **Anomalies detected** | **YES** |

## Key Takeaway

The same employee workstation image, with 6 synthesized files and coordinated
cross-source artifacts, transforms from 'clean employee' to 'active insider
threat / test scenario' — and no production forensic tool can tell the difference.