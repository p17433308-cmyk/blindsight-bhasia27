# BlindSight — Clean vs Poisoned Comparison

Generated: 2026-10-22T12:56:02.721905

## Side-by-Side Evidence Comparison

| Evidence Type | Clean Image | Poisoned Image | Injected |
|--------------|-------------|----------------|----------|
| MFT records | 6 files (docs, photos) | 12 files | +6 (mimikatz, procdump, lsass dump, credentials, archive, persistence) |
| Prefetch | 5 programs (Office, Chrome, Teams) | 8 programs | +3 (mimikatz, procdump, rar) |
| Chrome History | 6 URLs (Gmail, Docs, LinkedIn) | 10 URLs | +4 (mimikatz download, MEGA upload, MITRE) |
| EVTX events | 0 | 5 | +5 (logon, process creation, service install) |
| Memory dump | N/A | 4 phantom processes | cmd→mimikatz→procdump, rar |

## Forensic Tool Results

| Tool | Clean Verdict | Poisoned Verdict | Detected Injection? |
|------|--------------|-------------------|---------------------|
| Sleuthkit/Autopsy | Normal workstation | Active breach evidence | **NO** |
| python-evtx | N/A | Valid security events | **NO** |
| PECmd (Prefetch) | Normal applications | Attack tools executed | **NO** |
| SQLite browser tools | Normal browsing | Suspicious browsing | **NO** |
| Volatility3 | N/A | Malware process tree | **NO** |
| **BlindSight Validator** | Clean | **Anomalies detected** | **YES** |

## Key Takeaway

The same employee workstation image, with 6 injected files and coordinated
cross-source artifacts, transforms from 'clean employee' to 'active insider
threat / data breach' — and no production forensic tool can tell the difference.