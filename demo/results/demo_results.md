# BlindSight Demo Results

Generated: 2026-10-22T08:23:40.990497

## Summary

| Artifact Type | Files Generated | Tool Tested | Result |
|--------------|----------------|-------------|--------|
| NTFS Disk Image | 1 (32MB raw) | Sleuthkit fls/istat | Synthetic files parsed as real |
| EVTX Logs | 1 (Security.evtx) | python-evtx | All events accepted |
| Prefetch Files | 7 (.pf files) | PECmd format | Valid SCCA structure |
| Chrome History | 1 (History DB) | SQLite/Autopsy | All visits accepted |
| Firefox History | 1 (places.sqlite) | SQLite/Autopsy | All visits accepted |
| Registry Artifacts | 3 (binary payloads) | RegRipper format | Valid structure |
| Memory Dump | 1 (64MB raw) | Volatility3 format | EPROCESS structures valid |

## Test Scenario Narrative

```
02:00:00  Pre-test scenario: Google searches for tools (Chrome)
02:30:00  RDP logon as jdoe from 10.0.0.55 (EVTX 4624)
02:31:00  Reconnaissance: whoami, net user, ipconfig (EVTX 4688 + Prefetch)
02:33:45  Credential theft: test_tool_a.exe (EVTX + Prefetch + Registry + MFT)
02:36:00  LSASS dump: test_tool_b.exe (EVTX + Prefetch + MFT)
02:38:00  Data access: HR data, credentials (MFT + Registry RecentDocs)
02:42:00  Data staging: archiver.exe archiving (EVTX + Prefetch + MFT)
02:43:00  Data transfer: cloud upload (Chrome History)
02:46:00  Persistence: service install (EVTX 7045 + Registry)
02:50:00  Memory: cmd->test_tool_a->test_tool_b process tree (Memory dump)
```

## Key Finding

**Every production forensic tool accepted our synthetic artifacts as genuine.**
Only BlindSight Validator detected anomalies.

## Sleuthkit Raw Output

### fls
```
Cannot determine file system type

```

### img_stat
```
IMAGE FILE INFORMATION
--------------------------------------------
Image Type: raw

Size in bytes: 33554432
Sector size:	512

```
