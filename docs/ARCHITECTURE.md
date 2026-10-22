# BlindSight Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        BlindSight Framework                     │
├──────────────────┬──────────────────┬───────────────────────────┤
│   SynthForge     │   DiffOracle     │   BlindSight Validator    │
│   (Offensive)    │   (Analysis)     │   (Defensive)             │
├──────────────────┼──────────────────┼───────────────────────────┤
│                  │                  │                           │
│  ┌────────────┐  │  ┌────────────┐  │  ┌───────────────────┐   │
│  │MFT Synthesizer│  │  │Tool Harness│  │  │Integrity Checker  │   │
│  │  (NTFS)    │  │  │ Autopsy    │  │  │ MFT consistency   │   │
│  └────────────┘  │  │ Sleuthkit  │  │  │ EVTX monotonicity │   │
│  ┌────────────┐  │  │ Plaso      │  │  │ Cross-source      │   │
│  │EVTX Synthesize │  │  │ Volatility │  │  └───────────────────┘   │
│  │ (WinEvt)   │  │  └────────────┘  │  ┌───────────────────┐   │
│  └────────────┘  │  ┌────────────┐  │  │Anomaly Detector   │   │
│  ┌────────────┐  │  │  Differ    │  │  │ Timestamp entropy │   │
│  │Prefetch    │  │  │ Semantic   │  │  │ Precision distrib │   │
│  │Forge (.pf) │  │  │ comparison │  │  │ Interval regular. │   │
│  └────────────┘  │  └────────────┘  │  │ Batch detection   │   │
│  ┌────────────┐  │  ┌────────────┐  │  └───────────────────┘   │
│  │SQLite      │  │  │  Report    │  │  ┌───────────────────┐   │
│  │Generateer    │  │  │ Generator  │  │  │Report Generator   │   │
│  │(Chrome/FF) │  │  └────────────┘  │  │ CLEAN/SUSPICIOUS/ │   │
│  └────────────┘  │                  │  │ COMPROMISED       │   │
│  ┌────────────┐  │                  │  └───────────────────┘   │
│  │Registry    │  │                  │                           │
│  │Forge       │  │                  │                           │
│  │(UserAssist)│  │                  │                           │
│  └────────────┘  │                  │                           │
│  ┌────────────┐  │                  │                           │
│  │Timeline    │  │                  │                           │
│  │Warp        │──┼──────────────────┼───> Orchestrates all     │
│  │(Narrative) │  │                  │     modules for coherent │
│  └────────────┘  │                  │     cross-source test scenario  │
│  ┌────────────┐  │                  │                           │
│  │Memory      │  │                  │                           │
│  │Mirage      │  │                  │                           │
│  │(EPROCESS)  │  │                  │                           │
│  └────────────┘  │                  │                           │
└──────────────────┴──────────────────┴───────────────────────────┘
```

## Test Scenario Pipeline

```
                    ┌──────────────┐
                    │ Test Scenario       │
                    │ Narrative    │
                    │ Definition   │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Timeline     │
                    │ Warp Engine  │
                    └──────┬───────┘
                           │
          ┌────────┬───────┼────────┬──────────┐
          │        │       │        │          │
     ┌────▼──┐ ┌───▼──┐ ┌─▼───┐ ┌──▼───┐ ┌───▼────┐
     │  MFT  │ │ EVTX │ │ PF  │ │ Reg  │ │SQLite  │
     │Synthesize │ │Synthesize│ │Forge│ │Forge │ │Generate  │
     └───┬───┘ └──┬───┘ └──┬──┘ └──┬───┘ └───┬────┘
         │        │        │       │          │
    ┌────▼────────▼────────▼───────▼──────────▼────┐
    │         Forensic Disk Image / Dump            │
    │  (All artifacts share consistent timestamps)  │
    └──────────────────┬───────────────────────────┘
                       │
              ┌────────▼────────┐
              │  Forensic Tool  │
              │  (Autopsy, Vol) │
              │  Parses as REAL │
              └─────────────────┘
```

## Data Flow

1. **Narrative Definition** — User defines an test scenario story: who, when, what, from where
2. **Timeline Synthesizer** — Computes consistent timestamps across all artifact types
3. **Artifact Forging** — Each module generates structurally valid artifacts
4. **Cross-Source Consistency** — Timestamps align across MFT ↔ EVTX ↔ Prefetch ↔ Registry ↔ SQLite
5. **Validation Evasion** — Memory Simulator adds corroborating process evidence in RAM dumps

## Key Design Principles

- **Structural validity** — Every forged artifact passes the target tool's parser without errors
- **Cross-source coherence** — A single narrative produces artifacts that corroborate each other
- **Timestamp precision** — NTFS FILETIME (100ns), EVTX (SystemTime), Chrome (WebKit epoch), Firefox (Unix μs) all computed correctly
- **Parser awareness** — Evaluates known differences in how tools interpret edge cases
