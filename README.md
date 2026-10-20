# BlindSight

**Systematic Exploitation of Forensic Tools to Fabricate Digital Evidence**

> Prajwal Chowdary & Dr. Sapna Prasad B Honnavalli — PES University

---

## What Is This?

BlindSight demonstrates that digital forensic tools can be systematically deceived into reporting fabricated evidence as genuine. We introduce five novel attack classes targeting the forensic toolchain itself — not to destroy or hide evidence, but to **make tools produce convincing false evidence**.

A 2026 Systematization of Knowledge survey covering 123 anti-forensic papers found **zero** research on attacking forensic tools themselves. BlindSight fills that gap.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BlindSight Framework                      │
├───────────────────┬─────────────────┬───────────────────────┤
│    BlindForge     │   DiffOracle    │  BlindSight Validator │
│    (Offensive)    │   (Analysis)    │     (Defensive)       │
├───────────────────┼─────────────────┼───────────────────────┤
│ MFT Injector      │ Tool Harness    │ Integrity Checker     │
│ EVTX Injector     │ Semantic Differ │ Anomaly Detector      │
│ Prefetch Forge    │ Report Gen      │ Cross-Source Validator │
│ SQLite Poisoner   │                 │ Validation Reports    │
│ Registry Forge    │                 │                       │
│ Timeline Warp     │                 │                       │
│ Memory Mirage     │                 │                       │
└───────────────────┴─────────────────┴───────────────────────┘
```

**Timeline Warp** orchestrates all modules — define one attack narrative and it generates consistent, corroborating artifacts across every source.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full architecture and data flow diagrams.

## Attack Classes

| # | Attack | Description | Target Artifacts |
|---|--------|-------------|-----------------|
| 1 | **Parser Differentials** | Craft artifacts that different tools interpret contradictorily | MFT, EVTX, Registry |
| 2 | **Ghost Injection** | Inject structurally valid records for activity that never occurred | MFT, EVTX, Prefetch, Registry, SQLite |
| 3 | **Timeline Poisoning** | Cross-source timestamp manipulation corrupting timeline reconstruction | All artifact types |
| 4 | **Memory Mirage** | Fabricated process structures in memory dumps | EPROCESS, VAD, Handle Tables |
| 5 | **SQLite Phantom Records** | Injected browser history/downloads indistinguishable from genuine | Chrome, Firefox, Safari DBs |

## Project Structure

```
blindsight-bhasia27/
├── blindforge/                  # Offensive toolkit
│   ├── core/
│   │   ├── mft_injector.py          # NTFS MFT entry fabrication
│   │   ├── evtx_injector.py         # Windows Event Log injection
│   │   ├── prefetch_forge.py        # Prefetch file fabrication
│   │   ├── registry_forge.py        # Registry artifact injection
│   │   ├── sqlite_poisoner.py       # Browser history injection
│   │   ├── timeline_warp.py         # Cross-source timeline poisoning
│   │   └── mem_mirage.py            # Memory dump process injection
│   └── cli.py                       # Command-line interface
├── difforacle/                  # Parser differential finder
│   ├── harness.py                   # Multi-tool execution harness
│   ├── differ.py                    # Semantic output comparison
│   └── report.py                    # Differential reports
├── blindsight_validator/        # Defensive tool
│   ├── integrity.py                 # Cross-tool validation
│   ├── anomaly.py                   # Structural anomaly detection
│   └── report.py                    # Validation reports
├── docs/
│   └── ARCHITECTURE.md              # Architecture & data flow
├── cfp/
│   └── submission.md                # Conference submission
└── datasets/
    └── manifests/                   # Benchmark ground truth
```

## Quick Start

```bash
# Clone
git clone https://github.com/prajwalchowdary2/blindsight-bhasia27.git
cd blindsight-bhasia27

# Install
pip install -e .

# Generate a complete fabricated attack narrative
blindforge narrative --user jdoe --computer WORKSTATION-01 \
    --source-ip 10.0.0.55 --output ./demo_output

# Inject a ghost file into an MFT
blindforge mft --mft raw_mft.bin --filename "stolen_data.xlsx" \
    --timestamp "2026-06-15T14:30:00+00:00"

# Inject a logon event into EVTX
blindforge evtx --evtx Security.evtx --event-type logon \
    --username admin --source-ip 192.168.1.100

# Validate evidence integrity
blindforge validate --mft suspicious_mft.bin --evtx suspicious.evtx
```

## Individual Module PoCs

Each module runs standalone:

```bash
python -m blindforge.core.mft_injector
python -m blindforge.core.evtx_injector
python -m blindforge.core.prefetch_forge
python -m blindforge.core.sqlite_poisoner
python -m blindforge.core.registry_forge
python -m blindforge.core.timeline_warp
python -m blindforge.core.mem_mirage
```

## Targeted Forensic Tools

| Tool | Version Tested | Attack Surface |
|------|---------------|----------------|
| Autopsy / Sleuthkit | 4.21+ | MFT parsing, timeline, file carving |
| Volatility3 | 2.5+ | EPROCESS scanning, pool tag analysis |
| Plaso / log2timeline | 20240+ | Multi-source timeline reconstruction |
| RegRipper | 3.0+ | Registry hive analysis |
| PECmd | 1.5+ | Prefetch file parsing |

## Responsible Disclosure

- All parser differentials will be disclosed to affected tool maintainers **90 days** before any presentation
- Affected tools: Autopsy/TSK, Volatility3, Plaso/log2timeline
- This research improves forensic tool robustness and evidence validation practices

## Legal

This tool is provided for **authorized security research and forensic tool testing only**. Do not use it to fabricate evidence in actual investigations or legal proceedings. The authors are not responsible for misuse.

## Citation

```bibtex
@misc{chowdary2027blindsight,
  title={BlindSight: Weaponizing Parser Differentials to Fabricate Forensic Evidence},
  author={Chowdary, Prajwal and Honnavalli, Sapna Prasad B},
  year={2027}
}
```

## License

MIT License — See [LICENSE](LICENSE) for details.
