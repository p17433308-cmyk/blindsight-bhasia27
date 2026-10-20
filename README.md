# BlindSight

**Systematic Exploitation of Forensic Tools to Fabricate Digital Evidence**

> Prajwal Chowdary & Dr. Sapna Prasad B Honnavalli — PES University

## What Is This?

BlindSight demonstrates that digital forensic tools can be systematically deceived into reporting fabricated evidence as genuine. We introduce five novel attack classes targeting the forensic toolchain itself — not to destroy or hide evidence, but to **make tools produce convincing false evidence**.

This project includes:

- **BlindForge** — Offensive toolkit for forensic artifact fabrication
- **DiffOracle** — Automated parser differential finder across forensic tools
- **BlindSight Validator** — Defensive framework for detecting fabricated artifacts

## Attack Classes

| Attack | Description | Target Artifacts |
|--------|-------------|-----------------|
| **Parser Differentials** | Craft artifacts that different tools interpret contradictorily | MFT, EVTX, Registry |
| **Ghost Injection** | Inject structurally valid records for activity that never occurred | MFT, EVTX, Prefetch, Registry, SQLite |
| **Timeline Poisoning** | Cross-source timestamp manipulation corrupting timeline reconstruction | All artifact types |
| **Memory Mirage** | Fabricated process structures in memory dumps | EPROCESS, VAD, Handle Tables |
| **SQLite Phantom Records** | Injected browser history/downloads indistinguishable from genuine | Chrome, Firefox, Safari DBs |

## Project Structure

```
blindsight-bhasia27/
├── blindforge/              # Offensive toolkit
│   ├── core/
│   │   ├── mft_injector.py      # NTFS MFT entry fabrication
│   │   ├── evtx_injector.py     # Windows Event Log injection
│   │   ├── prefetch_forge.py    # Prefetch file fabrication
│   │   ├── registry_forge.py    # Registry artifact injection
│   │   ├── sqlite_poisoner.py   # Browser history injection
│   │   ├── timeline_warp.py     # Cross-source timeline poisoning
│   │   └── mem_mirage.py        # Memory dump process injection
│   └── cli.py                   # Command-line interface
├── difforacle/              # Parser differential finder
│   ├── harness.py               # Multi-tool execution harness
│   ├── differ.py                # Semantic output comparison
│   └── report.py                # Differential reports
├── blindsight_validator/    # Defensive tool
│   ├── integrity.py             # Cross-tool validation
│   ├── anomaly.py               # Structural anomaly detection
│   └── report.py                # Validation reports
├── cfp/                     # Conference submission
│   └── submission.md
└── datasets/                # Benchmark poisoned images
    └── manifests/
```

## Quick Start

```bash
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

Each module can be run standalone to demonstrate its capabilities:

```bash
python -m blindforge.core.mft_injector
python -m blindforge.core.evtx_injector
python -m blindforge.core.prefetch_forge
python -m blindforge.core.sqlite_poisoner
python -m blindforge.core.registry_forge
python -m blindforge.core.timeline_warp
python -m blindforge.core.mem_mirage
```

## Responsible Disclosure

- All parser differentials will be disclosed to affected tool maintainers 90 days before presentation
- Affected tools: Autopsy/TSK, Volatility3, Plaso/log2timeline
- This research is intended to improve forensic tool robustness and evidence validation practices

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

MIT License — See LICENSE for details.
