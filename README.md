# BlindSight

**Adversarial Robustness Testing of Digital Forensic Tool Parsers**

> Prajwal Chowdary & Dr. Sapna Prasad B Honnavalli — PES University

---

## What Is This?

BlindSight demonstrates that digital forensic tools can be systematically deceived into reporting synthetic evidence as genuine. We introduce five novel test classes targeting the forensic toolchain itself — not to destroy or hide evidence, but to evaluate whether tools can distinguish authentic artifacts from synthetically generated ones.

A 2026 Systematization of Knowledge survey covering 123 anti-forensic papers found **zero** research on adversarial testing of forensic tools themselves. BlindSight fills that gap.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    BlindSight Framework                      │
├───────────────────┬─────────────────┬───────────────────────┤
│    SynthForge     │   DiffOracle    │  BlindSight Validator │
│    (Red Team)     │   (Analysis)    │     (Blue Team)       │
├───────────────────┼─────────────────┼───────────────────────┤
│ MFT Generator     │ Tool Harness    │ Integrity Checker     │
│ EVTX Generator    │ Semantic Differ │ Anomaly Detector      │
│ Prefetch Generator│ Report Gen      │ Cross-Source Validator │
│ SQLite Generator  │                 │ Validation Reports    │
│ Registry Generator│                 │                       │
│ Timeline Synth.   │                 │                       │
│ Memory Simulator  │                 │                       │
└───────────────────┴─────────────────┴───────────────────────┘
```

**Timeline Synthesizer** orchestrates all modules — define one test narrative and it generates consistent, corroborating artifacts across every source.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full architecture and data flow diagrams.

## Test Classes

| # | Class | Description | Target Artifacts |
|---|-------|-------------|-----------------|
| 1 | **Parser Differentials** | Craft artifacts that different tools interpret contradictorily | MFT, EVTX, Registry |
| 2 | **Record Synthesis** | Generate structurally valid records for activity that never occurred | MFT, EVTX, Prefetch, Registry, SQLite |
| 3 | **Timeline Consistency** | Cross-source timestamp synthesis corrupting timeline reconstruction | All artifact types |
| 4 | **Process Simulation** | Synthetic process structures in memory dumps | EPROCESS, VAD, Handle Tables |
| 5 | **Database Records** | Synthetic browser history/downloads indistinguishable from genuine | Chrome, Firefox, Safari DBs |

## Project Structure

```
blindsight-bhasia27/
├── synthforge/                  # Red-team toolkit
│   ├── core/
│   │   ├── mft_generator.py         # NTFS MFT entry synthesis
│   │   ├── evtx_generator.py        # Windows Event Log synthesis
│   │   ├── prefetch_generator.py    # Prefetch file generation
│   │   ├── registry_generator.py    # Registry artifact synthesis
│   │   ├── sqlite_generator.py      # Browser history synthesis
│   │   ├── timeline_synthesizer.py  # Cross-source timeline synthesis
│   │   └── mem_simulator.py         # Memory dump process simulation
│   └── cli.py                       # Command-line interface
├── difforacle/                  # Parser differential finder
│   ├── harness.py                   # Multi-tool execution harness
│   ├── differ.py                    # Semantic output comparison
│   └── report.py                    # Differential reports
├── blindsight_validator/        # Blue-team defensive tool
│   ├── integrity.py                 # Cross-tool validation
│   ├── anomaly.py                   # Structural anomaly detection
│   └── report.py                    # Validation reports
├── demo/                        # Demo suite with real tool validation
├── docs/
│   └── ARCHITECTURE.md              # Architecture & data flow
└── cfp/
    └── submission.md                # Conference submission
```

## Quick Start

```bash
# Clone
git clone https://github.com/prajwalchowdary5/blindsight-bhasia27.git
cd blindsight-bhasia27

# Install
pip install -e .

# Generate a complete synthetic test narrative
synthforge narrative --user jdoe --computer WORKSTATION-01 \
    --source-ip 10.0.0.55 --output ./demo_output

# Validate evidence integrity
synthforge validate --mft suspicious_mft.bin --evtx suspicious.evtx
```

## Individual Module PoCs

Each module runs standalone:

```bash
python -m synthforge.core.mft_generator
python -m synthforge.core.evtx_generator
python -m synthforge.core.prefetch_generator
python -m synthforge.core.sqlite_generator
python -m synthforge.core.registry_generator
python -m synthforge.core.timeline_synthesizer
python -m synthforge.core.mem_simulator
```

## Targeted Forensic Tools

| Tool | Version Tested | Evaluation Surface |
|------|---------------|-------------------|
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

This tool is provided for **authorized security research and forensic tool testing only**. Do not use it to tamper with evidence in actual investigations or legal proceedings. The authors are not responsible for misuse.

## Citation

```bibtex
@misc{chowdary2027blindsight,
  title={BlindSight: Adversarial Robustness Testing of Digital Forensic Tool Parsers},
  author={Chowdary, Prajwal and Honnavalli, Sapna Prasad B},
  year={2027}
}
```

## License

MIT License — See [LICENSE](LICENSE) for details.
