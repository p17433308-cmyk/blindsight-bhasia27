# BlindSight — Black Hat Asia 2027 Briefings CFP Submission

---

## Session Title

BlindSight: Weaponizing Parser Differentials to Fabricate Forensic Evidence

---

## Track (Primary)

Forensics & Incident Response

## Track (Secondary)

Defense

---

## Format

40 minutes

---

## Audience Level

Advanced

---

## Abstract

Digital forensic investigations depend on the assumption that tools like Autopsy, Sleuthkit, Volatility, and Plaso produce accurate, consistent interpretations of evidence. We systematically dismantle this assumption. BlindSight introduces the first structured attack framework targeting the forensic toolchain itself — not to destroy evidence or hide artifacts, but to make forensic tools produce convincing false evidence that implicates innocent users or exonerates attackers.

We present five novel attack classes: (1) Parser Differentials — crafted artifacts that different forensic tools interpret contradictorily, producing conflicting timelines from identical evidence; (2) Ghost Injection — structurally valid MFT entries, Event Log records, Prefetch files, and registry keys referencing activity that never occurred; (3) Timeline Poisoning — cross-source timestamp manipulation that corrupts reconstructed event sequences; (4) Memory Mirage — fabricated process structures in memory dumps that fool Volatility into reporting phantom processes; and (5) SQLite Phantom Records — injected browser history and download records indistinguishable from genuine entries.

We release BlindForge, an open-source toolkit implementing these attacks, and BlindSight Validator, a defensive framework that detects fabricated artifacts through cross-tool consistency analysis and structural anomaly detection. We demonstrate all attacks live against current versions of major forensic tools, and provide a benchmark dataset of poisoned disk images with ground truth for community validation.

---

## Presentation Outline

### Introduction and Motivation (5 min)
- The forensic trust assumption: tools parse evidence correctly and consistently
- Real-world stakes: forensic output used in criminal prosecutions, incident response, and civil litigation
- Gap in prior art: anti-forensic research focuses on evidence destruction and concealment, not fabrication
- Reference: 2026 SoK survey of 123 anti-forensic papers found zero research on attacking forensic tools themselves

### Attack Taxonomy and Threat Model (5 min)
- Threat model: attacker with temporary write access to a disk image, memory dump, or live system
- Five attack classes defined: Parser Differentials, Ghost Injection, Timeline Poisoning, Memory Mirage, SQLite Phantom Records
- Mapping attack classes to forensic workflow stages (acquisition, analysis, timeline reconstruction, reporting)

### Parser Differentials Deep Dive (7 min)
- How NTFS MFT $STANDARD_INFORMATION vs $FILE_NAME timestamps are interpreted differently across Autopsy, Sleuthkit, and Plaso
- Crafting edge cases: timezone transitions, nanosecond precision boundaries, daylight saving cutover timestamps
- EVTX record parsing divergences across tools
- Demo: identical disk image producing two contradictory timelines in two tools

### Ghost Injection: Fabricating Evidence That Never Existed (8 min)
- MFT entry injection: creating structurally valid FILE records in unallocated MFT space
- Event Log injection: inserting logon events (4624), process creation (4688), and service installation (7045) records with valid checksums
- Prefetch fabrication: generating valid .pf files for executables never executed
- Registry artifact injection: UserAssist, RecentDocs, MRU, ShimCache entries
- Demo: Autopsy ingesting a disk image and displaying fabricated browser history, file access, and program execution as genuine evidence

### Timeline Poisoning and Memory Mirage (5 min)
- Cross-source timestamp manipulation: injecting conflicting timestamps across MFT, Event Logs, Prefetch, and Registry to corrupt Plaso/log2timeline output
- Memory Mirage: crafting EPROCESS, VAD tree, and handle table structures that Volatility3 parses as valid process trees
- Demo: Volatility3 showing a phantom malware process in a clean memory dump

### BlindSight Validator: Detection and Defense (5 min)
- Cross-tool consistency analysis: running the same evidence through multiple parsers and flagging contradictions
- Structural anomaly detection: MFT sequence number gaps, EVTX record ID discontinuities, Prefetch hash mismatches
- Timestamp entropy analysis: detecting statistically improbable timestamp distributions
- Integration into existing forensic workflows

### Implications and Responsible Disclosure (3 min)
- Legal implications: Daubert standard and tool reliability challenges
- Disclosure: findings shared with Autopsy, Sleuthkit, Volatility, and Plaso maintainers prior to presentation
- Released artifacts: BlindForge toolkit, BlindSight Validator, benchmark dataset with ground truth

### Q&A (2 min)

---

## Problem Statement

Every digital forensic investigation — whether in criminal prosecution, corporate incident response, or civil litigation — relies on the implicit assumption that forensic tools accurately and consistently interpret digital evidence. This assumption has never been systematically tested against an adversary who deliberately crafts evidence to exploit tool-specific parsing behaviors.

Current anti-forensic research focuses on two approaches: destroying evidence (wiping, encryption, secure deletion) and concealing evidence (steganography, slack space hiding, timestomping). Both are well-studied and detectable. A third, far more dangerous category remains unexplored: fabricating forensic evidence that tools accept as genuine.

We address this gap by identifying and exploiting parser differentials across major forensic tools, demonstrating that an attacker with brief write access to a system or evidence container can inject structurally valid artifacts — MFT entries, Event Log records, Prefetch files, registry keys, browser history — that forensic tools interpret as evidence of activity that never occurred. This has direct implications for the admissibility and reliability of digital evidence in legal proceedings.

---

## Audience Takeaways

1. **Forensic tools can be systematically deceived**: Attendees will understand five concrete attack classes that cause Autopsy, Sleuthkit, Volatility, and Plaso to report fabricated evidence as genuine — and learn which artifact types are most vulnerable to injection.

2. **Parser differentials undermine evidence consistency**: Attendees will learn that the same disk image can produce contradictory forensic narratives depending on which tool interprets it — a critical challenge for evidence admissibility that requires cross-tool validation as standard practice.

3. **Practical defense through cross-tool validation**: Attendees will gain the BlindSight Validator framework and methodology for detecting fabricated artifacts by correlating outputs across multiple forensic tools and applying structural anomaly detection — techniques they can integrate into their forensic workflows immediately.

---

## Research Novelty

This research is the first systematic study of offensive attacks targeting the forensic toolchain itself. While prior anti-forensic work focuses on evidence destruction (secure deletion, encryption) or concealment (steganography, timestomping), no published research has demonstrated the fabrication of structurally valid forensic artifacts designed to make tools produce false-positive evidence.

Our novel contributions include:
- The first taxonomy of forensic tool exploitation attack classes (Parser Differentials, Ghost Injection, Timeline Poisoning, Memory Mirage, SQLite Phantom Records)
- Discovery and documentation of parser differentials across Autopsy, Sleuthkit, Volatility3, and Plaso
- BlindForge: an open-source attack toolkit for forensic artifact fabrication
- BlindSight Validator: an open-source defensive framework for detecting fabricated artifacts
- A benchmark dataset of poisoned disk images with ground truth annotations

This directly addresses the gap identified by the 2026 Systematization of Knowledge survey on anti-forensics, which found zero research on attacks against forensic tools and processes across 123 reviewed papers.

---

## Prior Release & New Material

**Has any portion been previously published or presented?** No

**Estimated % of new material:** 100%

---

## Plans to Publish Elsewhere

No plans to submit or publish this research before Black Hat Asia 2027. If accepted, we will coordinate any subsequent academic publication to respect Black Hat's embargo requirements.

---

## New Vulnerabilities

**Yes.** We disclose parser differentials (inconsistent interpretation of identical evidence) across the following tools:
- Autopsy / The Sleuth Kit (NTFS MFT timestamp parsing, EVTX record handling)
- Volatility3 (EPROCESS structure validation, memory pool tag verification)
- Plaso / log2timeline (timestamp merging logic, source priority conflicts)

These are logic-level inconsistencies rather than memory corruption vulnerabilities. Affected systems: any forensic investigation using these tools on Windows artifacts. Potential impact: fabricated evidence accepted as genuine in forensic reports and legal proceedings.

**Disclosure Status:** We will notify all affected tool maintainers (Autopsy/TSK via Brian Carrier, Volatility Foundation, Plaso/log2timeline via Google) at least 90 days before presentation with full technical details and recommended mitigations.

---

## New Tools

**Yes.** Two open-source tools will be released:

1. **BlindForge** — Offensive toolkit for forensic artifact fabrication. Generates structurally valid NTFS MFT entries, Windows Event Log records, Prefetch files, registry artifacts, SQLite browser history records, and memory dump structures. Python-based, modular architecture. Purpose: demonstrate attacks and enable forensic tool developers to test parser robustness.

2. **BlindSight Validator** — Defensive framework for detecting fabricated forensic artifacts. Performs cross-tool output comparison, structural anomaly detection (sequence gaps, hash mismatches, timestamp entropy), and consistency scoring. Python-based. Purpose: enable forensic examiners to validate evidence integrity.

Both tools are proprietary during development and will be released as open-source (MIT license) at the time of presentation.

---

## Demo Plans

**Yes.** Three live demonstrations are planned:

1. **Parser Differential Demo** (3 min): A single disk image is analyzed by two different forensic tools. Each tool produces a different timeline of user activity — contradictory forensic narratives from identical evidence.

2. **Ghost Injection Demo** (4 min): A clean disk image is processed by BlindForge to inject fabricated browser history, program execution evidence, and login records. Autopsy then ingests the modified image and displays the fabricated activity as genuine evidence, complete with correct timestamps and cross-referenced artifacts.

3. **Memory Mirage Demo** (2 min): A clean Windows memory dump is modified to contain fabricated process structures. Volatility3 parses the dump and reports a phantom malware process with a full process tree, loaded modules, and network connections that never existed.

All demos run on the presenter's laptop with no network requirements.

---

## Speaker 1

- **First Name:** Prajwal
- **Last Name:** Chowdary
- **Title:** Security Researcher
- **Organization:** PES University
- **Email:** chowdaryprajwal2@gmail.com
- **Bio:** Prajwal Chowdary is a Security Researcher at PES University specializing in digital forensics, anti-forensics, and offensive security research. His work focuses on the intersection of forensic tool reliability and adversarial evidence manipulation, with prior research contributions in honeypot systems, forensic dataset generation, and file carver vulnerability analysis.
- **Speaker Role:** Speaker
- **Country:** India

## Speaker 2

- **Pre-Nominals:** Dr.
- **First Name:** Sapna
- **Last Name:** Prasad B Honnavalli
- **Title:** Professor
- **Organization:** PES University
- **Email:** [Dr. Sapna's email — fill before submission]
- **Bio:** Dr. Sapna Prasad B Honnavalli is a Professor at PES University with extensive experience in cybersecurity, digital forensics, and network security research. She has supervised numerous research projects in offensive security, honeypot architectures, and forensic tool development, and serves as a reviewer for leading security and forensics journals.
- **Speaker Role:** Speaker
- **Country:** India

---

## Message to the Review Board (optional)

This research addresses a critical blind spot in digital forensics that has direct implications for the legal admissibility of digital evidence worldwide. The 2026 Systematization of Knowledge survey on anti-forensics explicitly identified "attacks on forensic tools and processes" as an area with zero published research across 123 reviewed papers. We fill that gap with a comprehensive offensive framework, live demonstrations, and a defensive toolkit that the forensic community can deploy immediately. We believe this work will fundamentally change how forensic examiners validate evidence integrity and how tool developers approach parser robustness.

---

## Publication Timing/Embargo

We are comfortable with publication upon acceptance. Title, abstract, and speaker information may be published as early as 2 November 2026.
