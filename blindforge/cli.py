"""
BlindForge CLI — Command-line interface for forensic artifact fabrication.
"""

import argparse
import os
import sys
import tempfile
from datetime import datetime, timezone


def cmd_inject_mft(args):
    from .core.mft_injector import MFTInjector, create_empty_mft

    if args.create_test:
        mft_data = create_empty_mft(args.record_count or 256)
        with open(args.output, "wb") as f:
            f.write(mft_data)
        print(f"[+] Created test MFT: {args.output}")
        return

    injector = MFTInjector(args.mft)
    injector.load()

    ts = datetime.fromisoformat(args.timestamp) if args.timestamp else datetime.now(timezone.utc)

    rec = injector.inject_ghost_file(
        filename=args.filename,
        created=ts,
        modified=ts,
        accessed=ts,
        content=args.content.encode() if args.content else b"",
    )

    output = injector.save(args.output or args.mft + ".poisoned")
    print(f"[+] Injected '{args.filename}' as record #{rec}")
    print(f"[+] Saved to: {output}")


def cmd_inject_evtx(args):
    from .core.evtx_injector import (
        EVTXInjector, create_empty_evtx,
        logon_event_4624, process_creation_4688, service_install_7045,
    )

    if args.create_test:
        evtx_data = create_empty_evtx()
        with open(args.output, "wb") as f:
            f.write(evtx_data)
        print(f"[+] Created test EVTX: {args.output}")
        return

    injector = EVTXInjector(args.evtx)
    injector.load()

    ts = datetime.fromisoformat(args.timestamp) if args.timestamp else datetime.now(timezone.utc)
    rid = injector.get_last_record_id()

    if args.event_type == "logon":
        rec = logon_event_4624(rid, ts, username=args.username or "admin",
                               source_ip=args.source_ip or "10.0.0.1")
    elif args.event_type == "process":
        rec = process_creation_4688(rid, ts, process_name=args.process or "cmd.exe",
                                    command_line=args.cmdline or "cmd.exe")
    elif args.event_type == "service":
        rec = service_install_7045(rid, ts, service_name=args.service_name or "TestSvc",
                                   image_path=args.image_path or "C:\\svc.exe")
    else:
        print(f"[-] Unknown event type: {args.event_type}")
        return

    injector.inject_record(rec)
    output = injector.save(args.output or args.evtx + ".poisoned")
    print(f"[+] Injected {args.event_type} event (ID {rid})")
    print(f"[+] Saved to: {output}")


def cmd_narrative(args):
    from .core.timeline_warp import TimelineWarp, build_data_breach_narrative

    ts = datetime.fromisoformat(args.start_time) if args.start_time else None
    narrative = build_data_breach_narrative(
        target_user=args.user or "jdoe",
        target_computer=args.computer or "WORKSTATION-01",
        source_ip=args.source_ip or "10.0.0.55",
        start_time=ts,
    )

    output_dir = args.output or os.path.join(tempfile.gettempdir(), "blindforge_narrative")
    warp = TimelineWarp(output_dir)

    print(f"[*] Building narrative: {narrative.name}")
    results = warp.materialize(narrative)
    report = warp.generate_timeline_report(narrative)

    print(f"\n[+] Artifacts generated in: {output_dir}")
    for k, v in results.items():
        if isinstance(v, list):
            print(f"    {k}: {len(v)} files")
        elif isinstance(v, dict):
            for sub_k, sub_v in v.items():
                print(f"    {k}/{sub_k}: {sub_v}")
        else:
            print(f"    {k}: {v}")
    print(f"    report: {report}")


def cmd_validate(args):
    from blindsight_validator.integrity import MFTIntegrityChecker, EVTXIntegrityChecker
    from blindsight_validator.report import generate_validation_report

    alerts = []

    if args.mft:
        checker = MFTIntegrityChecker(args.mft)
        alerts.extend(checker.check_all())

    if args.evtx:
        checker = EVTXIntegrityChecker(args.evtx)
        alerts.extend(checker.check_all())

    if alerts:
        report = generate_validation_report(alerts, output_path=args.output)
        print(report)
    else:
        print("[+] No anomalies detected")


def main():
    parser = argparse.ArgumentParser(
        prog="blindforge",
        description="BlindForge — Forensic Artifact Fabrication Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command")

    # MFT injection
    mft_parser = subparsers.add_parser("mft", help="Inject ghost files into MFT")
    mft_parser.add_argument("--mft", help="Path to raw MFT file")
    mft_parser.add_argument("--filename", help="Ghost filename to inject")
    mft_parser.add_argument("--timestamp", help="ISO timestamp for the file")
    mft_parser.add_argument("--content", help="File content (small, resident)")
    mft_parser.add_argument("--output", "-o", help="Output path")
    mft_parser.add_argument("--create-test", action="store_true", help="Create test MFT")
    mft_parser.add_argument("--record-count", type=int, help="Records for test MFT")
    mft_parser.set_defaults(func=cmd_inject_mft)

    # EVTX injection
    evtx_parser = subparsers.add_parser("evtx", help="Inject events into EVTX")
    evtx_parser.add_argument("--evtx", help="Path to EVTX file")
    evtx_parser.add_argument("--event-type", choices=["logon", "process", "service"])
    evtx_parser.add_argument("--timestamp", help="ISO timestamp")
    evtx_parser.add_argument("--username", help="Target username")
    evtx_parser.add_argument("--source-ip", help="Source IP for logon")
    evtx_parser.add_argument("--process", help="Process path for 4688")
    evtx_parser.add_argument("--cmdline", help="Command line for 4688")
    evtx_parser.add_argument("--service-name", help="Service name for 7045")
    evtx_parser.add_argument("--image-path", help="Service image path for 7045")
    evtx_parser.add_argument("--output", "-o", help="Output path")
    evtx_parser.add_argument("--create-test", action="store_true")
    evtx_parser.set_defaults(func=cmd_inject_evtx)

    # Full narrative
    narr_parser = subparsers.add_parser("narrative", help="Generate full attack narrative")
    narr_parser.add_argument("--user", help="Target username")
    narr_parser.add_argument("--computer", help="Target computer name")
    narr_parser.add_argument("--source-ip", help="Attacker source IP")
    narr_parser.add_argument("--start-time", help="ISO start timestamp")
    narr_parser.add_argument("--output", "-o", help="Output directory")
    narr_parser.set_defaults(func=cmd_narrative)

    # Validation
    val_parser = subparsers.add_parser("validate", help="Validate evidence integrity")
    val_parser.add_argument("--mft", help="MFT file to validate")
    val_parser.add_argument("--evtx", help="EVTX file to validate")
    val_parser.add_argument("--output", "-o", help="Report output path")
    val_parser.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
