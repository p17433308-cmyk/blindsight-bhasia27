"""
BlindForge Registry Forge — Synthesize generated Windows Registry artifacts.

Creates fake UserAssist, RecentDocs, MRU, ShimCache, and AppCompatFlags
entries in raw registry hive files. Forensic tools parse these as evidence
of program execution and file access.
"""

import struct
import os
from datetime import datetime, timezone
from typing import Optional

NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Registry hive constants
REGF_MAGIC = b"regf"
HBIN_MAGIC = b"hbin"
NK_SIGNATURE = b"nk"
VK_SIGNATURE = b"vk"
LF_SIGNATURE = b"lf"

# Standard key flags
NK_KEY_IS_VOLATILE = 0x0001
NK_KEY_HIVE_EXIT = 0x0002
NK_KEY_HIVE_ENTRY = 0x0004
NK_KEY_NO_DELETE = 0x0008
NK_KEY_SYM_LINK = 0x0010
NK_KEY_COMP_NAME = 0x0020

# Value types
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11


def datetime_to_filetime(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - NTFS_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def rot13(data: bytes) -> bytes:
    """ROT13 for UserAssist entries (XOR with 13 for each byte of UTF-16)."""
    result = bytearray()
    for b in data:
        if 0x41 <= b <= 0x5A:
            result.append(((b - 0x41 + 13) % 26) + 0x41)
        elif 0x61 <= b <= 0x7A:
            result.append(((b - 0x61 + 13) % 26) + 0x61)
        else:
            result.append(b)
    return bytes(result)


class UserAssistEntry:
    """A single UserAssist registry value (evidence of GUI program execution)."""

    def __init__(
        self,
        program_path: str,
        run_count: int = 1,
        last_run: Optional[datetime] = None,
        focus_count: int = 1,
        focus_time_ms: int = 30000,
    ):
        self.program_path = program_path
        self.run_count = run_count
        self.last_run = last_run or datetime.now(timezone.utc)
        self.focus_count = focus_count
        self.focus_time_ms = focus_time_ms

    def get_value_name(self) -> str:
        return rot13(self.program_path.encode("ascii")).decode("ascii")

    def get_value_data(self) -> bytes:
        # UserAssist value data format (Windows 7+, version 5):
        # 4 bytes: session ID (0)
        # 4 bytes: run count
        # 4 bytes: focus count
        # 4 bytes: focus time (ms)
        # 44 bytes: padding/unknown
        # 8 bytes: last execution time (FILETIME)
        # 4 bytes: padding
        ft = datetime_to_filetime(self.last_run)

        data = struct.pack("<I", 0)  # session
        data += struct.pack("<I", self.run_count)
        data += struct.pack("<I", self.focus_count)
        data += struct.pack("<I", self.focus_time_ms)
        data += b"\x00" * 44  # unknown fields
        data += struct.pack("<Q", ft)
        data += b"\x00" * 4

        return data


class ShimCacheEntry:
    """A single ShimCache (AppCompatCache) entry."""

    def __init__(
        self,
        file_path: str,
        last_modified: Optional[datetime] = None,
        file_size: int = 0,
        exec_flag: bool = True,
    ):
        self.file_path = file_path
        self.last_modified = last_modified or datetime.now(timezone.utc)
        self.file_size = file_size
        self.exec_flag = exec_flag

    def to_bytes_win10(self) -> bytes:
        path_bytes = self.file_path.encode("utf-16-le")
        ft = datetime_to_filetime(self.last_modified)

        # Win10 format: path_length(4) + path(var) + timestamp(8) + data_size(4) + data(var)
        entry = struct.pack("<I", len(path_bytes))
        entry += path_bytes
        entry += struct.pack("<Q", ft)
        entry += struct.pack("<I", 0)  # data size

        return entry


class RecentDocsEntry:
    """A RecentDocs registry value (evidence of file access)."""

    def __init__(
        self,
        filename: str,
        extension: str,
        mru_position: int = 0,
    ):
        self.filename = filename
        self.extension = extension
        self.mru_position = mru_position

    def get_value_data(self) -> bytes:
        # RecentDocs value format: filename(UTF-16) + null + shell item data
        name_bytes = self.filename.encode("utf-16-le") + b"\x00\x00"
        # Simplified shell item (enough for forensic tools to parse)
        shell_item = struct.pack("<H", len(name_bytes) + 4)
        shell_item += name_bytes
        return name_bytes + shell_item


class RegistryGenerator:
    """High-level interface for forging registry artifacts."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def forge_userassist(
        self,
        entries: list[UserAssistEntry],
        hive_path: Optional[str] = None,
    ) -> str:
        """Create a registry data file with UserAssist entries.

        In a real test_case, these would be synthesized into NTUSER.DAT.
        For the PoC, we create the raw value data that can be imported.
        """
        output = os.path.join(self.output_dir, "userassist_payload.bin")
        with open(output, "wb") as f:
            for entry in entries:
                name = entry.get_value_name()
                data = entry.get_value_data()
                # Write: name_len(4) + name(var) + data_len(4) + data(var)
                name_bytes = name.encode("utf-16-le")
                f.write(struct.pack("<I", len(name_bytes)))
                f.write(name_bytes)
                f.write(struct.pack("<I", len(data)))
                f.write(data)
        return output

    def forge_shimcache(
        self,
        entries: list[ShimCacheEntry],
    ) -> str:
        """Create a ShimCache (AppCompatCache) payload."""
        output = os.path.join(self.output_dir, "shimcache_payload.bin")

        # Win10 header
        header = struct.pack("<I", 0x30)  # header size / signature
        header += struct.pack("<I", len(entries))

        with open(output, "wb") as f:
            f.write(header)
            for entry in entries:
                f.write(entry.to_bytes_win10())
        return output

    def forge_recentdocs(
        self,
        files: list[dict],
    ) -> str:
        """Create RecentDocs payload.

        Each dict: {"filename": str, "extension": str}
        """
        output = os.path.join(self.output_dir, "recentdocs_payload.bin")

        with open(output, "wb") as f:
            # MRU list (most recent first)
            mru_list = list(range(len(files)))
            f.write(struct.pack(f"<{len(mru_list)}I", *mru_list))

            for i, file_spec in enumerate(files):
                entry = RecentDocsEntry(
                    filename=file_spec["filename"],
                    extension=file_spec["extension"],
                    mru_position=i,
                )
                data = entry.get_value_data()
                f.write(struct.pack("<I", len(data)))
                f.write(data)
        return output

    def forge_full_test_case_evidence(
        self,
        executed_programs: list[dict],
        accessed_files: list[dict],
    ) -> dict:
        """Forge a complete set of registry artifacts for an test_case narrative.

        executed_programs: [{"path": str, "run_time": datetime, "run_count": int}]
        accessed_files: [{"filename": str, "extension": str}]
        """
        # UserAssist entries
        ua_entries = [
            UserAssistEntry(
                program_path=p["path"],
                run_count=p.get("run_count", 1),
                last_run=p.get("run_time"),
            )
            for p in executed_programs
        ]
        ua_path = self.forge_userassist(ua_entries)

        # ShimCache entries
        sc_entries = [
            ShimCacheEntry(
                file_path=p["path"],
                last_modified=p.get("run_time"),
            )
            for p in executed_programs
        ]
        sc_path = self.forge_shimcache(sc_entries)

        # RecentDocs
        rd_path = self.forge_recentdocs(accessed_files) if accessed_files else None

        return {
            "userassist": ua_path,
            "shimcache": sc_path,
            "recentdocs": rd_path,
        }


if __name__ == "__main__":
    import tempfile

    print("[BlindForge] Registry Forge — Registry Artifact Generation PoC")
    print("=" * 60)

    output_dir = os.path.join(tempfile.gettempdir(), "registry_generator")
    forge = RegistryGenerator(output_dir)

    executed = [
        {
            "path": "C:\\Users\\jdoe\\Desktop\\test_tool_a.exe",
            "run_time": datetime(2026, 6, 15, 2, 33, 0, tzinfo=timezone.utc),
            "run_count": 3,
        },
        {
            "path": "C:\\Windows\\Temp\\psexec.exe",
            "run_time": datetime(2026, 6, 15, 2, 35, 0, tzinfo=timezone.utc),
            "run_count": 1,
        },
        {
            "path": "C:\\Users\\jdoe\\Downloads\\test_tool_b.exe",
            "run_time": datetime(2026, 6, 15, 2, 40, 0, tzinfo=timezone.utc),
            "run_count": 2,
        },
    ]

    accessed = [
        {"filename": "credentials.xlsx", "extension": ".xlsx"},
        {"filename": "employee_database.csv", "extension": ".csv"},
        {"filename": "network_diagram.pdf", "extension": ".pdf"},
        {"filename": "vpn_config.ovpn", "extension": ".ovpn"},
    ]

    results = forge.forge_full_test_case_evidence(executed, accessed)

    print(f"\n[+] Forged registry artifacts in: {output_dir}")
    print(f"\n    UserAssist payload: {results['userassist']}")
    for p in executed:
        print(f"      {p['path']} (ran {p['run_count']}x, last: {p['run_time']})")

    print(f"\n    ShimCache payload: {results['shimcache']}")
    print(f"      {len(executed)} cached executables")

    print(f"\n    RecentDocs payload: {results['recentdocs']}")
    for f_spec in accessed:
        print(f"      {f_spec['filename']}")

    print("\n[+] Synthesize into NTUSER.DAT / SYSTEM hive on a disk image")
    print("[+] RegRipper/Registry Explorer will show program execution + file access")
    print("\n[!] None of these programs were run. No files were accessed.")
