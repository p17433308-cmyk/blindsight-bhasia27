"""
BlindForge Prefetch Forge — Generate Windows Prefetch files.

Generates valid Windows 10/11 Prefetch (.pf) files for executables that
were never run. Forensic tools (PECmd, Autopsy, etc.) parse these as
evidence of program execution.
"""

import struct
import os
import hashlib
from datetime import datetime, timezone
from typing import Optional

NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Prefetch format versions
PF_VERSION_WIN10 = 30  # Windows 10/11 (MAM compressed)
PF_VERSION_WIN8 = 26   # Windows 8/8.1
PF_VERSION_WIN7 = 23   # Windows 7 / Vista

# MAM signature (compressed prefetch in Win10+)
MAM_SIGNATURE = b"MAM\x04"

# Uncompressed prefetch signature
SCCA_SIGNATURE = b"SCCA"


def datetime_to_filetime(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - NTFS_EPOCH
    return int(delta.total_seconds() * 10_000_000)


def prefetch_hash(executable_path: str) -> int:
    """Calculate the SCCA hash for a given executable path.

    Windows uses this hash in the prefetch filename: EXENAME-XXXXXXXX.pf
    This implements the hash algorithm used by Windows 10/11.
    """
    path_upper = executable_path.upper()
    hash_val = 0
    for char in path_upper:
        hash_val = ((hash_val * 37) + ord(char)) & 0xFFFFFFFF
    return hash_val


class PrefetchFile:
    """Represents a Windows Prefetch file."""

    def __init__(
        self,
        executable_name: str,
        executable_path: str,
        version: int = PF_VERSION_WIN10,
    ):
        self.executable_name = executable_name
        self.executable_path = executable_path
        self.version = version
        self.run_count: int = 1
        self.last_run_times: list[datetime] = []
        self.volume_path: str = "\\VOLUME{01d7a8b9c0d1e2f3}"
        self.volume_creation_time: datetime = datetime(2024, 1, 15, tzinfo=timezone.utc)
        self.volume_serial: int = 0x3A4B5C6D
        self.file_references: list[str] = []
        self.directory_strings: list[str] = []

    def set_execution_times(
        self,
        last_run: datetime,
        previous_runs: Optional[list[datetime]] = None,
        run_count: Optional[int] = None,
    ) -> None:
        self.last_run_times = [last_run]
        if previous_runs:
            self.last_run_times.extend(previous_runs[:7])  # max 8 timestamps
        if run_count is not None:
            self.run_count = run_count
        else:
            self.run_count = len(self.last_run_times)

    def add_file_reference(self, path: str) -> None:
        self.file_references.append(path)

    def add_directory(self, path: str) -> None:
        self.directory_strings.append(path)

    def _build_file_metrics(self) -> bytes:
        metrics = bytearray()
        for ref_path in self.file_references:
            entry = struct.pack("<II", 0, 0)  # start time, duration
            path_bytes = ref_path.encode("utf-16-le")
            entry += struct.pack("<II", 0, len(path_bytes))
            entry += struct.pack("<I", 0)  # flags
            entry += path_bytes
            entry = entry.ljust(((len(entry) + 7) & ~7), b"\x00")
            metrics += entry
        return bytes(metrics)

    def _build_volume_info(self) -> bytes:
        vol_path = self.volume_path.encode("utf-16-le")
        vol_creation = datetime_to_filetime(self.volume_creation_time)

        vol_info = struct.pack(
            "<II",
            0x60,  # device path offset
            len(self.volume_path),  # device path length (chars)
        )
        vol_info += struct.pack("<QI", vol_creation, self.volume_serial)
        # Directory strings offset and count
        dir_strings = b""
        for d in self.directory_strings:
            d_bytes = d.encode("utf-16-le") + b"\x00\x00"
            dir_strings += struct.pack("<H", len(d)) + d_bytes

        vol_info += struct.pack("<II", 0x60 + len(vol_path), len(self.directory_strings))
        vol_info = vol_info.ljust(0x60, b"\x00")
        vol_info += vol_path
        vol_info += dir_strings

        return vol_info

    def to_bytes(self) -> bytes:
        exe_hash = prefetch_hash(self.executable_path)

        # File metrics section
        file_metrics = self._build_file_metrics()

        # Filename strings (just the executable path for now)
        filename_strings = self.executable_path.encode("utf-16-le") + b"\x00\x00"

        # Volume info
        volume_info = self._build_volume_info()

        # Timestamps array (up to 8 last run times)
        timestamps = bytearray()
        for i in range(8):
            if i < len(self.last_run_times):
                ft = datetime_to_filetime(self.last_run_times[i])
            else:
                ft = 0
            timestamps += struct.pack("<Q", ft)

        # Build the SCCA body
        exe_name_30 = self.executable_name.encode("utf-16-le")
        exe_name_30 = exe_name_30[:58].ljust(60, b"\x00")  # 30 chars max

        # Header offsets (version 30 layout)
        file_metrics_offset = 0x130  # after header
        filename_strings_offset = file_metrics_offset + len(file_metrics)
        volume_info_offset = filename_strings_offset + len(filename_strings)

        header = bytearray(struct.pack("<I", self.version))  # version
        header += SCCA_SIGNATURE
        header += struct.pack("<I", 0)  # unknown
        header += struct.pack(
            "<I",
            file_metrics_offset + len(file_metrics) + len(filename_strings) + len(volume_info) + 64,
        )  # file size
        header += exe_name_30
        header += struct.pack("<I", exe_hash)

        # Section offsets and counts
        header += struct.pack("<II", file_metrics_offset, len(self.file_references))
        header += struct.pack("<II", filename_strings_offset, len(filename_strings))
        header += struct.pack("<II", volume_info_offset, 1)  # 1 volume

        # Pad to reach timestamps at 0xD0
        if len(header) < 0xD0:
            header += bytearray(0xD0 - len(header))

        # Last run timestamps at 0xD0 (version 30)
        header += bytearray(timestamps)

        # Pad to 0x124 and write run count at 0x120
        if len(header) < 0x124:
            header += bytearray(0x124 - len(header))
        struct.pack_into("<I", header, 0x120, self.run_count)

        # Pad to first attribute offset
        if len(header) < file_metrics_offset:
            header += bytearray(file_metrics_offset - len(header))

        body = header + file_metrics + filename_strings + volume_info
        return bytes(body)

    def get_filename(self) -> str:
        exe_hash = prefetch_hash(self.executable_path)
        name = self.executable_name.upper().replace(".EXE", "")
        return f"{name}-{exe_hash:08X}.pf"

    def save(self, output_dir: str) -> str:
        filename = self.get_filename()
        path = os.path.join(output_dir, filename)
        data = self.to_bytes()
        with open(path, "wb") as f:
            f.write(data)
        return path


class PrefetchGenerator:
    """High-level interface for generating prefetch files."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def forge_execution(
        self,
        executable_name: str,
        executable_path: str,
        last_run: datetime,
        run_count: int = 1,
        previous_runs: Optional[list[datetime]] = None,
        loaded_dlls: Optional[list[str]] = None,
        directories: Optional[list[str]] = None,
    ) -> str:
        pf = PrefetchFile(executable_name, executable_path)
        pf.set_execution_times(last_run, previous_runs, run_count)

        # Add realistic file references
        pf.add_file_reference(executable_path)
        if loaded_dlls:
            for dll in loaded_dlls:
                pf.add_file_reference(dll)
        else:
            # Add common system DLLs
            pf.add_file_reference("\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32\\NTDLL.DLL")
            pf.add_file_reference("\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL")
            pf.add_file_reference("\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32\\KERNELBASE.DLL")
            pf.add_file_reference("\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32\\MSVCRT.DLL")

        if directories:
            for d in directories:
                pf.add_directory(d)
        else:
            pf.add_directory("\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32")
            pf.add_directory("\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS")

        return pf.save(self.output_dir)

    def forge_test_case_chain(
        self,
        tools: list[dict],
    ) -> list[str]:
        """Forge prefetch files for a sequence of test_caseer tools.

        Each dict: {"name": str, "path": str, "run_time": datetime,
                     "run_count": int}
        """
        paths = []
        for tool in tools:
            path = self.forge_execution(
                executable_name=tool["name"],
                executable_path=tool["path"],
                last_run=tool["run_time"],
                run_count=tool.get("run_count", 1),
            )
            paths.append(path)
        return paths


if __name__ == "__main__":
    import tempfile

    print("[BlindForge] Prefetch Forge — Program Execution Generation PoC")
    print("=" * 60)

    output_dir = os.path.join(tempfile.gettempdir(), "prefetch_generator")
    forge = PrefetchGenerator(output_dir)

    # Generate evidence of test_caseer tools being executed
    test_case_tools = [
        {
            "name": "TEST_TOOL_A.EXE",
            "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\USERS\\ADMIN\\DESKTOP\\TEST_TOOL_A.EXE",
            "run_time": datetime(2026, 6, 15, 2, 33, 0, tzinfo=timezone.utc),
            "run_count": 3,
        },
        {
            "name": "PSEXEC.EXE",
            "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\TEMP\\PSEXEC.EXE",
            "run_time": datetime(2026, 6, 15, 2, 35, 0, tzinfo=timezone.utc),
            "run_count": 1,
        },
        {
            "name": "PROCDUMP.EXE",
            "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\USERS\\ADMIN\\DOWNLOADS\\PROCDUMP.EXE",
            "run_time": datetime(2026, 6, 15, 2, 40, 0, tzinfo=timezone.utc),
            "run_count": 2,
        },
        {
            "name": "RAR.EXE",
            "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\WINRAR\\RAR.EXE",
            "run_time": datetime(2026, 6, 15, 2, 45, 0, tzinfo=timezone.utc),
            "run_count": 1,
        },
    ]

    paths = forge.forge_test_case_chain(test_case_tools)

    print(f"\n[+] Generated {len(paths)} prefetch files:")
    for i, p in enumerate(paths):
        print(f"    {os.path.basename(p)}")
        print(f"      Tool: {test_case_tools[i]['name']}")
        print(f"      Last Run: {test_case_tools[i]['run_time']}")
        print(f"      Run Count: {test_case_tools[i]['run_count']}")

    print(f"\n[+] Output directory: {output_dir}")
    print("[+] Drop these into C:\\Windows\\Prefetch on a disk image")
    print("[+] PECmd/Autopsy will report these programs were executed")
    print("\n[!] None of these tools were ever run on this system.")
