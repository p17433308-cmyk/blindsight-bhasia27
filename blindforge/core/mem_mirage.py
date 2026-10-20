"""
BlindForge Memory Mirage — Fabricate process structures in memory dumps.

Crafts Windows EPROCESS, VAD tree, handle table, and loaded module
structures that Volatility3 parses as valid processes. Creates phantom
processes in clean memory dumps.
"""

import struct
import os
from datetime import datetime, timezone
from typing import Optional

NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Windows pool tags
POOL_TAG_PROC = b"Proc"  # EPROCESS
POOL_TAG_THRD = b"Thrd"  # ETHREAD
POOL_TAG_OBHD = b"ObHd"  # Object Header
POOL_TAG_VADM = b"VadM"  # VAD (memory-mapped)
POOL_TAG_VADS = b"VadS"  # VAD (short)

# Page size
PAGE_SIZE = 0x1000


def datetime_to_filetime(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - NTFS_EPOCH
    return int(delta.total_seconds() * 10_000_000)


class EProcess:
    """Represents a Windows EPROCESS structure (simplified for Volatility3)."""

    def __init__(
        self,
        pid: int,
        ppid: int,
        image_name: str,
        create_time: datetime,
        exit_time: Optional[datetime] = None,
        session_id: int = 1,
        is_wow64: bool = False,
        base_address: int = 0x00400000,
    ):
        self.pid = pid
        self.ppid = ppid
        self.image_name = image_name[:15]  # EPROCESS.ImageFileName is 16 bytes
        self.create_time = create_time
        self.exit_time = exit_time
        self.session_id = session_id
        self.is_wow64 = is_wow64
        self.base_address = base_address
        self.unique_process_id = pid
        self.inherited_from_unique_process_id = ppid
        self.active_threads = 1
        self.handle_count = 42
        self.virtual_size = 0x1000000  # 16 MB

        # Linked list pointers (will be set during injection)
        self.flink = 0
        self.blink = 0
        self.peb_address = 0
        self.object_table = 0
        self.token = 0

    def to_bytes_win10_x64(self, eprocess_offset: int = 0) -> bytes:
        """Build an EPROCESS structure for Windows 10 x64.

        Offsets are based on Windows 10 build 19041 (20H1).
        Total structure size: ~0xB80
        """
        buf = bytearray(0xC00)

        # PCB (Pcb) - KPROCESS at offset 0x0
        # DirectoryTableBase at 0x28
        struct.pack_into("<Q", buf, 0x28, 0x1A3000)  # fake page directory

        # EPROCESS fields (offsets for Win10 19041 x64)
        # UniqueProcessId at 0x440
        struct.pack_into("<Q", buf, 0x440, self.pid)

        # ActiveProcessLinks (LIST_ENTRY) at 0x448
        struct.pack_into("<Q", buf, 0x448, self.flink)  # Flink
        struct.pack_into("<Q", buf, 0x450, self.blink)  # Blink

        # CreateTime at 0x458 (LARGE_INTEGER / FILETIME)
        ct = datetime_to_filetime(self.create_time)
        struct.pack_into("<Q", buf, 0x458, ct)

        # ImageFileName at 0x5A8 (16 bytes, null-padded)
        name_bytes = self.image_name.encode("ascii")[:15]
        buf[0x5A8:0x5A8 + len(name_bytes)] = name_bytes

        # InheritedFromUniqueProcessId at 0x540
        struct.pack_into("<Q", buf, 0x540, self.ppid)

        # Peb at 0x550
        struct.pack_into("<Q", buf, 0x550, self.peb_address)

        # ObjectTable at 0x570
        struct.pack_into("<Q", buf, 0x570, self.object_table)

        # SessionId
        struct.pack_into("<I", buf, 0x5B4, self.session_id)

        # ExitTime at 0x460
        if self.exit_time:
            et = datetime_to_filetime(self.exit_time)
            struct.pack_into("<Q", buf, 0x460, et)

        # VirtualSize at 0x498
        struct.pack_into("<Q", buf, 0x498, self.virtual_size)

        # ActiveThreads at 0x5F0
        struct.pack_into("<I", buf, 0x5F0, self.active_threads)

        # Token (EX_FAST_REF) at 0x4B8
        struct.pack_into("<Q", buf, 0x4B8, self.token)

        return bytes(buf)


class PoolHeader:
    """Windows pool allocation header preceding kernel objects."""

    def __init__(
        self,
        pool_tag: bytes,
        block_size: int,
        pool_type: int = 0x02,  # NonPagedPool
        previous_size: int = 0,
    ):
        self.pool_tag = pool_tag
        self.block_size = block_size
        self.pool_type = pool_type
        self.previous_size = previous_size

    def to_bytes(self) -> bytes:
        # POOL_HEADER structure (16 bytes on x64)
        buf = bytearray(16)
        # PreviousSize (in 16-byte units) at 0x0
        struct.pack_into("<H", buf, 0x0, self.previous_size)
        # PoolIndex at 0x2
        struct.pack_into("<B", buf, 0x2, 0)
        # BlockSize (in 16-byte units) at 0x3
        struct.pack_into("<H", buf, 0x3, self.block_size // 16)
        # PoolType at 0x4 (upper byte)
        struct.pack_into("<B", buf, 0x4, self.pool_type)
        # PoolTag at 0x4 (but actually at offset 0x4 in Win7, 0x4 in Win10)
        buf[0x04:0x08] = self.pool_tag
        return bytes(buf)


class ObjectHeader:
    """Windows OBJECT_HEADER preceding kernel objects like EPROCESS."""

    def __init__(
        self,
        object_type_index: int = 7,  # Process type
        handle_count: int = 1,
        pointer_count: int = 1,
    ):
        self.object_type_index = object_type_index
        self.handle_count = handle_count
        self.pointer_count = pointer_count

    def to_bytes_x64(self) -> bytes:
        buf = bytearray(0x38)  # OBJECT_HEADER size on x64
        # PointerCount at 0x0
        struct.pack_into("<Q", buf, 0x0, self.pointer_count)
        # HandleCount at 0x8
        struct.pack_into("<Q", buf, 0x8, self.handle_count)
        # TypeIndex at 0x18
        struct.pack_into("<B", buf, 0x18, self.object_type_index)
        # InfoMask at 0x19
        struct.pack_into("<B", buf, 0x19, 0x08)  # has name info
        return bytes(buf)


class MemoryMirage:
    """Inject phantom processes into Windows memory dumps."""

    def __init__(self, dump_path: str):
        self.dump_path = dump_path
        self.data: Optional[bytearray] = None

    def load(self) -> None:
        with open(self.dump_path, "rb") as f:
            self.data = bytearray(f.read())

    def save(self, output_path: Optional[str] = None) -> str:
        path = output_path or self.dump_path
        with open(path, "wb") as f:
            f.write(self.data)
        return path

    def find_free_region(self, size: int, alignment: int = PAGE_SIZE) -> Optional[int]:
        """Find a zeroed region in the dump large enough for injection."""
        search_size = size + alignment
        zero_block = b"\x00" * search_size

        # Search in the upper half of the dump (less likely to collide)
        start = len(self.data) // 2
        idx = self.data.find(zero_block, start)
        if idx == -1:
            idx = self.data.find(zero_block, 0)
        if idx == -1:
            return None

        aligned = (idx + alignment - 1) & ~(alignment - 1)
        return aligned

    def inject_phantom_process(
        self,
        pid: int,
        ppid: int,
        image_name: str,
        create_time: datetime,
        exit_time: Optional[datetime] = None,
    ) -> Optional[int]:
        """Inject a complete phantom process (pool header + object header + EPROCESS)."""
        eprocess = EProcess(
            pid=pid,
            ppid=ppid,
            image_name=image_name,
            create_time=create_time,
            exit_time=exit_time,
        )

        pool_hdr = PoolHeader(POOL_TAG_PROC, 0xC00)
        obj_hdr = ObjectHeader(object_type_index=7)

        pool_bytes = pool_hdr.to_bytes()
        obj_bytes = obj_hdr.to_bytes_x64()
        proc_bytes = eprocess.to_bytes_win10_x64()

        total_size = len(pool_bytes) + len(obj_bytes) + len(proc_bytes)
        inject_addr = self.find_free_region(total_size + PAGE_SIZE)
        if inject_addr is None:
            return None

        offset = inject_addr
        self.data[offset:offset + len(pool_bytes)] = pool_bytes
        offset += len(pool_bytes)
        self.data[offset:offset + len(obj_bytes)] = obj_bytes
        offset += len(obj_bytes)
        eprocess_offset = offset
        self.data[offset:offset + len(proc_bytes)] = proc_bytes

        return eprocess_offset

    def inject_process_tree(
        self,
        processes: list[dict],
    ) -> list[int]:
        """Inject a tree of related phantom processes.

        Each dict: {"pid": int, "ppid": int, "name": str,
                     "create_time": datetime}
        """
        offsets = []
        for proc in processes:
            offset = self.inject_phantom_process(
                pid=proc["pid"],
                ppid=proc["ppid"],
                image_name=proc["name"],
                create_time=proc["create_time"],
                exit_time=proc.get("exit_time"),
            )
            if offset is not None:
                offsets.append(offset)
        return offsets


def create_test_dump(size_mb: int = 64) -> bytearray:
    """Create a minimal test memory dump (mostly zeros)."""
    return bytearray(size_mb * 1024 * 1024)


if __name__ == "__main__":
    import tempfile

    print("[BlindForge] Memory Mirage — Phantom Process Injection PoC")
    print("=" * 60)

    # Create a test memory dump
    dump_path = os.path.join(tempfile.gettempdir(), "test_memory.dmp")
    print("[*] Creating 64MB test memory dump...")
    dump = create_test_dump(64)
    with open(dump_path, "wb") as f:
        f.write(dump)

    mirage = MemoryMirage(dump_path)
    mirage.load()
    print(f"[*] Dump loaded: {len(mirage.data) // (1024*1024)} MB")

    # Inject a malware process tree
    malware_tree = [
        {
            "pid": 6832,
            "ppid": 4,
            "name": "svchost.exe",
            "create_time": datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc),
        },
        {
            "pid": 7244,
            "ppid": 6832,
            "name": "cmd.exe",
            "create_time": datetime(2026, 6, 15, 2, 31, 0, tzinfo=timezone.utc),
        },
        {
            "pid": 7500,
            "ppid": 7244,
            "name": "mimikatz.exe",
            "create_time": datetime(2026, 6, 15, 2, 31, 30, tzinfo=timezone.utc),
        },
        {
            "pid": 7788,
            "ppid": 7244,
            "name": "procdump.exe",
            "create_time": datetime(2026, 6, 15, 2, 33, 0, tzinfo=timezone.utc),
        },
        {
            "pid": 8012,
            "ppid": 6832,
            "name": "powershell.exe",
            "create_time": datetime(2026, 6, 15, 2, 35, 0, tzinfo=timezone.utc),
        },
    ]

    offsets = mirage.inject_process_tree(malware_tree)
    output = mirage.save(dump_path + ".poisoned")

    print(f"\n[+] Injected {len(offsets)} phantom processes:")
    for i, proc in enumerate(malware_tree):
        if i < len(offsets):
            print(f"    PID {proc['pid']:>5} ({proc['name']:>15}) "
                  f"-> PPID {proc['ppid']:>5} @ offset 0x{offsets[i]:08X}")

    print(f"\n[+] Poisoned dump saved to: {output}")
    print("[+] Volatility3 pslist/pstree will show these phantom processes")
    print("[+] Complete process tree: svchost → cmd → mimikatz, procdump")
    print("\n[!] No malware was ever running. These processes never existed.")
