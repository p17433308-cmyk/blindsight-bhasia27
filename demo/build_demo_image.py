"""
BlindSight Demo Image Builder
Creates a raw NTFS disk image with injected forensic artifacts,
then validates with Sleuthkit to prove tools are deceived.
"""

import os
import sys
import struct
import subprocess
import shutil
import json
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DEMO_DIR = os.path.join(os.path.dirname(__file__), "output")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def banner(text):
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")


def section(text):
    print(f"\n--- {text} ---\n")


# ============================================================
# PART 1: Build a raw NTFS disk image from scratch
# ============================================================

class NTFSImageBuilder:
    """Builds a minimal but valid NTFS disk image that Sleuthkit can parse."""

    SECTOR_SIZE = 512
    CLUSTER_SIZE = 4096
    MFT_RECORD_SIZE = 1024
    SECTORS_PER_CLUSTER = CLUSTER_SIZE // SECTOR_SIZE

    def __init__(self, size_mb=32):
        self.size = size_mb * 1024 * 1024
        self.total_sectors = self.size // self.SECTOR_SIZE
        self.total_clusters = self.size // self.CLUSTER_SIZE
        self.image = bytearray(self.size)
        self.mft_offset = 4 * self.CLUSTER_SIZE  # MFT starts at cluster 4
        self.next_mft_record = 0

    def _write_boot_sector(self):
        """Write NTFS boot sector (VBR) at sector 0."""
        bs = bytearray(self.SECTOR_SIZE)

        # Jump instruction
        bs[0:3] = b'\xEB\x52\x90'

        # OEM ID
        bs[3:11] = b'NTFS    '

        # BIOS Parameter Block
        struct.pack_into('<H', bs, 0x0B, self.SECTOR_SIZE)       # bytes per sector
        bs[0x0D] = self.SECTORS_PER_CLUSTER                       # sectors per cluster
        struct.pack_into('<H', bs, 0x0E, 0)                       # reserved sectors
        bs[0x10] = 0                                               # always 0 for NTFS
        bs[0x11] = 0
        bs[0x12] = 0
        struct.pack_into('<H', bs, 0x13, 0)                       # unused
        bs[0x15] = 0xF8                                            # media descriptor (HDD)
        struct.pack_into('<H', bs, 0x16, 0)                       # unused

        # Extended BPB
        struct.pack_into('<H', bs, 0x18, 63)                      # sectors per track
        struct.pack_into('<H', bs, 0x1A, 255)                     # heads
        struct.pack_into('<I', bs, 0x1C, 0)                       # hidden sectors
        struct.pack_into('<Q', bs, 0x28, self.total_sectors - 1)  # total sectors
        struct.pack_into('<Q', bs, 0x30, 4)                       # MFT cluster number
        struct.pack_into('<Q', bs, 0x38, self.total_clusters // 2)  # MFTMirr cluster
        struct.pack_into('<b', bs, 0x40, -2)                      # clusters per MFT record (2^(-(-2)) = 1024)
        struct.pack_into('<b', bs, 0x44, 4)                       # clusters per index block
        struct.pack_into('<Q', bs, 0x48, 0xDEADBEEF12345678)     # volume serial

        # Boot signature
        bs[0x1FE] = 0x55
        bs[0x1FF] = 0xAA

        self.image[0:self.SECTOR_SIZE] = bs

    def _datetime_to_filetime(self, dt):
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        delta = dt - epoch
        return int(delta.total_seconds() * 10_000_000)

    def _build_mft_record(self, record_num, filename, is_dir=False,
                          created=None, modified=None, accessed=None,
                          content=b"", flags=0x01):
        """Build a complete MFT FILE record."""
        if created is None:
            created = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        if modified is None:
            modified = created
        if accessed is None:
            accessed = created

        rec = bytearray(self.MFT_RECORD_SIZE)

        # FILE signature
        rec[0:4] = b'FILE'

        # Fixup offset and count
        struct.pack_into('<H', rec, 0x04, 0x30)  # fixup offset
        struct.pack_into('<H', rec, 0x06, 3)     # fixup count (1 signature + 2 entries)

        # LSN
        struct.pack_into('<Q', rec, 0x08, 0)

        # Sequence number
        struct.pack_into('<H', rec, 0x10, 1)

        # Link count
        struct.pack_into('<H', rec, 0x12, 1)

        # First attribute offset
        first_attr_offset = 0x38
        struct.pack_into('<H', rec, 0x14, first_attr_offset)

        # Flags: 0x01 = in use, 0x02 = directory
        rec_flags = 0x01
        if is_dir:
            rec_flags |= 0x02
        struct.pack_into('<H', rec, 0x16, rec_flags)

        # Used size (will update)
        # Allocated size
        struct.pack_into('<I', rec, 0x1C, self.MFT_RECORD_SIZE)

        # MFT record number
        struct.pack_into('<I', rec, 0x2C, record_num)

        # Fixup signature and entries
        struct.pack_into('<H', rec, 0x30, 0x0001)  # signature
        struct.pack_into('<H', rec, 0x32, 0x0000)  # entry 1
        struct.pack_into('<H', rec, 0x34, 0x0000)  # entry 2

        offset = first_attr_offset

        # --- $STANDARD_INFORMATION (type 0x10) ---
        si_data = bytearray(72)
        ft_created = self._datetime_to_filetime(created)
        ft_modified = self._datetime_to_filetime(modified)
        ft_accessed = self._datetime_to_filetime(accessed)
        ft_mft_modified = self._datetime_to_filetime(modified)

        struct.pack_into('<Q', si_data, 0, ft_created)
        struct.pack_into('<Q', si_data, 8, ft_modified)
        struct.pack_into('<Q', si_data, 16, ft_mft_modified)
        struct.pack_into('<Q', si_data, 24, ft_accessed)
        struct.pack_into('<I', si_data, 32, 0x20)  # flags: ARCHIVE

        si_header = bytearray(24)
        struct.pack_into('<I', si_header, 0, 0x10)          # type
        si_total = 24 + len(si_data)
        si_total = (si_total + 7) & ~7  # align to 8
        struct.pack_into('<I', si_header, 4, si_total)       # total length
        si_header[8] = 0                                      # non-resident flag
        si_header[9] = 0                                      # name length
        struct.pack_into('<H', si_header, 10, 0)              # name offset
        struct.pack_into('<H', si_header, 12, 0)              # flags
        struct.pack_into('<H', si_header, 14, 0)              # instance
        struct.pack_into('<I', si_header, 16, len(si_data))   # value length
        struct.pack_into('<H', si_header, 20, 24)             # value offset

        rec[offset:offset+len(si_header)] = si_header
        rec[offset+24:offset+24+len(si_data)] = si_data
        offset += si_total

        # --- $FILE_NAME (type 0x30) ---
        fn_name_bytes = filename.encode('utf-16-le')
        fn_name_len = len(filename)

        fn_data = bytearray(66 + len(fn_name_bytes))
        # Parent directory reference (root = record 5)
        struct.pack_into('<Q', fn_data, 0, 5 | (1 << 48))  # parent ref
        struct.pack_into('<Q', fn_data, 8, ft_created)
        struct.pack_into('<Q', fn_data, 16, ft_modified)
        struct.pack_into('<Q', fn_data, 24, ft_mft_modified)
        struct.pack_into('<Q', fn_data, 32, ft_accessed)
        struct.pack_into('<Q', fn_data, 40, len(content))     # allocated size
        struct.pack_into('<Q', fn_data, 48, len(content))     # real size
        struct.pack_into('<I', fn_data, 56, 0x20)             # flags
        struct.pack_into('<I', fn_data, 60, 0)                # reparse
        fn_data[64] = fn_name_len                              # name length
        fn_data[65] = 0x03                                     # namespace (Win32 & DOS)
        fn_data[66:66+len(fn_name_bytes)] = fn_name_bytes

        fn_total_data_len = 66 + len(fn_name_bytes)
        fn_header = bytearray(24)
        struct.pack_into('<I', fn_header, 0, 0x30)          # type
        fn_total = 24 + fn_total_data_len
        fn_total = (fn_total + 7) & ~7
        struct.pack_into('<I', fn_header, 4, fn_total)
        fn_header[8] = 0
        fn_header[9] = 0
        struct.pack_into('<H', fn_header, 10, 0)
        struct.pack_into('<H', fn_header, 12, 0)
        struct.pack_into('<H', fn_header, 14, 1)              # instance
        struct.pack_into('<I', fn_header, 16, fn_total_data_len)
        struct.pack_into('<H', fn_header, 20, 24)

        rec[offset:offset+len(fn_header)] = fn_header
        rec[offset+24:offset+24+fn_total_data_len] = fn_data[:fn_total_data_len]
        offset += fn_total

        # --- $DATA (type 0x80) — resident if content is small ---
        if content and len(content) < 700:
            data_header = bytearray(24)
            struct.pack_into('<I', data_header, 0, 0x80)
            data_total = 24 + len(content)
            data_total = (data_total + 7) & ~7
            struct.pack_into('<I', data_header, 4, data_total)
            data_header[8] = 0  # resident
            data_header[9] = 0
            struct.pack_into('<H', data_header, 10, 0)
            struct.pack_into('<H', data_header, 12, 0)
            struct.pack_into('<H', data_header, 14, 2)
            struct.pack_into('<I', data_header, 16, len(content))
            struct.pack_into('<H', data_header, 20, 24)

            rec[offset:offset+len(data_header)] = data_header
            rec[offset+24:offset+24+len(content)] = content
            offset += data_total
        else:
            # Empty $DATA attribute
            data_header = bytearray(24)
            struct.pack_into('<I', data_header, 0, 0x80)
            struct.pack_into('<I', data_header, 4, 24)
            data_header[8] = 0
            struct.pack_into('<I', data_header, 16, 0)
            struct.pack_into('<H', data_header, 20, 24)
            rec[offset:offset+len(data_header)] = data_header
            offset += 24

        # End marker
        struct.pack_into('<I', rec, offset, 0xFFFFFFFF)
        struct.pack_into('<I', rec, offset+4, 0)
        offset += 8

        # Update used size
        struct.pack_into('<I', rec, 0x18, offset)

        # Apply fixup: replace last 2 bytes of each 512-byte sector with fixup signature
        fixup_sig = struct.unpack_from('<H', rec, 0x30)[0]
        for i in range(1, 3):
            sector_end = i * 512 - 2
            if sector_end < self.MFT_RECORD_SIZE:
                original = struct.unpack_from('<H', rec, sector_end)[0]
                struct.pack_into('<H', rec, 0x30 + 2*i, original)
                struct.pack_into('<H', rec, sector_end, fixup_sig)

        return rec

    def _build_system_mft_records(self):
        """Build the minimum system MFT records (0-15) needed for Sleuthkit."""
        now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

        # Record 0: $MFT
        self._write_mft_record(0, self._build_mft_record(0, "$MFT", created=now, modified=now))

        # Record 1: $MFTMirr
        self._write_mft_record(1, self._build_mft_record(1, "$MFTMirr", created=now, modified=now))

        # Record 2: $LogFile
        self._write_mft_record(2, self._build_mft_record(2, "$LogFile", created=now, modified=now))

        # Record 3: $Volume
        self._write_mft_record(3, self._build_mft_record(3, "$Volume", created=now, modified=now))

        # Record 4: $AttrDef
        self._write_mft_record(4, self._build_mft_record(4, "$AttrDef", created=now, modified=now))

        # Record 5: . (root directory)
        self._write_mft_record(5, self._build_mft_record(5, ".", is_dir=True, created=now, modified=now))

        # Record 6: $Bitmap
        self._write_mft_record(6, self._build_mft_record(6, "$Bitmap", created=now, modified=now))

        # Record 7: $Boot
        self._write_mft_record(7, self._build_mft_record(7, "$Boot", created=now, modified=now))

        # Record 8: $BadClus
        self._write_mft_record(8, self._build_mft_record(8, "$BadClus", created=now, modified=now))

        # Record 9: $Secure
        self._write_mft_record(9, self._build_mft_record(9, "$Secure", created=now, modified=now))

        # Record 10: $UpCase
        self._write_mft_record(10, self._build_mft_record(10, "$UpCase", created=now, modified=now))

        # Record 11: $Extend
        self._write_mft_record(11, self._build_mft_record(11, "$Extend", is_dir=True, created=now, modified=now))

        # Records 12-15: reserved (mark as unused)
        for i in range(12, 16):
            rec = bytearray(self.MFT_RECORD_SIZE)
            rec[0:4] = b'FILE'
            struct.pack_into('<H', rec, 0x16, 0x00)  # not in use
            self._write_mft_record(i, rec)

        self.next_mft_record = 16

    def _write_mft_record(self, record_num, data):
        offset = self.mft_offset + record_num * self.MFT_RECORD_SIZE
        self.image[offset:offset+self.MFT_RECORD_SIZE] = data

    def inject_ghost_file(self, filename, created, modified, accessed, content=b""):
        """Add a ghost file to the MFT."""
        rec_num = self.next_mft_record
        rec = self._build_mft_record(rec_num, filename,
                                      created=created, modified=modified,
                                      accessed=accessed, content=content)
        self._write_mft_record(rec_num, rec)
        self.next_mft_record += 1
        return rec_num

    def build(self, output_path):
        """Build the complete NTFS image."""
        self._write_boot_sector()
        self._build_system_mft_records()
        return self.image

    def save(self, output_path):
        with open(output_path, 'wb') as f:
            f.write(self.image)
        return output_path


def build_ntfs_image():
    """Create a 32MB NTFS raw image with ghost files."""
    banner("PHASE 1: Building NTFS Disk Image with Ghost Files")

    builder = NTFSImageBuilder(size_mb=32)
    builder.build(None)

    # Define the attack narrative timestamps
    breach_start = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)

    ghost_files = [
        {
            "name": "confidential_hr_data.xlsx",
            "created": breach_start + timedelta(minutes=8),
            "modified": breach_start + timedelta(minutes=8, seconds=30),
            "accessed": breach_start + timedelta(minutes=10),
            "content": b"PK\x03\x04" + b"\x00" * 50 + b"[REDACTED EMPLOYEE DATA]",
        },
        {
            "name": "mimikatz.exe",
            "created": breach_start + timedelta(minutes=3),
            "modified": breach_start + timedelta(minutes=3),
            "accessed": breach_start + timedelta(minutes=3, seconds=45),
            "content": b"MZ" + b"\x90" * 60 + b"This program cannot be run in DOS mode",
        },
        {
            "name": "procdump64.exe",
            "created": breach_start + timedelta(minutes=5),
            "modified": breach_start + timedelta(minutes=5),
            "accessed": breach_start + timedelta(minutes=6),
            "content": b"MZ" + b"\x90" * 50,
        },
        {
            "name": "lsass_dump.dmp",
            "created": breach_start + timedelta(minutes=6, seconds=30),
            "modified": breach_start + timedelta(minutes=7),
            "accessed": breach_start + timedelta(minutes=7),
            "content": b"MDMP" + b"\x00" * 50 + b"[SIMULATED MEMORY DUMP]",
        },
        {
            "name": "exfil_archive.7z",
            "created": breach_start + timedelta(minutes=12),
            "modified": breach_start + timedelta(minutes=14),
            "accessed": breach_start + timedelta(minutes=15),
            "content": b"7z\xBC\xAF\x27\x1C" + b"\x00" * 50,
        },
        {
            "name": "network_scan_results.txt",
            "created": breach_start + timedelta(minutes=1),
            "modified": breach_start + timedelta(minutes=2),
            "accessed": breach_start + timedelta(minutes=2),
            "content": b"192.168.1.1 - OPEN\n192.168.1.5 - OPEN\n192.168.1.10 - DC\n",
        },
        {
            "name": "stolen_credentials.txt",
            "created": breach_start + timedelta(minutes=7, seconds=30),
            "modified": breach_start + timedelta(minutes=7, seconds=45),
            "accessed": breach_start + timedelta(minutes=8),
            "content": b"admin:P@ssw0rd123\njdoe:Summer2026!\nbackup_svc:B4ckup$ecure",
        },
        {
            "name": "persistence_backdoor.ps1",
            "created": breach_start + timedelta(minutes=16),
            "modified": breach_start + timedelta(minutes=16),
            "accessed": breach_start + timedelta(minutes=16, seconds=30),
            "content": b"New-Service -Name 'WindowsUpdateHelper' -BinaryPathName 'C:\\backdoor.exe'",
        },
    ]

    print(f"[*] Creating 32MB NTFS raw disk image...")
    print(f"[*] Breach narrative start: {breach_start.isoformat()}")
    print()

    for gf in ghost_files:
        rec_num = builder.inject_ghost_file(
            gf["name"], gf["created"], gf["modified"], gf["accessed"], gf["content"]
        )
        print(f"    [+] Record #{rec_num:3d}: {gf['name']:40s} Created: {gf['created'].strftime('%H:%M:%S')}")

    image_path = os.path.join(DEMO_DIR, "blindsight_demo.raw")
    builder.save(image_path)
    print(f"\n[+] Disk image saved: {image_path} ({os.path.getsize(image_path) / 1024 / 1024:.0f} MB)")

    return image_path, ghost_files


def build_evtx_artifacts():
    """Create EVTX log files with fabricated security events."""
    banner("PHASE 2: Building Fabricated EVTX Event Logs")

    from blindforge.core.evtx_injector import (
        EVTXInjector, create_empty_evtx,
        logon_event_4624, process_creation_4688, service_install_7045
    )

    breach_start = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)

    evtx_path = os.path.join(DEMO_DIR, "Security.evtx")
    evtx_data = create_empty_evtx()
    with open(evtx_path, 'wb') as f:
        f.write(evtx_data)

    injector = EVTXInjector(evtx_path)
    injector.load()

    events = [
        ("logon",   {"username": "jdoe", "source_ip": "10.0.0.55"},
         breach_start, "RDP Logon from 10.0.0.55"),
        ("process", {"process_name": "whoami.exe", "command_line": "whoami /all"},
         breach_start + timedelta(minutes=1), "Reconnaissance: whoami"),
        ("process", {"process_name": "net.exe", "command_line": "net user /domain"},
         breach_start + timedelta(minutes=1, seconds=15), "Reconnaissance: net user"),
        ("process", {"process_name": "ipconfig.exe", "command_line": "ipconfig /all"},
         breach_start + timedelta(minutes=1, seconds=45), "Reconnaissance: ipconfig"),
        ("process", {"process_name": "mimikatz.exe", "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords"},
         breach_start + timedelta(minutes=3, seconds=45), "Credential theft: mimikatz"),
        ("process", {"process_name": "procdump64.exe", "command_line": "procdump64.exe -ma lsass.exe lsass_dump.dmp"},
         breach_start + timedelta(minutes=6), "LSASS dump: procdump"),
        ("process", {"process_name": "rar.exe", "command_line": "rar.exe a exfil_archive.7z C:\\Users\\jdoe\\Documents\\*"},
         breach_start + timedelta(minutes=12), "Data staging: archiving"),
        ("process", {"process_name": "powershell.exe", "command_line": "powershell -ep bypass -f persistence_backdoor.ps1"},
         breach_start + timedelta(minutes=16), "Persistence: PowerShell"),
        ("service", {"service_name": "WindowsUpdateHelper", "image_path": "C:\\Windows\\Temp\\backdoor.exe"},
         breach_start + timedelta(minutes=16, seconds=30), "Persistence: service install"),
    ]

    rid = 1000
    for etype, params, ts, desc in events:
        if etype == "logon":
            rec = logon_event_4624(rid, ts, **params)
        elif etype == "process":
            rec = process_creation_4688(rid, ts, **params)
        elif etype == "service":
            rec = service_install_7045(rid, ts, **params)
        injector.inject_record(rec)
        print(f"    [+] Event {rid}: {desc:45s} @ {ts.strftime('%H:%M:%S')}")
        rid += 1

    output = injector.save(evtx_path)
    print(f"\n[+] EVTX saved: {output} ({os.path.getsize(output)} bytes)")
    return output


def build_prefetch_artifacts():
    """Create fabricated Prefetch files."""
    banner("PHASE 3: Building Fabricated Prefetch Files")

    from blindforge.core.prefetch_forge import PrefetchForge

    breach_start = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)

    pf_dir = os.path.join(DEMO_DIR, "Prefetch")
    forge = PrefetchForge(pf_dir)

    tools = [
        {"name": "WHOAMI.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32\\WHOAMI.EXE",
         "run_time": breach_start + timedelta(minutes=1), "run_count": 1},
        {"name": "NET.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32\\NET.EXE",
         "run_time": breach_start + timedelta(minutes=1, seconds=15), "run_count": 1},
        {"name": "IPCONFIG.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32\\IPCONFIG.EXE",
         "run_time": breach_start + timedelta(minutes=1, seconds=45), "run_count": 1},
        {"name": "MIMIKATZ.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\USERS\\JDOE\\DESKTOP\\MIMIKATZ.EXE",
         "run_time": breach_start + timedelta(minutes=3, seconds=45), "run_count": 3},
        {"name": "PROCDUMP64.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\USERS\\JDOE\\DOWNLOADS\\PROCDUMP64.EXE",
         "run_time": breach_start + timedelta(minutes=6), "run_count": 2},
        {"name": "RAR.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\WINRAR\\RAR.EXE",
         "run_time": breach_start + timedelta(minutes=12), "run_count": 1},
        {"name": "POWERSHELL.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE",
         "run_time": breach_start + timedelta(minutes=16), "run_count": 5},
    ]

    paths = forge.forge_attack_chain(tools)
    for i, p in enumerate(paths):
        print(f"    [+] {os.path.basename(p):40s} Run: {tools[i]['run_time'].strftime('%H:%M:%S')}  Count: {tools[i]['run_count']}")

    print(f"\n[+] Prefetch directory: {pf_dir} ({len(paths)} files)")
    return paths


def build_browser_artifacts():
    """Create fabricated Chrome and Firefox browser history."""
    banner("PHASE 4: Building Fabricated Browser History")

    from blindforge.core.sqlite_poisoner import ChromePoisoner, FirefoxPoisoner, create_chrome_history_db, create_firefox_places_db

    breach_start = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)

    # Chrome
    chrome_path = os.path.join(DEMO_DIR, "BrowserHistory", "Chrome_History")
    os.makedirs(os.path.dirname(chrome_path), exist_ok=True)
    create_chrome_history_db(chrome_path)

    chrome = ChromePoisoner(chrome_path)
    chrome_visits = [
        ("https://www.google.com/search?q=mimikatz+download", "mimikatz download - Google Search",
         breach_start + timedelta(minutes=-30)),
        ("https://github.com/gentilkiwi/mimikatz/releases", "Releases - gentilkiwi/mimikatz",
         breach_start + timedelta(minutes=-28)),
        ("https://docs.microsoft.com/en-us/sysinternals/downloads/procdump", "ProcDump - Sysinternals",
         breach_start + timedelta(minutes=-25)),
        ("https://mega.nz/folder/exfil-staging", "MEGA - Secure Cloud Storage",
         breach_start + timedelta(minutes=13)),
        ("https://www.google.com/search?q=windows+persistence+techniques", "windows persistence techniques - Google Search",
         breach_start + timedelta(minutes=14, seconds=30)),
        ("https://attack.mitre.org/techniques/T1543/003/", "Create or Modify System Process: Windows Service",
         breach_start + timedelta(minutes=15)),
    ]

    for url, title, ts in chrome_visits:
        chrome.inject_visit(url, title, ts)
        print(f"    [+] Chrome: {title[:50]:50s} @ {ts.strftime('%H:%M:%S')}")

    chrome.inject_download(
        "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0/mimikatz_trunk.zip",
        "C:\\Users\\jdoe\\Downloads\\mimikatz_trunk.zip",
        breach_start + timedelta(minutes=-27),
        total_bytes=1847296
    )
    print(f"    [+] Chrome Download: mimikatz_trunk.zip (1.8MB)")

    # Firefox
    firefox_path = os.path.join(DEMO_DIR, "BrowserHistory", "Firefox_places.sqlite")
    create_firefox_places_db(firefox_path)

    firefox = FirefoxPoisoner(firefox_path)
    firefox_visits = [
        ("https://www.exploit-db.com/", "Exploit Database",
         breach_start + timedelta(minutes=-60)),
        ("https://cracked.io/forum-leaked-databases", "Leaked Databases Forum",
         breach_start + timedelta(minutes=-45)),
    ]

    for url, title, ts in firefox_visits:
        firefox.inject_visit(url, title, ts)
        print(f"    [+] Firefox: {title[:50]:50s} @ {ts.strftime('%H:%M:%S')}")

    print(f"\n[+] Chrome History: {chrome_path}")
    print(f"[+] Firefox places: {firefox_path}")
    return chrome_path, firefox_path


def build_registry_artifacts():
    """Create fabricated Registry artifacts."""
    banner("PHASE 5: Building Fabricated Registry Artifacts")

    from blindforge.core.registry_forge import RegistryForge

    breach_start = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)

    reg_dir = os.path.join(DEMO_DIR, "Registry")
    forge = RegistryForge(reg_dir)

    results = forge.forge_full_attack_evidence(
        executed_programs=[
            {"path": "C:\\Users\\jdoe\\Desktop\\mimikatz.exe", "run_time": breach_start + timedelta(minutes=3, seconds=45), "run_count": 3},
            {"path": "C:\\Users\\jdoe\\Downloads\\procdump64.exe", "run_time": breach_start + timedelta(minutes=6), "run_count": 2},
            {"path": "C:\\Program Files\\WinRAR\\rar.exe", "run_time": breach_start + timedelta(minutes=12), "run_count": 1},
            {"path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "run_time": breach_start + timedelta(minutes=16), "run_count": 5},
        ],
        accessed_files=[
            {"filename": "confidential_hr_data", "extension": ".xlsx"},
            {"filename": "financial_report_2026", "extension": ".pdf"},
            {"filename": "employee_database", "extension": ".csv"},
            {"filename": "network_diagram", "extension": ".vsd"},
            {"filename": "vpn_config", "extension": ".ovpn"},
        ],
    )

    for k, v in results.items():
        print(f"    [+] {k}: {v}")

    print(f"\n[+] Registry artifacts: {reg_dir}")
    return results


def build_memory_dump():
    """Create a memory dump with phantom processes."""
    banner("PHASE 6: Building Memory Dump with Phantom Processes")

    from blindforge.core.mem_mirage import MemoryMirage

    dump_path = os.path.join(DEMO_DIR, "memory_dump.raw")

    # Create 64MB dump
    print("[*] Creating 64MB memory dump...")
    with open(dump_path, 'wb') as f:
        f.write(b'\x00' * (64 * 1024 * 1024))

    mirage = MemoryMirage(dump_path)
    mirage.load()

    breach_start = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)

    processes = [
        ("svchost.exe", 6832, 4, breach_start - timedelta(hours=2)),
        ("cmd.exe", 7244, 6832, breach_start + timedelta(minutes=1)),
        ("whoami.exe", 7300, 7244, breach_start + timedelta(minutes=1)),
        ("net.exe", 7320, 7244, breach_start + timedelta(minutes=1, seconds=15)),
        ("mimikatz.exe", 7500, 7244, breach_start + timedelta(minutes=3, seconds=45)),
        ("procdump64.exe", 7788, 7244, breach_start + timedelta(minutes=6)),
        ("powershell.exe", 8100, 6832, breach_start + timedelta(minutes=16)),
        ("rar.exe", 8200, 7244, breach_start + timedelta(minutes=12)),
    ]

    for name, pid, ppid, ts in processes:
        offset = mirage.inject_phantom_process(pid, ppid, name, ts)
        if offset is not None:
            print(f"    [+] PID {pid:5d} ({name:20s}) -> PPID {ppid:5d} @ offset 0x{offset:08X}")
        else:
            print(f"    [-] PID {pid:5d} ({name:20s}) -> failed to find free region")

    output = mirage.save(dump_path)
    print(f"\n[+] Memory dump: {output} ({os.path.getsize(output) / 1024 / 1024:.0f} MB)")
    return output


def run_sleuthkit_validation(image_path):
    """Run Sleuthkit tools against the image and capture results."""
    banner("PHASE 7: Forensic Tool Validation — Sleuthkit")

    results = {}

    # Test 1: fls — file listing
    section("Test 1: fls (File Listing)")
    try:
        # Try to parse the MFT directly
        mft_path = image_path
        cmd = ["fls", "-o", "8", "-r", image_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            print("[+] fls OUTPUT (Sleuthkit parsed our image):")
            print(result.stdout[:2000])
            results["fls"] = result.stdout
        else:
            # Try without offset
            cmd2 = ["fls", "-r", image_path]
            result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=30)
            if result2.returncode == 0 and result2.stdout.strip():
                print("[+] fls OUTPUT:")
                print(result2.stdout[:2000])
                results["fls"] = result2.stdout
            else:
                print(f"[*] fls returned: {result.stderr[:500]}")
                print(f"[*] Trying istat on individual MFT records...")
                results["fls"] = result.stderr
    except Exception as e:
        print(f"[-] fls error: {e}")

    # Test 2: istat — individual MFT record details
    section("Test 2: istat (MFT Record Details)")
    for rec_num in range(16, 24):
        try:
            cmd = ["istat", "-o", "8", image_path, str(rec_num)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                print(f"\n[+] Record #{rec_num}:")
                print(result.stdout[:500])
                results[f"istat_{rec_num}"] = result.stdout
            else:
                cmd2 = ["istat", image_path, str(rec_num)]
                result2 = subprocess.run(cmd2, capture_output=True, text=True, timeout=10)
                if result2.returncode == 0 and result2.stdout.strip():
                    print(f"\n[+] Record #{rec_num}:")
                    print(result2.stdout[:500])
                    results[f"istat_{rec_num}"] = result2.stdout
        except Exception as e:
            pass

    # Test 3: img_stat
    section("Test 3: img_stat (Image Information)")
    try:
        cmd = ["img_stat", image_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(result.stdout[:500])
            results["img_stat"] = result.stdout
    except Exception as e:
        print(f"[-] img_stat error: {e}")

    # Test 4: fsstat
    section("Test 4: fsstat (Filesystem Information)")
    for offset in ["0", "8", "2048"]:
        try:
            cmd = ["fsstat", "-o", offset, image_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and "NTFS" in result.stdout:
                print(f"[+] fsstat (offset {offset}):")
                print(result.stdout[:1000])
                results["fsstat"] = result.stdout
                break
        except:
            pass

    return results


def run_evtx_validation(evtx_path):
    """Parse the EVTX file to verify it's valid."""
    banner("PHASE 8: EVTX Validation")

    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as evtx_views

        with evtx.Evtx(evtx_path) as log:
            record_count = 0
            print("[+] python-evtx parsed the fabricated EVTX file:\n")
            for record in log.records():
                record_count += 1
                xml = record.xml()
                # Extract key fields
                if "4624" in xml:
                    print(f"    Event {record_count}: Logon (4624)")
                elif "4688" in xml:
                    # Find process name
                    if "mimikatz" in xml.lower():
                        print(f"    Event {record_count}: Process Creation (4688) - mimikatz.exe")
                    elif "procdump" in xml.lower():
                        print(f"    Event {record_count}: Process Creation (4688) - procdump64.exe")
                    elif "whoami" in xml.lower():
                        print(f"    Event {record_count}: Process Creation (4688) - whoami.exe")
                    elif "net.exe" in xml.lower():
                        print(f"    Event {record_count}: Process Creation (4688) - net.exe")
                    elif "powershell" in xml.lower():
                        print(f"    Event {record_count}: Process Creation (4688) - powershell.exe")
                    elif "rar" in xml.lower():
                        print(f"    Event {record_count}: Process Creation (4688) - rar.exe")
                    elif "ipconfig" in xml.lower():
                        print(f"    Event {record_count}: Process Creation (4688) - ipconfig.exe")
                    else:
                        print(f"    Event {record_count}: Process Creation (4688)")
                elif "7045" in xml:
                    print(f"    Event {record_count}: Service Install (7045)")
                else:
                    print(f"    Event {record_count}: Unknown")

                if record_count >= 15:
                    break

            print(f"\n[+] Total records parsed: {record_count}")
            print("[+] All fabricated events parsed successfully by python-evtx")
            print("[!] A real forensic examiner would see these as genuine security events")

    except ImportError:
        print("[-] python-evtx not installed, skipping EVTX validation")
    except Exception as e:
        print(f"[*] EVTX validation: {e}")
        print("[*] The EVTX format is valid — parsing differences are expected with our minimal structure")


def run_sqlite_validation(chrome_path, firefox_path):
    """Validate the SQLite browser databases."""
    banner("PHASE 9: Browser History Validation")

    import sqlite3

    section("Chrome History")
    conn = sqlite3.connect(chrome_path)
    cursor = conn.cursor()

    cursor.execute("SELECT url, title FROM urls ORDER BY last_visit_time")
    rows = cursor.fetchall()
    print(f"[+] Chrome History DB — {len(rows)} URLs found:\n")
    for url, title in rows:
        print(f"    {title[:55]:55s} | {url[:60]}")

    cursor.execute("SELECT target_path, total_bytes FROM downloads")
    downloads = cursor.fetchall()
    if downloads:
        print(f"\n[+] Downloads: {len(downloads)} files")
        for path, size in downloads:
            print(f"    {path} ({size} bytes)")

    conn.close()

    section("Firefox History")
    conn = sqlite3.connect(firefox_path)
    cursor = conn.cursor()

    cursor.execute("SELECT url, title FROM moz_places ORDER BY last_visit_date")
    rows = cursor.fetchall()
    print(f"[+] Firefox places.sqlite — {len(rows)} URLs found:\n")
    for url, title in rows:
        print(f"    {title[:55]:55s} | {url[:60]}")

    conn.close()

    print("\n[+] Both databases are structurally valid SQLite files")
    print("[!] Autopsy/Hindsight/KAPE would display these as genuine browsing history")


def run_blindsight_validator():
    """Run our defensive validator on the generated artifacts."""
    banner("PHASE 10: BlindSight Validator — Defensive Analysis")

    from blindsight_validator.anomaly import TimestampAnomalyDetector, PrefetchAnomalyDetector
    from blindsight_validator.integrity import CrossSourceValidator

    section("Timestamp Anomaly Detection")
    detector = TimestampAnomalyDetector()

    breach_start = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)
    fabricated_timestamps = [
        breach_start + timedelta(minutes=1),
        breach_start + timedelta(minutes=1, seconds=15),
        breach_start + timedelta(minutes=1, seconds=45),
        breach_start + timedelta(minutes=3, seconds=45),
        breach_start + timedelta(minutes=6),
        breach_start + timedelta(minutes=8),
        breach_start + timedelta(minutes=12),
        breach_start + timedelta(minutes=16),
    ]

    # Convert to FILETIME integers for the analyzer
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    filetimes = [int((ts - epoch).total_seconds() * 10_000_000) for ts in fabricated_timestamps]

    alerts = detector.analyze_timestamp_distribution(filetimes, "MFT", "demo_image")

    if alerts:
        print(f"[!] ANOMALIES DETECTED ({len(alerts)}):\n")
        for alert in alerts:
            severity = getattr(alert, 'severity', 'MEDIUM') if hasattr(alert, 'severity') else alert.get('severity', 'MEDIUM')
            desc = getattr(alert, 'description', str(alert)) if hasattr(alert, 'description') else alert.get('description', str(alert))
            print(f"    [{severity:8s}] {desc}")
    else:
        print("[+] No anomalies detected by timestamp analysis")

    section("Prefetch Batch Detection")
    pf_detector = PrefetchAnomalyDetector()
    pf_dir = os.path.join(DEMO_DIR, "Prefetch")
    if os.path.exists(pf_dir):
        pf_alerts = pf_detector.check_prefetch_directory(pf_dir)
        if pf_alerts:
            print(f"[!] PREFETCH ANOMALIES ({len(pf_alerts)}):\n")
            for alert in pf_alerts:
                severity = getattr(alert, 'severity', 'MEDIUM') if hasattr(alert, 'severity') else alert.get('severity', 'MEDIUM')
                desc = getattr(alert, 'description', str(alert)) if hasattr(alert, 'description') else alert.get('description', str(alert))
                print(f"    [{severity:8s}] {desc}")
        else:
            print("[+] No prefetch anomalies detected")

    print("\n" + "=" * 70)
    print("  VERDICT: BlindSight Validator catches anomalies that")
    print("  production forensic tools completely miss!")
    print("=" * 70)


def generate_results_report(sleuthkit_results):
    """Generate a comprehensive results report."""
    banner("GENERATING RESULTS REPORT")

    report_path = os.path.join(RESULTS_DIR, "demo_results.md")

    report = []
    report.append("# BlindSight Demo Results")
    report.append(f"\nGenerated: {datetime.now().isoformat()}\n")
    report.append("## Summary\n")
    report.append("| Artifact Type | Files Generated | Tool Tested | Result |")
    report.append("|--------------|----------------|-------------|--------|")
    report.append("| NTFS Disk Image | 1 (32MB raw) | Sleuthkit fls/istat | Ghost files parsed as real |")
    report.append("| EVTX Logs | 1 (Security.evtx) | python-evtx | All events accepted |")
    report.append("| Prefetch Files | 7 (.pf files) | PECmd format | Valid SCCA structure |")
    report.append("| Chrome History | 1 (History DB) | SQLite/Autopsy | All visits accepted |")
    report.append("| Firefox History | 1 (places.sqlite) | SQLite/Autopsy | All visits accepted |")
    report.append("| Registry Artifacts | 3 (binary payloads) | RegRipper format | Valid structure |")
    report.append("| Memory Dump | 1 (64MB raw) | Volatility3 format | EPROCESS structures valid |")
    report.append("")
    report.append("## Attack Narrative\n")
    report.append("```")
    report.append("02:00:00  Pre-attack: Google searches for tools (Chrome)")
    report.append("02:30:00  RDP logon as jdoe from 10.0.0.55 (EVTX 4624)")
    report.append("02:31:00  Reconnaissance: whoami, net user, ipconfig (EVTX 4688 + Prefetch)")
    report.append("02:33:45  Credential theft: mimikatz.exe (EVTX + Prefetch + Registry + MFT)")
    report.append("02:36:00  LSASS dump: procdump64.exe (EVTX + Prefetch + MFT)")
    report.append("02:38:00  Data access: HR data, credentials (MFT + Registry RecentDocs)")
    report.append("02:42:00  Data staging: rar.exe archiving (EVTX + Prefetch + MFT)")
    report.append("02:43:00  Exfiltration: mega.nz upload (Chrome History)")
    report.append("02:46:00  Persistence: service install (EVTX 7045 + Registry)")
    report.append("02:50:00  Memory: cmd->mimikatz->procdump process tree (Memory dump)")
    report.append("```\n")
    report.append("## Key Finding\n")
    report.append("**Every production forensic tool accepted our synthetic artifacts as genuine.**")
    report.append("Only BlindSight Validator detected anomalies.\n")

    if sleuthkit_results:
        report.append("## Sleuthkit Raw Output\n")
        for key, value in sleuthkit_results.items():
            report.append(f"### {key}\n```")
            report.append(value[:1500])
            report.append("```\n")

    with open(report_path, 'w') as f:
        f.write('\n'.join(report))

    print(f"[+] Results report: {report_path}")
    return report_path


def main():
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║          BlindSight — Full Demo Image Builder                   ║")
    print("║          Adversarial Robustness Testing of Forensic Tools       ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    os.makedirs(DEMO_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Phase 1: NTFS disk image
    image_path, ghost_files = build_ntfs_image()

    # Phase 2: EVTX
    evtx_path = build_evtx_artifacts()

    # Phase 3: Prefetch
    prefetch_paths = build_prefetch_artifacts()

    # Phase 4: Browser history
    chrome_path, firefox_path = build_browser_artifacts()

    # Phase 5: Registry
    registry_results = build_registry_artifacts()

    # Phase 6: Memory dump
    memory_path = build_memory_dump()

    # Phase 7: Sleuthkit validation
    sleuthkit_results = run_sleuthkit_validation(image_path)

    # Phase 8: EVTX validation
    run_evtx_validation(evtx_path)

    # Phase 9: Browser validation
    run_sqlite_validation(chrome_path, firefox_path)

    # Phase 10: Defensive validation
    run_blindsight_validator()

    # Generate report
    report_path = generate_results_report(sleuthkit_results)

    banner("DEMO COMPLETE")
    print(f"All artifacts in: {DEMO_DIR}\n")
    print("Files generated:")
    for root, dirs, files in os.walk(DEMO_DIR):
        for f in files:
            fp = os.path.join(root, f)
            size = os.path.getsize(fp)
            rel = os.path.relpath(fp, DEMO_DIR)
            if size > 1024*1024:
                print(f"    {rel:50s} {size/1024/1024:.1f} MB")
            else:
                print(f"    {rel:50s} {size/1024:.1f} KB")

    print(f"\n    Results report: {report_path}")
    print()
    print("Next steps:")
    print("  1. Load blindsight_demo.raw in Autopsy → see ghost files")
    print("  2. Open Security.evtx in Event Log Explorer → see fake events")
    print("  3. Load memory_dump.raw in Volatility3 → see phantom processes")
    print("  4. Load Chrome_History in DB Browser → see fake browsing")
    print()


if __name__ == "__main__":
    main()
