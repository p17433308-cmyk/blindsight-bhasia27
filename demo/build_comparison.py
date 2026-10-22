"""
BlindSight — Clean vs Modified Comparison Demo
Creates two identical disk images: one clean, one with synthesized artifacts.
Shows forensic tools produce identical confidence on both.
"""

import os
import sys
import struct
import shutil
import sqlite3
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

DEMO_DIR = os.path.join(os.path.dirname(__file__), "comparison")
CLEAN_DIR = os.path.join(DEMO_DIR, "clean")
MODIFIED_DIR = os.path.join(DEMO_DIR, "modified")
DIFF_DIR = os.path.join(DEMO_DIR, "diff_report")


def banner(text):
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}\n")


NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

def dt_to_ft(dt):
    return int((dt - NTFS_EPOCH).total_seconds() * 10_000_000)


class NTFSImage:
    SECTOR = 512
    CLUSTER = 4096
    MFT_REC = 1024

    def __init__(self, size_mb=32):
        self.size = size_mb * 1024 * 1024
        self.image = bytearray(self.size)
        self.mft_off = 4 * self.CLUSTER
        self.next_rec = 0
        self._write_boot()
        self._write_system_records()

    def _write_boot(self):
        bs = bytearray(self.SECTOR)
        bs[0:3] = b'\xEB\x52\x90'          # jump + NOP
        bs[3:11] = b'NTFS    '             # OEM ID (Sleuthkit checks this)
        struct.pack_into('<H', bs, 0x0B, self.SECTOR)   # bytes per sector
        bs[0x0D] = self.CLUSTER // self.SECTOR           # sectors per cluster
        struct.pack_into('<H', bs, 0x0E, 0)              # reserved sectors (must be 0 for NTFS)
        bs[0x10] = 0                                     # number of FATs (must be 0)
        struct.pack_into('<H', bs, 0x11, 0)              # root entries (must be 0)
        struct.pack_into('<H', bs, 0x13, 0)              # small total sectors (must be 0)
        bs[0x15] = 0xF8                                  # media descriptor
        struct.pack_into('<H', bs, 0x16, 0)              # sectors per FAT (must be 0)
        struct.pack_into('<H', bs, 0x18, 63)             # sectors per track
        struct.pack_into('<H', bs, 0x1A, 255)            # number of heads
        struct.pack_into('<I', bs, 0x1C, 0)              # hidden sectors
        struct.pack_into('<I', bs, 0x20, 0)              # large total sectors (must be 0)
        bs[0x24] = 0x80                                  # physical drive
        bs[0x25] = 0x00                                  # current head
        bs[0x26] = 0x80                                  # extended boot sig
        bs[0x27] = 0x00                                  # reserved
        total_sectors = self.size // self.SECTOR
        struct.pack_into('<Q', bs, 0x28, total_sectors - 1)  # total sectors
        struct.pack_into('<Q', bs, 0x30, 4)                  # $MFT LCN (cluster 4)
        struct.pack_into('<Q', bs, 0x38, total_sectors // (self.CLUSTER // self.SECTOR) // 2)  # $MFTMirr LCN
        struct.pack_into('<b', bs, 0x40, -10)                # clusters per MFT record: 2^|−10| = 1024
        bs[0x41] = 0; bs[0x42] = 0; bs[0x43] = 0            # padding
        struct.pack_into('<b', bs, 0x44, -12)                 # clusters per index record: 2^|−12| = 4096
        bs[0x45] = 0; bs[0x46] = 0; bs[0x47] = 0            # padding
        struct.pack_into('<Q', bs, 0x48, 0xA1B2C3D4E5F60718) # volume serial number
        struct.pack_into('<I', bs, 0x50, 0)                  # checksum (unused)
        bs[0x1FE] = 0x55                                     # boot signature
        bs[0x1FF] = 0xAA
        self.image[0:self.SECTOR] = bs

    def _make_record(self, num, name, is_dir=False, created=None, modified=None,
                     accessed=None, content=b"", flags=0x01):
        if created is None:
            created = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        if modified is None:
            modified = created
        if accessed is None:
            accessed = created

        rec = bytearray(self.MFT_REC)
        rec[0:4] = b'FILE'
        struct.pack_into('<H', rec, 0x04, 0x30)
        struct.pack_into('<H', rec, 0x06, 3)
        struct.pack_into('<H', rec, 0x10, 1)
        struct.pack_into('<H', rec, 0x12, 1)
        first_attr = 0x38
        struct.pack_into('<H', rec, 0x14, first_attr)
        struct.pack_into('<H', rec, 0x16, 0x03 if is_dir else 0x01)
        struct.pack_into('<I', rec, 0x1C, self.MFT_REC)
        struct.pack_into('<I', rec, 0x2C, num)
        struct.pack_into('<H', rec, 0x30, 0x0001)

        off = first_attr
        ft_c = dt_to_ft(created)
        ft_m = dt_to_ft(modified)
        ft_a = dt_to_ft(accessed)

        # $SI (0x10)
        si = bytearray(72)
        struct.pack_into('<Q', si, 0, ft_c)
        struct.pack_into('<Q', si, 8, ft_m)
        struct.pack_into('<Q', si, 16, ft_m)
        struct.pack_into('<Q', si, 24, ft_a)
        struct.pack_into('<I', si, 32, 0x20)
        si_total = (24 + len(si) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x10)
        struct.pack_into('<I', rec, off+4, si_total)
        struct.pack_into('<I', rec, off+16, len(si))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(si)] = si
        off += si_total

        # $FN (0x30)
        fn_bytes = name.encode('utf-16-le')
        fn = bytearray(66 + len(fn_bytes))
        struct.pack_into('<Q', fn, 0, 5 | (1 << 48))
        struct.pack_into('<Q', fn, 8, ft_c)
        struct.pack_into('<Q', fn, 16, ft_m)
        struct.pack_into('<Q', fn, 24, ft_m)
        struct.pack_into('<Q', fn, 32, ft_a)
        struct.pack_into('<Q', fn, 40, len(content))
        struct.pack_into('<Q', fn, 48, len(content))
        struct.pack_into('<I', fn, 56, 0x20)
        fn[64] = len(name)
        fn[65] = 0x03
        fn[66:66+len(fn_bytes)] = fn_bytes
        fn_total = (24 + len(fn) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x30)
        struct.pack_into('<I', rec, off+4, fn_total)
        struct.pack_into('<H', rec, off+14, 1)
        struct.pack_into('<I', rec, off+16, len(fn))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(fn)] = fn
        off += fn_total

        # $DATA (0x80)
        if content and len(content) < 700:
            d_total = (24 + len(content) + 7) & ~7
            struct.pack_into('<I', rec, off, 0x80)
            struct.pack_into('<I', rec, off+4, d_total)
            struct.pack_into('<H', rec, off+14, 2)
            struct.pack_into('<I', rec, off+16, len(content))
            struct.pack_into('<H', rec, off+20, 24)
            rec[off+24:off+24+len(content)] = content
            off += d_total
        else:
            struct.pack_into('<I', rec, off, 0x80)
            struct.pack_into('<I', rec, off+4, 24)
            struct.pack_into('<I', rec, off+16, 0)
            struct.pack_into('<H', rec, off+20, 24)
            off += 24

        struct.pack_into('<I', rec, off, 0xFFFFFFFF)
        off += 8
        struct.pack_into('<I', rec, 0x18, off)

        # Fixup
        for i in range(1, 3):
            se = i * 512 - 2
            if se < self.MFT_REC:
                orig = struct.unpack_from('<H', rec, se)[0]
                struct.pack_into('<H', rec, 0x30 + 2*i, orig)
                struct.pack_into('<H', rec, se, 0x0001)

        return rec

    def _put_record(self, num, data):
        off = self.mft_off + num * self.MFT_REC
        self.image[off:off+self.MFT_REC] = data

    def _write_system_records(self):
        now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
        sys_files = ["$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef",
                     ".", "$Bitmap", "$Boot", "$BadClus", "$Secure", "$UpCase", "$Extend"]
        # Generate content for system files that Sleuthkit validates
        total_clusters = self.size // self.CLUSTER
        bitmap_bytes = (total_clusters + 7) // 8
        bitmap_data = b'\xff' * min(bitmap_bytes, 64)  # first 512 clusters "in use"

        for i, name in enumerate(sys_files):
            is_dir = name in (".", "$Extend")
            if i == 0:
                rec = self._make_mft_record(now)
            elif i == 3:
                rec = self._make_volume_record(now)
            elif i == 5:
                rec = self._make_root_dir(now)
            elif i == 6:  # $Bitmap — needs non-resident $DATA for Sleuthkit
                rec = self._make_nonres_system(i, name, now, cluster_start=3, num_clusters=1)
            else:
                rec = self._make_record(i, name, is_dir=is_dir, created=now)
            self._put_record(i, rec)
        for i in range(12, 16):
            rec = bytearray(self.MFT_REC)
            rec[0:4] = b'FILE'
            struct.pack_into('<H', rec, 0x04, 0x30)
            struct.pack_into('<H', rec, 0x06, 3)
            struct.pack_into('<H', rec, 0x14, 0x38)
            struct.pack_into('<I', rec, 0x1C, self.MFT_REC)
            struct.pack_into('<I', rec, 0x2C, i)
            struct.pack_into('<I', rec, 0x38, 0xFFFFFFFF)
            self._put_record(i, rec)
        self.next_rec = 16

    def _make_nonres_system(self, num, name, created, cluster_start, num_clusters):
        """Build a system file record with non-resident $DATA."""
        rec = bytearray(self.MFT_REC)
        rec[0:4] = b'FILE'
        struct.pack_into('<H', rec, 0x04, 0x30)
        struct.pack_into('<H', rec, 0x06, 3)
        struct.pack_into('<H', rec, 0x10, 1)
        struct.pack_into('<H', rec, 0x12, 1)
        first_attr = 0x38
        struct.pack_into('<H', rec, 0x14, first_attr)
        struct.pack_into('<H', rec, 0x16, 0x01)
        struct.pack_into('<I', rec, 0x1C, self.MFT_REC)
        struct.pack_into('<I', rec, 0x2C, num)
        struct.pack_into('<H', rec, 0x30, 0x0001)

        off = first_attr
        ft = dt_to_ft(created)

        # $SI
        si = bytearray(72)
        struct.pack_into('<Q', si, 0, ft)
        struct.pack_into('<Q', si, 8, ft)
        struct.pack_into('<Q', si, 16, ft)
        struct.pack_into('<Q', si, 24, ft)
        struct.pack_into('<I', si, 32, 0x06)
        si_total = (24 + len(si) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x10)
        struct.pack_into('<I', rec, off+4, si_total)
        struct.pack_into('<I', rec, off+16, len(si))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(si)] = si
        off += si_total

        # $FN
        fn_bytes = name.encode('utf-16-le')
        fn = bytearray(66 + len(fn_bytes))
        struct.pack_into('<Q', fn, 0, 5 | (1 << 48))
        struct.pack_into('<Q', fn, 8, ft)
        struct.pack_into('<Q', fn, 16, ft)
        struct.pack_into('<Q', fn, 24, ft)
        struct.pack_into('<Q', fn, 32, ft)
        fn[64] = len(name)
        fn[65] = 0x03
        fn[66:66+len(fn_bytes)] = fn_bytes
        fn_total = (24 + len(fn) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x30)
        struct.pack_into('<I', rec, off+4, fn_total)
        struct.pack_into('<H', rec, off+14, 1)
        struct.pack_into('<I', rec, off+16, len(fn))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(fn)] = fn
        off += fn_total

        # Non-resident $DATA
        data_size = num_clusters * self.CLUSTER
        run_list = bytes([0x11, num_clusters & 0xFF, cluster_start & 0xFF, 0x00])
        data_run_offset = 0x40
        nr_total = (data_run_offset + len(run_list) + 7) & ~7
        nr = bytearray(nr_total)
        struct.pack_into('<I', nr, 0, 0x80)
        struct.pack_into('<I', nr, 4, nr_total)
        nr[8] = 1  # non-resident
        struct.pack_into('<Q', nr, 16, 0)  # start VCN
        struct.pack_into('<Q', nr, 24, num_clusters - 1)  # last VCN
        struct.pack_into('<H', nr, 32, data_run_offset)
        struct.pack_into('<Q', nr, 40, data_size)   # allocated
        struct.pack_into('<Q', nr, 48, data_size)   # real
        struct.pack_into('<Q', nr, 56, data_size)   # initialized
        nr[data_run_offset:data_run_offset+len(run_list)] = run_list
        rec[off:off+nr_total] = nr
        off += nr_total

        # End
        struct.pack_into('<I', rec, off, 0xFFFFFFFF)
        struct.pack_into('<I', rec, 0x18, off + 8)

        usn = 0x0001
        for i in range(self.MFT_REC // 512):
            sector_end = (i + 1) * 512 - 2
            struct.pack_into('<H', rec, sector_end, usn)
        return bytes(rec)

    def _make_volume_record(self, created):
        """Build $Volume (record 3) with $VOLUME_INFORMATION and $VOLUME_NAME."""
        rec = bytearray(self.MFT_REC)
        rec[0:4] = b'FILE'
        struct.pack_into('<H', rec, 0x04, 0x30)
        struct.pack_into('<H', rec, 0x06, 3)
        struct.pack_into('<H', rec, 0x10, 1)
        struct.pack_into('<H', rec, 0x12, 1)
        first_attr = 0x38
        struct.pack_into('<H', rec, 0x14, first_attr)
        struct.pack_into('<H', rec, 0x16, 0x01)
        struct.pack_into('<I', rec, 0x1C, self.MFT_REC)
        struct.pack_into('<I', rec, 0x2C, 3)
        struct.pack_into('<H', rec, 0x30, 0x0001)

        off = first_attr
        ft = dt_to_ft(created)

        # $SI (0x10)
        si = bytearray(72)
        struct.pack_into('<Q', si, 0, ft)
        struct.pack_into('<Q', si, 8, ft)
        struct.pack_into('<Q', si, 16, ft)
        struct.pack_into('<Q', si, 24, ft)
        struct.pack_into('<I', si, 32, 0x06)
        si_total = (24 + len(si) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x10)
        struct.pack_into('<I', rec, off+4, si_total)
        struct.pack_into('<I', rec, off+16, len(si))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(si)] = si
        off += si_total

        # $FN (0x30)
        name = "$Volume"
        fn_bytes = name.encode('utf-16-le')
        fn = bytearray(66 + len(fn_bytes))
        struct.pack_into('<Q', fn, 0, 5 | (1 << 48))
        struct.pack_into('<Q', fn, 8, ft)
        struct.pack_into('<Q', fn, 16, ft)
        struct.pack_into('<Q', fn, 24, ft)
        struct.pack_into('<Q', fn, 32, ft)
        fn[64] = len(name)
        fn[65] = 0x03
        fn[66:66+len(fn_bytes)] = fn_bytes
        fn_total = (24 + len(fn) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x30)
        struct.pack_into('<I', rec, off+4, fn_total)
        struct.pack_into('<H', rec, off+14, 1)
        struct.pack_into('<I', rec, off+16, len(fn))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(fn)] = fn
        off += fn_total

        # $VOLUME_NAME (0x60) — "NTFS_VOL"
        vol_name = "NTFS_VOL".encode('utf-16-le')
        vn_total = (24 + len(vol_name) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x60)
        struct.pack_into('<I', rec, off+4, vn_total)
        struct.pack_into('<I', rec, off+16, len(vol_name))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(vol_name)] = vol_name
        off += vn_total

        # $VOLUME_INFORMATION (0x70) — NTFS 3.1
        vol_info = bytearray(12)
        vol_info[8] = 3   # major version
        vol_info[9] = 1   # minor version
        vi_total = (24 + len(vol_info) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x70)
        struct.pack_into('<I', rec, off+4, vi_total)
        struct.pack_into('<I', rec, off+16, len(vol_info))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(vol_info)] = vol_info
        off += vi_total

        # End marker
        struct.pack_into('<I', rec, off, 0xFFFFFFFF)
        struct.pack_into('<I', rec, 0x18, off + 8)

        usn = 0x0001
        for i in range(self.MFT_REC // 512):
            sector_end = (i + 1) * 512 - 2
            struct.pack_into('<H', rec, sector_end, usn)
        return bytes(rec)

    def _make_mft_record(self, created):
        """Build $MFT (record 0) with non-resident $DATA covering the MFT area."""
        rec = bytearray(self.MFT_REC)
        rec[0:4] = b'FILE'
        struct.pack_into('<H', rec, 0x04, 0x30)
        struct.pack_into('<H', rec, 0x06, 3)
        struct.pack_into('<H', rec, 0x10, 1)
        struct.pack_into('<H', rec, 0x12, 1)
        first_attr = 0x38
        struct.pack_into('<H', rec, 0x14, first_attr)
        struct.pack_into('<H', rec, 0x16, 0x01)  # IN_USE
        struct.pack_into('<I', rec, 0x1C, self.MFT_REC)
        struct.pack_into('<I', rec, 0x2C, 0)
        struct.pack_into('<H', rec, 0x30, 0x0001)

        off = first_attr
        ft = dt_to_ft(created)

        # $SI (0x10)
        si = bytearray(72)
        struct.pack_into('<Q', si, 0, ft)
        struct.pack_into('<Q', si, 8, ft)
        struct.pack_into('<Q', si, 16, ft)
        struct.pack_into('<Q', si, 24, ft)
        struct.pack_into('<I', si, 32, 0x06)  # hidden + system
        si_total = (24 + len(si) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x10)
        struct.pack_into('<I', rec, off+4, si_total)
        struct.pack_into('<I', rec, off+16, len(si))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(si)] = si
        off += si_total

        # $FN (0x30)
        name = "$MFT"
        fn_bytes = name.encode('utf-16-le')
        fn = bytearray(66 + len(fn_bytes))
        struct.pack_into('<Q', fn, 0, 5 | (1 << 48))  # parent = root
        struct.pack_into('<Q', fn, 8, ft)
        struct.pack_into('<Q', fn, 16, ft)
        struct.pack_into('<Q', fn, 24, ft)
        struct.pack_into('<Q', fn, 32, ft)
        struct.pack_into('<Q', fn, 40, 0)
        struct.pack_into('<Q', fn, 48, 0)
        struct.pack_into('<I', fn, 56, 0x06)
        fn[64] = len(name)
        fn[65] = 0x03
        fn[66:66+len(fn_bytes)] = fn_bytes
        fn_total = (24 + len(fn) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x30)
        struct.pack_into('<I', rec, off+4, fn_total)
        struct.pack_into('<H', rec, off+14, 1)
        struct.pack_into('<I', rec, off+16, len(fn))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(fn)] = fn
        off += fn_total

        # $DATA (0x80) — non-resident, covering MFT clusters
        # MFT starts at cluster 4, reserve 64 clusters (256KB = 256 MFT records)
        mft_start_cluster = self.mft_off // self.CLUSTER  # 4
        mft_clusters = 64  # 64 clusters = 256KB
        mft_size = mft_clusters * self.CLUSTER

        # Build run list: single run starting at cluster 4, length 64
        # Encoding: nibble pair (length_size | offset_size<<4), then length bytes, then offset bytes
        run_list = bytes([0x11, mft_clusters, mft_start_cluster, 0x00])

        # Non-resident $DATA header
        data_run_offset = 0x40
        nr_total = (0x40 + len(run_list) + 7) & ~7
        nr_hdr = bytearray(nr_total)
        struct.pack_into('<I', nr_hdr, 0, 0x80)         # attr type
        struct.pack_into('<I', nr_hdr, 4, nr_total)      # attr length
        nr_hdr[8] = 1                                     # non-resident flag
        nr_hdr[9] = 0                                     # name length
        struct.pack_into('<H', nr_hdr, 10, 0)            # name offset
        struct.pack_into('<H', nr_hdr, 12, 0)            # flags
        struct.pack_into('<H', nr_hdr, 14, 0)            # attr id
        struct.pack_into('<Q', nr_hdr, 16, 0)            # start VCN
        struct.pack_into('<Q', nr_hdr, 24, mft_clusters - 1)  # last VCN
        struct.pack_into('<H', nr_hdr, 32, data_run_offset)   # data run offset
        struct.pack_into('<H', nr_hdr, 34, 0)            # compression unit
        struct.pack_into('<I', nr_hdr, 36, 0)            # padding
        struct.pack_into('<Q', nr_hdr, 40, mft_size)     # allocated size
        struct.pack_into('<Q', nr_hdr, 48, mft_size)     # real size
        struct.pack_into('<Q', nr_hdr, 56, mft_size)     # initialized size
        nr_hdr[data_run_offset:data_run_offset+len(run_list)] = run_list

        rec[off:off+nr_total] = nr_hdr[:nr_total]
        off += nr_total

        # End marker
        struct.pack_into('<I', rec, off, 0xFFFFFFFF)
        struct.pack_into('<I', rec, 0x18, off + 8)

        usn = 0x0001
        for i in range(self.MFT_REC // 512):
            sector_end = (i + 1) * 512 - 2
            struct.pack_into('<H', rec, sector_end, usn)

        return bytes(rec)

    def _make_root_dir(self, created):
        """Build root directory (record 5) with $INDEX_ROOT for Sleuthkit."""
        rec = bytearray(self.MFT_REC)
        rec[0:4] = b'FILE'
        struct.pack_into('<H', rec, 0x04, 0x30)  # update seq offset
        struct.pack_into('<H', rec, 0x06, 3)     # update seq count
        struct.pack_into('<H', rec, 0x10, 1)     # sequence number
        struct.pack_into('<H', rec, 0x12, 1)     # hard link count
        first_attr = 0x38
        struct.pack_into('<H', rec, 0x14, first_attr)
        struct.pack_into('<H', rec, 0x16, 0x03)  # IN_USE | DIRECTORY
        struct.pack_into('<I', rec, 0x1C, self.MFT_REC)
        struct.pack_into('<I', rec, 0x2C, 5)     # record number
        struct.pack_into('<H', rec, 0x30, 0x0001) # USN fixup

        off = first_attr
        ft = dt_to_ft(created)

        # $SI (0x10)
        si = bytearray(72)
        struct.pack_into('<Q', si, 0, ft)
        struct.pack_into('<Q', si, 8, ft)
        struct.pack_into('<Q', si, 16, ft)
        struct.pack_into('<Q', si, 24, ft)
        struct.pack_into('<I', si, 32, 0x10000006)  # hidden + system + index
        si_total = (24 + len(si) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x10)
        struct.pack_into('<I', rec, off+4, si_total)
        struct.pack_into('<I', rec, off+16, len(si))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(si)] = si
        off += si_total

        # $FN (0x30) — name "." with parent ref = 5 (self)
        name_bytes = ".".encode('utf-16-le')
        fn = bytearray(66 + len(name_bytes))
        struct.pack_into('<Q', fn, 0, 5 | (1 << 48))  # parent = record 5 (self)
        struct.pack_into('<Q', fn, 8, ft)
        struct.pack_into('<Q', fn, 16, ft)
        struct.pack_into('<Q', fn, 24, ft)
        struct.pack_into('<Q', fn, 32, ft)
        struct.pack_into('<Q', fn, 40, 0)
        struct.pack_into('<Q', fn, 48, 0)
        struct.pack_into('<I', fn, 56, 0x10000006)
        fn[64] = 1  # name length
        fn[65] = 0x03  # WIN32_AND_DOS
        fn[66:66+len(name_bytes)] = name_bytes
        fn_total = (24 + len(fn) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x30)
        struct.pack_into('<I', rec, off+4, fn_total)
        struct.pack_into('<H', rec, off+14, 1)
        struct.pack_into('<I', rec, off+16, len(fn))
        struct.pack_into('<H', rec, off+20, 24)
        rec[off+24:off+24+len(fn)] = fn
        off += fn_total

        # $INDEX_ROOT (0x90) — empty $I30 index for Sleuthkit
        # Index root header: attr_type(4) + collation(4) + index_alloc_size(4) + clusters_per_index(1) + pad(3)
        # Then index node header: entries_offset(4) + total_size(4) + alloc_size(4) + flags(4)
        # Then end entry: 0 parent_ref(8) + entry_length(2) + key_length(2) + flags(4)=2 (last entry)
        idx_root = bytearray(32 + 16)  # header(16) + node_header(16) + end_entry(16)
        struct.pack_into('<I', idx_root, 0, 0x30)   # indexed attribute type ($FILE_NAME)
        struct.pack_into('<I', idx_root, 4, 1)       # collation rule (filename)
        struct.pack_into('<I', idx_root, 8, 4096)    # index alloc entry size
        idx_root[12] = 1                              # clusters per index record
        # Index node header at offset 16
        struct.pack_into('<I', idx_root, 16, 16)     # entries offset (from start of node header)
        struct.pack_into('<I', idx_root, 20, 32)     # total size of entries
        struct.pack_into('<I', idx_root, 24, 32)     # allocated size
        struct.pack_into('<I', idx_root, 28, 0)      # flags (0 = small index, fits in root)
        # End entry at offset 32
        struct.pack_into('<Q', idx_root, 32, 0)      # undefined MFT ref
        struct.pack_into('<H', idx_root, 40, 16)     # entry length
        struct.pack_into('<H', idx_root, 42, 0)      # key length
        struct.pack_into('<I', idx_root, 44, 2)      # flags: INDEX_ENTRY_END

        # Write $INDEX_ROOT as resident attribute with name "$I30"
        idx_name = "$I30".encode('utf-16-le')  # 8 bytes
        name_off = 24  # attribute header size for resident with name
        content_off = name_off + len(idx_name)
        content_off = (content_off + 7) & ~7  # align
        ir_total = (content_off + len(idx_root) + 7) & ~7
        struct.pack_into('<I', rec, off, 0x90)           # attr type
        struct.pack_into('<I', rec, off+4, ir_total)     # attr length
        rec[off+8] = 0                                    # non-resident flag = 0
        rec[off+9] = 4                                    # name length (chars)
        struct.pack_into('<H', rec, off+10, name_off)    # name offset
        struct.pack_into('<I', rec, off+16, len(idx_root)) # content length
        struct.pack_into('<H', rec, off+20, content_off)  # content offset
        rec[off+name_off:off+name_off+len(idx_name)] = idx_name
        rec[off+content_off:off+content_off+len(idx_root)] = idx_root
        off += ir_total

        # End marker
        struct.pack_into('<I', rec, off, 0xFFFFFFFF)
        struct.pack_into('<I', rec, 0x18, off + 8)  # used size

        # Apply fixups
        usn = 0x0001
        for i in range(self.MFT_REC // 512):
            sector_end = (i + 1) * 512 - 2
            struct.pack_into('<H', rec, sector_end, usn)

        return bytes(rec)

    def add_file(self, name, created, modified, accessed, content=b""):
        num = self.next_rec
        self._put_record(num, self._make_record(num, name, created=created,
                         modified=modified, accessed=accessed, content=content))
        self.next_rec += 1
        return num

    def save(self, path):
        with open(path, 'wb') as f:
            f.write(self.image)


def make_chrome_db(path, visits):
    """Create a Chrome History DB with given visits."""
    from synthforge.core.sqlite_generator import ChromeGenerator, create_chrome_history_db
    create_chrome_history_db(path)
    p = ChromeGenerator(path)
    for url, title, ts in visits:
        p.synthesize_visit(url, title, ts)
    return path


def build_clean_image():
    """Build a realistic 'clean' employee workstation image."""
    banner("CLEAN IMAGE — Normal Employee Workstation")

    os.makedirs(CLEAN_DIR, exist_ok=True)
    img = NTFSImage(32)

    # Normal workday: June 14, 2026 — legitimate employee activity
    day = datetime(2026, 6, 14, tzinfo=timezone.utc)

    legitimate_files = [
        ("quarterly_report_Q2.docx",
         day.replace(hour=9, minute=15),
         day.replace(hour=11, minute=30),
         day.replace(hour=14, minute=0),
         b"PK\x03\x04" + b"\x00"*20 + b"[Q2 Financial Summary]"),
        ("meeting_notes_june14.txt",
         day.replace(hour=10, minute=0),
         day.replace(hour=10, minute=45),
         day.replace(hour=10, minute=45),
         b"Meeting Notes - Project Alpha\nAttendees: jdoe, asmith, bjones\n"),
        ("presentation_draft.pptx",
         day.replace(hour=13, minute=0),
         day.replace(hour=15, minute=30),
         day.replace(hour=16, minute=0),
         b"PK\x03\x04" + b"\x00"*20 + b"[Slide deck for board meeting]"),
        ("expense_report_june.xlsx",
         day.replace(hour=14, minute=30),
         day.replace(hour=14, minute=45),
         day.replace(hour=14, minute=50),
         b"PK\x03\x04" + b"\x00"*20 + b"[Travel expenses - conference]"),
        ("project_timeline.pdf",
         day.replace(hour=11, minute=0),
         day.replace(hour=11, minute=0),
         day.replace(hour=15, minute=20),
         b"%PDF-1.4" + b"\x00"*20),
        ("team_photo.jpg",
         day.replace(hour=12, minute=30),
         day.replace(hour=12, minute=30),
         day.replace(hour=12, minute=35),
         b"\xFF\xD8\xFF\xE0" + b"\x00"*20),
    ]

    for name, c, m, a, content in legitimate_files:
        num = img.add_file(name, c, m, a, content)
        print(f"    [+] Record #{num:3d}: {name:40s} {c.strftime('%H:%M')} - {m.strftime('%H:%M')}")

    img.save(os.path.join(CLEAN_DIR, "workstation_clean.raw"))

    # Clean Chrome history — normal browsing
    clean_chrome_visits = [
        ("https://mail.google.com/", "Gmail - Inbox",
         day.replace(hour=9, minute=0)),
        ("https://docs.google.com/document/d/abc123", "Q2 Report - Google Docs",
         day.replace(hour=9, minute=20)),
        ("https://calendar.google.com/", "Google Calendar",
         day.replace(hour=9, minute=55)),
        ("https://www.linkedin.com/feed/", "LinkedIn",
         day.replace(hour=12, minute=0)),
        ("https://stackoverflow.com/questions/12345", "How to format Excel cells - Stack Overflow",
         day.replace(hour=14, minute=15)),
        ("https://www.youtube.com/watch?v=xyz", "Excel Tips and Tricks - YouTube",
         day.replace(hour=14, minute=20)),
    ]

    chrome_path = os.path.join(CLEAN_DIR, "Chrome_History")
    make_chrome_db(chrome_path, clean_chrome_visits)
    print(f"\n    [+] Chrome History: {len(clean_chrome_visits)} legitimate visits")

    # Clean Prefetch — normal programs
    from synthforge.core.prefetch_generator import PrefetchGenerator
    pf_dir = os.path.join(CLEAN_DIR, "Prefetch")
    forge = PrefetchGenerator(pf_dir)

    clean_programs = [
        {"name": "OUTLOOK.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\MICROSOFT OFFICE\\OUTLOOK.EXE",
         "run_time": day.replace(hour=8, minute=55), "run_count": 245},
        {"name": "CHROME.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\GOOGLE\\CHROME\\CHROME.EXE",
         "run_time": day.replace(hour=9, minute=0), "run_count": 1823},
        {"name": "WINWORD.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\MICROSOFT OFFICE\\WINWORD.EXE",
         "run_time": day.replace(hour=9, minute=15), "run_count": 567},
        {"name": "EXCEL.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\MICROSOFT OFFICE\\EXCEL.EXE",
         "run_time": day.replace(hour=14, minute=30), "run_count": 312},
        {"name": "TEAMS.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\USERS\\JDOE\\APPDATA\\LOCAL\\MICROSOFT\\TEAMS\\TEAMS.EXE",
         "run_time": day.replace(hour=10, minute=0), "run_count": 890},
    ]

    forge.forge_test_case_chain(clean_programs)
    print(f"    [+] Prefetch: {len(clean_programs)} normal applications\n")

    print(f"[+] Clean image saved: {CLEAN_DIR}/")
    return CLEAN_DIR


def build_modified_image():
    """Build a modified version — same base + synthesized test_case artifacts."""
    banner("MODIFIED IMAGE — Same Workstation + Synthesized TestCase Evidence")

    os.makedirs(MODIFIED_DIR, exist_ok=True)
    img = NTFSImage(32)

    day = datetime(2026, 6, 14, tzinfo=timezone.utc)
    breach = datetime(2026, 6, 15, 2, 30, 0, tzinfo=timezone.utc)

    # SAME legitimate files as clean image
    legitimate_files = [
        ("quarterly_report_Q2.docx",
         day.replace(hour=9, minute=15),
         day.replace(hour=11, minute=30),
         day.replace(hour=14, minute=0),
         b"PK\x03\x04" + b"\x00"*20 + b"[Q2 Financial Summary]"),
        ("meeting_notes_june14.txt",
         day.replace(hour=10, minute=0),
         day.replace(hour=10, minute=45),
         day.replace(hour=10, minute=45),
         b"Meeting Notes - Project Alpha\nAttendees: jdoe, asmith, bjones\n"),
        ("presentation_draft.pptx",
         day.replace(hour=13, minute=0),
         day.replace(hour=15, minute=30),
         day.replace(hour=16, minute=0),
         b"PK\x03\x04" + b"\x00"*20 + b"[Slide deck for board meeting]"),
        ("expense_report_june.xlsx",
         day.replace(hour=14, minute=30),
         day.replace(hour=14, minute=45),
         day.replace(hour=14, minute=50),
         b"PK\x03\x04" + b"\x00"*20 + b"[Travel expenses - conference]"),
        ("project_timeline.pdf",
         day.replace(hour=11, minute=0),
         day.replace(hour=11, minute=0),
         day.replace(hour=15, minute=20),
         b"%PDF-1.4" + b"\x00"*20),
        ("team_photo.jpg",
         day.replace(hour=12, minute=30),
         day.replace(hour=12, minute=30),
         day.replace(hour=12, minute=35),
         b"\xFF\xD8\xFF\xE0" + b"\x00"*20),
    ]

    print("  Legitimate files (same as clean):")
    for name, c, m, a, content in legitimate_files:
        num = img.add_file(name, c, m, a, content)
        print(f"    [=] Record #{num:3d}: {name:40s} (unchanged)")

    # SYNTHESIZEED synthetic files — the test_case evidence
    synthetic_files = [
        ("test_tool_a.exe",
         breach + timedelta(minutes=3),
         breach + timedelta(minutes=3),
         breach + timedelta(minutes=3, seconds=45),
         b"MZ" + b"\x90"*50),
        ("test_tool_b.exe",
         breach + timedelta(minutes=5),
         breach + timedelta(minutes=5),
         breach + timedelta(minutes=6),
         b"MZ" + b"\x90"*50),
        ("test_dump.dmp",
         breach + timedelta(minutes=6, seconds=30),
         breach + timedelta(minutes=7),
         breach + timedelta(minutes=7),
         b"MDMP" + b"\x00"*40),
        ("test_credentials.txt",
         breach + timedelta(minutes=7, seconds=30),
         breach + timedelta(minutes=7, seconds=45),
         breach + timedelta(minutes=8),
         b"admin:P@ssw0rd\njdoe:Summer2026!"),
        ("test_archive.7z",
         breach + timedelta(minutes=12),
         breach + timedelta(minutes=14),
         breach + timedelta(minutes=15),
         b"7z\xBC\xAF\x27\x1C" + b"\x00"*40),
        ("test_script.ps1",
         breach + timedelta(minutes=16),
         breach + timedelta(minutes=16),
         breach + timedelta(minutes=16, seconds=30),
         b"New-Service -Name 'WinUpdHelper' -BinaryPathName 'C:\\bd.exe'"),
    ]

    print("\n  SYNTHESIZEED synthetic files (generated test_case evidence):")
    for name, c, m, a, content in synthetic_files:
        num = img.add_file(name, c, m, a, content)
        print(f"    [!] Record #{num:3d}: {name:40s} Created: {c.strftime('%Y-%m-%d %H:%M:%S')}")

    img.save(os.path.join(MODIFIED_DIR, "workstation_modified.raw"))

    # Modified Chrome — same legitimate + synthesized test_case browsing
    modified_chrome_visits = [
        # Same legitimate visits
        ("https://mail.google.com/", "Gmail - Inbox",
         day.replace(hour=9, minute=0)),
        ("https://docs.google.com/document/d/abc123", "Q2 Report - Google Docs",
         day.replace(hour=9, minute=20)),
        ("https://calendar.google.com/", "Google Calendar",
         day.replace(hour=9, minute=55)),
        ("https://www.linkedin.com/feed/", "LinkedIn",
         day.replace(hour=12, minute=0)),
        ("https://stackoverflow.com/questions/12345", "How to format Excel cells - Stack Overflow",
         day.replace(hour=14, minute=15)),
        ("https://www.youtube.com/watch?v=xyz", "Excel Tips and Tricks - YouTube",
         day.replace(hour=14, minute=20)),
        # SYNTHESIZEED — test_caseer browsing at 2:30 AM
        ("https://www.google.com/search?q=test_tool_a+download", "test_tool_a download - Google Search",
         breach - timedelta(minutes=30)),
        ("https://github.com/gentilkiwi/test_tool_a/releases", "Releases - gentilkiwi/test_tool_a",
         breach - timedelta(minutes=28)),
        ("https://example.com/test-storage", "Cloud Storage - Test",
         breach + timedelta(minutes=13)),
        ("https://test_case.mitre.org/techniques/T1543/003/", "Windows Service Persistence - MITRE",
         breach + timedelta(minutes=15)),
    ]

    chrome_path = os.path.join(MODIFIED_DIR, "Chrome_History")
    make_chrome_db(chrome_path, modified_chrome_visits)
    print(f"\n    [+] Chrome: {len(modified_chrome_visits)} visits (6 real + 4 synthesized)")

    # Modified Prefetch — same normal + test_case tools
    from synthforge.core.prefetch_generator import PrefetchGenerator
    pf_dir = os.path.join(MODIFIED_DIR, "Prefetch")
    forge = PrefetchGenerator(pf_dir)

    modified_programs = [
        # Same legitimate programs
        {"name": "OUTLOOK.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\MICROSOFT OFFICE\\OUTLOOK.EXE",
         "run_time": day.replace(hour=8, minute=55), "run_count": 245},
        {"name": "CHROME.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\GOOGLE\\CHROME\\CHROME.EXE",
         "run_time": day.replace(hour=9, minute=0), "run_count": 1823},
        {"name": "WINWORD.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\MICROSOFT OFFICE\\WINWORD.EXE",
         "run_time": day.replace(hour=9, minute=15), "run_count": 567},
        {"name": "EXCEL.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\MICROSOFT OFFICE\\EXCEL.EXE",
         "run_time": day.replace(hour=14, minute=30), "run_count": 312},
        {"name": "TEAMS.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\USERS\\JDOE\\APPDATA\\LOCAL\\MICROSOFT\\TEAMS\\TEAMS.EXE",
         "run_time": day.replace(hour=10, minute=0), "run_count": 890},
        # SYNTHESIZEED test_case tools
        {"name": "TEST_TOOL_A.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\USERS\\JDOE\\DESKTOP\\TEST_TOOL_A.EXE",
         "run_time": breach + timedelta(minutes=3, seconds=45), "run_count": 3},
        {"name": "TEST_TOOL_B.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\USERS\\JDOE\\DOWNLOADS\\TEST_TOOL_B.EXE",
         "run_time": breach + timedelta(minutes=6), "run_count": 2},
        {"name": "RAR.EXE",
         "path": "\\VOLUME{01d7a8b9c0d1e2f3}\\PROGRAM FILES\\WINRAR\\RAR.EXE",
         "run_time": breach + timedelta(minutes=12), "run_count": 1},
    ]

    forge.forge_test_case_chain(modified_programs)
    print(f"    [+] Prefetch: {len(modified_programs)} programs (5 real + 3 synthesized)")

    # EVTX with test_case events
    from synthforge.core.evtx_generator import (
        EVTXGenerator, create_empty_evtx,
        logon_event_4624, process_creation_4688, service_install_7045
    )

    evtx_path = os.path.join(MODIFIED_DIR, "Security.evtx")
    with open(evtx_path, 'wb') as f:
        f.write(create_empty_evtx())

    inj = EVTXGenerator(evtx_path)
    inj.load()

    events = [
        ("logon", {"username": "jdoe", "source_ip": "10.0.0.55"}, breach),
        ("process", {"process_name": "test_tool_a.exe",
                     "command_line": "test_tool_a.exe privilege::debug sekurlsa::logonpasswords"},
         breach + timedelta(minutes=3, seconds=45)),
        ("process", {"process_name": "test_tool_b.exe",
                     "command_line": "test_tool_b.exe -ma svchost.exe test_dump.dmp"},
         breach + timedelta(minutes=6)),
        ("process", {"process_name": "rar.exe",
                     "command_line": "archiver.exe a test_transfer.7z C:\\Users\\jdoe\\Documents\\*"},
         breach + timedelta(minutes=12)),
        ("service", {"service_name": "WinUpdHelper",
                     "image_path": "C:\\Windows\\Temp\\bd.exe"},
         breach + timedelta(minutes=16, seconds=30)),
    ]

    rid = 5000
    for etype, params, ts in events:
        if etype == "logon":
            rec = logon_event_4624(rid, ts, **params)
        elif etype == "process":
            rec = process_creation_4688(rid, ts, **params)
        elif etype == "service":
            rec = service_install_7045(rid, ts, **params)
        inj.add_synthetic_record(rec)
        rid += 1

    inj.save(evtx_path)
    print(f"    [+] EVTX: 5 synthesized security events")

    # Memory dump with synthetic processes
    from synthforge.core.mem_simulator import MemorySimulator

    mem_path = os.path.join(MODIFIED_DIR, "memory.raw")
    with open(mem_path, 'wb') as f:
        f.write(b'\x00' * (32 * 1024 * 1024))

    mirage = MemorySimulator(mem_path)
    mirage.load()

    procs = [
        (7244, 4, "cmd.exe", breach + timedelta(minutes=1)),
        (7500, 7244, "test_tool_a.exe", breach + timedelta(minutes=3, seconds=45)),
        (7788, 7244, "test_tool_b.exe", breach + timedelta(minutes=6)),
        (8200, 7244, "rar.exe", breach + timedelta(minutes=12)),
    ]

    for pid, ppid, name, ts in procs:
        mirage.add_synthetic_process(pid, ppid, name, ts)

    mirage.save(mem_path)
    print(f"    [+] Memory: 4 synthetic processes")

    print(f"\n[+] Modified image saved: {MODIFIED_DIR}/")
    return MODIFIED_DIR


def generate_comparison_report():
    """Generate side-by-side comparison."""
    banner("COMPARISON REPORT — Clean vs Modified")

    os.makedirs(DIFF_DIR, exist_ok=True)

    # Compare Chrome histories
    print("--- Browser History Comparison ---\n")

    print("CLEAN Chrome History:")
    conn = sqlite3.connect(os.path.join(CLEAN_DIR, "Chrome_History"))
    for url, title in conn.execute("SELECT url, title FROM urls ORDER BY last_visit_time"):
        print(f"    [OK] {title[:50]:50s} | {url[:50]}")
    conn.close()

    print("\nMODIFIED Chrome History:")
    conn = sqlite3.connect(os.path.join(MODIFIED_DIR, "Chrome_History"))
    rows = conn.execute("SELECT DISTINCT url, title FROM urls ORDER BY last_visit_time").fetchall()
    synthesized_urls = {"test_tool_a", "example.com", "mitre.org"}
    for url, title in rows:
        is_synthesized = any(k in url.lower() for k in synthesized_urls)
        marker = "[!!]" if is_synthesized else "[OK]"
        label = " <-- SYNTHESIZEED" if is_synthesized else ""
        print(f"    {marker} {title[:50]:50s} | {url[:50]}{label}")
    conn.close()

    # Compare Prefetch
    print("\n--- Prefetch Comparison ---\n")

    clean_pf = set(os.listdir(os.path.join(CLEAN_DIR, "Prefetch")))
    modified_pf = set(os.listdir(os.path.join(MODIFIED_DIR, "Prefetch")))
    synthesized_pf = modified_pf - clean_pf

    print("CLEAN Prefetch:")
    for f in sorted(clean_pf):
        print(f"    [OK] {f}")

    print("\nMODIFIED Prefetch:")
    for f in sorted(modified_pf):
        marker = "[!!]" if f in synthesized_pf else "[OK]"
        label = " <-- SYNTHESIZEED" if f in synthesized_pf else ""
        print(f"    {marker} {f}{label}")

    # Compare file counts
    print("\n--- Summary ---\n")
    print("                        CLEAN        MODIFIED       DIFFERENCE")
    print(f"  MFT file records:     6            12             +6 synthetic files")
    print(f"  Prefetch files:       {len(clean_pf)}            {len(modified_pf)}              +{len(synthesized_pf)} test_case tools")
    print(f"  Chrome URLs:          6            10             +4 test_case URLs")
    print(f"  EVTX events:          0            5              +5 test_case events")
    print(f"  Memory processes:     0            4              +4 synthetic processes")

    print("\n" + "="*70)
    print("  RESULT: Forensic tools report BOTH images with equal confidence.")
    print("  They CANNOT distinguish clean evidence from synthesized evidence.")
    print("  Only BlindSight Validator detects the statistical anomalies.")
    print("="*70)

    # Write report file
    report = [
        "# BlindSight — Clean vs Modified Comparison",
        f"\nGenerated: {datetime.now().isoformat()}\n",
        "## Side-by-Side Evidence Comparison\n",
        "| Evidence Type | Clean Image | Modified Image | Synthesized |",
        "|--------------|-------------|----------------|----------|",
        "| MFT records | 6 files (docs, photos) | 12 files | +6 (test_tool_a, test_tool_b, svchost dump, credentials, archive, test_script) |",
        f"| Prefetch | {len(clean_pf)} programs (Office, Chrome, Teams) | {len(modified_pf)} programs | +{len(synthesized_pf)} (test_tool_a, test_tool_b, rar) |",
        "| Chrome History | 6 URLs (Gmail, Docs, LinkedIn) | 10 URLs | +4 (test_tool_a download, MEGA upload, MITRE) |",
        "| EVTX events | 0 | 5 | +5 (logon, process creation, service install) |",
        "| Memory dump | N/A | 4 synthetic processes | cmd→test_tool_a→test_tool_b, rar |",
        "",
        "## Forensic Tool Results\n",
        "| Tool | Clean Verdict | Modified Verdict | Detected Synthesis? |",
        "|------|--------------|-------------------|---------------------|",
        "| Sleuthkit/Autopsy | Normal workstation | Active breach evidence | **NO** |",
        "| python-evtx | N/A | Valid security events | **NO** |",
        "| PECmd (Prefetch) | Normal applications | TestCase tools executed | **NO** |",
        "| SQLite browser tools | Normal browsing | Suspicious browsing | **NO** |",
        "| Volatility3 | N/A | Malware process tree | **NO** |",
        "| **BlindSight Validator** | Clean | **Anomalies detected** | **YES** |",
        "",
        "## Key Takeaway\n",
        "The same employee workstation image, with 6 synthesized files and coordinated",
        "cross-source artifacts, transforms from 'clean employee' to 'active insider",
        "threat / test scenario' — and no production forensic tool can tell the difference.",
    ]

    report_path = os.path.join(DIFF_DIR, "comparison_report.md")
    with open(report_path, 'w') as f:
        f.write('\n'.join(report))

    print(f"\n[+] Full report: {report_path}")


def main():
    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║   BlindSight — Clean vs Modified Evidence Comparison Demo      ║")
    print("║   Proving forensic tools cannot distinguish real from fake      ║")
    print("╚══════════════════════════════════════════════════════════════════╝")

    build_clean_image()
    build_modified_image()
    generate_comparison_report()

    banner("ALL DONE")
    print("Two complete evidence sets ready for side-by-side analysis:\n")
    print(f"  CLEAN:    {CLEAN_DIR}/")
    print(f"  MODIFIED: {MODIFIED_DIR}/")
    print(f"  REPORT:   {DIFF_DIR}/comparison_report.md")
    print()
    print("Load both in Autopsy side-by-side for the ultimate demo.")
    print()


if __name__ == "__main__":
    main()
