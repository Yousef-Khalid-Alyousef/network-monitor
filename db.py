import sqlite3
import datetime
import threading
from typing import List, Optional

import config

_db_lock = threading.Lock()

def _get_conn():
    # SQLite in Python can be tricky across threads if check_same_thread=True.
    return sqlite3.connect(config.DB_FILE, check_same_thread=False)

def init_db():
    with _db_lock:
        with _get_conn() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    connection_count INTEGER DEFAULT 0
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    data_bytes INTEGER DEFAULT 0,
                    entry_point TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    timestamp TEXT,
                    domain TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                )
            ''')

def record_connection(mac: str) -> None:
    with _db_lock:
        with _get_conn() as conn:
            conn.execute('''
                INSERT INTO devices (mac, connection_count)
                VALUES (?, 1)
                ON CONFLICT(mac) DO UPDATE SET connection_count = connection_count + 1
            ''', (mac,))

def get_connection_count(mac: str) -> int:
    with _db_lock:
        with _get_conn() as conn:
            row = conn.execute('SELECT connection_count FROM devices WHERE mac = ?', (mac,)).fetchone()
            return row[0] if row else 0

def start_session(mac: str, entry_point: str) -> int:
    now = datetime.datetime.now().isoformat()
    with _db_lock:
        with _get_conn() as conn:
            cursor = conn.execute('''
                INSERT INTO sessions (mac, start_time, entry_point)
                VALUES (?, ?, ?)
            ''', (mac, now, entry_point))
            return cursor.lastrowid

def end_session(session_id: int, total_bytes: int) -> None:
    now = datetime.datetime.now().isoformat()
    with _db_lock:
        with _get_conn() as conn:
            conn.execute('''
                UPDATE sessions
                SET end_time = ?, data_bytes = ?
                WHERE id = ?
            ''', (now, total_bytes, session_id))

def log_domain(session_id: int, domain: str) -> None:
    now = datetime.datetime.now().isoformat()
    with _db_lock:
        with _get_conn() as conn:
            conn.execute('''
                INSERT INTO history (session_id, timestamp, domain)
                VALUES (?, ?, ?)
            ''', (session_id, now, domain))

def get_session_domains(session_id: int, limit: int = 20) -> List[str]:
    with _db_lock:
        with _get_conn() as conn:
            rows = conn.execute('''
                SELECT domain FROM history
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (session_id, limit)).fetchall()
            return [row[0] for row in rows]
