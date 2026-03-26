from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


@dataclass(slots=True)
class User:
    id: int
    username: str
    password_hash: str
    created_at: str


@dataclass(slots=True)
class StoredFile:
    id: str
    original_name: str
    stored_name: str
    content_type: str
    size_bytes: int
    sha256_hex: str
    uploaded_at: str
    uploaded_by: str


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    original_name TEXT NOT NULL,
                    stored_name TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256_hex TEXT NOT NULL,
                    uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    uploaded_by TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def count_users(self) -> int:
        with self.connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
            return int(row["count"])

    def upsert_user(self, username: str, password_hash: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
                ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash
                """,
                (username, password_hash),
            )
            conn.commit()

    def get_user_by_username(self, username: str) -> User | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, created_at FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not row:
                return None
            return User(
                id=row["id"],
                username=row["username"],
                password_hash=row["password_hash"],
                created_at=row["created_at"],
            )

    def insert_file(
        self,
        *,
        file_id: str,
        original_name: str,
        stored_name: str,
        content_type: str,
        size_bytes: int,
        sha256_hex: str,
        uploaded_by: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO files (id, original_name, stored_name, content_type, size_bytes, sha256_hex, uploaded_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (file_id, original_name, stored_name, content_type, size_bytes, sha256_hex, uploaded_by),
            )
            conn.commit()

    def list_files(self) -> list[StoredFile]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, original_name, stored_name, content_type, size_bytes, sha256_hex, uploaded_at, uploaded_by
                FROM files
                ORDER BY uploaded_at DESC
                """
            ).fetchall()
            return [
                StoredFile(
                    id=row["id"],
                    original_name=row["original_name"],
                    stored_name=row["stored_name"],
                    content_type=row["content_type"],
                    size_bytes=row["size_bytes"],
                    sha256_hex=row["sha256_hex"],
                    uploaded_at=row["uploaded_at"],
                    uploaded_by=row["uploaded_by"],
                )
                for row in rows
            ]

    def get_file(self, file_id: str) -> StoredFile | None:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT id, original_name, stored_name, content_type, size_bytes, sha256_hex, uploaded_at, uploaded_by
                FROM files
                WHERE id = ?
                """,
                (file_id,),
            ).fetchone()
            if not row:
                return None
            return StoredFile(
                id=row["id"],
                original_name=row["original_name"],
                stored_name=row["stored_name"],
                content_type=row["content_type"],
                size_bytes=row["size_bytes"],
                sha256_hex=row["sha256_hex"],
                uploaded_at=row["uploaded_at"],
                uploaded_by=row["uploaded_by"],
            )

    def delete_file(self, file_id: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
            conn.commit()
