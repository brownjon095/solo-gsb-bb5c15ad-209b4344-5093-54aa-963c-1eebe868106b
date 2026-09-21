"""SQLite 连接管理与自动建表。"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id     TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    payload      TEXT NOT NULL,              -- 规范化后的 JSON 文本
    content_hash TEXT NOT NULL,              -- type + payload 的 SHA-256，用于幂等比对
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'acked')),
    created_at   TEXT NOT NULL,              -- 固定 6 位小数的 UTC ISO-8601
    acked_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at, event_id);
CREATE INDEX IF NOT EXISTS idx_events_status ON events (status);

-- 已用 nonce 登记：(source, nonce) 复合主键天然防同来源重放。
-- 与 events 的写入在同一个 BEGIN IMMEDIATE 事务中完成，并发重放仅一次成功。
CREATE TABLE IF NOT EXISTS used_nonces (
    source  TEXT NOT NULL,
    nonce   TEXT NOT NULL,
    seen_at INTEGER NOT NULL,                -- 登记时刻的 Unix 秒，用于惰性清理
    PRIMARY KEY (source, nonce)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_used_nonces_seen_at ON used_nonces (seen_at);
"""

# 多连接并发打开时，设置 journal_mode=WAL 需要排他锁，可能立即返回
# SQLITE_BUSY；退避重试，避免可恢复的锁等待冒泡为启动/连接错误。
_INIT_BUSY_RETRIES = 10
_INIT_BUSY_BACKOFF_SECONDS = 0.02


class Database:
    """单共享连接 + 可重入锁。

    SQLite 写操作本身串行，锁进一步保证“插入 + 回读”复合操作的原子性，
    使并发重复请求只保留首个版本。WAL 模式提升读写并发。
    """

    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self._init_pragma("journal_mode=WAL")
            # busy_timeout 先于其余 DDL 设置，让建表阶段的锁争用也会等待
            self._conn.execute("PRAGMA busy_timeout=5000")
            # CREATE TABLE/INDEX IF NOT EXISTS：旧库启动时只增量补建新表，
            # 已有的 events 表及其数据保持不动。
            self._conn.executescript(SCHEMA)

    def _init_pragma(self, pragma: str) -> None:
        """执行需要排他锁的启动 PRAGMA，遇到 SQLITE_BUSY 时退避重试。"""
        for attempt in range(_INIT_BUSY_RETRIES):
            try:
                self._conn.execute(f"PRAGMA {pragma}")
                return
            except sqlite3.OperationalError as exc:
                if str(exc) != "database is locked" or attempt == _INIT_BUSY_RETRIES - 1:
                    raise
                time.sleep(_INIT_BUSY_BACKOFF_SECONDS * (attempt + 1))

    @property
    def conn(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        with self.lock:
            try:
                self._conn.close()
            except sqlite3.OperationalError as exc:
                # 多连接同时关闭时，WAL 收尾 checkpoint 可能瞬时遇锁；
                # 进程结束场景下无需重试，避免可恢复的清理错误冒泡。
                if str(exc) != "database is locked":
                    raise
