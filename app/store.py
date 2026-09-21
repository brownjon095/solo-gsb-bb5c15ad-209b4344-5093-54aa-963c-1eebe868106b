"""事件存取层：幂等写入、时间游标分页、确认、nonce 重放登记。"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from .auth import NONCE_RETENTION_SECONDS
from .db import Database

STATUS_PENDING = "pending"
STATUS_ACKED = "acked"

# 多连接场景下 BEGIN IMMEDIATE 可能立即返回 SQLITE_BUSY；短暂退避后重试，
# 避免高并发写争用时把可恢复的锁等待冒泡成 500。
_BUSY_RETRIES = 10
_BUSY_BACKOFF_SECONDS = 0.02


class EventConflictError(Exception):
    """event_id 已存在，但提交的内容与首个版本不同。"""

    def __init__(self, event_id: str) -> None:
        super().__init__(event_id)
        self.event_id = event_id


class BatchConflictError(Exception):
    """批量事件与库中已存记录内容冲突（整批未写入）。"""

    def __init__(self, event_ids: list[str]) -> None:
        super().__init__(", ".join(event_ids))
        self.event_ids = event_ids


class ReplayError(Exception):
    """同来源的 nonce 已被登记（重放请求）。"""

    def __init__(self, source: str) -> None:
        super().__init__(source)
        self.source = source


class EventNotFoundError(Exception):
    pass


class InvalidCursorError(Exception):
    pass


def utcnow_iso() -> str:
    """固定 6 位小数的 UTC ISO-8601 字符串，保证字典序 == 时间序。"""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond:06d}Z"


def canonical_json(value: Any) -> str:
    """规范化 JSON：键排序、无空白，使语义相同的 payload 得到相同文本。"""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(type_: str, payload: Any) -> str:
    return hashlib.sha256(f"{type_}\n{canonical_json(payload)}".encode("utf-8")).hexdigest()


def _row_to_event(row) -> dict:
    return {
        "event_id": row["event_id"],
        "type": row["type"],
        "payload": json.loads(row["payload"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "acked_at": row["acked_at"],
    }


def encode_cursor(created_at: str, event_id: str) -> str:
    raw = json.dumps({"created_at": created_at, "event_id": event_id}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str) -> tuple[str, str]:
    try:
        data = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        return str(data["created_at"]), str(data["event_id"])
    except Exception as exc:
        raise InvalidCursorError(cursor) from exc


class EventStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    def _run_immediate_tx(self, operation):
        """在连接锁内执行 BEGIN IMMEDIATE 事务。

        operation 接收当前连接，在事务中执行全部读写并返回结果；commit 由
        本函数统一完成，任何异常均回滚。多连接争用写锁导致的 SQLITE_BUSY
        （BEGIN 阶段或事务中被另一个连接的写锁阻塞且超过 busy_timeout）
        按指数退避重试整个操作，保证可恢复的锁等待不会冒泡为 500。
        """
        with self.db.lock:
            for attempt in range(_BUSY_RETRIES):
                try:
                    self.db.conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as exc:
                    if str(exc) != "database is locked" or attempt == _BUSY_RETRIES - 1:
                        raise
                    time.sleep(_BUSY_BACKOFF_SECONDS * (attempt + 1))
                    continue
                try:
                    result = operation(self.db.conn)
                    self.db.conn.execute("COMMIT")
                    return result
                except sqlite3.OperationalError as exc:
                    # 仅当连接仍在事务中时回滚；BEGIN 成功后的 BUSY 同样整体重试
                    if self.db.conn.in_transaction:
                        self.db.conn.execute("ROLLBACK")
                    if str(exc) == "database is locked" and attempt < _BUSY_RETRIES - 1:
                        time.sleep(_BUSY_BACKOFF_SECONDS * (attempt + 1))
                        continue
                    raise
                except Exception:
                    if self.db.conn.in_transaction:
                        self.db.conn.execute("ROLLBACK")
                    raise

    def _prune_nonces(self, conn, now: int) -> None:
        """惰性清理超出保留期的 nonce 行；调用方须已持有写事务。

        保留期（660s）长于时间戳窗口（300s），保证任何可能被接受的
        时间戳对应的 nonce 在其有效期内必然仍在表中。
        """
        conn.execute(
            "DELETE FROM used_nonces WHERE seen_at < ?",
            (now - NONCE_RETENTION_SECONDS,),
        )

    def create_event(
        self,
        event_id: str,
        type_: str,
        payload: Any,
        *,
        source: str,
        nonce: str,
    ) -> tuple[dict, bool]:
        """幂等写入，并在同一写事务内登记来源 nonce。

        返回 (事件记录, 是否新建)。nonce 登记（同来源主键冲突即重放）、
        内容冲突检查、事件插入与回读全部在一个 BEGIN IMMEDIATE 事务中
        完成：连接级锁 + 立即写锁使并发请求彼此串行，因此并发重放只有
        首个请求成功，其余抛 ReplayError 且零写入；并发重复 event_id
        只保留首个版本，内容不同则抛 EventConflictError（同样回滚，
        nonce 不会被登记）。
        """
        digest = content_hash(type_, payload)
        body_json = canonical_json(payload)
        now = int(time.time())

        def operation(conn):
            self._prune_nonces(conn, now)
            reused = conn.execute(
                "SELECT 1 FROM used_nonces WHERE source = ? AND nonce = ?",
                (source, nonce),
            ).fetchone()
            if reused is not None:
                raise ReplayError(source)

            row = conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is not None and row["content_hash"] != digest:
                raise EventConflictError(event_id)
            created = row is None
            if created:
                conn.execute(
                    """
                    INSERT INTO events
                        (event_id, type, payload, content_hash, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (event_id, type_, body_json, digest, STATUS_PENDING, utcnow_iso()),
                )
            conn.execute(
                "INSERT INTO used_nonces (source, nonce, seen_at) VALUES (?, ?, ?)",
                (source, nonce, now),
            )
            if created:
                row = conn.execute(
                    "SELECT * FROM events WHERE event_id = ?", (event_id,)
                ).fetchone()
            return row, created

        row, created = self._run_immediate_tx(operation)
        return _row_to_event(row), created

    def create_events_batch(
        self,
        items: list[tuple[str, str, Any]],
        *,
        source: str,
        nonce: str,
    ) -> list[tuple[dict, bool]]:
        """批量幂等写入：nonce 登记、冲突检查与全部插入在单一事务内完成。

        items 需已按 event_id 去重（批内归并在 API 层完成）。同来源 nonce
        已用抛 ReplayError；任一 event_id 与库中记录内容冲突则整批零写入
        并抛 BatchConflictError（两种情况下 nonce 均不会登记，客户端可用
        新 nonce 重试）。否则返回与 items 顺序对齐的 (事件记录, 是否新建)
        列表。连接级锁 + BEGIN IMMEDIATE 使并发批次彼此串行：要么整批
        提交（含 nonce 登记），要么整批回滚，并发重放仅一次成功。
        """
        if not items:
            return []
        prepared = [
            (event_id, type_, payload, content_hash(type_, payload))
            for event_id, type_, payload in items
        ]
        ids = [event_id for event_id, _, _, _ in prepared]
        placeholders = ", ".join("?" for _ in ids)
        now = int(time.time())

        def operation(conn):
            self._prune_nonces(conn, now)
            reused = conn.execute(
                "SELECT 1 FROM used_nonces WHERE source = ? AND nonce = ?",
                (source, nonce),
            ).fetchone()
            if reused is not None:
                raise ReplayError(source)

            rows = conn.execute(
                f"SELECT * FROM events WHERE event_id IN ({placeholders})", ids
            ).fetchall()
            existing = {row["event_id"]: row for row in rows}
            conflicts = [
                event_id
                for event_id, _, _, digest in prepared
                if event_id in existing and existing[event_id]["content_hash"] != digest
            ]
            if conflicts:
                raise BatchConflictError(conflicts)
            for event_id, type_, payload, digest in prepared:
                if event_id in existing:
                    continue
                conn.execute(
                    """
                    INSERT INTO events
                        (event_id, type, payload, content_hash, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        type_,
                        canonical_json(payload),
                        digest,
                        STATUS_PENDING,
                        utcnow_iso(),
                    ),
                )
            conn.execute(
                "INSERT INTO used_nonces (source, nonce, seen_at) VALUES (?, ?, ?)",
                (source, nonce, now),
            )
            return conn.execute(
                f"SELECT * FROM events WHERE event_id IN ({placeholders})", ids
            ).fetchall(), existing

        rows, existing = self._run_immediate_tx(operation)
        by_id = {row["event_id"]: row for row in rows}
        return [
            (_row_to_event(by_id[event_id]), event_id not in existing)
            for event_id, _, _, _ in prepared
        ]

    def get_event(self, event_id: str) -> dict:
        with self.db.lock:
            row = self.db.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise EventNotFoundError(event_id)
        return _row_to_event(row)

    def list_events(
        self, limit: int, cursor: str | None = None, status: str | None = None
    ) -> dict:
        """按 (created_at, event_id) 升序的键集分页（时间游标）。"""
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if cursor is not None:
            c_created, c_id = decode_cursor(cursor)
            clauses.append("(created_at > ? OR (created_at = ? AND event_id > ?))")
            params.extend([c_created, c_created, c_id])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        # 与批量写入共用一条连接，加锁保证不会读到未提交事务的中间状态
        with self.db.lock:
            rows = self.db.conn.execute(
                f"SELECT * FROM events {where} ORDER BY created_at, event_id LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
        has_more = len(rows) > limit
        items = [_row_to_event(r) for r in rows[:limit]]
        next_cursor = (
            encode_cursor(items[-1]["created_at"], items[-1]["event_id"]) if has_more else None
        )
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

    def ack_event(self, event_id: str) -> dict:
        """确认单条事件。幂等：重复确认返回当前状态。"""
        with self.db.lock:
            self.db.conn.execute(
                "UPDATE events SET status = ?, acked_at = ? WHERE event_id = ? AND status = ?",
                (STATUS_ACKED, utcnow_iso(), event_id, STATUS_PENDING),
            )
            row = self.db.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise EventNotFoundError(event_id)
        return _row_to_event(row)
