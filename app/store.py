"""事件存取层：幂等写入、依赖门禁、时间游标分页、确认、nonce 重放登记。"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Iterable

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


class DependencyError(Exception):
    """依赖门禁校验失败（整批零写入）。

    self_dependents: 自依赖的 event_id 列表；
    missing: {event_id: [既不在库中也不在同批的依赖]}；
    cycle: 批内环路径（首尾相接，如 ["a", "b", "a"]），无环时为 None。
    """

    def __init__(
        self,
        self_dependents: list[str],
        missing: dict[str, list[str]],
        cycle: list[str] | None,
    ) -> None:
        super().__init__("invalid event dependencies")
        self.self_dependents = self_dependents
        self.missing = missing
        self.cycle = cycle


class EventBlockedError(Exception):
    """确认事件时仍有未 ack 的依赖。"""

    def __init__(self, event_id: str, blockers: list[str]) -> None:
        super().__init__(event_id)
        self.event_id = event_id
        self.blockers = blockers


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


def content_hash(type_: str, payload: Any, depends_on: Iterable[str] = ()) -> str:
    """内容指纹：type + 规范化 payload + 依赖集合（排序去重，不计顺序）。

    空依赖时与引入依赖特性前的算法逐字节一致，旧库中已有事件的指纹
    保持不变，重投仍判幂等。
    """
    text = f"{type_}\n{canonical_json(payload)}"
    deps = sorted(set(depends_on))
    if deps:
        text += f"\n{canonical_json(deps)}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _row_to_event(row, depends_on: Iterable[str] = ()) -> dict:
    return {
        "event_id": row["event_id"],
        "type": row["type"],
        "payload": json.loads(row["payload"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "acked_at": row["acked_at"],
        "depends_on": list(depends_on),
    }


def _load_dependencies(conn, event_ids: Iterable[str]) -> dict[str, list[str]]:
    """批量读取事件的依赖集合（按 depends_on 字典序），无依赖的事件映射为空列表。"""
    ids = list(dict.fromkeys(event_ids))
    deps: dict[str, list[str]] = {event_id: [] for event_id in ids}
    if not ids:
        return deps
    placeholders = ", ".join("?" for _ in ids)
    rows = conn.execute(
        "SELECT event_id, depends_on FROM event_dependencies "
        f"WHERE event_id IN ({placeholders}) ORDER BY event_id, depends_on",
        ids,
    ).fetchall()
    for row in rows:
        deps[row["event_id"]].append(row["depends_on"])
    return deps


def _find_cycle(graph: dict[str, list[str]]) -> list[str] | None:
    """DFS 三色标记找环：返回首尾相接的环路径，无环返回 None。

    节点与邻边均按字典序遍历，同一图得到的路径稳定（便于错误回报与测试）。
    """
    color: dict[str, int] = {}  # 1=在栈上（灰） 2=已完成（黑），缺省=未访问
    stack: list[str] = []

    def dfs(node: str) -> list[str] | None:
        color[node] = 1
        stack.append(node)
        for dep in graph.get(node, ()):
            if color.get(dep) == 1:
                return stack[stack.index(dep):] + [dep]
            if color.get(dep) is None:
                found = dfs(dep)
                if found is not None:
                    return found
        stack.pop()
        color[node] = 2
        return None

    for node in sorted(graph):
        if color.get(node) is None:
            found = dfs(node)
            if found is not None:
                return found
    return None


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

    @staticmethod
    def _check_dependencies(conn, new_items: list[tuple[str, list[str]]]) -> None:
        """依赖门禁：拒绝自依赖、引用必须已在库中或同批、批内无环。

        只校验本次新建的事件（库中已有事件在首次写入时已通过同样校验）。
        任一失败抛 DependencyError；调用方在写事务内，回滚即整批零写入。
        环只可能出现在批内：库中事件写入时其依赖必须已存在，不可能回指
        批内新事件，因此只需在批内新建事件构成的子图上找环。
        """
        if not new_items:
            return
        batch_ids = {event_id for event_id, _ in new_items}
        self_dependents: list[str] = []
        external: set[str] = set()
        for event_id, deps in new_items:
            if event_id in deps:
                self_dependents.append(event_id)
            external.update(dep for dep in deps if dep not in batch_ids)
        existing: set[str] = set()
        if external:
            placeholders = ", ".join("?" for _ in external)
            rows = conn.execute(
                f"SELECT event_id FROM events WHERE event_id IN ({placeholders})",
                sorted(external),
            ).fetchall()
            existing = {row["event_id"] for row in rows}
        missing: dict[str, list[str]] = {}
        for event_id, deps in new_items:
            absent = [
                dep
                for dep in deps
                if dep != event_id and dep not in batch_ids and dep not in existing
            ]
            if absent:
                missing[event_id] = absent
        graph = {
            event_id: [dep for dep in deps if dep in batch_ids and dep != event_id]
            for event_id, deps in new_items
        }
        cycle = _find_cycle(graph)
        if self_dependents or missing or cycle is not None:
            raise DependencyError(self_dependents, missing, cycle)

    def create_event(
        self,
        event_id: str,
        type_: str,
        payload: Any,
        depends_on: Iterable[str] = (),
        *,
        source: str,
        nonce: str,
    ) -> tuple[dict, bool]:
        """幂等写入，并在同一写事务内登记来源 nonce、校验依赖门禁。

        返回 (事件记录, 是否新建)。nonce 登记（同来源主键冲突即重放）、
        内容冲突检查（指纹含依赖集合）、依赖校验（引用必须已在库中、
        拒绝自依赖）、事件与依赖插入、回读全部在一个 BEGIN IMMEDIATE
        事务中完成：连接级锁 + 立即写锁使并发请求彼此串行，因此并发
        重放只有首个请求成功，其余抛 ReplayError 且零写入；并发重复
        event_id 只保留首个版本，内容不同则抛 EventConflictError，
        依赖非法则抛 DependencyError（均回滚，nonce 不会被登记）。
        """
        deps = sorted(set(depends_on))
        digest = content_hash(type_, payload, deps)
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
                self._check_dependencies(conn, [(event_id, deps)])
                conn.execute(
                    """
                    INSERT INTO events
                        (event_id, type, payload, content_hash, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (event_id, type_, body_json, digest, STATUS_PENDING, utcnow_iso()),
                )
                if deps:
                    conn.executemany(
                        "INSERT INTO event_dependencies (event_id, depends_on) VALUES (?, ?)",
                        [(event_id, dep) for dep in deps],
                    )
            conn.execute(
                "INSERT INTO used_nonces (source, nonce, seen_at) VALUES (?, ?, ?)",
                (source, nonce, now),
            )
            if created:
                row = conn.execute(
                    "SELECT * FROM events WHERE event_id = ?", (event_id,)
                ).fetchone()
            return row, created, _load_dependencies(conn, [event_id])[event_id]

        row, created, stored_deps = self._run_immediate_tx(operation)
        return _row_to_event(row, stored_deps), created

    def create_events_batch(
        self,
        items: list[tuple[str, str, Any, Iterable[str]]],
        *,
        source: str,
        nonce: str,
    ) -> list[tuple[dict, bool]]:
        """批量幂等写入：nonce 登记、依赖门禁、冲突检查与全部插入在单一事务内完成。

        items 需已按 event_id 去重（批内归并在 API 层完成），每项为
        (event_id, type, payload, depends_on)。依赖可指向库中已有事件或
        同批任意位置的事件；引用缺失、自依赖或批内环抛 DependencyError。
        同来源 nonce 已用抛 ReplayError；任一 event_id 与库中记录内容
        （含依赖集合）冲突抛 BatchConflictError。三种情况均整批零写入、
        nonce 不登记，客户端可用新 nonce 重试。否则返回与 items 顺序对齐
        的 (事件记录, 是否新建) 列表。连接级锁 + BEGIN IMMEDIATE 使并发
        批次彼此串行：要么整批提交（含 nonce 登记），要么整批回滚。
        """
        if not items:
            return []
        prepared = []
        for event_id, type_, payload, deps in items:
            norm_deps = sorted(set(deps))
            prepared.append(
                (event_id, type_, payload, norm_deps, content_hash(type_, payload, norm_deps))
            )
        ids = [event_id for event_id, _, _, _, _ in prepared]
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
                for event_id, _, _, _, digest in prepared
                if event_id in existing and existing[event_id]["content_hash"] != digest
            ]
            if conflicts:
                raise BatchConflictError(conflicts)
            new_items = [p for p in prepared if p[0] not in existing]
            self._check_dependencies(
                conn, [(event_id, deps) for event_id, _, _, deps, _ in new_items]
            )
            for event_id, type_, payload, deps, digest in new_items:
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
                if deps:
                    conn.executemany(
                        "INSERT INTO event_dependencies (event_id, depends_on) VALUES (?, ?)",
                        [(event_id, dep) for dep in deps],
                    )
            conn.execute(
                "INSERT INTO used_nonces (source, nonce, seen_at) VALUES (?, ?, ?)",
                (source, nonce, now),
            )
            rows = conn.execute(
                f"SELECT * FROM events WHERE event_id IN ({placeholders})", ids
            ).fetchall()
            return rows, existing, _load_dependencies(conn, ids)

        rows, existing, deps_map = self._run_immediate_tx(operation)
        by_id = {row["event_id"]: row for row in rows}
        return [
            (_row_to_event(by_id[event_id], deps_map[event_id]), event_id not in existing)
            for event_id, _, _, _, _ in prepared
        ]

    def get_event(self, event_id: str) -> dict:
        with self.db.lock:
            row = self.db.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            deps = _load_dependencies(self.db.conn, [event_id])
        if row is None:
            raise EventNotFoundError(event_id)
        return _row_to_event(row, deps[event_id])

    def list_events(
        self, limit: int, cursor: str | None = None, status: str | None = None
    ) -> dict:
        """按 (created_at, event_id) 升序的键集分页（时间游标）。"""
        return self._page_events(limit, cursor, status=status, ready_only=False)

    def list_ready_events(self, limit: int, cursor: str | None = None) -> dict:
        """只列出全部依赖均已 ack 的 pending 事件（同样的键集分页规则）。"""
        return self._page_events(limit, cursor, status=STATUS_PENDING, ready_only=True)

    def _page_events(
        self, limit: int, cursor: str | None, *, status: str | None, ready_only: bool
    ) -> dict:
        clauses: list[str] = []
        params: list[Any] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if ready_only:
            # 不存在任何未 ack 的依赖：无依赖的事件天然满足
            clauses.append(
                "NOT EXISTS ("
                "SELECT 1 FROM event_dependencies d "
                "JOIN events p ON p.event_id = d.depends_on "
                "WHERE d.event_id = events.event_id AND p.status <> ?)"
            )
            params.append(STATUS_ACKED)
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
            deps_map = _load_dependencies(self.db.conn, [row["event_id"] for row in rows])
        has_more = len(rows) > limit
        items = [_row_to_event(r, deps_map[r["event_id"]]) for r in rows[:limit]]
        next_cursor = (
            encode_cursor(items[-1]["created_at"], items[-1]["event_id"]) if has_more else None
        )
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

    def ack_event(self, event_id: str) -> dict:
        """确认单条事件。幂等：重复确认返回当前状态。

        事件仍有未 ack 的依赖时抛 EventBlockedError（携带 blockers 列表），
        状态保持不变；前置事件确认后再次调用即可立即解锁。
        """
        with self.db.lock:
            row = self.db.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is None:
                raise EventNotFoundError(event_id)
            if row["status"] == STATUS_PENDING:
                blockers = [
                    r["depends_on"]
                    for r in self.db.conn.execute(
                        """
                        SELECT d.depends_on
                        FROM event_dependencies d
                        JOIN events p ON p.event_id = d.depends_on
                        WHERE d.event_id = ? AND p.status <> ?
                        ORDER BY d.depends_on
                        """,
                        (event_id, STATUS_ACKED),
                    ).fetchall()
                ]
                if blockers:
                    raise EventBlockedError(event_id, blockers)
                self.db.conn.execute(
                    "UPDATE events SET status = ?, acked_at = ? WHERE event_id = ? AND status = ?",
                    (STATUS_ACKED, utcnow_iso(), event_id, STATUS_PENDING),
                )
                row = self.db.conn.execute(
                    "SELECT * FROM events WHERE event_id = ?", (event_id,)
                ).fetchone()
            deps = _load_dependencies(self.db.conn, [event_id])
        return _row_to_event(row, deps[event_id])
