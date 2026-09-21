"""事件存取层：幂等写入、时间游标分页、确认、nonce 重放登记、依赖门禁。"""
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

# 每个事件最多声明的唯一依赖数量（API 层同样校验，这里只做防御性常量）
MAX_DEPENDENCIES = 20

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
    """依赖门禁失败：自依赖、引用不存在（且不在同批）或批内依赖环。

    errors 按“条目在去重后批次中的位置（pos）”归集：
      {"index": pos, "reason": "self_dependency", "event_id": ...}
      {"index": pos, "reason": "missing_dependency",
       "event_id": ..., "missing": [event_id, ...]}
      {"index": pos, "reason": "dependency_cycle", "event_id": ..., "cycle": [...]}
    单条入箱时 pos 恒为 0。任一错误都导致整批回滚、零写入。
    """

    def __init__(self, errors: list[dict]) -> None:
        super().__init__(json.dumps(errors, ensure_ascii=False))
        self.errors = errors


class EventBlockedError(Exception):
    """确认事件时仍有未完成（pending）的前置依赖。"""

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


def normalize_dependencies(depends_on: Iterable[str] | None) -> list[str]:
    """依赖集合规范化：去重、排序。集合语义，不依赖提交顺序。"""
    if not depends_on:
        return []
    return sorted(set(depends_on))


def content_hash(type_: str, payload: Any, depends_on: Iterable[str] | None = None) -> str:
    """内容指纹：type + 规范化 payload（+ 规范化依赖集合）。

    依赖仅在非空时追加一段：升级前写入的旧事件不带依赖，旧库已有指纹
    保持不变，因此旧库增量建表后无需回填即可与新代码的比对结果一致；
    新事件带依赖提交时，依赖集合（排序去重后）参与幂等内容比对。
    """
    basis = f"{type_}\n{canonical_json(payload)}"
    deps = normalize_dependencies(depends_on)
    if deps:
        basis += "\nDEPS\n" + json.dumps(deps, separators=(",", ":"))
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def _detect_dependency_errors(
    prepared: list[tuple[str, str, str, str, list[str]]],
    available: set[str],
) -> list[dict]:
    """在入箱事务内校验依赖，返回错误列表（空列表表示通过）。

    prepared 为去重后的待写条目 (event_id, type, payload, digest, deps)；
    available 为“此刻引用合法”的事件集合 = 库中已有事件 ∪ 本批条目。

    检查三类：
      1. 自依赖（含重复声明自身 ID）；
      2. 引用既不在库中也不在同批（批量允许引用同批任意位置）；
      3. 本批新条目之间的依赖环（环只可能由新边构成，库图保证无环）。

    环检测对本批新节点构成的子图做迭代式 DFS，按固定排序推进，
    因此报告的环路径确定、可复现。
    """
    positions = {event_id: pos for pos, (event_id, *_) in enumerate(prepared)}
    batch_ids = set(positions)
    errors: list[dict] = []
    graphs: dict[str, list[str]] = {}

    for pos, (event_id, _, _, _, deps) in enumerate(prepared):
        if event_id in deps:
            errors.append(
                {"index": pos, "reason": "self_dependency", "event_id": event_id}
            )
        missing = sorted(dep for dep in deps if dep != event_id and dep not in available)
        if missing:
            errors.append(
                {
                    "index": pos,
                    "reason": "missing_dependency",
                    "event_id": event_id,
                    "missing": missing,
                }
            )
        # 仅本批新节点之间的边参与环检测；指向库中节点的边不可能成环
        graphs[event_id] = sorted(
            dep for dep in deps if dep != event_id and dep in batch_ids
        )

    color: dict[str, int] = {}  # 0=未访问 1=在当前 DFS 栈中 2=已完成

    def walk(start: str) -> None:
        # 显式栈的迭代 DFS：(节点, 下一条边位置)
        stack: list[tuple[str, int]] = [(start, 0)]
        color[start] = 1
        while stack:
            node, edge_pos = stack[-1]
            neighbors = graphs[node]
            if edge_pos < len(neighbors):
                nxt = neighbors[edge_pos]
                stack[-1] = (node, edge_pos + 1)
                if color.get(nxt, 0) == 0:
                    color[nxt] = 1
                    stack.append((nxt, 0))
                elif color[nxt] == 1:
                    path_nodes = [n for n, _ in stack]
                    cut = path_nodes.index(nxt)
                    cycle = path_nodes[cut:] + [nxt]
                    errors.append(
                        {
                            "index": positions[node],
                            "reason": "dependency_cycle",
                            "event_id": node,
                            "cycle": cycle,
                        }
                    )
            else:
                color[node] = 2
                stack.pop()

    for event_id in sorted(batch_ids):
        if color.get(event_id, 0) == 0:
            walk(event_id)

    errors.sort(key=lambda e: (e["index"], e["reason"]))
    return errors


def _row_to_event(row, deps: Iterable[str] | None = None) -> dict:
    return {
        "event_id": row["event_id"],
        "type": row["type"],
        "payload": json.loads(row["payload"]),
        "status": row["status"],
        "created_at": row["created_at"],
        "acked_at": row["acked_at"],
        "depends_on": sorted(deps) if deps is not None else [],
    }


def _dependencies_for(conn, event_ids: Iterable[str]) -> dict[str, list[str]]:
    """批量读取多个事件的依赖集合（事务内/连接锁内调用）。"""
    ids = list(event_ids)
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    result = {event_id: [] for event_id in ids}
    rows = conn.execute(
        f"SELECT event_id, depends_on FROM event_dependencies WHERE event_id IN ({placeholders})",
        ids,
    ).fetchall()
    for row in rows:
        result[row["event_id"]].append(row["depends_on"])
    return result


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
        depends_on: Iterable[str] | None = None,
    ) -> tuple[dict, bool]:
        """幂等写入，并在同一写事务内登记来源 nonce。

        返回 (事件记录, 是否新建)。nonce 登记（同来源主键冲突即重放）、
        内容冲突检查、依赖门禁（引用必须已在库中、禁止自依赖）、事件与
        依赖边插入及回读全部在一个 BEGIN IMMEDIATE 事务中完成：连接级锁
        + 立即写锁使并发请求彼此串行，因此并发重放只有首个请求成功，其余
        抛 ReplayError 且零写入；并发重复 event_id 只保留首个版本，内容
        不同则抛 EventConflictError（同样回滚，nonce 不会被登记）。
        """
        deps = normalize_dependencies(depends_on)
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
                if deps:
                    dep_placeholders = ", ".join("?" for _ in deps)
                    existing_ids = {
                        r["event_id"]
                        for r in conn.execute(
                            f"SELECT event_id FROM events WHERE event_id IN ({dep_placeholders})",
                            deps,
                        ).fetchall()
                    }
                else:
                    existing_ids = set()
                dep_errors = _detect_dependency_errors(
                    [(event_id, type_, body_json, digest, deps)], existing_ids
                )
                if dep_errors:
                    raise DependencyError(dep_errors)
                conn.execute(
                    """
                    INSERT INTO events
                        (event_id, type, payload, content_hash, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (event_id, type_, body_json, digest, STATUS_PENDING, utcnow_iso()),
                )
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
            dep_map = _dependencies_for(conn, [event_id])
            return row, dep_map[event_id], created

        row, dep_rows, created = self._run_immediate_tx(operation)
        return _row_to_event(row, dep_rows), created

    def create_events_batch(
        self,
        items: list[tuple[str, str, Any]],
        *,
        source: str,
        nonce: str,
    ) -> list[tuple[dict, bool]]:
        """批量幂等写入：nonce 登记、冲突与依赖检查、全部插入在单一事务内完成。

        items 需已按 event_id 去重（批内归并在 API 层完成）；每个条目为
        (event_id, type, payload) 或 (event_id, type, payload, depends_on)。
        依赖可引用同批任意位置（前向引用合法）。同来源 nonce 已用抛
        ReplayError；任一 event_id 与库中记录内容冲突则整批零写入并抛
        BatchConflictError；自依赖、引用缺失（不在库中且不在同批）、批内
        依赖环均抛 DependencyError（错误按去重后位置 pos 归集）——三种
        情况下 nonce 均不会登记，客户端可用新 nonce 重试。否则返回与
        items 顺序对齐的 (事件记录, 是否新建) 列表。连接级锁 +
        BEGIN IMMEDIATE 使并发批次彼此串行：要么整批提交（含 nonce 登记
        与依赖边），要么整批回滚，并发重放仅一次成功。
        """
        if not items:
            return []
        prepared = []
        for item in items:
            event_id, type_, payload = item[:3]
            deps = normalize_dependencies(item[3] if len(item) > 3 else None)
            prepared.append((event_id, type_, payload, content_hash(type_, payload, deps), deps))
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
                for event_id, _, _, digest, _ in prepared
                if event_id in existing and existing[event_id]["content_hash"] != digest
            ]
            if conflicts:
                raise BatchConflictError(conflicts)

            # 引用合法性的“可用集合”= 同批条目 ∪ 库中已存在的被引用事件。
            # 上面的 rows 只覆盖批内 ID，故另查批外被引用的依赖是否落库。
            referenced = {
                dep
                for _, _, _, _, deps in prepared
                for dep in deps
                if dep not in set(ids)
            }
            if referenced:
                ref_list = list(referenced)
                ref_placeholders = ", ".join("?" for _ in ref_list)
                referenced_in_db = {
                    r["event_id"]
                    for r in conn.execute(
                        f"SELECT event_id FROM events WHERE event_id IN ({ref_placeholders})",
                        ref_list,
                    ).fetchall()
                }
            else:
                referenced_in_db = set()
            dep_errors = _detect_dependency_errors(
                prepared, set(ids) | referenced_in_db
            )
            if dep_errors:
                raise DependencyError(dep_errors)

            for event_id, type_, payload, digest, _ in prepared:
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
            for event_id, _, _, _, deps in prepared:
                if event_id in existing:
                    # 已存在事件的依赖集合不可变，幂等重放不重复写入依赖边
                    continue
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
            dep_map = _dependencies_for(conn, ids)
            return rows, existing, dep_map

        rows, existing, dep_map = self._run_immediate_tx(operation)
        by_id = {row["event_id"]: row for row in rows}
        return [
            (_row_to_event(by_id[event_id], dep_map[event_id]), event_id not in existing)
            for event_id, _, _, _, _ in prepared
        ]

    def get_event(self, event_id: str) -> dict:
        with self.db.lock:
            row = self.db.conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            dep_map = _dependencies_for(self.db.conn, [event_id]) if row is not None else {}
        if row is None:
            raise EventNotFoundError(event_id)
        return _row_to_event(row, dep_map.get(event_id, []))

    def _list_page(self, where: str, params: list[Any], limit: int) -> dict:
        """按 (created_at, event_id) 升序的键集分页（时间游标），并附带依赖集合。"""
        # 与写入共用一条连接，加锁保证不会读到未提交事务的中间状态
        with self.db.lock:
            rows = self.db.conn.execute(
                f"SELECT * FROM events {where} ORDER BY created_at, event_id LIMIT ?",
                (*params, limit + 1),
            ).fetchall()
            dep_map = _dependencies_for(self.db.conn, [r["event_id"] for r in rows])
        has_more = len(rows) > limit
        page_rows = rows[:limit]
        items = [_row_to_event(r, dep_map[r["event_id"]]) for r in page_rows]
        next_cursor = (
            encode_cursor(items[-1]["created_at"], items[-1]["event_id"]) if has_more else None
        )
        return {"items": items, "next_cursor": next_cursor, "has_more": has_more}

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
        return self._list_page(where, params, limit)

    def list_ready(self, limit: int, cursor: str | None = None) -> dict:
        """列出“全部依赖均已 ack”的 pending 事件，游标规则与 /events 一致。

        就绪判定：不存在一条 event_dependencies 边指向仍为 pending 的事件。
        无依赖的 pending 事件天然就绪。ack 只会把 pending 变为 acked，
        判定集合单调扩大，因此前置事件确认提交后本查询立即解锁后继事件。
        """
        clauses = [
            "status = ?",
            """NOT EXISTS (
                SELECT 1 FROM event_dependencies d
                JOIN events p ON p.event_id = d.depends_on
                WHERE d.event_id = events.event_id AND p.status = 'pending'
            )""",
        ]
        params: list[Any] = [STATUS_PENDING]
        if cursor is not None:
            c_created, c_id = decode_cursor(cursor)
            clauses.append("(created_at > ? OR (created_at = ? AND event_id > ?))")
            params.extend([c_created, c_created, c_id])
        return self._list_page(f"WHERE {' AND '.join(clauses)}", params, limit)

    def ack_event(self, event_id: str) -> dict:
        """确认单条事件。幂等：重复确认返回当前状态。

        pending 事件若仍有未完成（pending）的前置依赖则拒绝并抛
        EventBlockedError（携带 blocker event_id 列表）；依赖全部 ack 后
        立即可确认。门禁判定与状态翻转在同一个 BEGIN IMMEDIATE 事务内
        完成，故并发确认同一事件只有一次真正翻转，且不会在依赖确认与
        后继确认之间读到中间状态。
        """

        def operation(conn):
            row = conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            if row is None:
                raise EventNotFoundError(event_id)
            blockers = [
                r["depends_on"]
                for r in conn.execute(
                    """
                    SELECT d.depends_on
                    FROM event_dependencies d
                    JOIN events p ON p.event_id = d.depends_on
                    WHERE d.event_id = ? AND p.status = 'pending'
                    ORDER BY d.depends_on
                    """,
                    (event_id,),
                ).fetchall()
            ]
            if blockers:
                raise EventBlockedError(event_id, blockers)
            if row["status"] == STATUS_PENDING:
                conn.execute(
                    "UPDATE events SET status = ?, acked_at = ? WHERE event_id = ?",
                    (STATUS_ACKED, utcnow_iso(), event_id),
                )
                row = conn.execute(
                    "SELECT * FROM events WHERE event_id = ?", (event_id,)
                ).fetchone()
            dep_map = _dependencies_for(conn, [event_id])
            return row, dep_map[event_id]

        row, deps = self._run_immediate_tx(operation)
        return _row_to_event(row, deps)
