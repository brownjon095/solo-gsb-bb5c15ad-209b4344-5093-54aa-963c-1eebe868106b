"""Webhook 收件箱 API。"""
from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError, field_validator

from .auth import (
    NONCE_MAX_LENGTH,
    WebhookAuthError,
    WebhookAuthenticator,
)
from .db import Database
from .store import (
    MAX_DEPENDENCIES,
    BatchConflictError,
    DependencyError,
    EventBlockedError,
    EventConflictError,
    EventNotFoundError,
    EventStore,
    InvalidCursorError,
    ReplayError,
    content_hash,
    normalize_dependencies,
)


class EventIn(BaseModel):
    event_id: str = Field(min_length=1, max_length=128)
    type: str = Field(min_length=1, max_length=128)
    payload: Any
    # 可选依赖门禁：至多 20 个唯一 event_id；集合语义，重复声明自动去重、
    # 顺序无关。引用合法性（已在库中或同批）、自依赖与批内环在写事务内校验。
    depends_on: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list
    )

    @field_validator("depends_on")
    @classmethod
    def _validate_depends_on(cls, value: list[str]) -> list[str]:
        normalized = normalize_dependencies(value)
        if len(normalized) > MAX_DEPENDENCIES:
            raise ValueError(f"depends_on accepts at most {MAX_DEPENDENCIES} unique event_ids")
        return normalized


class EventOut(BaseModel):
    event_id: str
    type: str
    payload: Any
    status: Literal["pending", "acked"]
    created_at: str
    acked_at: str | None = None
    depends_on: list[str] = Field(default_factory=list)


class EventPage(BaseModel):
    items: list[EventOut]
    next_cursor: str | None
    has_more: bool


class EventBatchIn(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=100)


class BatchItemOut(EventOut):
    created: bool


class EventBatchOut(BaseModel):
    items: list[BatchItemOut]


@dataclass(frozen=True)
class AuthenticatedRequest:
    """验签通过后的请求上下文。"""

    source: str
    nonce: str
    body: bytes


# 供 openapi_extra 使用：把四个签名头登记到 Swagger 文档
_SIGNATURE_HEADER_PARAMS = [
    {
        "name": "X-Webhook-Source",
        "in": "header",
        "required": True,
        "schema": {"type": "string"},
        "description": "来源标识，对应 WEBHOOK_SECRETS_JSON 中的键",
    },
    {
        "name": "X-Webhook-Timestamp",
        "in": "header",
        "required": True,
        "schema": {"type": "integer"},
        "description": "Unix 秒；与服务器时间偏离超过 300 秒即拒绝",
    },
    {
        "name": "X-Webhook-Nonce",
        "in": "header",
        "required": True,
        "schema": {"type": "string", "maxLength": 128},
        "description": "来源内唯一的一次性随机串，重放同一 nonce 返回 401",
    },
    {
        "name": "X-Webhook-Signature",
        "in": "header",
        "required": True,
        "schema": {"type": "string"},
        "description": "HMAC-SHA256(timestamp + \\n + nonce + \\n + 原始请求体) 的十六进制摘要",
    },
]


def _ingestion_openapi(model: type[BaseModel]) -> dict:
    return {
        "parameters": _SIGNATURE_HEADER_PARAMS,
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": model.model_json_schema(ref_template="#/components/schemas/{model}")
                }
            },
        },
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    # 启动时自动建表（CREATE TABLE IF NOT EXISTS，旧库增量补建
    # used_nonces / event_dependencies，旧数据保留）
    db = Database(os.environ.get("DATABASE_PATH", "events.db"))
    # WEBHOOK_SECRETS_JSON 配置非法时快速失败，避免以“全部 401”的状态静默运行
    app.state.authenticator = WebhookAuthenticator.from_env()
    app.state.store = EventStore(db)
    yield
    db.close()


app = FastAPI(title="Webhook Inbox", version="1.2.0", lifespan=lifespan)


def get_store(request: Request) -> EventStore:
    return request.app.state.store


async def require_signature(request: Request) -> AuthenticatedRequest:
    """校验 X-Webhook-Source / Timestamp / Nonce / Signature 四个请求头。

    必须在路由内手动解析 JSON：FastAPI 对模型参数的体校验先于依赖求解，
    若声明 pydantic 模型参数，畸形体会先返回 422，绕过签名校验（且签名
    必须覆盖未经解析的原始字节）。任一条件不满足统一 401，且此时尚未
    触碰数据库，天然零写入。
    """
    source = request.headers.get("x-webhook-source", "")
    timestamp = request.headers.get("x-webhook-timestamp", "")
    nonce = request.headers.get("x-webhook-nonce", "")
    signature = request.headers.get("x-webhook-signature", "")
    body = await request.body()

    missing = not source or not timestamp or not nonce or not signature
    if missing or len(nonce) > NONCE_MAX_LENGTH:
        raise HTTPException(status_code=401, detail="unauthorized")

    authenticator: WebhookAuthenticator = request.app.state.authenticator
    try:
        authenticator.verify(source, timestamp, nonce, signature, body)
    except WebhookAuthError:
        raise HTTPException(status_code=401, detail="unauthorized") from None
    return AuthenticatedRequest(source=source, nonce=nonce, body=body)


def _parse_json_body(body: bytes, model: type[BaseModel]) -> BaseModel:
    """验签通过后再解析请求体；任何解析/校验错误仍以标准 422 返回。"""
    try:
        data = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise RequestValidationError(
            [
                {
                    "type": "json_invalid",
                    "loc": ("body",),
                    "msg": "JSON decode error",
                    "input": body[:200].decode("utf-8", errors="replace"),
                }
            ]
        )
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from None


def _dependency_detail(error: dict) -> dict:
    """存储层依赖错误（pos 下标）转对外结构；单条入箱时去掉 index。"""
    return {key: value for key, value in error.items() if key != "index"}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post(
    "/events",
    response_model=EventOut,
    status_code=201,
    # 体在路由内手动解析（鉴权必须先于体校验），这里手动把请求体模型补进 OpenAPI
    openapi_extra=_ingestion_openapi(EventIn),
)
def create_event(
    response: Response,
    auth: AuthenticatedRequest = Depends(require_signature),
    store: EventStore = Depends(get_store),
):
    """提交事件。重复提交（内容相同，含依赖集合）返回 200 与首个版本；
    内容不同返回 409；自依赖或引用不存在的事件返回 422。"""
    event = _parse_json_body(auth.body, EventIn)
    assert isinstance(event, EventIn)
    try:
        record, created = store.create_event(
            event.event_id,
            event.type,
            event.payload,
            source=auth.source,
            nonce=auth.nonce,
            depends_on=event.depends_on,
        )
    except EventConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail=f"event_id '{exc.event_id}' already exists with different content",
        )
    except DependencyError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "dependency validation failed",
                "errors": [_dependency_detail(e) for e in exc.errors],
            },
        )
    except ReplayError:
        raise HTTPException(status_code=401, detail="unauthorized") from None
    response.status_code = 201 if created else 200
    return record


@app.post(
    "/events/batch",
    response_model=EventBatchOut,
    status_code=201,
    openapi_extra=_ingestion_openapi(EventBatchIn),
)
def create_events_batch(
    response: Response,
    auth: AuthenticatedRequest = Depends(require_signature),
    store: EventStore = Depends(get_store),
):
    """批量提交事件（1~100 个），整批原子写入。

    批内同 event_id 且内容语义相同（type/payload/依赖集合均按集合语义
    归一）视为重复，映射到同一结果；同 ID 内容不同返回 422 并标出冲突
    下标。与库中记录内容冲突返回 409 及对应下标，且整批零写入。依赖
    可引用同批任意位置（前向引用合法）；自依赖、引用缺失（不在库中且
    不在同批）、批内依赖环均返回 422，给出错条目的原始下标与环路径，
    同样整批零写入。无冲突时单事务写入全部新事件，按原输入顺序返回
    记录与 created 标记；全部已存在时返回 200，否则 201。
    """
    batch = _parse_json_body(auth.body, EventBatchIn)
    assert isinstance(batch, EventBatchIn)

    # 批内按 event_id 归并：分组 + 语义级内容比对（与单条接口同一套指纹，
    # 依赖集合排序去重后参与指纹，因此声明顺序与重复项不影响比对结果）
    groups: dict[str, list[int]] = {}
    for idx, event in enumerate(batch.events):
        groups.setdefault(event.event_id, []).append(idx)

    intra_conflicts = []
    unique_items: list[tuple[str, str, Any, list[str]]] = []
    unique_pos: dict[str, int] = {}
    for event_id, indices in groups.items():
        first = batch.events[indices[0]]
        digest = content_hash(first.type, first.payload, first.depends_on)
        if any(
            content_hash(
                batch.events[i].type,
                batch.events[i].payload,
                batch.events[i].depends_on,
            )
            != digest
            for i in indices[1:]
        ):
            intra_conflicts.append({"event_id": event_id, "indices": indices})
        else:
            unique_pos[event_id] = len(unique_items)
            unique_items.append(
                (event_id, first.type, first.payload, normalize_dependencies(first.depends_on))
            )
    if intra_conflicts:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "duplicate event_id with different content in batch",
                "conflicts": intra_conflicts,
            },
        )

    try:
        results = store.create_events_batch(
            unique_items, source=auth.source, nonce=auth.nonce
        )
    except BatchConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "events already exist with different content",
                "conflicts": [
                    {"event_id": event_id, "indices": groups[event_id]}
                    for event_id in exc.event_ids
                ],
            },
        )
    except DependencyError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "dependency validation failed",
                "errors": [
                    {
                        # 存储层下标针对去重后的批次；展开回原始输入下标
                        **{
                            key: value
                            for key, value in error.items()
                            if key not in ("index", "event_id")
                        },
                        "event_id": unique_items[error["index"]][0],
                        "indices": groups[unique_items[error["index"]][0]],
                    }
                    for error in exc.errors
                ],
            },
        )
    except ReplayError:
        raise HTTPException(status_code=401, detail="unauthorized") from None

    items = []
    any_created = False
    for event in batch.events:
        record, created = results[unique_pos[event.event_id]]
        any_created = any_created or created
        items.append({**record, "created": created})
    if not any_created:
        response.status_code = 200
    return {"items": items}


@app.get("/events", response_model=EventPage)
def list_events(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    status: Literal["pending", "acked"] | None = Query(default=None),
    store: EventStore = Depends(get_store),
):
    """按时间游标分页查询事件（升序）。"""
    try:
        return store.list_events(limit=limit, cursor=cursor, status=status)
    except InvalidCursorError:
        raise HTTPException(status_code=400, detail="invalid cursor")


@app.get("/events/ready", response_model=EventPage)
def list_ready_events(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    store: EventStore = Depends(get_store),
):
    """按与 /events 相同的游标规则，列出全部依赖均已 ack 的 pending 事件。

    无依赖的 pending 事件始终就绪；任一前置依赖仍 pending 则不列出。
    前置事件确认提交后后继立即解锁（就绪集合随 ack 单调扩大）。
    """
    try:
        return store.list_ready(limit=limit, cursor=cursor)
    except InvalidCursorError:
        raise HTTPException(status_code=400, detail="invalid cursor")


@app.get("/events/{event_id}", response_model=EventOut)
def get_event(event_id: str, store: EventStore = Depends(get_store)):
    try:
        return store.get_event(event_id)
    except EventNotFoundError:
        raise HTTPException(status_code=404, detail="event not found")


@app.post("/events/{event_id}/ack", response_model=EventOut)
def ack_event(event_id: str, store: EventStore = Depends(get_store)):
    """确认单条事件（幂等）。尚有未完成依赖时返回 409 与 blockers。"""
    try:
        return store.ack_event(event_id)
    except EventNotFoundError:
        raise HTTPException(status_code=404, detail="event not found")
    except EventBlockedError as exc:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "event has pending dependencies",
                "event_id": exc.event_id,
                "blockers": exc.blockers,
            },
        )
