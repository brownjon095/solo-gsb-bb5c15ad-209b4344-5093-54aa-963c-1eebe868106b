import hashlib
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.auth import (
    SIGNATURE_MAX_SKEW_SECONDS,
    WebhookAuthError,
    WebhookAuthenticator,
    compute_signature,
    parse_secrets_config,
    signing_payload,
)
from app.db import Database
from app.main import app
from app.store import (
    BatchConflictError,
    DependencyError,
    EventBlockedError,
    EventConflictError,
    EventNotFoundError,
    EventStore,
    ReplayError,
)

SOURCE = "demo"
SECRET = b"test-secret"
SECRETS_JSON = json.dumps({SOURCE: {"current": SECRET.decode()}})


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("WEBHOOK_SECRETS_JSON", SECRETS_JSON)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def store(tmp_path):
    s = EventStore(Database(str(tmp_path / "store.db")))
    yield s
    s.db.close()


def make_event(i: int) -> dict:
    return {"event_id": f"evt-{i:04d}", "type": "user.created", "payload": {"n": i}}


def sign(body: bytes, *, secret=SECRET, ts=None, nonce=None) -> dict:
    """构造四个签名头；默认使用当前时间与随机 nonce。"""
    ts = str(int(time.time())) if ts is None else str(ts)
    nonce = f"nonce-{time.time_ns()}" if nonce is None else nonce
    signature = compute_signature(secret, ts, nonce, body)
    return {
        "X-Webhook-Source": SOURCE,
        "X-Webhook-Timestamp": ts,
        "X-Webhook-Nonce": nonce,
        "X-Webhook-Signature": signature,
    }


def headers(**overrides) -> dict:
    """允许逐头篡改（如 source/ts/nonce/signature）。先对给定 body 正确签名再覆盖。"""
    body = overrides.pop("body")
    secret = overrides.pop("secret", SECRET)
    ts = overrides.pop("ts", None)
    nonce = overrides.pop("nonce", None)
    h = sign(body, secret=secret, ts=ts, nonce=nonce)
    h.update(overrides)
    return h


def post_event(client, event: dict, **sign_kwargs):
    body = json.dumps(event).encode()
    h = sign(body, **sign_kwargs)
    return client.post("/events", content=body, headers=h)


def post_batch(client, events: list[dict], **sign_kwargs):
    body = json.dumps({"events": events}).encode()
    h = sign(body, **sign_kwargs)
    return client.post("/events/batch", content=body, headers=h)


# ---------- API 层：基本功能 ----------


def test_create_event_returns_201(client):
    r = post_event(client, make_event(1))
    assert r.status_code == 201
    body = r.json()
    assert body["event_id"] == "evt-0001"
    assert body["type"] == "user.created"
    assert body["payload"] == {"n": 1}
    assert body["status"] == "pending"
    assert body["acked_at"] is None
    assert body["created_at"]


def test_duplicate_same_content_returns_consistent_result(client):
    first = post_event(client, make_event(1))
    dup = post_event(client, make_event(1))
    assert first.status_code == 201
    assert dup.status_code == 200
    assert dup.json() == first.json()  # 返回与首个版本一致的结果


def test_duplicate_is_semantic_not_textual(client):
    post_event(client, {"event_id": "e1", "type": "t", "payload": {"a": 1, "b": 2}})
    r = post_event(client, {"event_id": "e1", "type": "t", "payload": {"b": 2, "a": 1}})
    assert r.status_code == 200  # 键序不同但语义相同，不算冲突


def test_same_id_different_content_returns_409(client):
    post_event(client, make_event(1))
    r = post_event(
        client, {"event_id": "evt-0001", "type": "user.created", "payload": {"n": 999}}
    )
    assert r.status_code == 409
    r2 = post_event(
        client, {"event_id": "evt-0001", "type": "other.type", "payload": {"n": 1}}
    )
    assert r2.status_code == 409
    # 冲突写入不会覆盖首个版本
    assert client.get("/events/evt-0001").json()["payload"] == {"n": 1}


def test_validation_error(client):
    body = json.dumps({"event_id": "x"}).encode()
    assert client.post("/events", content=body, headers=sign(body)).status_code == 422
    body = json.dumps({"event_id": "", "type": "t", "payload": {}}).encode()
    assert client.post("/events", content=body, headers=sign(body)).status_code == 422


def test_get_single_event(client):
    post_event(client, make_event(1))
    r = client.get("/events/evt-0001")
    assert r.status_code == 200
    assert r.json()["event_id"] == "evt-0001"
    assert client.get("/events/nope").status_code == 404


def test_pagination_walks_all_events_in_order(client):
    for i in range(25):
        post_event(client, make_event(i))

    seen, cursor, pages = [], None, 0
    while True:
        params = {"limit": 10}
        if cursor:
            params["cursor"] = cursor
        r = client.get("/events", params=params)
        assert r.status_code == 200
        body = r.json()
        seen.extend(item["event_id"] for item in body["items"])
        cursor = body["next_cursor"]
        pages += 1
        if not body["has_more"]:
            break

    assert pages == 3
    assert len(seen) == 25
    assert len(set(seen)) == 25  # 无重复
    assert seen == sorted(seen)  # 按 event_id 字典序（此处与时间序一致）
    assert cursor is None


def test_pagination_invalid_cursor(client):
    assert client.get("/events", params={"cursor": "!!!bad!!!"}).status_code == 400


def test_status_filter(client):
    for i in range(5):
        post_event(client, make_event(i))
    client.post("/events/evt-0001/ack")
    client.post("/events/evt-0003/ack")

    pending = client.get("/events", params={"status": "pending"}).json()
    acked = client.get("/events", params={"status": "acked"}).json()
    assert len(pending["items"]) == 3
    assert len(acked["items"]) == 2
    assert {i["event_id"] for i in acked["items"]} == {"evt-0001", "evt-0003"}


def test_ack_event(client):
    post_event(client, make_event(1))
    r = client.post("/events/evt-0001/ack")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "acked"
    assert body["acked_at"]

    again = client.post("/events/evt-0001/ack")  # 幂等
    assert again.status_code == 200
    assert again.json()["status"] == "acked"

    assert client.get("/events/evt-0001").json()["status"] == "acked"


def test_ack_not_found(client):
    assert client.post("/events/nope/ack").status_code == 404


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


# ---------- 批量接口 ----------


def test_batch_create_all_new(client):
    events = [make_event(i) for i in range(3)]
    r = post_batch(client, events)
    assert r.status_code == 201
    items = r.json()["items"]
    assert [it["event_id"] for it in items] == [e["event_id"] for e in events]  # 原输入顺序
    assert all(it["created"] for it in items)
    assert all(it["status"] == "pending" for it in items)
    for e in events:  # 全部落库
        assert client.get(f"/events/{e['event_id']}").status_code == 200


def test_batch_intra_duplicates_map_to_same_result(client):
    events = [
        {"event_id": "e1", "type": "t", "payload": {"a": 1, "b": 2}},
        {"event_id": "e2", "type": "t", "payload": {"x": 1}},
        {"event_id": "e1", "type": "t", "payload": {"b": 2, "a": 1}},  # 键序不同，语义相同
    ]
    r = post_batch(client, events)
    assert r.status_code == 201
    items = r.json()["items"]
    assert items[0] == items[2]  # 重复项映射到同一结果（含 created 标记）
    assert items[0]["created"] is True
    assert len(client.get("/events").json()["items"]) == 2  # 只落库两条


def test_batch_intra_conflict_returns_422_and_zero_writes(client):
    events = [
        {"event_id": "e1", "type": "t", "payload": {"v": 1}},
        {"event_id": "e2", "type": "t", "payload": {"v": 2}},
        {"event_id": "e1", "type": "t", "payload": {"v": 999}},
    ]
    r = post_batch(client, events)
    assert r.status_code == 422
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [0, 2]}]
    assert client.get("/events").json()["items"] == []  # 整批零写入


def test_batch_db_conflict_returns_409_and_zero_writes(client):
    post_event(client, {"event_id": "e1", "type": "t", "payload": {"v": 1}})
    events = [
        {"event_id": "e2", "type": "t", "payload": {"v": 2}},
        {"event_id": "e1", "type": "t", "payload": {"v": 999}},  # 与库中首版冲突
    ]
    r = post_batch(client, events)
    assert r.status_code == 409
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [1]}]
    assert client.get("/events/e2").status_code == 404  # 整批零写入
    assert client.get("/events/e1").json()["payload"] == {"v": 1}  # 首版未被覆盖


def test_batch_db_conflict_reports_all_indices_of_duplicates(client):
    post_event(client, {"event_id": "e1", "type": "t", "payload": {"v": 1}})
    dup = {"event_id": "e1", "type": "t", "payload": {"v": 2}}
    r = post_batch(client, [dup, make_event(5), dup])
    assert r.status_code == 409
    assert r.json()["detail"]["conflicts"] == [{"event_id": "e1", "indices": [0, 2]}]
    assert client.get("/events/evt-0005").status_code == 404


def test_batch_existing_same_content_marked_not_created(client):
    first = post_event(client, make_event(1)).json()
    r = post_batch(client, [make_event(1), make_event(2)])
    assert r.status_code == 201  # 含有新事件
    items = r.json()["items"]
    assert items[0]["created"] is False
    assert items[0]["created_at"] == first["created_at"]  # 返回库中首个版本
    assert items[1]["created"] is True


def test_batch_all_duplicates_returns_200(client):
    post_event(client, make_event(1))
    r = post_batch(client, [make_event(1), make_event(1)])
    assert r.status_code == 200
    assert all(not it["created"] for it in r.json()["items"])


def test_batch_returns_current_state_for_existing(client):
    post_event(client, make_event(1))
    client.post("/events/evt-0001/ack")
    r = post_batch(client, [make_event(1)])
    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["created"] is False
    assert item["status"] == "acked"  # 返回库中当前状态，不回退


def test_batch_size_limits(client):
    body = json.dumps({"events": []}).encode()
    assert client.post("/events/batch", content=body, headers=sign(body)).status_code == 422
    body = json.dumps({"events": [make_event(i) for i in range(101)]}).encode()
    assert client.post("/events/batch", content=body, headers=sign(body)).status_code == 422
    assert post_batch(client, [make_event(i) for i in range(100)]).status_code == 201


def test_batch_validation_error(client):
    body = json.dumps({}).encode()
    assert client.post("/events/batch", content=body, headers=sign(body)).status_code == 422
    body = json.dumps({"events": [{"event_id": "x"}]}).encode()
    assert client.post("/events/batch", content=body, headers=sign(body)).status_code == 422


# ---------- API 层：签名与重放防护 ----------


def test_missing_headers_all_rejected_401(client):
    body = json.dumps(make_event(1)).encode()
    assert client.post("/events", content=body).status_code == 401
    # 逐个头缺失均为 401
    full = sign(body)
    for name in (
        "X-Webhook-Source",
        "X-Webhook-Timestamp",
        "X-Webhook-Nonce",
        "X-Webhook-Signature",
    ):
        h = {k: v for k, v in full.items() if k != name}
        assert client.post("/events", content=body, headers=h).status_code == 401


def test_batch_missing_headers_rejected_401(client):
    body = json.dumps({"events": [make_event(1)]}).encode()
    assert client.post("/events/batch", content=body).status_code == 401


def test_unknown_source_401(client):
    body = json.dumps(make_event(1)).encode()
    h = headers(body=body, **{"X-Webhook-Source": "attacker"})
    assert client.post("/events", content=body, headers=h).status_code == 401
    assert client.get("/events").json()["items"] == []  # 零写入


def test_bad_signature_401(client):
    body = json.dumps(make_event(1)).encode()
    h = headers(body=body, **{"X-Webhook-Signature": "00" * 32})
    assert client.post("/events", content=body, headers=h).status_code == 401
    # 非十六进制 / 长度不对同样 401，而不是 500
    h = headers(body=body, **{"X-Webhook-Signature": "not-a-signature"})
    assert client.post("/events", content=body, headers=h).status_code == 401


def test_signature_must_cover_exact_raw_body(client):
    body = json.dumps(make_event(1)).encode()
    # 签名与实际发送体不一致（中途被篡改）→ 401
    h = sign(b'{"event_id":"other"}')
    assert client.post("/events", content=body, headers=h).status_code == 401
    assert client.get("/events").json()["items"] == []


def test_signature_accepts_uppercase_and_padding(client):
    body = json.dumps(make_event(1)).encode()
    ts = str(int(time.time()))
    nonce = "upper-case-nonce"
    digest = compute_signature(SECRET, ts, nonce, body).upper()
    h = {
        "X-Webhook-Source": SOURCE,
        "X-Webhook-Timestamp": ts,
        "X-Webhook-Nonce": nonce,
        "X-Webhook-Signature": f"  {digest}  ",
    }
    assert client.post("/events", content=body, headers=h).status_code == 201


def test_timestamp_skew_beyond_window_401(client):
    body = json.dumps(make_event(1)).encode()
    future = int(time.time()) + SIGNATURE_MAX_SKEW_SECONDS + 1
    past = int(time.time()) - SIGNATURE_MAX_SKEW_SECONDS - 1
    assert client.post(
        "/events", content=body, headers=sign(body, ts=future)
    ).status_code == 401
    assert client.post(
        "/events", content=body, headers=sign(body, ts=past)
    ).status_code == 401


def test_timestamp_boundary_and_non_integer(client):
    body = json.dumps(make_event(1)).encode()
    # 恰好 300 秒仍在窗口内
    ts = int(time.time()) + SIGNATURE_MAX_SKEW_SECONDS
    assert client.post(
        "/events", content=body, headers=sign(body, ts=ts)
    ).status_code == 201
    # 非整数时间戳 401，且优先于畸形 JSON 的 422
    h = headers(body=b"{bad", **{"X-Webhook-Timestamp": "not-a-number"})
    assert client.post("/events", content=b"{bad", headers=h).status_code == 401


def test_auth_401_takes_precedence_over_malformed_body_422(client):
    # 无签名头 + 畸形 JSON：必须是 401（不能让解析错误绕过验签）
    assert client.post("/events", content=b"{not json").status_code == 401
    # 签名正确覆盖畸形体时才走到解析阶段 → 422
    body = b"{not json"
    assert client.post(
        "/events", content=body, headers=sign(body)
    ).status_code == 422


def test_nonce_too_long_401(client):
    body = json.dumps(make_event(1)).encode()
    assert client.post(
        "/events", content=body, headers=sign(body, nonce="x" * 129)
    ).status_code == 401


def test_single_replay_returns_401_and_zero_write(client):
    body = json.dumps(make_event(1)).encode()
    h = sign(body, nonce="replay-once")
    assert client.post("/events", content=body, headers=h).status_code == 201
    # 原样重放：401，且不产生重复事件
    replay = client.post("/events", content=body, headers=h)
    assert replay.status_code == 401
    items = client.get("/events").json()["items"]
    assert len(items) == 1


def test_single_replay_with_tampered_body_still_401(client):
    body = json.dumps(make_event(1)).encode()
    h = sign(body, nonce="replay-tamper")
    assert client.post("/events", content=body, headers=h).status_code == 201
    # 用同一 nonce 重放，即便请求体被改写且重签（合法密钥），也一律 401
    other = json.dumps(make_event(2)).encode()
    tampered = sign(other, nonce="replay-tamper")
    r = client.post("/events", content=other, headers=tampered)
    assert r.status_code == 401
    assert client.get("/events/evt-0002").status_code == 404


def test_batch_replay_returns_401_and_zero_write(client):
    events = [make_event(10), make_event(11)]
    body = json.dumps({"events": events}).encode()
    h = sign(body, nonce="batch-replay")
    assert client.post("/events/batch", content=body, headers=h).status_code == 201

    other_body = json.dumps({"events": [make_event(12)]}).encode()
    h2 = sign(other_body, nonce="batch-replay")
    r = client.post("/events/batch", content=other_body, headers=h2)
    assert r.status_code == 401  # 同来源 nonce 已用
    assert client.get("/events/evt-0012").status_code == 404  # 零写入
    assert {i["event_id"] for i in client.get("/events").json()["items"]} == {
        "evt-0010",
        "evt-0011",
    }


def test_nonce_scoped_per_source(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "two.db"))
    monkeypatch.setenv(
        "WEBHOOK_SECRETS_JSON",
        json.dumps({"a": {"current": "secret-a"}, "b": {"current": "secret-b"}}),
    )
    with TestClient(app) as c:
        body_a = json.dumps({"event_id": "ea", "type": "t", "payload": {}}).encode()
        body_b = json.dumps({"event_id": "eb", "type": "t", "payload": {}}).encode()
        # 不同来源使用相同 nonce 字符串互不影响
        ts = str(int(time.time()))
        ha = {
            "X-Webhook-Source": "a",
            "X-Webhook-Timestamp": ts,
            "X-Webhook-Nonce": "shared-nonce",
            "X-Webhook-Signature": compute_signature(b"secret-a", ts, "shared-nonce", body_a),
        }
        hb = {
            "X-Webhook-Source": "b",
            "X-Webhook-Timestamp": ts,
            "X-Webhook-Nonce": "shared-nonce",
            "X-Webhook-Signature": compute_signature(b"secret-b", ts, "shared-nonce", body_b),
        }
        assert c.post("/events", content=body_a, headers=ha).status_code == 201
        assert c.post("/events", content=body_b, headers=hb).status_code == 201


def test_nonce_not_consumed_on_conflict_and_is_reusable(client):
    # 409 时事务回滚，nonce 不登记；客户端修正内容后可用同一 nonce 重试
    post_event(client, {"event_id": "e1", "type": "t", "payload": {"v": 1}})
    body = json.dumps({"event_id": "e1", "type": "t", "payload": {"v": 2}}).encode()
    r = client.post("/events", content=body, headers=sign(body, nonce="n-retry"))
    assert r.status_code == 409
    body2 = json.dumps({"event_id": "e2", "type": "t", "payload": {"v": 3}}).encode()
    r2 = client.post("/events", content=body2, headers=sign(body2, nonce="n-retry"))
    assert r2.status_code == 201


# ---------- 密钥轮换 ----------


def _rotation_client(tmp_path, monkeypatch, valid_until: int):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "rot.db"))
    monkeypatch.setenv(
        "WEBHOOK_SECRETS_JSON",
        json.dumps(
            {
                SOURCE: {
                    "current": "new-secret",
                    "previous": "old-secret",
                    "previous_valid_until": valid_until,
                }
            }
        ),
    )
    return TestClient(app)


def test_previous_key_accepted_within_grace(tmp_path, monkeypatch):
    with _rotation_client(tmp_path, monkeypatch, int(time.time()) + 3600) as c:
        body = json.dumps(make_event(1)).encode()
        # 旧密钥签名在宽限期内被接受
        assert c.post(
            "/events", content=body, headers=sign(body, secret=b"old-secret")
        ).status_code == 201
        # 当前密钥照常工作
        assert post_event(client=c, event=make_event(2), secret=b"new-secret").status_code == 201
        # 旧密钥 + 已用 nonce 仍然是重放 401（旧密钥不绕过防重放）
        body3 = json.dumps(make_event(3)).encode()
        h = sign(body3, secret=b"old-secret", nonce="old-nonce")
        assert c.post("/events", content=body3, headers=h).status_code == 201
        assert c.post("/events", content=body3, headers=h).status_code == 401


def test_previous_key_rejected_after_grace(tmp_path, monkeypatch):
    with _rotation_client(tmp_path, monkeypatch, int(time.time()) - 1) as c:
        body = json.dumps(make_event(1)).encode()
        assert c.post(
            "/events", content=body, headers=sign(body, secret=b"old-secret")
        ).status_code == 401
        assert c.post(
            "/events", content=body, headers=sign(body, secret=b"new-secret")
        ).status_code == 201


def test_invalid_secrets_config_fails_fast_at_startup(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "bad.db"))
    monkeypatch.setenv("WEBHOOK_SECRETS_JSON", "{not-json")
    with pytest.raises(ValueError):
        with TestClient(app):
            pass


def test_previous_requires_valid_until(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "bad2.db"))
    monkeypatch.setenv(
        "WEBHOOK_SECRETS_JSON", json.dumps({SOURCE: {"current": "a", "previous": "b"}})
    )
    with pytest.raises(ValueError):
        with TestClient(app):
            pass


def test_empty_config_rejects_everything(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "empty.db"))
    monkeypatch.delenv("WEBHOOK_SECRETS_JSON", raising=False)
    with TestClient(app) as c:
        body = json.dumps(make_event(1)).encode()
        assert c.post("/events", content=body, headers=sign(body)).status_code == 401


# ---------- 认证器单元测试 ----------


def test_signing_payload_is_exact_concatenation():
    assert signing_payload("123", "n-1", b'{"a":1}') == b'123\nn-1\n{"a":1}'


def test_authenticator_verify_cases():
    auth = WebhookAuthenticator(parse_secrets_config(SECRETS_JSON))
    body = b"{}"
    ts = "1000"
    now = 1100  # 偏移 100 秒

    # 正常通过
    auth.verify(SOURCE, ts, "n1", compute_signature(SECRET, ts, "n1", body), body, now=now)

    # 窗口边界：恰好 300 秒通过，301 秒拒绝
    auth.verify(SOURCE, "800", "n2", compute_signature(SECRET, "800", "n2", body), body, now=now)
    with pytest.raises(WebhookAuthError):
        auth.verify(SOURCE, "699", "n3", compute_signature(SECRET, "699", "n3", body), body, now=now)

    # 未知来源 / 错误签名 / 畸形签名 / 时间戳非整数 / nonce 超长
    with pytest.raises(WebhookAuthError):
        auth.verify("ghost", ts, "n4", compute_signature(SECRET, ts, "n4", body), body, now=now)
    with pytest.raises(WebhookAuthError):
        auth.verify(SOURCE, ts, "n5", "0" * 64, body, now=now)
    with pytest.raises(WebhookAuthError):
        auth.verify(SOURCE, ts, "n6", "zzzz", body, now=now)
    with pytest.raises(WebhookAuthError):
        auth.verify(SOURCE, "soon", "n7", "0" * 64, body, now=now)
    with pytest.raises(WebhookAuthError):
        auth.verify(SOURCE, ts, "x" * 129, "0" * 64, body, now=now)

    # 大写与首尾空白可接受
    auth.verify(
        SOURCE,
        ts,
        "n8",
        " " + compute_signature(SECRET, ts, "n8", body).upper() + " ",
        body,
        now=now,
    )


def test_authenticator_previous_key_grace_logic():
    sources = parse_secrets_config(
        json.dumps(
            {
                SOURCE: {
                    "current": "new",
                    "previous": "old",
                    "previous_valid_until": 1000,
                }
            }
        )
    )
    auth = WebhookAuthenticator(sources)
    body, ts = b"{}", "999"

    # now <= valid_until：旧密钥通过
    auth.verify(SOURCE, ts, "n1", compute_signature(b"old", ts, "n1", body), body, now=1000)
    # now > valid_until：旧密钥拒绝，新密钥仍可用
    with pytest.raises(WebhookAuthError):
        auth.verify(SOURCE, ts, "n2", compute_signature(b"old", ts, "n2", body), body, now=1001)
    auth.verify(SOURCE, ts, "n3", compute_signature(b"new", ts, "n3", body), body, now=1001)


def test_parse_secrets_config_accepts_iso8601_until():
    sources = parse_secrets_config(
        json.dumps(
            {
                SOURCE: {
                    "current": "a",
                    "previous": "b",
                    "previous_valid_until": "2026-10-01T00:00:00Z",
                }
            }
        )
    )
    assert sources[SOURCE].previous == b"b"
    assert sources[SOURCE].previous_valid_until > 0


# ---------- 存储层：并发与持久化 ----------


def test_concurrent_duplicates_keep_first_version(store):
    def submit(i):
        return store.create_event(
            "evt-x", "t", {"v": "first"}, source=SOURCE, nonce=f"dup-{i}"
        )

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(64)))

    assert sum(created for _, created in results) == 1  # 只有一个请求真正写入
    first = results[0][0]
    assert all(rec == first for rec, _ in results)  # 所有结果一致（首个版本）


def test_concurrent_conflicting_content_single_winner(store):
    def submit(i):
        try:
            rec, _ = store.create_event(
                "evt-y",
                "t",
                {"v": "a" if i % 2 == 0 else "b"},
                source=SOURCE,
                nonce=f"conf-{i}",
            )
            return ("ok", json.dumps(rec["payload"], sort_keys=True))
        except EventConflictError:
            return ("conflict", None)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(64)))

    winners = {payload for status, payload in results if status == "ok"}
    assert len(winners) == 1  # 并发下只接受了一个版本
    assert any(status == "conflict" for status, _ in results)  # 另一方全部 409
    stored = store.get_event("evt-y")
    assert json.dumps(stored["payload"], sort_keys=True) == next(iter(winners))


def test_concurrent_replay_single_winner_single_api(tmp_path):
    """多连接并发用同一 (source, nonce) 投递：仅一次成功，其余重放 401、零写入。"""
    path = str(tmp_path / "replay.db")

    def submit(_):
        s = EventStore(Database(path))  # 每线程独立连接，绕过进程内锁验证 DB 级串行
        try:
            _, created = s.create_event(
                "evt-r", "t", {"v": 1}, source=SOURCE, nonce="fixed-nonce"
            )
            return ("ok", created)
        except ReplayError:
            return ("replay", None)
        finally:
            s.db.close()

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(32)))

    oks = [r for r in results if r[0] == "ok"]
    assert len(oks) == 1
    assert oks[0][1] is True


def test_concurrent_replay_single_winner_batch(tmp_path):
    path = str(tmp_path / "batch-replay.db")
    batch = [("evt-rb1", "t", {"k": 1}), ("evt-rb2", "t", {"k": 2})]

    def submit(_):
        s = EventStore(Database(path))
        try:
            res = s.create_events_batch(batch, source=SOURCE, nonce="fixed-batch-nonce")
            return ("ok", all(created for _, created in res))
        except ReplayError:
            return ("replay", None)
        finally:
            s.db.close()

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(32)))

    assert [r for r in results if r[0] == "ok"] == [("ok", True)]

    checker = EventStore(Database(path))
    assert checker.get_event("evt-rb1")["payload"] == {"k": 1}
    assert checker.get_event("evt-rb2")["payload"] == {"k": 2}
    checker.db.close()


def test_persistence_across_reopen(tmp_path):
    path = str(tmp_path / "persist.db")
    s1 = EventStore(Database(path))
    s1.create_event("evt-p", "t", {"k": 1}, source=SOURCE, nonce="p1")
    s1.ack_event("evt-p")
    s1.db.close()

    s2 = EventStore(Database(path))  # 重新打开同一文件
    rec = s2.get_event("evt-p")
    assert rec["status"] == "acked"
    assert rec["acked_at"]
    assert rec["payload"] == {"k": 1}
    # nonce 登记同样持久化：重开后重放仍被拒
    with pytest.raises(ReplayError):
        s2.create_event("evt-q", "t", {"k": 2}, source=SOURCE, nonce="p1")
    s2.db.close()


def test_legacy_database_without_nonce_table_upgrades(tmp_path):
    """兼容升级前只含 events 表的现有数据库：启动补表，旧数据保留。"""
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE events (
            event_id     TEXT PRIMARY KEY,
            type         TEXT NOT NULL,
            payload      TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            created_at   TEXT NOT NULL,
            acked_at     TEXT
        );
        CREATE INDEX idx_events_created_at ON events (created_at, event_id);
        CREATE INDEX idx_events_status ON events (status);
        INSERT INTO events VALUES ('evt-old', 't', '{"k":0}', 'deadbeef',
                                   'pending', '2026-09-01T00:00:00.000000Z', NULL);
        """
    )
    conn.commit()
    conn.close()

    db = Database(path)  # 启动迁移：IF NOT EXISTS 补建 used_nonces
    store = EventStore(db)
    assert store.get_event("evt-old")["payload"] == {"k": 0}  # 旧数据无损
    store.create_event("evt-new", "t", {"k": 1}, source=SOURCE, nonce="legacy-n1")
    with pytest.raises(ReplayError):
        store.create_event("evt-new2", "t", {"k": 2}, source=SOURCE, nonce="legacy-n1")
    db.close()


# ---------- 存储层：批量原子性 ----------


def test_store_batch_conflict_rolls_back_everything(store):
    store.create_event("evt-1", "t", {"v": 1}, source=SOURCE, nonce="b0")
    with pytest.raises(BatchConflictError) as exc_info:
        store.create_events_batch(
            [("evt-2", "t", {"v": 2}), ("evt-1", "t", {"v": 9})],
            source=SOURCE,
            nonce="b1",
        )
    assert exc_info.value.event_ids == ["evt-1"]
    with pytest.raises(EventNotFoundError):
        store.get_event("evt-2")  # 整批零写入
    assert store.get_event("evt-1")["payload"] == {"v": 1}


def test_concurrent_identical_batches_single_created(store):
    batch = [("evt-b1", "t", {"k": 1}), ("evt-b2", "t", {"k": 2})]

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(
                lambda i: store.create_events_batch(
                    batch, source=SOURCE, nonce=f"same-batch-{i}"
                ),
                range(16),
            )
        )

    for pos in range(2):
        assert sum(created for _, created in (res[pos] for res in outcomes)) == 1
    first_records = [rec for rec, _ in outcomes[0]]
    assert all([rec for rec, _ in res] == first_records for res in outcomes)  # 均为首个版本


def test_concurrent_conflicting_batches_no_partial_commit(store):
    def submit(i):
        tag = "a" if i % 2 == 0 else "b"
        try:
            res = store.create_events_batch(
                [("evt-shared", "t", {"v": tag}), (f"evt-uniq-{i}", "t", {"v": i})],
                source=SOURCE,
                nonce=f"cb-{i}",
            )
            return (tag, res)
        except BatchConflictError:
            return (tag, None)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(32)))

    winner = store.get_event("evt-shared")["payload"]["v"]
    # 与首版内容一致的批次整批成功，其余整批冲突
    assert sum(created for tag, res in results if res for _, created in [res[0]]) == 1
    for i, (tag, res) in enumerate(results):
        if tag == winner:
            assert res is not None
            assert store.get_event(f"evt-uniq-{i}")["payload"] == {"v": i}
        else:
            assert res is None
            with pytest.raises(EventNotFoundError):
                store.get_event(f"evt-uniq-{i}")  # 冲突批次零写入，无部分提交


# ---------- 依赖门禁：入箱校验 ----------


def event_with_deps(eid: str, deps: list[str] | None = None, payload=None) -> dict:
    return {
        "event_id": eid,
        "type": "t",
        "payload": {} if payload is None else payload,
        "depends_on": deps or [],
    }


def test_single_event_with_depends_on_persists_and_returns_sorted(client):
    post_event(client, make_event(1))
    post_event(client, make_event(2))
    r = post_event(
        client, event_with_deps("child", ["evt-0002", "evt-0001", "evt-0001"])
    )
    assert r.status_code == 201
    assert r.json()["depends_on"] == ["evt-0001", "evt-0002"]  # 去重 + 排序
    assert client.get("/events/child").json()["depends_on"] == ["evt-0001", "evt-0002"]


def test_single_missing_dependency_returns_422_and_zero_write(client):
    r = post_event(client, event_with_deps("lonely", ["ghost"]))
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["message"] == "dependency validation failed"
    assert detail["errors"] == [
        {"reason": "missing_dependency", "event_id": "lonely", "missing": ["ghost"]}
    ]
    assert client.get("/events/lonely").status_code == 404  # 零写入
    assert client.get("/events").json()["items"] == []


def test_single_self_dependency_returns_422(client):
    r = post_event(client, event_with_deps("self", ["self"]))
    assert r.status_code == 422
    assert r.json()["detail"]["errors"][0]["reason"] == "self_dependency"
    assert client.get("/events/self").status_code == 404


def test_too_many_unique_dependencies_returns_422(client):
    too_many = [f"d{i}" for i in range(21)]
    r = post_event(client, event_with_deps("fat", too_many))
    assert r.status_code == 422
    # 恰好 20 个、且全部已在库时可以通过
    for i in range(20):
        post_event(client, {"event_id": f"d{i}", "type": "t", "payload": {}})
    ok = post_event(client, event_with_deps("ok20", [f"d{i}" for i in range(20)]))
    assert ok.status_code == 201


def test_dependency_set_order_and_duplicates_do_not_matter(client):
    post_event(client, {"event_id": "p1", "type": "t", "payload": {}})
    post_event(client, {"event_id": "p2", "type": "t", "payload": {}})
    first = post_event(
        client, event_with_deps("k", ["p2", "p1", "p2", "p1"])
    )
    assert first.status_code == 201
    # 仅顺序/重复不同：语义相同，幂等返回 200 与首个版本
    again = post_event(client, event_with_deps("k", ["p1", "p2"]))
    assert again.status_code == 200
    assert again.json() == first.json()


def test_dependency_set_part_of_idempotent_content_comparison(client):
    post_event(client, {"event_id": "p1", "type": "t", "payload": {}})
    post_event(client, {"event_id": "p2", "type": "t", "payload": {}})
    post_event(client, event_with_deps("k", ["p1"]))
    # type/payload 相同但依赖集合不同 → 409
    r = post_event(client, event_with_deps("k", ["p1", "p2"]))
    assert r.status_code == 409
    r2 = post_event(client, event_with_deps("k", []))
    assert r2.status_code == 409


def test_batch_forward_references_any_position_accepted(client):
    events = [
        event_with_deps("c", ["b"]),   # 引用后面位置的 b
        event_with_deps("b", ["a"]),   # 引用后面位置的 a
        event_with_deps("a", []),
    ]
    r = post_batch(client, events)
    assert r.status_code == 201
    assert [it["event_id"] for it in r.json()["items"]] == ["c", "b", "a"]
    for eid in ("a", "b", "c"):
        assert client.get(f"/events/{eid}").status_code == 200


def test_batch_missing_dependency_returns_422_with_indices_and_zero_write(client):
    events = [
        event_with_deps("ok", []),
        event_with_deps("bad", ["ghost", "phantom"]),
    ]
    r = post_batch(client, events)
    assert r.status_code == 422
    errors = r.json()["detail"]["errors"]
    assert errors == [
        {
            "reason": "missing_dependency",
            "event_id": "bad",
            "missing": ["ghost", "phantom"],
            "indices": [1],
        }
    ]
    assert client.get("/events/ok").status_code == 404   # 整批零写入
    assert client.get("/events/bad").status_code == 404


def test_batch_missing_dependency_indices_expand_for_intra_duplicates(client):
    events = [
        event_with_deps("dup", ["ghost"]),
        event_with_deps("other", []),
        event_with_deps("dup", ["ghost"]),  # 与 0 同 ID 同内容，展开为 [0, 2]
    ]
    r = post_batch(client, events)
    assert r.status_code == 422
    assert r.json()["detail"]["errors"][0]["indices"] == [0, 2]
    assert client.get("/events/other").status_code == 404  # 整批零写入


def test_batch_self_dependency_returns_422(client):
    r = post_batch(client, [event_with_deps("solo", ["solo"])])
    assert r.status_code == 422
    assert r.json()["detail"]["errors"][0]["reason"] == "self_dependency"
    assert client.get("/events/solo").status_code == 404


def test_batch_cycle_returns_422_with_cycle_path_and_zero_write(client):
    events = [
        event_with_deps("p", ["q"]),
        event_with_deps("q", ["r"]),
        event_with_deps("r", ["p"]),
        event_with_deps("outside", []),
    ]
    r = post_batch(client, events)
    assert r.status_code == 422
    errors = r.json()["detail"]["errors"]
    assert len(errors) == 1
    err = errors[0]
    assert err["reason"] == "dependency_cycle"
    # 环路径首尾相接，且闭合于环上节点
    assert err["cycle"][0] == err["cycle"][-1]
    assert set(err["cycle"]) == {"p", "q", "r"}
    assert err["indices"] == [2]
    for eid in ("p", "q", "r", "outside"):
        assert client.get(f"/events/{eid}").status_code == 404  # 整批零写入


def test_batch_self_loop_reported_separately_from_cycle(client):
    events = [
        event_with_deps("p", ["q"]),
        event_with_deps("q", ["p", "q"]),  # 既在环上又自依赖
    ]
    r = post_batch(client, events)
    assert r.status_code == 422
    reasons = {e["reason"] for e in r.json()["detail"]["errors"]}
    assert reasons == {"self_dependency", "dependency_cycle"}


def test_batch_cycle_mixed_with_existing_db_events_rejected(client):
    # a 已在库中；批内 b -> c -> b 成环（与 a 无关），仍须拒绝整批
    post_event(client, event_with_deps("a", []))
    r = post_batch(
        client,
        [event_with_deps("b", ["c", "a"]), event_with_deps("c", ["b"])],
    )
    assert r.status_code == 422
    assert r.json()["detail"]["errors"][0]["reason"] == "dependency_cycle"
    assert client.get("/events/b").status_code == 404
    assert client.get("/events/c").status_code == 404


def test_batch_intra_duplicate_with_different_dependencies_is_422(client):
    events = [
        event_with_deps("dup", []),
        event_with_deps("other", []),
        event_with_deps("dup", ["other"]),  # 同 event_id，依赖集合不同
    ]
    r = post_batch(client, events)
    assert r.status_code == 422
    assert r.json()["detail"]["conflicts"] == [{"event_id": "dup", "indices": [0, 2]}]
    assert client.get("/events/other").status_code == 404


def test_batch_replays_keep_dependencies_idempotent(client):
    post_event(client, event_with_deps("a", []))
    body = json.dumps({"events": [event_with_deps("b", ["a"])]}).encode()
    h = sign(body, nonce="dep-batch-idem")
    assert client.post("/events/batch", content=body, headers=h).status_code == 201
    # 同 nonce 重放：401 且状态不变
    assert client.post("/events/batch", content=body, headers=h).status_code == 401
    assert client.get("/events/b").json()["depends_on"] == ["a"]


# ---------- 依赖门禁：/events/ready 与确认解锁 ----------


def _chain(client, *ids: str) -> None:
    """构造 id1 -> id2 -> ... 的依赖链（全部在一个批次，前向引用）。"""
    events = []
    for pos, eid in enumerate(ids):
        deps = [ids[pos + 1]] if pos + 1 < len(ids) else []
        events.append(event_with_deps(eid, deps))
    assert post_batch(client, events).status_code == 201


def test_ready_lists_only_pending_events_with_all_dependencies_acked(client):
    _chain(client, "c", "b", "a")  # c 依赖 b，b 依赖 a
    post_event(client, make_event(99))  # 无依赖事件，天然就绪
    ready = client.get("/events/ready").json()["items"]
    assert {e["event_id"] for e in ready} == {"a", "evt-0099"}

    client.post("/events/a/ack")
    ready = client.get("/events/ready").json()["items"]
    assert {e["event_id"] for e in ready} == {"b", "evt-0099"}  # c 仍被 b 阻塞

    client.post("/events/b/ack")
    ready = client.get("/events/ready").json()["items"]
    assert {e["event_id"] for e in ready} == {"c", "evt-0099"}

    client.post("/events/c/ack")
    ready = client.get("/events/ready").json()["items"]
    assert {e["event_id"] for e in ready} == {"evt-0099"}  # acked 事件不再出现


def test_ack_blocked_returns_409_with_blockers(client):
    _chain(client, "c", "b", "a")
    r = client.post("/events/c/ack")
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail == {
        "message": "event has pending dependencies",
        "event_id": "c",
        "blockers": ["b"],
    }
    assert client.get("/events/c").json()["status"] == "pending"  # 未被确认

    client.post("/events/a/ack")
    assert client.post("/events/c/ack").status_code == 409  # b 仍 pending
    client.post("/events/b/ack")
    assert client.post("/events/c/ack").status_code == 200  # 前置齐备，立即解锁


def test_ack_blockers_lists_all_pending_dependencies_sorted(client):
    post_event(client, event_with_deps("p1", []))
    post_event(client, event_with_deps("p2", []))
    post_event(client, event_with_deps("child", ["p2", "p1"]))
    r = client.post("/events/child/ack")
    assert r.status_code == 409
    assert r.json()["detail"]["blockers"] == ["p1", "p2"]
    client.post("/events/p1/ack")
    r = client.post("/events/child/ack")
    assert r.status_code == 409
    assert r.json()["detail"]["blockers"] == ["p2"]  # 已 ack 的不再阻塞


def test_ack_is_still_idempotent_after_success(client):
    _chain(client, "b", "a")
    client.post("/events/a/ack")
    assert client.post("/events/b/ack").status_code == 200
    again = client.post("/events/b/ack")  # 已 ack：幂等返回，不再检查门禁
    assert again.status_code == 200
    assert again.json()["status"] == "acked"


def test_ack_blocked_on_acked_event_with_pending_successor(client):
    # 依赖已 ack 后事件被确认；之后即便语义上“前置状态”不动，重复确认仍 200
    _chain(client, "b", "a")
    client.post("/events/a/ack")
    client.post("/events/b/ack")
    assert client.post("/events/a/ack").status_code == 200  # 幂等
    assert client.post("/events/b/ack").status_code == 200


def test_ready_never_lists_events_with_pending_transitive_dependency(client):
    # 菱形依赖：d 依赖 b、c；b、c 均依赖 a。只 ack a 时 d 不就绪
    events = [
        event_with_deps("d", ["b", "c"]),
        event_with_deps("b", ["a"]),
        event_with_deps("c", ["a"]),
        event_with_deps("a", []),
    ]
    post_batch(client, events)
    client.post("/events/a/ack")
    ready = {e["event_id"] for e in client.get("/events/ready").json()["items"]}
    assert ready == {"b", "c"}
    client.post("/events/b/ack")
    ready = {e["event_id"] for e in client.get("/events/ready").json()["items"]}
    assert ready == {"c"}  # d 仍被 c 阻塞
    client.post("/events/c/ack")
    ready = {e["event_id"] for e in client.get("/events/ready").json()["items"]}
    assert ready == {"d"}  # 前置全部 ack，立即解锁


def test_ready_respects_cursor_pagination_rules(client):
    _chain(client, "b", "a")
    post_event(client, make_event(99))  # 无依赖、晚于链创建，构成第二个就绪项
    page = client.get("/events/ready", params={"limit": 1}).json()
    assert [e["event_id"] for e in page["items"]] == ["a"]
    assert page["has_more"] is True
    nxt = page["next_cursor"]
    page2 = client.get("/events/ready", params={"limit": 1, "cursor": nxt}).json()
    assert [e["event_id"] for e in page2["items"]] == ["evt-0099"]
    assert page2["has_more"] is False
    assert page2["next_cursor"] is None  # b 尚不就绪，没有更多就绪项
    client.post("/events/a/ack")
    page4 = client.get("/events/ready").json()
    assert [e["event_id"] for e in page4["items"]] == ["b", "evt-0099"]
    assert client.get("/events/ready", params={"cursor": "!!!bad!!!"}).status_code == 400


# ---------- 依赖门禁：并发确认 ----------


def test_concurrent_ack_chain_unlocks_in_order(store):
    store.create_event("a", "t", {}, source=SOURCE, nonce="ca")
    store.create_event(
        "b", "t", {}, source=SOURCE, nonce="cb", depends_on=["a"]
    )

    def ack(eid):
        try:
            return store.ack_event(eid)["status"]
        except EventBlockedError as exc:
            return f"blocked:{','.join(exc.blockers)}"

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: ack("b"), range(16)))
    assert set(outcomes) == {"blocked:a"}  # a 确认前，并发确认 b 全部 409 语义

    assert store.ack_event("a")["status"] == "acked"
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(lambda _: ack("b"), range(16)))
    assert outcomes.count("acked") == 16  # 解锁后并发确认均成功且幂等，无 500
    assert store.get_event("b")["status"] == "acked"


def test_concurrent_ack_same_event_multi_connection(tmp_path):
    """多连接并发确认同一无依赖事件：恰好一次翻转，其余幂等成功。"""
    path = str(tmp_path / "ack-race.db")
    seed = EventStore(Database(path))
    seed.create_event("evt-ack", "t", {}, source=SOURCE, nonce="seed")
    seed.db.close()

    def submit(_):
        s = EventStore(Database(path))
        try:
            rec = s.ack_event("evt-ack")
            return rec["status"]
        finally:
            s.db.close()

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, range(32)))
    assert all(r == "acked" for r in results)

    checker = EventStore(Database(path))
    assert checker.get_event("evt-ack")["status"] == "acked"
    assert checker.get_event("evt-ack")["acked_at"]
    checker.db.close()


def test_concurrent_ack_with_concurrent_parent_unlock_multi_connection(tmp_path):
    """一个线程确认前置，其余线程同时确认后继：解锁后后继必然可确认。"""
    path = str(tmp_path / "ack-unlock.db")
    seed = EventStore(Database(path))
    seed.create_event("pa", "t", {}, source=SOURCE, nonce="pa")
    seed.create_event("pb", "t", {}, source=SOURCE, nonce="pb", depends_on=["pa"])
    seed.db.close()

    def submit(spec):
        role, _ = spec
        s = EventStore(Database(path))
        try:
            if role == "parent":
                s.ack_event("pa")
                return "parent-acked"
            try:
                s.ack_event("pb")
                return "child-acked"
            except EventBlockedError:
                return "blocked"
        finally:
            s.db.close()

    work = [("child", i) for i in range(15)] + [("parent", 0)]
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(submit, work))
    assert results.count("parent-acked") == 1
    # 被阻塞的子确认可在解锁后重试成功；最终 pb 一定 acked
    final = EventStore(Database(path))
    assert final.ack_event("pb")["status"] == "acked"
    final.db.close()


# ---------- 依赖门禁：存储层与旧库迁移 ----------


def test_store_dependency_errors_are_transactional(store):
    store.create_event("a", "t", {}, source=SOURCE, nonce="d0")
    # 自依赖
    with pytest.raises(DependencyError) as exc:
        store.create_event(
            "s", "t", {}, source=SOURCE, nonce="d1", depends_on=["s"]
        )
    assert exc.value.errors[0]["reason"] == "self_dependency"
    # 缺失引用
    with pytest.raises(DependencyError) as exc:
        store.create_event(
            "m", "t", {}, source=SOURCE, nonce="d2", depends_on=["nope"]
        )
    assert exc.value.errors[0]["missing"] == ["nope"]
    with pytest.raises(EventNotFoundError):
        store.get_event("m")
    # 修正后用全新 nonce 成功；失败批次的 nonce 未被登记
    store.create_event("nope", "t", {}, source=SOURCE, nonce="d3")
    store.create_event(
        "m", "t", {}, source=SOURCE, nonce="d4", depends_on=["nope", "a"]
    )
    assert store.get_event("m")["depends_on"] == ["a", "nope"]


def test_store_batch_cycle_raises_with_path_and_rolls_back(store):
    with pytest.raises(DependencyError) as exc:
        store.create_events_batch(
            [
                ("p", "t", {}, ["q"]),
                ("q", "t", {}, ["r"]),
                ("r", "t", {}, ["p"]),
            ],
            source=SOURCE,
            nonce="cyc",
        )
    err = exc.value.errors[0]
    assert err["reason"] == "dependency_cycle"
    assert err["cycle"][0] == err["cycle"][-1]
    for eid in ("p", "q", "r"):
        with pytest.raises(EventNotFoundError):
            store.get_event(eid)


def test_store_ack_blocked_error_carries_blockers(store):
    store.create_event("a", "t", {}, source=SOURCE, nonce="k0")
    store.create_event(
        "b", "t", {}, source=SOURCE, nonce="k1", depends_on=["a"]
    )
    with pytest.raises(EventBlockedError) as exc:
        store.ack_event("b")
    assert exc.value.event_id == "b"
    assert exc.value.blockers == ["a"]
    store.ack_event("a")
    assert store.ack_event("b")["status"] == "acked"


def test_store_ready_excludes_and_unlocks(store):
    store.create_event("a", "t", {}, source=SOURCE, nonce="r0")
    store.create_event("b", "t", {}, source=SOURCE, nonce="r1", depends_on=["a"])
    page = store.list_ready(limit=50)
    assert [e["event_id"] for e in page["items"]] == ["a"]
    store.ack_event("a")
    page = store.list_ready(limit=50)
    assert [e["event_id"] for e in page["items"]] == ["b"]
    store.ack_event("b")
    assert store.list_ready(limit=50)["items"] == []


def test_legacy_database_upgrades_with_dependency_table_and_keeps_data(tmp_path):
    """旧库（events + used_nonces，无 event_dependencies）增量建表、数据保留，
    且旧事件的 content_hash 不回填也能正常做幂等比对。"""
    path = str(tmp_path / "legacy-deps.db")
    # 旧版指纹算法：sha256(type + \\n + 规范化payload)，与新算法的无依赖分支一致
    legacy_digest = hashlib.sha256(
        't\n{"k":0}'.encode("utf-8")
    ).hexdigest()
    conn = sqlite3.connect(path)
    conn.executescript(
        f"""
        CREATE TABLE events (
            event_id     TEXT PRIMARY KEY,
            type         TEXT NOT NULL,
            payload      TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            created_at   TEXT NOT NULL,
            acked_at     TEXT
        );
        CREATE INDEX idx_events_created_at ON events (created_at, event_id);
        CREATE INDEX idx_events_status ON events (status);
        INSERT INTO events VALUES ('evt-old', 't', '{{"k":0}}', '{legacy_digest}',
                                   'pending', '2026-09-01T00:00:00.000000Z', NULL);
        CREATE TABLE used_nonces (
            source TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
            PRIMARY KEY (source, nonce)
        ) WITHOUT ROWID;
        """
    )
    conn.commit()
    conn.close()

    db = Database(path)  # 启动迁移：IF NOT EXISTS 补建 event_dependencies 及索引
    store = EventStore(db)
    # 旧数据无损，且无依赖事件默认就绪
    assert store.get_event("evt-old")["payload"] == {"k": 0}
    assert store.get_event("evt-old")["depends_on"] == []
    ready = store.list_ready(limit=50)
    assert [e["event_id"] for e in ready["items"]] == ["evt-old"]

    # 旧事件可作为新事件的前置依赖；依赖功能在迁移后的库上完全可用
    store.create_event(
        "evt-new", "t", {"k": 1}, source=SOURCE, nonce="legacy-deps-1",
        depends_on=["evt-old"],
    )
    # evt-old 自身无依赖、仍就绪；evt-new 被阻塞，不出现在 ready 中
    ready = store.list_ready(limit=50)
    assert [e["event_id"] for e in ready["items"]] == ["evt-old"]
    with pytest.raises(EventBlockedError):
        store.ack_event("evt-new")
    store.ack_event("evt-old")
    ready = store.list_ready(limit=50)
    assert [e["event_id"] for e in ready["items"]] == ["evt-new"]  # 立即解锁
    assert store.ack_event("evt-new")["status"] == "acked"

    # 旧指纹（无 DEPS 段）与新算法对“无依赖内容”的计算一致：
    # 旧事件以相同内容重投仍按幂等处理而非 409
    rec, created = store.create_event(
        "evt-old", "t", {"k": 0}, source=SOURCE, nonce="legacy-deps-2"
    )
    assert created is False
    assert rec["payload"] == {"k": 0}
    db.close()
