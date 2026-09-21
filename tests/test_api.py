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
