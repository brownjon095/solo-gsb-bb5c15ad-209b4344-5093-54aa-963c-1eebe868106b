"""来源签名（HMAC-SHA256）与重放防护的密钥管理、验签逻辑。

请求头：
  X-Webhook-Source   来源标识，对应 WEBHOOK_SECRETS_JSON 中的键
  X-Webhook-Timestamp  Unix 秒（整数），偏离服务器时间超过 300 秒即拒绝
  X-Webhook-Nonce    来源内唯一的一次性随机串（1~128 字符）
  X-Webhook-Signature HMAC-SHA256 的十六进制摘要

签名串固定为：timestamp + "\n" + nonce + "\n" + 原始请求体（字节）。
验签使用 hmac.compare_digest 做常量时间比较。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

SIGNATURE_MAX_SKEW_SECONDS = 300
NONCE_MIN_LENGTH = 1
NONCE_MAX_LENGTH = 128

# nonce 至少保留一个完整时间窗口，额外余量覆盖时钟漂移与窗口内的延迟重放
NONCE_RETENTION_SECONDS = SIGNATURE_MAX_SKEW_SECONDS * 2 + 60


class WebhookAuthError(Exception):
    """任一鉴权条件不满足（缺头、来源未知、时间戳越界、签名错误等）。"""


@dataclass(frozen=True)
class SourceKey:
    secret: bytes
    previous: bytes | None = None
    # previous 密钥的宽限期截止时刻（Unix 秒）；过期后旧签名一律拒绝
    previous_valid_until: int | None = None


def signing_payload(timestamp: str, nonce: str, body: bytes) -> bytes:
    """构造待签名内容：timestamp + 换行 + nonce + 换行 + 原始请求体。"""
    return timestamp.encode("ascii") + b"\n" + nonce.encode("utf-8") + b"\n" + body


def compute_signature(secret: bytes, timestamp: str, nonce: str, body: bytes) -> str:
    return hmac.new(
        secret, signing_payload(timestamp, nonce, body), hashlib.sha256
    ).hexdigest()


def _parse_valid_until(value: Any) -> int:
    """把 previous_valid_until 解析为 Unix 秒整数。

    接受整数（Unix 秒）或字符串（ISO-8601，末尾 Z 视作 UTC，无时区的朴素
    时间按 UTC 解释）。布尔值是 int 子类但语义非法，需显式拒绝。
    """
    if isinstance(value, bool):
        raise ValueError("previous_valid_until must be an integer unix time or ISO-8601 string")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            raise ValueError(f"invalid previous_valid_until: {value!r}") from None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    raise ValueError("previous_valid_until must be an integer unix time or ISO-8601 string")


def parse_secrets_config(raw: str | None) -> dict[str, SourceKey]:
    """解析 WEBHOOK_SECRETS_JSON。

    形如：
      {"shopify": {"current": "s3cr3t",
                   "previous": "old-s3cr3t",
                   "previous_valid_until": "2026-10-01T00:00:00Z"}}
    previous / previous_valid_until 均可选，但若给了其中一个就必须同时给另一个。
    """
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"WEBHOOK_SECRETS_JSON is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not data:
        raise ValueError("WEBHOOK_SECRETS_JSON must be a non-empty JSON object")

    sources: dict[str, SourceKey] = {}
    for source, conf in data.items():
        if not isinstance(source, str) or not source:
            raise ValueError("source names must be non-empty strings")
        if not isinstance(conf, dict):
            raise ValueError(f"secret config for source {source!r} must be an object")
        current = conf.get("current")
        if not isinstance(current, str) or not current:
            raise ValueError(f"source {source!r} requires a non-empty 'current' secret")

        previous = conf.get("previous")
        valid_until = conf.get("previous_valid_until")
        if previous is not None and (not isinstance(previous, str) or not previous):
            raise ValueError(f"'previous' for source {source!r} must be a non-empty string")
        if (previous is None) != (valid_until is None):
            raise ValueError(
                f"source {source!r}: 'previous' and 'previous_valid_until' must be "
                "provided together during key rotation"
            )
        parsed_until = _parse_valid_until(valid_until) if valid_until is not None else None
        sources[source] = SourceKey(
            secret=current.encode("utf-8"),
            previous=previous.encode("utf-8") if previous is not None else None,
            previous_valid_until=parsed_until,
        )
    return sources


class WebhookAuthenticator:
    def __init__(self, sources: dict[str, SourceKey]) -> None:
        self._sources = sources

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "WebhookAuthenticator":
        env = env if env is not None else os.environ
        return cls(parse_secrets_config(env.get("WEBHOOK_SECRETS_JSON")))

    @property
    def has_sources(self) -> bool:
        return bool(self._sources)

    def verify(
        self,
        source: str,
        timestamp: str,
        nonce: str,
        provided_signature: str,
        body: bytes,
        *,
        now: int | None = None,
    ) -> None:
        """全部通过则返回 None，否则抛 WebhookAuthError（API 层统一映射为 401）。

        所有失败分支对外表现一致（401），不向调用方泄露是哪一步失败。
        """
        current_time = now if now is not None else int(datetime.now(timezone.utc).timestamp())

        # 1) 时间戳必须是整数 Unix 秒且偏离不超过 300 秒
        try:
            ts = int(timestamp)
        except (TypeError, ValueError):
            raise WebhookAuthError("invalid timestamp")
        if abs(current_time - ts) > SIGNATURE_MAX_SKEW_SECONDS:
            raise WebhookAuthError("timestamp outside allowed window")

        # 2) nonce 长度约束（防止超长头滥用）
        if not (NONCE_MIN_LENGTH <= len(nonce) <= NONCE_MAX_LENGTH):
            raise WebhookAuthError("invalid nonce")

        # 3) 来源必须已登记
        key = self._sources.get(source)
        if key is None:
            raise WebhookAuthError("unknown source")

        # 4) 以 current 密钥常量时间验签；轮换宽限期内再尝试 previous
        candidate = _normalize_signature(provided_signature)
        expected_current = compute_signature(key.secret, timestamp, nonce, body)
        if _signature_equal(candidate, expected_current):
            return
        if (
            key.previous is not None
            and key.previous_valid_until is not None
            and current_time <= key.previous_valid_until
        ):
            expected_previous = compute_signature(key.previous, timestamp, nonce, body)
            if _signature_equal(candidate, expected_previous):
                return
        raise WebhookAuthError("signature mismatch")


_HEX_SIGNATURE = re.compile(r"^[0-9a-f]{64}$")


def _signature_equal(candidate: str, expected: str) -> bool:
    """常量时间比较；候选值不是 64 位十六进制时直接判否。

    hmac.compare_digest 要求两侧均为 ASCII，先用正则隔离畸形输入（如非
    ASCII 头值），避免 TypeError 冒泡成 500。
    """
    if not _HEX_SIGNATURE.match(candidate):
        return False
    return hmac.compare_digest(candidate, expected)


def _normalize_signature(signature: str) -> str:
    """去掉首尾空白并转小写，便于调用方传入大写/带空白的摘要。"""
    if not isinstance(signature, str):
        return ""
    return signature.strip().lower()
