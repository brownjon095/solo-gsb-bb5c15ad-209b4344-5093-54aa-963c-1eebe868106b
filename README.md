# Webhook Inbox

基于 FastAPI + SQLite 的 webhook 收件箱服务。接收事件、**来源签名校验与重放防护**、幂等去重、按时间游标分页查询、单条确认，数据持久化到 SQLite。

## 功能

- **来源签名 + 重放防护**（`POST /events` 与 `POST /events/batch` 均强制）
  - 每个请求必须携带 `X-Webhook-Source`、`X-Webhook-Timestamp`、`X-Webhook-Nonce`、`X-Webhook-Signature` 四个请求头
  - 签名串固定为 `timestamp + "\n" + nonce + "\n" + 原始请求体`，使用来源密钥做 **HMAC-SHA256**，十六进制输出，服务端常量时间比较
  - 时间戳偏离服务器时间超过 **300 秒**、来源未知、签名错误、nonce 为空/超长，一律 **401 且零写入**
  - **同来源 nonce 只能使用一次**：重放返回 401。nonce 登记与事件入库在**同一个 SQLite 写事务**内，并发重放只有一次成功
  - 支持密钥轮换：`current` 为现用密钥，`previous` + `previous_valid_until` 定义旧密钥的宽限期，过期后旧签名立即失效
- **POST /events** 提交事件（`event_id` / `type` / `payload`）
  - 并发重复请求只保留**首个版本**，所有重复请求返回与首次一致的结果
  - 相同 `event_id` 但内容（`type` 或 `payload`）不同 → **409 Conflict**
  - 内容比对是语义级的：JSON 键序不同但内容相同视为同一事件
- **POST /events/batch** 原子批量提交（1~100 个事件，结构同单条接口）
  - 批内同 `event_id` 内容语义相同 → 视为重复，映射到同一结果；内容不同 → **422** 并标出冲突下标
  - 与库中记录内容冲突 → **409** 并标出对应下标，**整批零写入**
  - 无冲突时**单一事务**写入全部新事件，按原输入顺序返回记录与每项 `created` 标记
- **GET /events** 按时间游标分页查询（键集分页，支持 `status` 过滤）
- **POST /events/{event_id}/ack** 单条确认（幂等，重复确认返回当前状态）
- **GET /events/{event_id}** 查询单条事件
- 事件与处理状态（`pending` / `acked`）持久化到 SQLite，**启动时自动建表**；含 `used_nonces` 防重放表，升级已有数据库时只增量补表、不动旧数据

## 快速开始（Docker，一键启动）

```bash
docker compose up --build
```

服务监听容器内 8000 端口，Compose 已映射到宿主机 **8000** 端口：

- API 地址： http://localhost:8000
- 交互式文档（Swagger UI）： http://localhost:8000/docs
- 健康检查： `curl http://localhost:8000/healthz`

SQLite 数据文件存放在命名卷 `webhook-data`（容器内 `/data/events.db`），容器重建后数据不丢失。

Compose 内置了一个开箱即用的演示来源密钥（来源名 `demo`，密钥 `dev-only-secret-change-me`），**生产环境必须覆盖**（见下文“配置”）。

不使用 Compose 也可以：

```bash
docker build -t webhook-inbox .
docker run -d -p 8000:8000 \
  -e WEBHOOK_SECRETS_JSON='{"demo":{"current":"dev-only-secret-change-me"}}' \
  -v webhook-data:/data webhook-inbox
```

## 来源签名与重放防护

### 请求头

| 请求头 | 必填 | 说明 |
| --- | --- | --- |
| `X-Webhook-Source` | 是 | 来源标识，必须是 `WEBHOOK_SECRETS_JSON` 中已登记的键，否则 401 |
| `X-Webhook-Timestamp` | 是 | 生成签名时的 Unix 秒（整数）。与服务器时间相差超过 300 秒即 401 |
| `X-Webhook-Nonce` | 是 | 一次性随机串（1~128 字符）。**同一来源内**重复使用即视为重放，返回 401 |
| `X-Webhook-Signature` | 是 | HMAC-SHA256 十六进制摘要（大小写、首尾空白不敏感） |

签名串（注意换行与原始字节）：

```
<timestamp> + "\n" + <nonce> + "\n" + <原始请求体字节>
```

使用该来源配置中的密钥计算：

```
signature = HMAC_SHA256(secret, signing_string)  # 输出十六进制
```

签名覆盖的是**未经解析的原始请求体**：中间任何字节被改动（包括 JSON 重排）都会导致验签失败。

### 配置：`WEBHOOK_SECRETS_JSON`

一个 JSON 对象，键为来源名，值为密钥配置：

```json
{
  "shopify": {
    "current": "当前强随机密钥"
  },
  "stripe": {
    "current": "新密钥",
    "previous": "上一版密钥",
    "previous_valid_until": "2026-10-01T00:00:00Z"
  }
}
```

- `current`（必填）：现用密钥。
- `previous`（可选）：轮换中的旧密钥；必须与 `previous_valid_until` **成对出现**。
- `previous_valid_until`（可选）：旧密钥宽限期截止时刻，接受 Unix 秒整数或 ISO-8601 字符串（末尾 `Z` 表示 UTC）。**仅在当前时间不晚于该时刻时**，旧密钥签名才被接受；过期后一律 401。
- 未设置该环境变量或为空对象时，所有入箱请求都会被拒绝（401）；JSON 非法或配置结构错误时服务启动失败（快速报错）。

轮换流程：先把旧密钥放到 `previous`、设置一个足够调用方切换的宽限期，再把新密钥放入 `current`；待所有调用方切换完成后，移除 `previous` / `previous_valid_until` 并重新部署。

### 签名示例（Python）

```python
import hashlib, hmac, json, time, urllib.request

source = "demo"
secret = b"dev-only-secret-change-me"

body = json.dumps(
    {"event_id": "evt-001", "type": "order.paid", "payload": {"amount": 100}},
    separators=(",", ":"),
).encode()
timestamp = str(int(time.time()))
nonce = "9f1c0a7e-3b2e-4d6a-8f90-1a2b3c4d5e6f"   # 每个请求唯一，建议 UUID
signing = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + body
signature = hmac.new(secret, signing, hashlib.sha256).hexdigest()

req = urllib.request.Request(
    "http://localhost:8000/events",
    data=body,
    method="POST",
    headers={
        "Content-Type": "application/json",
        "X-Webhook-Source": source,
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Nonce": nonce,
        "X-Webhook-Signature": signature,
    },
)
print(urllib.request.urlopen(req).status)  # 201
```

### 签名示例（curl + openssl）

```bash
BODY='{"event_id":"evt-001","type":"order.paid","payload":{"amount":100}}'
TS=$(date +%s)
NONCE=$(cat /proc/sys/kernel/random/uuid)
SIGNING=$(printf '%s\n%s\n%s' "$TS" "$NONCE" "$BODY")
SIG=$(printf '%s' "$SIGNING" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.*= //')

curl -i -X POST http://localhost:8000/events \
  -H 'Content-Type: application/json' \
  -H "X-Webhook-Source: demo" \
  -H "X-Webhook-Timestamp: $TS" \
  -H "X-Webhook-Nonce: $NONCE" \
  -H "X-Webhook-Signature: $SIG" \
  -d "$BODY"
```

> 注意：重发请求时必须重新生成 `timestamp` 与 `nonce`；原样重放上一次的四个头会被判定为重放（401）。

### 失败响应

所有鉴权失败统一返回，不区分具体原因（避免向攻击者泄露是哪一步失败）：

```json
{"detail": "unauthorized"}
```

| 情况 | 状态码 |
| --- | --- |
| 缺少任一头 / 来源未知 / 签名不匹配 / 时间戳超窗 / nonce 超长 / **同来源 nonce 已使用（重放）** | 401，零写入 |
| 签名合法但请求体不是合法 JSON 或不满足字段约束 | 422 |
| 单条 `event_id` 内容冲突 | 409 |
| 批内内容冲突 422；与库中内容冲突 409（均整批零写入，nonce 不登记，可用新 nonce 重试） | 422 / 409 |

## API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/events` | 提交事件（**需签名头**）。首次 `201`，重复（内容相同）`200`，内容冲突 `409`，鉴权失败 `401` |
| POST | `/events/batch` | 原子批量提交（1~100 个，**需签名头**）。有新事件 `201`，全部重复 `200`；批内冲突 `422`、与库冲突 `409`、重放/鉴权失败 `401`，均整批零写入 |
| GET | `/events?limit=&cursor=&status=` | 时间游标分页查询，`limit` 默认 50、最大 200 |
| GET | `/events/{event_id}` | 查询单条事件，不存在 `404` |
| POST | `/events/{event_id}/ack` | 确认事件（幂等），不存在 `404` |
| GET | `/healthz` | 健康检查 |

### 提交事件

首次返回 `201`；再次提交相同内容（**重新签名、换新 nonce**）返回 `200`，响应体与首次完全一致（均为首个版本的数据）：

```json
{
  "event_id": "evt-001",
  "type": "order.paid",
  "payload": {"amount": 100},
  "status": "pending",
  "created_at": "2026-09-20T12:00:00.000000Z",
  "acked_at": null
}
```

相同 `event_id` 不同内容返回 `409`：

```json
{"detail": "event_id 'evt-001' already exists with different content"}
```

### 批量提交事件

一次提交 1~100 个事件（结构与单条接口相同，整批共用一组签名头，签名覆盖整批 JSON），整批原子写入：要么全部落库，要么零写入。响应按**原输入顺序**返回，每项附带 `created` 标记；批内相同 `event_id` 且内容语义相同（键序无关）视为重复，映射到同一结果。任一事件为新事件时返回 `201`，全部已存在时返回 `200`。

```json
{
  "items": [
    {"event_id": "evt-101", "type": "order.paid", "payload": {"amount": 100}, "status": "pending", "created_at": "2026-09-21T03:00:00.000000Z", "acked_at": null, "created": true},
    {"event_id": "evt-102", "type": "order.paid", "payload": {"amount": 200}, "status": "pending", "created_at": "2026-09-21T03:00:00.000100Z", "acked_at": null, "created": true},
    {"event_id": "evt-101", "type": "order.paid", "payload": {"amount": 100}, "status": "pending", "created_at": "2026-09-21T03:00:00.000000Z", "acked_at": null, "created": true}
  ]
}
```

批内同一 `event_id` 内容不同 → `422`，标出冲突下标，整批零写入：

```json
{
  "detail": {
    "message": "duplicate event_id with different content in batch",
    "conflicts": [{"event_id": "evt-101", "indices": [0, 2]}]
  }
}
```

与库中已存事件内容冲突 → `409`，同样标出对应下标，整批零写入且已存首版不被覆盖：

```json
{
  "detail": {
    "message": "events already exist with different content",
    "conflicts": [{"event_id": "evt-101", "indices": [1]}]
  }
}
```

### 分页查询

```bash
# 第一页
curl "http://localhost:8000/events?limit=2"
# 用响应中的 next_cursor 取下一页
curl "http://localhost:8000/events?limit=2&cursor=<next_cursor>"
# 只看未确认的事件
curl "http://localhost:8000/events?status=pending"
```

响应：

```json
{
  "items": [ ... ],
  "next_cursor": "eyJjcmVhdGVkX2F0Ijoi...",
  "has_more": true
}
```

事件按 `(created_at, event_id)` 升序排列；`next_cursor` 为不透明游标（base64 编码的时间 + ID），`has_more=false` 时 `next_cursor` 为 `null`。非法游标返回 `400`。

### 确认事件

```bash
curl -X POST http://localhost:8000/events/evt-001/ack
```

返回 `200`，`status` 变为 `acked` 并写入 `acked_at`；重复确认仍返回 `200`（幂等）。

## 幂等、防重放与并发设计

- **签名先于解析**：入箱路由先读取原始请求体完成 HMAC 校验，再解析 JSON。这样即使请求体是畸形 JSON，鉴权失败仍返回 401（而非让 422 绕过验签），且鉴权阶段完全不触碰数据库，天然零写入。
- **nonce 登记与入库同事务**：`used_nonces (source, nonce)` 复合主键 + 事件插入在单个 `BEGIN IMMEDIATE` 事务中完成，连接级锁与 SQLite 的写串行化共同保证并发重放（包括多连接）中**只有首个请求提交成功**，其余请求事务回滚并返回 401。内容冲突（409/409 批量冲突、422 批内冲突）同样回滚，nonce 不被登记，调用方修正后可用同一 nonce 重试。
- **时间窗 + nonce 双保险**：时间戳窗口把可重放区间限制在 300 秒内；nonce 行至少保留 660 秒（2 倍窗口加余量），惰性清理，保证任何可能被接受的旧时间戳都无法重放。
- 事件写入路径在同事务内「查重 + 插入 + 回读」；SQLite（WAL 模式）串行化并发写，因此并发重复 `event_id` 只有一个真正落库，其余请求读到首个版本并原样返回。
- 内容指纹 = `SHA-256(type + 规范化JSON(payload))`（键排序、去空白），指纹不同即 `409`，已存数据不会被覆盖。批量接口在批内归并与库级比对中复用同一套指纹规则。
- 批量写入在**单一事务**内完成「nonce 登记 + 查库比对 + 全部插入 + 回读」（连接级锁 + `BEGIN IMMEDIATE`），并发批次彼此串行：任一冲突即整批回滚，不产生部分提交，也不会覆盖首个版本。
- 验签使用 `hmac.compare_digest` 常量时间比较；所有鉴权失败返回相同的 401 响应，不泄露失败环节。

## 配置

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WEBHOOK_SECRETS_JSON` | Compose 内置演示值 `{"demo":{"current":"dev-only-secret-change-me"}}`；裸机运行未设置时拒绝所有入箱请求 | 来源密钥配置（JSON）。支持 `current` 与可选的 `previous` / `previous_valid_until` 轮换宽限期 |
| `DATABASE_PATH` | 容器内 `/data/events.db`，本地运行为 `./events.db` | SQLite 文件路径，父目录自动创建，启动时自动建表/补表 |

生产环境建议通过 Compose 的环境覆盖或 `.env` 注入强随机密钥，例如：

```yaml
environment:
  WEBHOOK_SECRETS_JSON: '{"shopify":{"current":"${SHOPIFY_WEBHOOK_SECRET}"}}'
```

生成一个随机密钥：`openssl rand -hex 32`。

修改宿主机端口映射：编辑 `docker-compose.yml` 中的 `ports`，如 `"8080:8000"`（容器内始终监听 **8000**）。

## 本地开发与测试

```bash
pip install -r requirements-dev.txt
export WEBHOOK_SECRETS_JSON='{"demo":{"current":"dev-only-secret-change-me"}}'
pytest tests/ -q                 # 55 个测试：签名/重放/密钥轮换、幂等、409、分页、ack、批量原子性、并发、旧库迁移、持久化
DATABASE_PATH=./events.db uvicorn app.main:app --reload --port 8000
```

## 项目结构

```
app/
  main.py    # FastAPI 路由、签名头依赖与请求模型（验签后手动解析原始体）
  auth.py    # WEBHOOK_SECRETS_JSON 解析、HMAC-SHA256 验签、时间窗与轮换宽限
  store.py   # nonce 登记 + 幂等写入（同一写事务）、游标分页、确认（存储层）
  db.py      # SQLite 连接、WAL、自动建表（events / used_nonces）
tests/
  test_api.py
Dockerfile
docker-compose.yml
requirements.txt / requirements-dev.txt
```
