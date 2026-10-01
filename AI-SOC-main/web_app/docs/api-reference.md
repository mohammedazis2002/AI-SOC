# API reference (FastAPI)

**Base URL (local Docker):** `http://localhost:8001`  
**OpenAPI / Swagger UI:** `GET /docs`  
**OpenAPI JSON:** `GET /openapi.json`

There is **no** global path prefix (e.g. `/api/v1`); routes are mounted at the application root.

---

## Authentication

### JWT bearer token

Protected routes expect:

```http
Authorization: Bearer <access_token>
```

The access token is returned by **`POST /login`**. The JWT **subject (`sub`)** is the user’s MongoDB `_id` as a string.

| Setting (env / config) | Default | Purpose |
|------------------------|---------|---------|
| `JWT_SECRET` | `change-me-in-production` | HMAC signing key — **must be changed in production** |
| `jwt_algorithm` | `HS256` | Algorithm (code constant) |
| `access_token_expire_minutes` | `1440` (24h) | Token lifetime |

---

## Public endpoints

### `GET /health`

Liveness check. **No auth.**

**Response `200`**

```json
{ "status": "ok" }
```

---

### `POST /register`

Creates a user. **No auth.**

**Request body (JSON)**

| Field | Type | Constraints |
|-------|------|-------------|
| `name` | string | 1–200 chars |
| `email` | string | Valid email (normalized to lower case) |
| `password` | string | 8–128 chars |

**Responses**

| Code | Meaning |
|------|---------|
| `200` | User created |
| `409` | `detail`: `"Email already registered"` |
| `422` | Validation error (Pydantic) |
| `500` | First-user path only: Admin role missing (should not happen after seed) |

**Response body `200` (`RegisterResponse`)**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | User `_id` (hex) |
| `email` | string | Stored email |
| `name` | string | Display name |
| `status` | string | `"active"` (first user / superadmin) or `"pending"` |
| `message` | string | Human-readable outcome |

**Behaviour**

- If **no users** exist: new user is **superadmin**, **active**, assigned **Admin** role.
- Otherwise: **`pending`**, `role_id` null, not superadmin.

---

### `POST /login`

Issues a JWT. **No auth.**

**Request body (JSON)**

| Field | Type |
|-------|------|
| `email` | string |
| `password` | string |

**Responses**

| Code | Meaning |
|------|---------|
| `200` | Success |
| `401` | `detail`: `"Invalid email or password"` |
| `403` | `detail`: `"Account is not active"` (pending/rejected) |
| `422` | Validation error |

**Response body `200` (`TokenResponse`)**

| Field | Type |
|-------|------|
| `access_token` | string (JWT) |
| `token_type` | string — always `"bearer"` |

---

### `GET /me`

Returns the authenticated user. **Requires** `Authorization: Bearer`.

**Responses**

| Code | Meaning |
|------|---------|
| `200` | `UserPublic` |
| `401` | Missing/invalid token, user not found |
| `403` | User exists but `status` ≠ `active` |

**Response body `200` (`UserPublic`)**

| Field | Type |
|-------|------|
| `id` | string |
| `name` | string |
| `email` | string |
| `status` | string — `"pending"` \| `"active"` \| `"rejected"` |
| `role_id` | string \| null — MongoDB role `_id` hex |
| `is_superadmin` | boolean |
| `created_at` | string (ISO 8601 datetime) |
| `updated_at` | string (ISO 8601 datetime) |

---

## Dashboard (`/dashboard/...`)

Requires JWT, active user, and permission **`dashboard_access`** (all default seeded roles include it).

### `GET /dashboard/summary`

Aggregates **`alerts_processed`** in the same MongoDB database as the auth app (`MONGODB_*` / `MONGO_URI`).

**Query**

| Param | Default | Range |
|-------|---------|-------|
| `days` | `14` | 1–90 |

**Response (JSON, camelCase):** counts, `alertVolumeByDay[]`, `alertsBySource[]`, `recentAlerts[]`, plus legacy KPI fields (MTTR sparklines may be empty until wired).

---

## Alerts (`/alerts/...`)

Requires JWT, active user, and **`dashboard_access`**.

### `GET /alerts`

Paginated rows from **`alerts_processed`** (list shape for the Alerts table).

| Query param | Notes |
|-------------|--------|
| `page`, `limit` | Pagination (default `page=1`, `limit=50`, max `limit=200`) |
| `search` | Regex on `alert_id`, finding title/desc, src/dst IP |
| `severity` | Repeatable: `CRITICAL`, `HIGH`, … → `severity_id` |
| `status` | Repeatable: UI status → DB `status` variants |
| `source` | Substring on `siem_source`, `src_endpoint.hostname`, `asset_meta.hostname` |
| `date_range` | `1h` \| `24h` \| `7d` \| `custom` (`custom` = no time filter) |

**Response:** `{ "alerts": [...], "total", "page", "limit" }`

### `GET /alerts/{alert_id}`

Full enriched document (summary blocks + `raw` JSON). `alert_id` is the platform ID (e.g. `SOAR-…`).

### `GET /alerts/{alert_id}/similar`

Related alerts (same source IP or `category_uid`), excluding self.

---

## Admin endpoints (`/admin/...`)

---

## mTLS certificates (proxied) (`/mtls/...`)

These routes live in the web app backend and are intended for the Settings UI.

Access is restricted to users with role **Admin** or **Engineer** (or superadmin).

### `POST /mtls/certificates/issue`

Body:

- `common_name` (string)
- `ttl` (string, optional; Vault-style, e.g. `720h`)

Proxies to mTLS service: `POST /api/v1/certificates/wazuh`

### `POST /mtls/certificates/renew`

Same body, proxies to: `POST /api/v1/certificates/wazuh/renew`

### `POST /mtls/certificates/revoke`

Body:

- `serial_number` (string)

Proxies to: `POST /api/v1/certificates/revoke`

All routes below require:

1. Valid JWT (`Authorization: Bearer`)
2. User `status === "active"`
3. Permission **`user_management`** **or** **superadmin** (superadmin bypasses permission checks via merged permissions)

---

### `GET /admin/roles`

Lists all roles (for UI or `assign-role`).

**Response `200`:** array of `RolePublic`

| Field | Type |
|-------|------|
| `id` | string |
| `name` | string |
| `permissions` | object |

**`permissions` object**

| Field | Type |
|-------|------|
| `user_management` | boolean |
| `dashboard_access` | boolean |
| `backend_access` | boolean |

---

### `GET /admin/users/pending`

Lists users with `status === "pending"`, sorted by `created_at` ascending.

**Response `200`:** array of `UserPendingItem`

| Field | Type |
|-------|------|
| `id` | string |
| `name` | string |
| `email` | string |
| `status` | string |
| `created_at` | string (ISO 8601) |

---

### `POST /admin/users/{user_id}/approve`

Sets user `status` to **`active`**. Cannot target superadmin.

| Code | Meaning |
|------|---------|
| `200` | `UserPublic` returned |
| `400` | Invalid id / cannot modify superadmin |
| `403` | Missing permission |
| `404` | User not found |

Writes **audit** action `user_approved`.

---

### `POST /admin/users/{user_id}/reject`

Sets user `status` to **`rejected`**. Cannot target superadmin.

Same error pattern as approve. Audit action: `user_rejected`.

---

### `POST /admin/users/{user_id}/assign-role`

**Request body (JSON)**

| Field | Type |
|-------|------|
| `role_id` | string — must be valid MongoDB ObjectId hex |

Cannot change superadmin’s role. Audit action: `role_assigned` (includes `role_id`, `role_name` in details).

| Code | Meaning |
|------|---------|
| `200` | `UserPublic` |
| `400` | Invalid user id / role id / cannot change superadmin |
| `403` | Missing permission |
| `404` | User or role not found |

---

## Common error shape (FastAPI)

Validation errors often return:

```json
{
  "detail": [
    {
      "type": "...",
      "loc": ["body", "field"],
      "msg": "...",
      "input": ...
    }
  ]
}
```

Simple errors use:

```json
{ "detail": "string message" }
```

---

## RBAC (permission keys)

Used in code and stored on each **role** document:

| Key | Typical use |
|-----|----------------|
| `user_management` | Approve/reject users, assign roles, list pending |
| `dashboard_access` | Reserved for future UI/API gates |
| `backend_access` | Reserved for future UI/API gates |

**Superadmin** users are treated as having **all** permissions `true` without reading the role document.
