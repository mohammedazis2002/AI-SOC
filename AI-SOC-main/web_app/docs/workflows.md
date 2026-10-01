# Workflows

## 1. Cold start (empty database)

1. **MongoDB** starts (via Docker Compose or your own instance).
2. **Backend** starts. On **lifespan**:
   - Connects with `MONGO_URI` / `MONGO_DB_NAME`.
   - Runs **`seed_roles_if_empty`**: inserts `Admin`, `L1`–`L3`, `Engineer` with permission flags if the `roles` collection is empty. On startup, any legacy **`L4`** role is removed and former L4 users are reassigned to **`L3`**.
   - Creates a **unique index** on `users.email`.
3. **No users exist** until someone registers.

## 2. Superadmin bootstrap (first registration)

1. A user submits **`POST /register`** with `name`, `email`, `password`.
2. If the backend finds **zero** users in `users`:
   - That user becomes **`is_superadmin: true`**, **`status: active`**, and is assigned the **Admin** role (`role_id` → Admin document).
   - They can **log in immediately** (no approval).
3. **Subsequent** registrations use the normal pending flow (below).

## 3. Normal registration (after first user)

1. **`POST /register`** creates a user with:
   - `status: "pending"`
   - `role_id: null`
   - `is_superadmin: false`
2. They **cannot** log in until an admin approves them (`status` must be `active` for `POST /login`).

## 4. Admin approval / rejection

Requires a caller with **`user_management`** permission (from the Admin role or superadmin override).

1. **`GET /admin/users/pending`** — list pending users.
2. **`POST /admin/users/{user_id}/approve`** — sets `status` to `active`.
3. **`POST /admin/users/{user_id}/reject`** — sets `status` to `rejected` (cannot target superadmin).

Audit entries are written for approve/reject (see [Data model](data-model.md)).

## 5. Role assignment

1. **`GET /admin/roles`** — list roles and IDs (for `assign-role`).
2. **`POST /admin/users/{user_id}/assign-role`** with `{ "role_id": "<ObjectId string>" }`.
3. Superadmin users **cannot** have their role changed via this endpoint.

## 6. Login and JWT

1. **`POST /login`** with email + password.
2. If credentials match and `status === "active"`, response includes **`access_token`** (JWT).
3. Client stores the token (frontend: Zustand persist + `localStorage` key `cybolt-auth`).
4. **`GET /me`** with header `Authorization: Bearer <token>` returns the current user profile.

**Rejected or pending** users receive **403** on login (inactive).

## 7. Frontend (browser) flow

1. User opens the SPA (`/`). Dashboard and other pages may use **mock data** without logging in.
2. **Sign in** (`/login`): credentials → `POST /login` → token saved → `GET /me` (via `loginWithToken`) → user shown in top bar.
3. **Register** (`/register`): `POST /register` → toast with backend message; first user is superadmin; others await approval.
4. **Auth bootstrap** (`AuthBootstrap` component): after Zustand rehydrates from storage, **`refreshSession()`** calls `GET /me` if a token exists; invalid/expired token clears auth state.
5. **Sign out**: clears token and user in the store.

## 8. Permission checks (backend)

- **Not** hardcoded by role name strings in route logic.
- **`get_user_permissions`** loads the user’s role document and merges `permissions.*` booleans.
- **Superadmin** is treated as having **all** permissions true.
- **`require_permission("user_management")`** (and similar) guards admin routes.

See [API reference](api-reference.md) for exact endpoints.
