# Operations

## Docker Compose (recommended for backend + DB)

The web app API is **`web-app-backend`** in the **AI-SOC** repo root `docker-compose.yml`. It shares the platform **MongoDB** (`mongodb` service) and reads the **root** `.env`.

From the **AI-SOC** repository root:

```bash
cp .env.example .env
# Edit .env: set JWT_SECRET to a long random string in production
docker compose up --build web-app-backend
```

| Service | Image / build | Host port | Notes |
|---------|---------------|-----------|--------|
| `mongodb` | *(platform)* | `27017` | Shared with SOAR; credentials from root `.env` |
| `web-app-backend` | `web_app/backend/Dockerfile` | **8001** | `env_file: .env` at repo root; `MONGODB_HOST=mongodb` set in compose |

## Environment variables (standardized names)

| Variable | Purpose |
|----------|---------|
| `MONGODB_HOST` | Mongo host (`localhost` for local, `mongodb` in Docker network) |
| `MONGODB_PORT` | Mongo port (default `27017`) |
| `MONGODB_DATABASE` | Database name (default `soar_db`) |
| `MONGODB_USERNAME` | Mongo username |
| `MONGODB_PASSWORD` | Mongo password |
| `MONGODB_AUTH_SOURCE` | Auth source DB (default `admin`) |
| `MONGO_URI` | Optional full URI override; if present, it takes precedence |
| `JWT_SECRET` | JWT signing secret |

Example (`.env`):

```env
MONGODB_HOST=localhost
MONGODB_PORT=27017
MONGODB_DATABASE=soar_db
MONGODB_USERNAME=root
MONGODB_PASSWORD=strongpassword123
MONGODB_AUTH_SOURCE=admin
MONGO_URI=mongodb://root:strongpassword123@mongodb:27017/soar_db?authSource=admin
JWT_SECRET=your_secret
```

In Docker Compose, backend gets `MONGODB_HOST=mongodb` automatically so containers can connect correctly.

---

## Health checks

- **API:** `GET http://localhost:8001/health` → `{ "status": "ok" }`
- **MongoDB:** use `docker compose ps` / container logs; no HTTP health port exposed by default.

---

## Seed script (roles only)

Roles are also seeded **automatically** on API startup (`lifespan`). To run manually:

```bash
cd backend
# Ensure .env is present with MONGODB_* values (or MONGO_URI)
PYTHONPATH=. python scripts/seed_roles.py
```

Idempotent: if `roles` already has documents, inserts nothing.

---

## Local backend without Docker

1. Install Python 3.12+ (3.14 may lack wheels for some deps).
2. Create venv, `pip install -r backend/requirements.txt`.
3. Start MongoDB locally and set `MONGODB_*` (or `MONGO_URI`) plus `JWT_SECRET`.
4. From `backend/`:

```bash
export PYTHONPATH=.
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

---

## Frontend against local API

1. Start backend on port **8001**.
2. In `frontend/.env`:

```env
VITE_API_URL=http://localhost:8001
```

3. `cd frontend && npm run dev`.

---

## Certificate issuance (Settings → Certificates)

Visible only to users with role **Admin** or **Engineer** (or superadmin).

The UI calls the web app backend, which proxies to the mTLS service certificate endpoints.

### Backend env

Set this in the **AI-SOC repo root** `.env` (consumed by `web-app-backend`):

```env
# Base URL for the mTLS service certificate API (Vault PKI)
# Docker default (service name `api` from main compose):
MTLS_CERT_API_URL=https://api:8443/api/v1/certificates
```

Note: the proxy currently connects with TLS verification disabled (dev/self-signed). For production,
mount the CA and enable verification.

---

## Troubleshooting

| Symptom | Things to check |
|---------|-------------------|
| `401` on `/me` | Token expired or wrong `JWT_SECRET` between issue and verify |
| `403` on login | User not `active` (pending/rejected) |
| CORS errors | Backend allows `*` in dev; for locked-down origins, update `CORSMiddleware` in `backend/app/main.py` |
| Mongo connection refused | `MONGODB_HOST` / `MONGODB_PORT`; in Docker, host must be `mongodb` not `localhost` from backend container |
| First register fails “Admin role missing” | DB empty and seed failed — run `seed_roles.py` or wipe `roles` and restart API |

---

## Production checklist (short)

- [ ] Strong `JWT_SECRET`, rotate periodically.
- [ ] Restrict CORS to real UI origins.
- [ ] TLS termination (reverse proxy) in front of FastAPI.
- [ ] MongoDB auth, network isolation, backups.
- [ ] Do not expose MongoDB port publicly (compose already omits it).
