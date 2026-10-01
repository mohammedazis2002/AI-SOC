# Cybolt

**Documentation:** see **[`docs/`](docs/README.md)** (workflows, API reference, data model, frontend, operations).

Monorepo layout:

| Path | Description |
|------|-------------|
| **`frontend/`** | Vite + React + TypeScript (Cybolt UI) |
| **`backend/`** | FastAPI + MongoDB (auth & RBAC API) |

### Quick start

**Frontend** (from `frontend/`):

```bash
cd frontend && npm install && npm run dev
```

**Backend** (Docker, from the **AI-SOC** repo root — uses root `.env` and main `docker-compose.yml`):

```bash
cp .env.example .env   # at repo root
docker compose up --build web-app-backend
```

API: `http://localhost:8001/docs` · UI dev server: `http://localhost:5173` (default Vite port).

Copy `frontend/.env.example` to `frontend/.env` and set `VITE_API_URL` so the UI can reach the backend.
