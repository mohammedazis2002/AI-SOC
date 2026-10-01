# Frontend (Cybolt UI)

Location: **`frontend/`**  
Stack: **Vite**, **React**, **TypeScript**, **Tailwind CSS v4**, **React Router**, **TanStack Query**, **Zustand**, **Axios**, **Recharts**.

---

## Environment

Copy **`frontend/.env.example`** → **`frontend/.env`**.

| Variable | Purpose |
|----------|---------|
| `VITE_API_URL` | Base URL of the FastAPI backend **without trailing slash** (e.g. `http://localhost:8001`) |

If unset, **`src/lib/api.ts`** defaults to `http://localhost:8001`.

Vite only exposes env vars prefixed with **`VITE_`**.

---

## Application entry

| File | Role |
|------|------|
| `index.html` | SPA shell |
| `src/main.tsx` | Renders app; calls **`registerAuthTokenGetter(() => useAuthStore.getState().token)`** so Axios can attach JWT without circular imports |
| `src/App.tsx` | `QueryClientProvider`, `TooltipProvider`, `BrowserRouter`, routes |

---

## Routing

| Path | Layout | Data source |
|------|--------|-------------|
| `/` | `MainLayout` | Mock (dashboard) |
| `/alerts`, `/alerts/:id` | `MainLayout` | Mock |
| `/investigations`, `/review`, `/analytics`, `/system`, `/settings` | `MainLayout` | Mock |
| `/login` | Standalone | **Backend** `POST /login` |
| `/register` | Standalone | **Backend** `POST /register` |

Global UI: **`CommandPalette`** (⌘K), **`Toaster`**, **`AuthBootstrap`**.

---

## State management

| Store | Persistence | Purpose |
|-------|-------------|---------|
| `useAppStore` | Not persisted | Sidebar, filters, command palette, mock notification toasts, etc. |
| `useAuthStore` | **persist** (`localStorage`, key `cybolt-auth`) | JWT `token` only; `user` loaded via API |

**Auth flow**

1. `loginWithCredentials` clears old token, `POST /login`, then `loginWithToken` → `GET /me`.
2. `AuthBootstrap` subscribes to **`persist.onFinishHydration`** and runs **`refreshSession()`** to validate stored JWT.
3. Logout clears `token` and `user`.

---

## HTTP client

| File | Role |
|------|------|
| `src/lib/api.ts` | Shared Axios instance, `Authorization` interceptor |
| `src/lib/auth-api.ts` | `loginRequest`, `registerRequest`, `fetchMe` |

---

## Mock vs backend

| Module | Behaviour |
|--------|------------|
| `src/hooks/useAlerts.ts`, `useAlert.ts`, `useDashboard.ts`, `useSystemHealth.ts` | Use **`MOCK = true`** (or equivalent): delayed promises + `src/data/mockAlerts.ts` |
| Auth | Real HTTP to backend when user uses Login/Register pages |

To connect more features later: set `MOCK` to `false` and implement `fetch`/`api` calls matching future backend routes.

---

## Build & dev

```bash
cd frontend
npm install
npm run dev      # Vite dev server (default http://localhost:5173)
npm run build
npm run preview  # Production build preview
```

---

## Styling & design tokens

- Global styles: `src/index.css` (Tailwind import + CSS variables).
- Fonts: Inter / JetBrains Mono (see `index.html` / Tailwind `fontFamily`).
- Components: composable UI under `src/components/ui/` (Radix + Tailwind).
