from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.db import close_db, connect_db
from app.models import COLLECTION_USERS
from app.routes import admin as admin_routes
from app.routes import auth as auth_routes
from app.routes import alerts as alerts_routes
from app.routes import incidents as incidents_routes
from app.routes import analytics as analytics_routes
from app.routes import dashboard as dashboard_routes
from app.routes import mtls_certs as mtls_certs_routes
from app.routes import settings as settings_routes
from app.routes import system as system_routes
from app.services.seed_roles import retire_l4_role_if_present, seed_roles_if_empty


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = await connect_db()
    await seed_roles_if_empty(db)
    await retire_l4_role_if_present(db)
    await db[COLLECTION_USERS].create_index("email", unique=True)
    yield
    await close_db()


settings = get_settings()
app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(admin_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(analytics_routes.router)
app.include_router(alerts_routes.router)
app.include_router(incidents_routes.router)
app.include_router(mtls_certs_routes.router)
app.include_router(settings_routes.router)
app.include_router(system_routes.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
