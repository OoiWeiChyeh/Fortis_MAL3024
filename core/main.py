import logging

from fastapi import FastAPI

from .frameworks import seed_all_frameworks, FRAMEWORK_NAMES
from engine import check_model_available
from .security import LocalOriginGuard
from .store import init_db
from .routers import upload, chat, report, engagements, intel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Fortis — AI Cybersecurity Advisor", version="1.0.0")

# The UI is served same-origin, so no CORS policy is needed. The former
# wildcard CORS let any web page read engagement data; the guard below
# also blocks cross-site writes and DNS-rebinding (see core/security.py).
app.add_middleware(LocalOriginGuard)

app.include_router(engagements.router)
app.include_router(upload.router)
app.include_router(chat.router)
app.include_router(report.router)
app.include_router(intel.router)


@app.on_event("startup")
async def startup():
    logger.info("Initializing client/engagement database")
    init_db()
    logger.info("Seeding framework reference corpus: %s", FRAMEWORK_NAMES)
    seed_all_frameworks()
    warning = await check_model_available()
    if warning:
        logger.warning(warning)


@app.get("/health")
async def health():
    model_warning = await check_model_available()
    return {
        "status": "ok" if not model_warning else "degraded",
        "detail": model_warning,
        "frameworks_loaded": FRAMEWORK_NAMES,
    }
