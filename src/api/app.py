import asyncio
import logging
from contextlib import suppress
from datetime import datetime, time as dtime
from zoneinfo import ZoneInfo

import uvicorn
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from mangum import Mangum

from api.routers import chat, embeddings, model
from api.setting import (
    API_ROUTE_PREFIX,
    DESCRIPTION,
    ENABLE_WARMUP_PINGER,
    SUMMARY,
    TITLE,
    VERSION,
    WARMUP_END_HOUR,
    WARMUP_INTERVAL_SECONDS,
    WARMUP_MODEL,
    WARMUP_START_HOUR,
    WARMUP_TIMEZONE,
)
from api.models.bedrock import bedrock_runtime

config = {
    "title": TITLE,
    "description": DESCRIPTION,
    "summary": SUMMARY,
    "version": VERSION,
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
app = FastAPI(**config)
warmup_task = None

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(model.router, prefix=API_ROUTE_PREFIX)
app.include_router(chat.router, prefix=API_ROUTE_PREFIX)
app.include_router(embeddings.router, prefix=API_ROUTE_PREFIX)


@app.get("/health")
async def health():
    """For health check if needed"""
    return {"status": "OK"}


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    logger = logging.getLogger(__name__)
    
    # Log essential info only - avoid sensitive data and performance overhead
    logger.warning(
        "Request validation failed: %s %s - %s", 
        request.method, 
        request.url.path,
        str(exc).split('\n')[0]  # First line only
    )
    
    return PlainTextResponse(str(exc), status_code=400)


handler = Mangum(app)


def _within_warmup_window(now: datetime) -> bool:
    if now.weekday() > 4:
        return False
    current = now.time()
    return dtime(hour=WARMUP_START_HOUR) <= current < dtime(hour=WARMUP_END_HOUR)


def _ping_bedrock() -> None:
    try:
        bedrock_runtime.converse(
            modelId=WARMUP_MODEL,
            messages=[{"role": "user", "content": [{"text": "ping"}]}],
            inferenceConfig={"maxTokens": 1, "temperature": 0},
        )
    except Exception as exc:  # pragma: no cover - best effort
        logging.getLogger(__name__).warning("Warmup ping failed: %s", exc)


async def warmup_ping_loop() -> None:
    tz = ZoneInfo(WARMUP_TIMEZONE)
    logger = logging.getLogger(__name__)
    logger.info(
        "Warmup pinger enabled: %s %02d:00-%02d:00 every %ds",
        WARMUP_TIMEZONE,
        WARMUP_START_HOUR,
        WARMUP_END_HOUR,
        WARMUP_INTERVAL_SECONDS,
    )
    while True:
        now = datetime.now(tz)
        if _within_warmup_window(now):
            await asyncio.to_thread(_ping_bedrock)
        await asyncio.sleep(WARMUP_INTERVAL_SECONDS)


@app.on_event("startup")
async def start_background_tasks():
    global warmup_task
    if ENABLE_WARMUP_PINGER:
        warmup_task = asyncio.create_task(warmup_ping_loop())


@app.on_event("shutdown")
async def stop_background_tasks():
    if warmup_task:
        warmup_task.cancel()
        with suppress(Exception):
            await warmup_task


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
