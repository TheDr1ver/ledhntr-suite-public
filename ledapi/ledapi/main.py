import logging

from fastapi import FastAPI, Depends, HTTPException, status
from contextlib import asynccontextmanager

from ledapi.config import(
    led,
    _log,
    redis_manager,
)
from ledapi.routes import(
    everyone,
    conman,
    hunter,
    dbadmin,
    admin
)
from ledapi.worker_manager import start_all_workers, stop_all_workers

# Set Logger
# logging.basicConfig(level=logging.DEBUG)

# Load FastAPI
app = FastAPI()
app.include_router(everyone.router, tags=["everyone"])
app.include_router(conman.router, tags=["conman"])
app.include_router(hunter.router, tags=["hunter"])
app.include_router(dbadmin.router, tags=["dbadmin"])
app.include_router(admin.router, tags=["admin"])

#;##############################################################################
#;### CONTEXT MANAGER
#;##############################################################################

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connect to redis
    if redis_manager.redis is None:
        _log.debug(f"Starting redis_manager")
        await redis_manager.connect()
        _log.debug(f"Connection result: {redis_manager.redis}")

    # Start plugin workers
    await start_all_workers()

    yield

    await stop_all_workers()

    # Disconnect from redis_manager
    await redis_manager.disconnect()

app.router.lifespan_context = lifespan

if __name__ == "__main__":
    import uvicorn, multiprocessing
    multiprocessing.freeze_support()
    uvicorn.run(app, host="0.0.0.0", port=8000)