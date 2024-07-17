import asyncio
import logging

from fastapi import BackgroundTasks, FastAPI, Depends, HTTPException, status
from contextlib import asynccontextmanager

from ledapi.config import(
    led,
    _log,
    redis_manager,
    wqm,
    xterm,
)
from ledapi.tasks import(
    clean_queues,
)
from ledapi.routes import(
    everyone,
    conman,
    hunter,
    dbadmin,
    admin,
    slack,
)
from ledapi.worker_manager import(
    start_all_workers,
    stop_all_workers,
    # start_scheduler,
    # stop_scheduler,
    schedule_bg_task,
)

# Set Logger
# logging.basicConfig(level=logging.DEBUG)

# Load FastAPI
app = FastAPI()
app.include_router(everyone.router, tags=["everyone"])
app.include_router(conman.router, tags=["conman"])
app.include_router(hunter.router, tags=["hunter"])
app.include_router(dbadmin.router, tags=["dbadmin"])
app.include_router(admin.router, tags=["admin"])
app.include_router(slack.router, tags=["slack"])

#;##############################################################################
#;### CONTEXT MANAGER
#;##############################################################################

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Connect to redis
    _log.debug(f"{xterm('BOLD_RED')}### MAIN ### OPENING REDIS CONNECTIONS{xterm('RESET')}")
    await redis_manager.check_redis_conn()

    # Start plugin workers
    _log.debug(f"{xterm('BOLD_RED')}### MAIN ### STARTING ALL WORKERS{xterm('RESET')}")
    await start_all_workers()

    bg_tasks = []
    _log.debug(f"{xterm('BOLD_RED')}### MAIN ### SCHEDULING clean queue task{xterm('RESET')}")
    task_clean_queues = asyncio.create_task(schedule_bg_task(
        task_name=clean_queues,
        task_args=[24, None],
        interval_seconds = 3600*24,
        timeout=60*5,
        result_ttl=60*60,
    ))
    bg_tasks.append(task_clean_queues)

    yield

    _log.debug(f"{xterm('BOLD_RED')}### MAIN ### CANCELING BACKGROUND TASKS{xterm('RESET')}")
    for t in bg_tasks:
        _log.debug(f"Canceling {t}")
        t.cancel()

    _log.debug(f"{xterm('BOLD_RED')}### MAIN ### STOPPING ALL WORKERS{xterm('RESET')}")
    await stop_all_workers()

    # Disconnect from redis_manager
    _log.debug(f"{xterm('BOLD_RED')}### MAIN ### DISCONNECTING FROM REDIS{xterm('RESET')}")
    await redis_manager.disconnect()

app.router.lifespan_context = lifespan



if __name__ == "__main__":
    import uvicorn, multiprocessing
    multiprocessing.freeze_support()
    uvicorn.run(app, host="0.0.0.0", port=8000)