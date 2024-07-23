import asyncio
import logging

from fastapi import BackgroundTasks, FastAPI, Depends, HTTPException, status
from contextlib import asynccontextmanager

from ledhntr.helpers import xterm

from ledapi.config import(
    led,
    _log,
    redis_manager,
    wqm,
)
from ledapi.tasks import(
    check_automation_schedules,
    clean_queues,
    start_automations,
    stop_automations,
    post_status,
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

    _log.debug(f"{xterm('BOLD_RED')}### MAIN ### SCHEDULING clean queue task{xterm('RESET')}")
    bg_tasks = await start_automations()

    #. Once slackbot is rolled into its own LEDHNTR Plugin this entry should
    #. effectively be turned into "init_bots" and each bot will have their own
    #. initialization routine.

    chat_clients = ['slack_client']

    await check_automation_schedules(
        bg_tasks,
        chat_clients=chat_clients
    )

    await post_status(
        chat_clients=chat_clients,
        text_lines=[":sunrise: *SERVER HAS FINISHED BOOTING* :sunrise:"]
    )

    yield

    await post_status(
        chat_clients=chat_clients,
        text_lines=[":rotating_light: *SERVER SHUTTING DOWN* :rotating_light:"]
    )

    _log.debug(f"{xterm('BOLD_RED')}### MAIN ### CANCELING BACKGROUND TASKS{xterm('RESET')}")
    await stop_automations(bg_tasks)

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