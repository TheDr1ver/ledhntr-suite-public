import asyncio

from ledapi.config import(
    _log,
    led,
    redis_manager,
)

from datetime import datetime, timedelta, UTC
from pprint import pformat
from redis.asyncio.client import Redis
from typing import Dict, List, Optional
import time

async def update_job_status(job_id, status):
    redis_pool: Redis = redis_manager.redis
    job_data = await redis_pool.get(job_id)
    if job_data:
        job_data = eval(job_data) # Convert string back to dictionary
        job_data["status"] = status
        if status == "complete":
            job_data["completed_at"] = datetime.now(UTC)
        await redis_pool.setex(job_id, timedelta(days=7), str(job_data))

def run_hunt(
    job_data: Dict = None
):
    asyncio.run(update_job_status(job_data['job_id'], "hunting"))

    # DO THE HUNTING STUFF
    _log.debug(f"#### I'M FLYING, JACK! ####")
    _log.debug(f"job_data: \n\t {pformat(job_data)}")
    time.sleep(15)

    asyncio.run(update_job_status(job_data['job_id'], "complete"))