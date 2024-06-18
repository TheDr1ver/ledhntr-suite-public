import asyncio
import ast

from ledapi.config import(
    _log,
    led,
    redis_manager,
)

from datetime import datetime, timedelta, timezone
from pprint import pformat
from redis.asyncio.client import Redis
from typing import Dict, List, Optional
import json
import time

async def update_job_status(job_id, status):
    '''
    redis_pool: Redis = redis_manager.redis
    job_data = await redis_pool.get(job_id)
    if job_data:
        job_data = eval(job_data) # Convert string back to dictionary
        job_data["status"] = status
        if status == "complete":
            job_data["completed_at"] = datetime.now(UTC)
        await redis_pool.setex(job_id, timedelta(days=7), str(job_data))
    '''
    try:
        redis_pool: Redis = redis_manager.redis
        job_data = await redis_pool.get(job_id)
        if job_data:
            # job_data = ast.literal_eval(job_data)
            # job_data = job_data.decode()
            job_data = json.loads(job_data.decode('utf-8'))
            job_data['status'] = status
            if status == "completed":
                job_data['completed_at'] = datetime.now(timezone.utc).isoformat()
            
            await redis_pool.setex(job_id, timedelta(days=7), json.dumps(job_data))
    except Exception as e:
        _log.error(f"Failed to update job status: {e}")
        raise

async def run_hunt(
    job_data: Dict = None
):
    '''
    # asyncio.run(update_job_status(job_data['job_id'], "hunting"))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(update_job_status(job_data['job_id'], "hunting"))

    # DO THE HUNTING STUFF
    _log.debug(f"#### I'M FLYING, JACK! ####")
    _log.debug(f"job_data: \n\t {pformat(job_data)}")
    time.sleep(15)

    # asyncio.run(update_job_status(job_data['job_id'], "complete"))
    loop.run_until_complete(update_job_status(job_data['job_id'], "complete"))
    '''
    try:
        #~ Schedule update_job to run in background
        asyncio.create_task(update_job_status(job_data['job_id'], "hunting"))

        #~ Add your hunt logic
        result = await hunt_stuff(job_data)

        #~ Update job status to complete
        await update_job_status(job_data['job_id'], "completed")
        return result

    except Exception as e:
        await update_job_status(job_data['job_id'], f"failed: {e}")
        raise

async def hunt_stuff(job_data):
    # DO THE HUNTING STUFF
    _log.debug(f"#### I'M FLYING, JACK! ####")
    _log.debug(f"job_data: \n\t {pformat(job_data)}")
    # time.sleep(15)
    await asyncio.sleep(15)
    return "Hunt completed!"

async def get_all_jobs():
    try:
        redis_pool: Redis = redis_manager.redis
        keys = await redis_pool.keys("*")
        job_statuses = {
            "queued": [],
            "running": [],
            "completed": [],
            "failed": [],
        }

        for key in keys:
            key_type = await redis_pool.type(key)
            if not key_type == b'string':
                continue
            job_data = await redis_pool.get(key)
            if job_data:
                job_data = json.loads(job_data.decode('utf-8'))
                status = job_data.get('status')
                job_id = job_data.get('job_id')
                if status and job_id:
                    job_statuses[status].append(job_data)

        return job_statuses
    except Exception as e:
        _log.error(f"Failed to poll job status: {e}")
        raise