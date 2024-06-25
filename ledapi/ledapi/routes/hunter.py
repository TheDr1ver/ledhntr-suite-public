from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
# from ledapi.ledapi import auth
# from ledapi.ledapi.config import led, _log, tdb
# import auth
# from config import led, _log, tdb
# from ledapi.auth import(
#     dep_check_user_role,
# )
from ledapi.models import(
    JobSubmission,
    role_hunter
)
from ledapi.user import(
    User,
    dep_check_user_role,
)
from ledapi.config import (
    led,
    _log,
    get_tdb,
    redis_manager,
    wqm,
)

from ledapi.tasks import(
    get_hunts,
    run_hunt,
)

from ledapi.worker_manager import(
    # worker_queues,
    get_all_workers,
    poll_job,
)
from ledapi.helpers import result_error_catching

from ledhntr.data_classes import Attribute, Entity, Relation

from datetime import datetime, timedelta, timezone
from pprint import pformat
from redis.asyncio.client import Redis
from typing import List, Dict
from uuid import uuid4
import json
import time
import traceback

router = APIRouter()

#@##############################################################################
#@### Job Queuing
#@##############################################################################
'''
jobs: Dict[str, Dict[str, str]] = {}
def background_task(job_id: str):
    time.sleep(15)
    jobs[job_id]["status"] = "completed"
    jobs[job_id]["result"] = "Task completed successfully"

# hunts: Dict[str, Dict[str, str]] = {}
# def background_hunt(job_id: str):
'''

#@##############################################################################
#@### HUNTER ENDPOINTS
#@##############################################################################

#~ Get all hunts
@router.get("/get-hunts")
async def get_hunts_ep(
    user: User = Depends(dep_check_user_role(role_hunter)),
    filter: str = Query(None, description="Only return these attributes"),
):
    """Return all hunts in the user's set database

    :param user: User making the request
    :type user: User, required
    :param filter: Comma-separated list of attributes to return
    :type filter: str, optional
    :return: Dictionary of "result", "status_code", and "count"
    :rtype: Dict
    """
    try:
        rez = await get_hunts(user, filter)
    except Exception as e:
        _log.debug(f"Error getting hunts: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details="Error getting hunts: {e}"
        )
    
    results = {
        'results': rez['results'],
        'message': None,
        'status_code': None,
        'count': rez['count'],
    }

    results['status_code'] = status.HTTP_200_OK
    return results

#~ Submit Hunt Job
@router.post("/run-hunt")
async def run_hunt_ep(
    job: JobSubmission = None,
    user: User = Depends(dep_check_user_role(role_hunter)),
):
    job_id = str(uuid4())
    job_data = {
        "job_id": job_id,
        "db_name": job.db_name or user.db_name,
        "hunt_name": job.hunt_name,
        "plugin": job.plugin,
        "status": "pending",
        "user_id": user.user_id,
        "forced": job.forced,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "sleep_time": job.sleep_time,
    }

    plugins = []
    if job.plugin == None or job.plugin.lower() == 'all':
        # queue = wqm.queues.get(job.plugin)
        for worker_name in wqm.queues.keys():
            for worker_id in range(wqm.conf[worker_name['threshold']]):
                try:
                    plugin = led.load_plugin(worker_name, duplicate=True)
                except Exception as e:
                    _log.error(f"{worker_name} is not a valid plugin: {e}")
                    continue
                plugins.append(plugin)

    queue = wqm.queues.get(job.plugin)
    if not queue:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Invalid worker name {job.plugin}. Must be one of {wqm.queues.keys()}"
        )

    try:    
        job_result = queue.enqueue_call(
            run_hunt,
            args=[job_data],
            job_id=job_data['job_id'],
            timeout=60*60,
            result_ttl=60*60*24,
            #on_success=DOSOMETHING,
            #on_failure=DOSOMETHINGELSE,
        )
        job_result
        
        job_data['job_result_id'] = job_result.id

        # Serialize the job_data
        job_data = json.dumps(job_data)

        # _log.debug(f"job_data: {pformat(job_data)}")
        return {"job_id": job_id, "status": "Job submitted"}

    except Exception as e:
        _log.debug(f"Error submitting job: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            # detail=f"Error submitting job: {e}"
            detail=f"Error submitting job: {e}\n\ntraceback: {traceback.format_exc()}"
        )

#~ Check all job statuses
@router.get("/check-jobs")
async def check_jobs_ep(
    user: User = Depends(dep_check_user_role(role_hunter)),
):
    try:
        # job_statuses = await get_all_jobs()
        job_statuses = await get_all_workers()
        return {
            "job_statuses": job_statuses,
            "status": status.HTTP_200_OK,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed getting job statuses: {e}"
            # detail=f"Failed getting job statuses: {e}\n\ntraceback: {traceback.format_exc()}"
        )
    
#~ Poll the status of a specific job_id
@router.get("/poll-job/{job_id}")
async def poll_job_ep(
    job_id: str,
    verified: bool = Depends(dep_check_user_role(role_hunter))
):
    try:
        response = await poll_job(job_id)
        return {
            "message": response,
            "status_code": status.HTTP_200_OK,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed polling job: {e}"
        )

#~ Enable/Disable hunt by DB+Name

#~ Run Hunts
#~   - All hunts
#~   - All hunts in DB
#~   - Specific hunt by name in DB