from datetime import datetime, timedelta, timezone
from pprint import pformat

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from redis.asyncio.client import Redis
from rq import Queue, Worker

from ledapi.models import(
    HuntSubmission,
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
from ledapi.helpers import handle_response

from ledhntr.data_classes import Attribute, Entity, Relation




from typing import List, Dict
from uuid import uuid4
import json
import time
import traceback

router = APIRouter()

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
        "job_result_ids": [],
    }

    try:
        result = await run_hunt(job_data)
        return result
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
        job_statuses = await get_all_workers(with_jobs=True)
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
    job_id: str = None,
    user: User = Depends(dep_check_user_role(role_hunter))
):
    '''
    try:
        response = await poll_job(job_id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed polling job: {e}"
        )
    if not response:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No job found with ID {job_id}"
        )
    return {
            "message": response,
            "status_code": status.HTTP_200_OK,
        }
    '''
    _log.debug(f"Polling job_id {job_id}")
    msg_400 = f"No job found with ID {job_id}"
    msg_500 = f"Failed polling job"

    response = await handle_response(
        poll_job,
        msg_400,
        msg_500,
        job_id
    )

    return response

#~ Add hunt
@router.post("/add-hunt")
async def add_hunt_ep(
    hunt: HuntSubmission = None,
    user: User = Depends(dep_check_user_role(role_hunter))
):
    _log.debug(f"Adding hunt: {hunt}")

#~ Enable/Disable hunt by DB+Name
@router.get("/enable-hunt/{db_name}/{hunt_name}")
async def enable_hunt_ep(
    db_name: str = None,
    hunt_name: str = None,
    user: User = Depends(dep_check_user_role(role_hunter))
):
    _log.debug(f"Enabling hunt {hunt_name} in {db_name}")
    msg_400 = f"Unable to find {hunt_name} in {db_name}"
    msg_500 = f"Failed enabling hunt"

    '''
    response = handle_response(
        enable_hunt,
        msg_400,
        msg_500,
        db_name,
        hunt_name,
    )

    return response
    '''

