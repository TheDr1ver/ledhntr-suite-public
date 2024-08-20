from datetime import datetime, timedelta, timezone
from pprint import pformat

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from redis.asyncio.client import Redis
from rq import Queue, Worker

from ledapi.models import(
    HuntSubmission,
    JobSubmission,
    ThingSubmission,
    ThingUpdate,
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
    # run_hunt,
    hunt_handler,
    add_thing_handler,
    replace_attributes_handler,
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
    job_data: JobSubmission = None,
    user: User = Depends(dep_check_user_role(role_hunter)),
):
    #& This job is ugly and needs to be reworked to look like the others
    #& e.g.
    #& _log.debug(f"Running slack event...")
    #& _log.debug(f"{pformat(request)}")
    #& msg_400 = f"Invalid input"
    #& msg_500 = f"Error running slack event"
    #&
    #&
    #& response = await handle_response(
    #&     event_handler,
    #&     msg_400,
    #&     msg_500,
    #&     request,
    #&     user,
    #& )
    #&
    #& _log.debug(f"Sending this to slack:")
    #& _log.debug(f"{pformat(response)}")
    #& return response

    '''
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
    '''
    _log.debug(f"Starting hunt")
    _log.debug(f"{pformat(job_data)}")

    msg_400 = None
    msg_500 = "Error running hunt stack"

    response = await handle_response(
        hunt_handler,
        msg_400,
        msg_500,
        job_data,
        user,
    )

    _log.debug(f"{pformat(response)}")
    return response

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

#~ Add hunt
@router.post("/add-hunt")
async def add_hunt_ep(
    hunt: HuntSubmission = None,
    user: User = Depends(dep_check_user_role(role_hunter))
):
    _log.debug(f"Adding hunt: {hunt}")

#~ Add thing
@router.post("/add-thing")
async def add_thing_ep(
    thing: ThingSubmission = None,
    user: User = Depends(dep_check_user_role(role_hunter))
):
    _log.debug(f"Adding thing: {thing}")
    msg_400 = f"Unable add {thing} to {thing.db_name}"
    msg_500 = f"Failed adding thing {thing}"
    response = handle_response(
        add_thing_handler,
        msg_400,
        msg_500,
        thing,
        user,
    )

@router.post('/replace-attributes')
async def replace_attributes_ep(
    thing: ThingUpdate = None,
    user: User = Depends(dep_check_user_role(role_hunter))
):
    _log.debug(f"Updating thing: {thing}")
    msg_400 = f"Unable to update {thing} in {thing.db_name}"
    msg_500 = f"Failed updating thing {thing}"
    response = handle_response(
        replace_attributes_handler,
        msg_400,
        msg_500,
        thing,
        user,
    )

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

