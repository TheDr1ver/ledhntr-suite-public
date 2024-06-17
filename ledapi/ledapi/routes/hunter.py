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
    tdb, 
    # ! redis_jq,
)
from ledapi.helpers import result_error_catching
# ! from ledapi.hunting import job_queues, process_job

from ledhntr.data_classes import Attribute, Entity, Relation

from datetime import datetime, timedelta, UTC
# ! from rq.registry import StartedJobRegistry
from typing import List, Dict
from uuid import uuid4
import time

router = APIRouter()

#@##############################################################################
#@### Job Queuing
#@##############################################################################
jobs: Dict[str, Dict[str, str]] = {}
def background_task(job_id: str):
    time.sleep(15)
    jobs[job_id]["status"] = "completed"
    jobs[job_id]["result"] = "Task completed successfully"

# hunts: Dict[str, Dict[str, str]] = {}
# def background_hunt(job_id: str):


#@##############################################################################
#@### HUNTER ENDPOINTS
#@##############################################################################

#~ Submit Hunt Job
#! Pick this up later. It's probably a step in the right direction, but I'm out
#! of time and don't want to mess with it too much until I can debug it.
'''
router.post("/submit-job")
async def submit_job(job: JobSubmission):
    job_id = str(uuid4())
    job_data = {
        "job_id": job_id,
        "target_db": job.target_db,
        "worker_name": job.worker_name,
        "status": "pending",
        "user_id": job.user_id,
        "forced": job.forced,
        "submitted_at": datetime.now(UTC),
        "completed_at": None,
    }

    queue = job_queues.get(job.worker_name)
    if not queue:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid worker name"
        )
    # Check if this worker type is already running
    registry = StartedJobRegistry(queue=queue)
    if len(registry.get_job_ids()) > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Worker is already running"
        )
    
    job_result = queue.enqueue(
        process_job, 
        job.target_db, 
        job.worker_name,
        job.user_id,
        job.forced
    )

    job_data["job_result_id"] = job_result.id

    #Save job details in Redis with expiry of 7 days
    redis_jq.setex(job_id, timedelta(days=7), str(job_data))

    return {"job_id": job_id, "status": "Job submitted"}
'''

#~ Get all hunts
@router.get("/get-hunts")
async def get_hunts(
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
    results = {
        'results': {},
        'message': None,
        'status_code': None,
        'count': 0,
    }
    all_dbs = []
    if user.db_name == "all":
        dbs = result_error_catching(tdb.get_all_dbs, "Failed to fetch databases")
        for db in dbs:
            all_dbs.append(str(db))
    else:
        all_dbs.append(user.db_name)

    for db in all_dbs:
        tdb.db_name = db
        so = Entity(label='hunt', has=[Attribute(label='hunt-active', value=True)])
        res = result_error_catching(tdb.find_things, f"Failed searching for {so}", so)
        if db not in results['results']:
            results['results'][db] = []
        for r in res:
            r:Entity
            if r.label=='hunt':
                # results['results'][db].append(r.to_dict())
                hunt_res = {
                    "hunt-name": r.get_attributes('hunt-name', True).value,
                    "hunt-string": r.get_attributes('hunt-string', True).value,
                    "hunt-service": r.get_attributes('hunt-service', True).value,
                    "hunt-endpoint": r.get_attributes('hunt-endpoint', True).value,
                }
                filter_vals: List[str] = filter.split(",") if filter else []
                for fv in filter_vals:
                    attrs = r.get_attributes(fv)
                    if attrs:
                        hunt_res[fv] = []
                        for attr in attrs:
                            hunt_res[fv].append(attr.value)
                results['results'][db].append(hunt_res)
                results['count']+=1

    results['status_code'] = status.HTTP_200_OK
    return results

#~ Test Job Queuing
@router.get("/start-job")
async def start_job(background_tasks: BackgroundTasks):
    job_id = str(uuid4())
    jobs[job_id] = {'status': "in_progress", "result": None}
    background_tasks.add_task(background_task, job_id)
    return {"job_id": job_id, "message": "Job started"}

@router.get("/get-jobs")
async def get_jobs():
    return jobs

#~ Enable/Disable hunt by DB+Name

#~ Run Hunts
#~   - All hunts
#~   - All hunts in DB
#~   - Specific hunt by name in DB