import asyncio
import ast
import json
import time

from datetime import datetime, timedelta, timezone
from fastapi import Query
from pprint import pformat
from redis.asyncio.client import Redis
from rq import Queue, Worker
from rq.job import Job
from typing import Dict, List, Optional

from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)

from ledapi.config import(
    _log,
    led,
    redis_manager,
    get_tdb,
    wqm,
)
from ledapi.helpers import result_error_catching
from ledapi.user import User
from ledapi.worker_manager import(
    update_job_status,
)

# worker_queues: Queue

#!##############################################################################
#! THESE SHOULD ALL BE REPLACED WITH INTERACTING WITH THE RQ QUEUE
#!##############################################################################

'''
async def update_job_status(job_id, status):
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
            _log.debug(f"Geting data from key {key}")
            job_data = await redis_pool.get(key)
            if job_data:
                _log.debug(f"Got job_data: {job_data}")
                try:
                    job_data = json.loads(job_data.decode('utf-8'))
                except Exception as e:
                    _log.error(f"Failed json.loads: {e}")
                    continue
                if not hasattr(job_data, 'get'):
                    _log.error(f"{job_data} doesn't have a 'get' attribute")
                    continue
                status = job_data.get('status')
                job_id = job_data.get('job_id')
                if status and job_id:
                    job_statuses[status].append(job_data)

        return job_statuses
    except Exception as e:
        _log.error(f"Failed to poll job status: {e}")
        raise
'''
#!##############################################################################
#! REPLACE ABOVE WITH RQ INTERACTIONS
#!##############################################################################

'''
async def fetch_jobs(job_ids):
    jobs = []
    for job_id in job_ids:
        job = Job.fetch(job_id, connection=redis_manager.syncredis)
        job_info = {
            "job_id": job.id,
            "status": job.get_status(),
            "result": job.result,
            "enqueued_at": job.enqueued_at.isoformat() if job.enqueued_at else None,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "ended_at": job.ended_at.isoformat() if job.ended_at else None,
            "exc_info": job.exc_info,
            "db_name": job.db_name if job.db_name else None,
            "hunt_name": job.hunt_name if job.hunt_name else None,
            "plugin": job.plugin if job.plugin else None,
            "user_id": job.user_id if job.user_id else None,
            "forced": job.forced if job.forced else None,
            # "submitted_at": datetime.now(timezone.utc).isoformat(),
            # "completed_at": None,
        }
        jobs.apend(job_info)
    return jobs

async def poll_job_statuses():
    try:
        job_statuses = {
            "queued": [],
            "running": [],
            "completed": [],
            "failed": [],
        }

        # Get Job IDs from different registries
        queued_job_ids = worker_queues.job_ids
        running_job_ids = worker_queues.started_job_registry.get_job_ids()
        finished_job_ids = worker_queues.finished_job_registry.get_job_ids()
        failed_job_ids = worker_queues.failed_job_registry.get_job_ids()

        # Fetch and categorize jobs
        job_statuses['queued'] = await fetch_jobs(queued_job_ids)
        job_statuses['running'] = await fetch_jobs(running_job_ids)
        job_statuses['completed'] = await fetch_jobs(finished_job_ids)
        job_statuses['failed'] = await fetch_jobs(failed_job_ids)

        return job_statuses

    except Exception as e:
        _log.error(f"Failed to poll job statuses: {e}")
        return None
'''
#!##############################################################################
#! ABOVE MAY HAVE BEEN A FEVER DREAM
#!##############################################################################

#@##############################################################################
#@ List all Active Hunts
#@##############################################################################

#@##############################################################################
#@ Run a Hunt
#@##############################################################################

'''
async def run_hunt(
    job_data: Dict = None
):
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
'''

async def get_hunts(
    user: User = None,
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
    tdb = get_tdb()
    results = {
        'results': {},
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
    return results

async def run_hunt(
    job_data: Dict = None,
    user: User = None,
):
    try:
        result = await hunt_stuff(job_data)
    except Exception as e:
        # set status as failed
        _log.debug(f"Failed running hunt_stuff: {e}")
        raise
    return result

async def plugin_hunt(
    plugin: object = None,
    dbs: List[str] = [],
):
    _log.debug(f"Running {plugin} against dbs {dbs}")

async def hunt_stuff(
    job_data: Dict = None,
    user: User = None,
):
    # DO THE HUNTING STUFF
    _log.debug(f"#### I'M FLYING, JACK! ####")
    _log.debug(f"job_data: \n\t {pformat(job_data)}")
    # time.sleep(15)
    #! await asyncio.sleep(job_data['sleep_time'])
    #! return "Hunt completed!"
    hunt_summary = None
    #~ Set up the database connection
    tdb = get_tdb()
    all_dbs = []
    if job_data['db_name'] == "all":
        dbs = result_error_catching(tdb.get_all_dbs, "Failed to fetch databases")
        for db in dbs:
            all_dbs.append(str(db))
    else:
        all_dbs.append(job_data['db_name'])

    #~ Get Plugins we want to search
    plugins = []
    if job_data['plugin']:
        plugin = led.load_plugin(job_data['plugin'].lower())
        plugins.append(plugin)
    else:
        for plugname, confs in wqm.conf.items():
            for i in range(confs['threshold']):
                plugin = led.load_plugin(plugname.lower(), duplicate=True)
                plugins.append(plugin)
    plugin_tasks = [asyncio.create_task(plugin_hunt(plugin)) for plugin in plugins]
    for task in plugin_tasks:
        #! TODO - MAKE SURE THAT ASYNC IS HANDLED PROPERLY
        #! KEEP IN MIND WE'VE GOT WORKER QUEUES TO CONSIDER THAT MIGHT COME INTO
        #! PLAY BEFORE GETTING TO THIS STAGE
        _log.debug(f"Doing stuff")
        active_hunts = plugin.find_active_hunts(tdb, ignore_freq=job_data['forced'])
        '''
        {'shodan_hosts_search': [<Entity(label=hunt,con=3.0,iid=0x826e801f8000000000000000,hunt-name=shodan-HUNT_INFRA,has=427)]}
        '''
        #@ Now I've got to run through the active hunts, hunt them, 
        #@ save the results, and return a summary when the job completes.
        #@ This is effectively AutoHunter().run_hunts() but I want it to be cleaner
        #@ Ideally caching and everything will be built in as well, but I'm not
        #@ worried about that just yet.

        
    return hunt_summary