import asyncio
import traceback

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
    """Handle which queue gets which hunt job

    Keyword arguments:
    argument -- description
    Return: return_description
    """
    plugins = []
    await wqm.check_config() #~ Make sure plugins and configs are loaded properly
    #* If we don't specify a plugin or explicitly specify 'all' then use all plugins
    if job_data['plugin'] == None or job_data['plugin'].lower() == 'all':
        for worker_name, details in wqm.conf.items():
            if details['_plugin_name'] not in plugins:
                plugins.append(details['_plugin_name'])
    else:
        plugins.append(job_data['plugin'].lower())

    plugin_queues = {}
    #* Get all the plugin names and their associated queues and workers
    #* Results in plugin_queues={'shodan': [('shodan.01',<Queue1>),('shodan.02',<Queue2>)]}
    for plugin in plugins:
        # worker_queues = [(worker, queue) for worker, queue in wqm.queues.items() if queue.name.startswith(plugin)]
        worker_queues = [(worker, details['queue']) for worker, details in wqm.conf.items() if details['queue'].name.startswith(plugin)]
        if worker_queues:
            plugin_queues[plugin] = worker_queues
        else:
            _log.debug(f"No queues available for {plugin}")

    for plugin, worker_queues in plugin_queues.items():
        #* Pick a queue/worker to use.
        #* If a queue belongs to an idle worker, pick that queue.
        #* If no workers are idle, pick the queue with the least amount of jobs.
        queue = None
        worker = None
        idle_worker = False
        for wq in worker_queues:
            workers = Worker.all(queue=wq[1])
            for w in workers:
                if w.state == 'idle':
                    worker = wq[0]
                    queue = wq[1]
                    idle_worker = True
                    _log.debug(f"Found idle worker {worker}. Using queue {queue}.")
            if idle_worker:
                break
            if queue is None:
                worker = wq[0]
                queue = wq[1]
                continue
            if len(queue.jobs) > len(wq[1].jobs):
                _log.debug(f"Found queue with lower job count {wq[1]} - {len(wq[1].jobs)} vs {len(queue.jobs)}")
                worker = wq[0]
                queue = wq[1]

        job_result = queue.enqueue_call(
            hunt_stuff,
            args=[job_data, worker],
            job_id=job_data['job_id'],
            timeout=60*60,
            result_ttl=60*60*24,
            #on_success=DOSOMETHING,
            #on_failure=DOSOMETHINGELSE,
        )

        job_data['job_result_ids'].append(job_result.id)

    #* Serialize the job_data
    # job_data = json.dumps(job_data)
    # _log.debug(f"job_data: {pformat(job_data)}")

    return {"job_ids": job_data['job_result_ids'], "status": "Job submitted"}

async def hunt_stuff(
    job_data: Dict = None,
    worker_name: str = "",
):
    await wqm.check_config() #~ Make sure plugins and configs are loaded properly
    # DO THE HUNTING STUFF
    _log.debug(f"#### I'M FLYING, JACK! ####")
    _log.debug(f"job_data: \n\t {pformat(job_data)}")
    # time.sleep(15)
    #! await asyncio.sleep(job_data['sleep_time'])
    #! return "Hunt completed!"
    hunt_summary = {}
    #~ Set up the database connection
    tdb = get_tdb()
    #~ If "all" is passed, get all databases availble
    all_dbs = []
    if job_data['db_name'] == "all":
        dbs = result_error_catching(tdb.get_all_dbs, "Failed to fetch databases")
        for db in dbs:
            all_dbs.append(str(db))
    else:
        all_dbs.append(job_data['db_name'])

    #~ Get Plugin we're going to use
    plugin = wqm.conf.get(worker_name)['_plugin']
    _log.debug(f"Dumping config for {worker_name}")
    _log.debug(f"{pformat(plugin.config.dumpall())}")
    plugin_name = wqm.conf.get(worker_name)['_plugin_name']

    #~ Run Hunts against all databases selected
    #@ This needs to be broken down into separate jobs so we're nto waiting on
    #@ database updates or caching when we could be running more Censys/Shodan queries
    #& GOING TO BREAK ALL THIS OUT INTO SMALLER FUNCTIONS
    for db_name in all_dbs:
        tdb.db_name = db_name
        #* Find active hunts
        #@ JOB1
        all_active_hunts = plugin.find_active_hunts(tdb, ignore_freq=job_data['forced'])
        #* Narrow it down to only one hunt if we've explicitly provided a name
        if job_data['hunt_name'] and not job_data['hunt_name'].lower()=='all':
            active_hunts = {}
            for endpoint, hunts in all_active_hunts.items():
                for hunt in hunts:
                    if hunt.get_attributes(label='hunt-name')[0].value == job_data['hunt_name']:
                        active_hunts[endpoint]=[hunt]
        else:
            active_hunts = all_active_hunts
        #* Load cached hunts from disk
        #@ JOB2 - DEPENDS ON JOB1 SUCCESS
        #TODO - cached_hunts = cache_plugin.load_cached_hunts(active_hunts, plugin_name, db_name)
        #* Run hunts
        #@ JOB3 - DEPENDS ON JOB1 SUCCESS
        try:
            hunt_results = plugin.run_hunts(
                active_hunts = active_hunts,
                # TODO cached_hunts = cached_hunts,
            )
        except Exception as e:
            msg = f"Error running hunts: {e}"
            _log.error(msg)
            msg += f"\nTraceback: {traceback.format_exc()}"
            _log.error(f"Traceback: {traceback.format_exc()}")
            hunt_summary[db_name]=msg
            continue
        #* Cache hunts to disk
        #@ JOB4 - DEPENDS ON JOB1 AND JOB3 SUCCESS
        #TODO - cache_plugin.cache_hunt_results(active_hunts, hunt_results, plugin_name, db_name)
        #* Add results to database
        #@ JOB5 - DEPENDS ON JOB1 AND JOB3 SUCCESS
        #. NOTE - bulk_add_hunt_results should reall be a function of the
        #. ConnectorPlugin and not a HNTRPlugin, but it's not worth fixing 
        #. that right now.
        try:
            plugin.bulk_add_hunt_results(tdb, hunt_results)
            #* Do some quick stats
            stats = {}
            for _, hunt_names in hunt_results.items():
                for hunt_name, hunt_found in hunt_names.items():
                    stats[hunt_name] = {'attributes':0, 'entities': 0, 'relations': 0}
                    hunt = hunt_found['hunt']
                    found = hunt_found['found']
                    if not found['things']:
                        continue
                    for thing in found['things']:
                        if isinstance(thing, Attribute):
                            stats[hunt_name]['attributes']+=1
                        elif isinstance(thing, Entity):
                            stats[hunt_name]['entities']+=1
                        elif isinstance(thing, Relation):
                            stats[hunt_name]['relations']+=1
            msg = f"Succesfully finished hunts: \n{pformat(stats)}"
        except Exception as e:
            msg = f"Error adding hunt results: {e}"
            _log.error(msg)
            _log.error(f"Traceback: {traceback.format_exc()}")
        #* Add summary for this database
        hunt_summary[db_name] = msg

    #TODO - RUN ENRICHMENTS
    #@ JOB6 - DEPENDS ON JOB5 SUCCESS
    '''
    #* https://python-rq.org/docs/
    from redis import Redis
    from rq.job import Dependency
    from rq import Queue

    queue = Queue(connection=Redis())
    job_1 = queue.enqueue(div_by_zero)
    dependency = Dependency(
        jobs=[job_1],
        allow_failure=True,    # allow_failure defaults to False
        enqueue_at_front=True  # enqueue_at_front defaults to False
    )
    job_2 = queue.enqueue(say_hello, depends_on=dependency)

    """
    job_2 will execute even though its dependency (job_1) fails,
    and it will be enqueued at the front of the queue.
    """
    '''

    #~ Close the TDB session so it's not left hanging
    if tdb.session and tdb.session.is_open():
        _log.debug(f"Closing tdb session.")
        tdb.session.close()

    return hunt_summary