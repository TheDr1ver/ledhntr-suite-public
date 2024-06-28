import time
import traceback

from datetime import datetime, timedelta, timezone
from fastapi import Query
from pprint import pformat
from redis.asyncio.client import Redis
from rq import Queue, Worker
from rq.job import Job, Dependency
from typing import Dict, List, Optional

from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)
from ledhntr.plugins import (
    HNTRPlugin,
    ConnectorPlugin,
    AnalyzerPlugin
)

from ledapi.config import(
    _log,
    led,
    get_tdb,
    wqm,
)
from ledapi.helpers import result_error_catching
from ledapi.user import User
from ledapi.worker_manager import(
    get_available_worker
)

#&##############################################################################
#& Internal Functions
#&##############################################################################

#~######################################
#~ run_hunt() tasks
#~######################################

#@ RUN HUNT JOB1 - FIND ACTIVE HUNTS
async def find_active_hunts_task(
    db_name: str = None,
    hntr_worker_name: str = None,
    forced: bool = False,
    hunt_name: str = None,
)->Dict:
    """find active hunts for a given plugin in a specific database

    :param db_name: name of the database to access, defaults to None
    :type db_name: str, required
    :param hntr_worker_name: Name of worker to pull plugin from. Plugin is
        associated with active hunts, defaults to None
    :type hntr_worker_name: str, required
    :param job_data: job_data passed from the user, defaults to None
    :type job_data: Dict, optional
    :return: All active hunts for the given plugin in the DB
    :rtype: Dict
    """
    _log.debug(f"Finding active hunts...")
    tdb = get_tdb()
    tdb.db_name = db_name
    #* Find active hunts
    hntr_plugin = wqm.conf.get(hntr_worker_name)['_plugin']
    try:
        all_active_hunts = hntr_plugin.find_active_hunts(tdb, ignore_freq=forced)
        #* Narrow it down to only one hunt if we've explicitly provided a name
        if hunt_name and not hunt_name.lower()=='all':
            active_hunts = {}
            for endpoint, hunts in all_active_hunts.items():
                for hunt in hunts:
                    if hunt.get_attributes(label='hunt-name')[0].value == hunt_name:
                        active_hunts[endpoint]=[hunt]
        else:
            active_hunts = all_active_hunts
        tdb.close_client()
    except Exception as e:
        _log.error(f"Failed finding hunts: {e}")
        _log.error(f"Traceback: {traceback.format_exc()}")
        tdb.close_client()
        raise Exception
    return active_hunts

#TODO RUN HUNT JOB2 - LOAD CACHED HUNTS FROM DISK - DEPENDS ON JOB1 SUCCESS

#@ RUN HUNT JOB3 - RUN HUNTS - DEPENDS ON JOB1 SUCCESS (and uses job2 results if any)
async def run_hunts_task(
    hntr_worker_name: str = None,
    active_hunts_id: str = None, # job_id
    #TODO cached_hunts: Dict = None,
):
    # while not active_hunts.is_finished:
    queue = wqm.conf.get(hntr_worker_name)['queue']
    last_job = queue.fetch_job(active_hunts_id)
    while not last_job.is_finished:
        _log.debug(f"{last_job.id} still not finished...")
        time.sleep(1)
    active_hunts = last_job.result
    _log.debug(f"Running active hunts.")
    hntr_plugin = wqm.conf.get(hntr_worker_name)['_plugin']
    try:
        hunt_results = hntr_plugin.run_hunts(
            active_hunts = active_hunts,
            # TODO cached_hunts = cached_hunts,
        )
    except Exception as e:
        msg = f"Error running hunts: {e}"
        _log.error(msg)
        msg += f"\nTraceback: {traceback.format_exc()}"
        _log.error(f"Traceback: {traceback.format_exc()}")
        raise Exception

    return hunt_results

#TODO RUN HUNT JOB4 - CACHE HUNT RESULTS TO DISK - DEPENDS ON JOB3 SUCCESS

#@ RUN HUNT JOB5 - ADD RESULTS TO DB - DEPENDS ON JOB3 SUCCESS
async def add_hunt_results_task(
    hntr_worker_name: str = None,
    db_name: str = None,
    hunt_results_id: str = None,
):
    queue = wqm.conf.get(hntr_worker_name)['queue']
    last_job = queue.fetch_job(hunt_results_id)
    while not last_job.is_finished:
        _log.debug(f"{last_job.id} still not finished...")
        time.sleep(1)
    hunt_results = last_job.result
    _log.debug(f"Adding hunt_results...")
    hntr_plugin = wqm.conf.get(hntr_worker_name)['_plugin']
    tdb = get_tdb()
    tdb.db_name = db_name
    try:
        hntr_plugin.bulk_add_hunt_results(tdb, hunt_results)
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
    tdb.close_client()
    return msg

#TODO RUN HUNT JOB6 - RUN ENRICHMENTS - DEPENDS ON JOB5 SUCCESS

#&##############################################################################
#& Internal Task Config and Job Queuing
#&##############################################################################

#~######################################
#~ run_hunt() config & queue
#~######################################

async def run_hunt_conf(
    job_data: Dict = None,
    worker_name: str = "",
):
    await wqm.check_config() #~ Make sure plugins and configs are loaded properly
    _log.debug(f"#### I'M FLYING, JACK! ####")
    _log.debug(f"job_data: \n\t {pformat(job_data)}")
    hunt_summary = {}

    #~ Get targeted database(s)
    all_dbs = []
    #~ If "all" is passed, get all databases availble
    if job_data['db_name'] == "all":
        #~ Set up the database connection
        tdb = get_tdb()
        dbs = result_error_catching(tdb.get_all_dbs, "Failed to fetch databases") #! Change to handle_response()
        for db in dbs:
            all_dbs.append(str(db))
        tdb.close_client()
    else:
        all_dbs.append(job_data['db_name'])

    #~ Get the Queue we're going to use
    queue = wqm.conf[worker_name]['queue']
    #! Honestly, this should probably be changed to a separate 'hunt' queue
    #! Doesn't make much sense to be adding it to a HNTR Plugin queue that
    #! should be dedicated for scanning

    #~ Run Hunts against all databases selected
    for db_name in all_dbs:
        try:
            forced = job_data['forced']
            hunt_name = job_data['hunt_name']
            hunt_db_job = queue.enqueue_call(
                run_hunt_job_queue,
                args=[db_name, worker_name, forced, hunt_name],
                timeout=60*60*2,
                result_ttl=60*60*24,
            )
        except Exception as e:
            _log.error(f"Failed running hunt against {db_name}: {e}")
            _log.error(f"Traceback: {traceback.format_exc()}")
            continue

        #* Add summary for this database
        # hunt_summary[db_name] = bulk_add_results
        hunt_db_job: Job
        hunt_summary[db_name] = {}
        hunt_summary[db_name]['job_id'] = hunt_db_job.id

    return hunt_summary

async def run_hunt_job_queue(
    db_name: str = None,
    worker_name: str = None,
    forced: bool = False,
    hunt_name: str = None,
):
    #. This only works like this right now because it's all reliant on the same
    #. worker/plugin. Once I have Job1 and 3 functionality inside the TypeDB_Client
    #. and Job2 functionality inside the HNTR plugin it will speed things up.
    #. As such, I'm going to submit them to separate jobs in the queue for now
    #. knowing that at a later date I'll have Queue1 for TypeDB-only stuff and 
    #. Queue2 for HNTR/{worker_name}-only stuff and they will be better distributed.
    """
    active_hunts = await find_active_hunts(
        db_name,
        worker_name,
        forced,
        hunt_name,
    )
    hunt_results = await run_hunts(worker_name, active_hunts)
    bulk_add_results = await add_hunt_results(worker_name, db_name, hunt_results)
    return bulk_add_results
    """

    result = {
        "active_hunts": None,
        "hunt_results": None,
        "bulk_add_results": None,
        "result": None,
    }

    #@ Queue find_active_hunts JOB1
    queue = wqm.conf[worker_name]['queue'] #~ Queue for HNTR Worker
    active_hunts = queue.enqueue_call(
        find_active_hunts_task,
        args=[db_name, worker_name, forced, hunt_name],
        timeout=60*5,
        result_ttl=60*60*2,
    )
    result['active_hunts'] = active_hunts.id

    #* Load cached hunts from disk
    #TODO JOB2 - DEPENDS ON JOB1 SUCCESS
    #TODO - cached_hunts = cache_plugin.load_cached_hunts(active_hunts, plugin_name, db_name)
    #TODO - We'll be grabbing a cache_plugin worker via _get_available_worker() for this

    #@ Set Dependency for JOB3
    run_hunts_dep = Dependency(
        jobs=[active_hunts],
        allow_failure=False,    # allow_failure defaults to False
        enqueue_at_front=False  # enqueue_at_front defaults to False
    )

    #@ Queue run_hunts JOB3
    hunt_results = queue.enqueue_call(
        run_hunts_task,
        depends_on=run_hunts_dep,
        args=[worker_name, active_hunts.id],
        timeout=60*60,
        result_ttl=60*60*24,
    )
    result['hunt_results'] = hunt_results.id

    #* Cache hunts to disk
    #TODO JOB4 - CACHE HUNTS TO DISK - DEPENDS ON JOB1 AND JOB3 SUCCESS
    #TODO - cache_plugin.cache_hunt_results(active_hunts, hunt_results, plugin_name, db_name)

    #@ Set Dependency for JOB5
    bulk_add_dep = Dependency(
        jobs=[hunt_results]
    )
    # clean_hr = await _clean_data(hunt_results.result)
    #@ Queue run_hunts JOB5
    bulk_add_results = queue.enqueue_call(
        add_hunt_results_task,
        depends_on=bulk_add_dep,
        args=[worker_name, db_name, hunt_results.id],
        timeout=60*60*4, #4 hrs is extreme - in no world should it take this long
        result_ttl=60*60*24,
    )
    result['bulk_add_results'] = bulk_add_results.id
    result['result'] = bulk_add_results.id

    #TODO - RUN ENRICHMENTS
    #TODO JOB6 - RUN ENRICHMENTS - DEPENDS ON JOB5 SUCCESS
    #TODO NOTE - this should never be queued run with 'force' inside hunt_stuff()
    #TODO Essentially we're just adding a job to enrich stuff when and if
    #TODO JOBS 1-5 successfully complete. Otherwise enrichments should be checked
    #TODO every hour on their own anyway.

    #@ Return all subsequent job_ids
    return result

#&##############################################################################
#& API Endpoint-Facing Functions
#&##############################################################################

#~##########################
#~ List all Active Hunts
#~##########################

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
    # TODO - THIS NEEDS TO BE TURNED INTO A QUEUED JOB WITH A 2-SEC TIMER
    tdb = get_tdb()
    # tdb = wqm.conf['typedb_client.01']['_plugin'] #! This works, so why can't I get list_dbs to work?
    results = {
        'results': {},
        'count': 0,
    }
    all_dbs = []
    if user.db_name == "all":
        dbs = result_error_catching(tdb.get_all_dbs, "Failed to fetch databases") #! Change to handle_response()
        for db in dbs:
            all_dbs.append(str(db))
    else:
        all_dbs.append(user.db_name)

    for db in all_dbs:
        tdb.db_name = db
        so = Entity(label='hunt', has=[Attribute(label='hunt-active', value=True)])
        res = result_error_catching(tdb.find_things, f"Failed searching for {so}", so) #! Change to handle_response()
        tdb.close_client()
        if not res:
            _log.debug(f"No results for {so} in {tdb.db_name}")
            continue
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

#~###############
#~ Run a Hunt
#~###############

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

    for plugin_name in plugins:
        worker_name = await get_available_worker(plugin_name)
        queue = wqm.conf[worker_name]['queue']

        job_result = queue.enqueue_call(
            run_hunt_conf,
            args=[job_data, worker_name],
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







