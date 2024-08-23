import logging
import time
import traceback

from datetime import datetime, timedelta, timezone
from fastapi import Query
from pprint import pformat
from redis.asyncio.client import Redis
from rq import Queue, Worker
from rq.job import Job, Dependency
from typing import Dict, List, Optional, Union

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

from ledhntr.helpers import xterm

from ledapi.config import(
    _log,
    led,
    get_tdb,
    wqm,
)
from ledapi.helpers import(
    result_error_catching,
    two_sec_grace,
)
from ledapi.user import User
from ledapi.worker_manager import(
    get_available_worker
)
from ledapi.models import(
    JobSubmission,
    ThingSubmission,
    ThingUpdate,
)

from typedb_client import TypeDBClient

#&##############################################################################
#& Internal Functions
#&##############################################################################
#~######################################
#~ Add Thing Task
#~######################################
async def add_thing_task(
    thing: ThingSubmission,
    user: User,
)->Union[Relation,Entity]:

    _log.debug(f"Adding thing {thing.thing} to database")
    if (tdb := get_tdb(db_name=thing.db_name)) is None:
        _log.error(f"Invalid database: {thing.db_name}")
        return False
    try:
        rez = tdb.add_thing(thing.thing, return_things=True)
    except Exception as e:
        _log.error(f"Failed finding hunts: {e}")
        _log.error(f"Traceback: {traceback.format_exc()}")
        tdb.close_client()
        raise Exception
    # return rez.to_dict()
    tdb.close_client()
    return rez

#~######################################
#~ Replace Attributes Task
#~ Used for updating actor-name or tags associated with a thing
#~######################################
async def replace_attributes_task(
    thingup: ThingUpdate,
    user: User,
)->Union[Relation, Entity]:
    _log.debug(f"Updating {thingup.attr_label} on {thingup.iid} in {thingup.db_name}")
    if (tdb := get_tdb(db_name=thingup.db_name)) is None:
        _log.error(f"Invalid database: {thingup.db_name}")
        return False
    tdb:TypeDBClient
    #; Pre-process for confidence == 0.0
    #; If it's explicitly set to 0, set it to 0.1 so we can mark it as
    #; having been touched.
    if thingup.attr_label=='confidence':
        if int(thingup.attr_values[0])==0:
            _log.debug(f"{xterm('BOLD_GREEN')}Setting confidence to 0.1{xterm('RESET')}")
            thingup.attr_values[0]=0.1
    try:
        so = Entity(label='entity')
        so.iid = thingup.iid
        #; Get the existing thing
        old_thing = tdb.find_things(so)[0]
        _log.debug(f"Retrieved {old_thing}")
        #; Get all attributes of this attr_label
        existing_attributes = old_thing.attrs(thingup.attr_label)
        _log.debug(f"Existing: {existing_attributes}")
        if existing_attributes is None:
            existing_attributes = []
        if not isinstance(existing_attributes, list):
            existing_attributes = [existing_attributes]
        #; If there's an existing value that's not in our new list
        #; remove it from the old thing
        _log.debug(f"existing_attributes: {existing_attributes}")
        _log.debug(f"thingup.attr_values: {thingup.attr_values}")
        for ea in existing_attributes:
            if ea not in thingup.attr_values:
                attr = Attribute(label=thingup.attr_label, value=ea)
                _log.debug(f"{xterm('BOLD_RED')}Detatching {attr} from {old_thing}")
                tdb.detach_attribute(
                    old_thing=old_thing,
                    attr=attr,
                )
        if existing_attributes:
            old_thing = tdb.find_things(so)[0]
            _log.debug(f"Retrieved updated {old_thing}")
        #; If there's something new in our list, add it.
        existing_attributes = old_thing.attrs(thingup.attr_label)
        if existing_attributes is None:
            existing_attributes = []
        if not isinstance(existing_attributes, list):
            existing_attributes = [existing_attributes]
        for new_attr in thingup.attr_values:
            attr = Attribute(label=thingup.attr_label, value=new_attr)
            if attr.value not in existing_attributes:
                _log.debug(f"{xterm('BOLD_GREEN')}Attaching {attr} to {old_thing}")
                old_thing = tdb.attach_attribute(
                    old_thing=old_thing,
                    attr=attr,
                    return_things=True,
                )
        if user.uuid:
            _log.debug(f"Attaching user-uuid {user.uuid} for {user.user_id} to {old_thing}")
            things = tdb.attach_attribute(
                old_thing,
                Attribute(label='user-uuid', value=user.uuid),
            )
        _log.debug(f"Final {thingup.attr_label}(s) for {old_thing}:\n"
                   f"{pformat(old_thing.attrs(thingup.attr_label))}")
    except Exception as e:
        _log.error(f"Failed finding hunts: {e}")
        _log.error(f"Traceback: {traceback.format_exc()}")
        tdb.close_client()
        raise Exception
    tdb.close_client()
    return old_thing


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
    hntr_plugin:HNTRPlugin = wqm.conf.get(hntr_worker_name)['_plugin']
    try:
        low_logging = False
        if _log.getEffectiveLevel() < logging.INFO:
            low_logging = True
            _log.setLevel('INFO')
        all_active_hunts = hntr_plugin.find_active_hunts(tdb, ignore_freq=forced)
        if low_logging:
            _log.setLevel('DEBUG')
        #* Narrow it down to only one hunt if we've explicitly provided a name
        if hunt_name and not hunt_name.lower()=='all':
            active_hunts = {}
            for endpoint, hunts in all_active_hunts.items():
                for hunt in hunts:
                    if hunt.get_attributes(label='hunt-name')[0].value == hunt_name:
                        active_hunts[endpoint]=[hunt]
        else:
            active_hunts = all_active_hunts
        _log.debug(f"{xterm('CYAN')}Found hunts: {active_hunts}{xterm('X')}")
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
    _log.setLevel('INFO')
    queue = wqm.conf.get(hntr_worker_name)['queue']
    last_job = queue.fetch_job(active_hunts_id)
    while not last_job.is_finished:
        _log.debug(f"{last_job.id} still not finished...")
        time.sleep(1)
    active_hunts = last_job.result
    _log.debug(f"Running active hunts.")
    hntr_plugin:HNTRPlugin = wqm.conf.get(hntr_worker_name)['_plugin']
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

    _log.setLevel('DEBUG')
    return hunt_results

#TODO RUN HUNT JOB4 - CACHE HUNT RESULTS TO DISK - DEPENDS ON JOB3 SUCCESS

#@ RUN HUNT JOB5 - ADD RESULTS TO DB - DEPENDS ON JOB3 SUCCESS
async def add_hunt_results_task(
    hntr_worker_name: str = None,
    db_name: str = None,
    hunt_results_id: str = None,
):
    _log.setLevel('INFO')
    queue = wqm.conf.get(hntr_worker_name)['queue']
    last_job = queue.fetch_job(hunt_results_id)
    while not last_job.is_finished:
        _log.debug(f"{last_job.id} still not finished...")
        time.sleep(1)
    hunt_results = last_job.result
    _log.debug(f"Adding hunt_results...")
    hntr_plugin:HNTRPlugin = wqm.conf.get(hntr_worker_name)['_plugin']
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
        msg = f"{xterm('GREEN')}Succesfully finished hunts: \n{pformat(stats)}{xterm('X')}"
    except Exception as e:
        msg = f"{xterm('RED')}Error adding hunt results: {e}{xterm('X')}"
        _log.error(msg)
        _log.error(f"Traceback: {traceback.format_exc()}")
    #~ Convert Hostname to Domain
    try:
        tdb.convert_hostname_to_domain()
    except Exception as e:
        msg += f"\n{xterm('RED')}Error converting hostname to domain: {e}{xterm('X')}"
        _log.error(e)
        _log.error(f"Traceback: {traceback.format_exc()}")
    #~ Update first/last seen
    try:
        tdb.super_update_first_last_seen()
    except Exception as e:
        msg += f"\n{xterm('RED')}Error updating first/last-seen times: {e}{xterm('X')}"
        _log.error(e)
        _log.error(f"Traceback: {traceback.format_exc()}")
    #~ Purge abandoned attributes
    try:
        tdb.purge_abandoned_attributes()
    except Exception as e:
        msg += f"\n{xterm('RED')}Error purging abandoned attributes: {e}{xterm('X')}"
        _log.error(e)
        _log.error(f"Traceback: {traceback.format_exc()}")
    tdb.close_client()
    _log.setLevel('DEBUG')
    _log.debug(msg)
    # // _log.debug(f"{xterm('YELLOW')}{pformat(hunt_results)}{xterm('X')}")
    return msg

#TODO RUN HUNT JOB6 - RUN ENRICHMENTS - DEPENDS ON JOB5 SUCCESS

#&##############################################################################
#& Internal Task Config and Job Queuing
#&##############################################################################

#~######################################
#~ run_hunt() config & queue
#~######################################

async def run_hunt_conf(
    job_data: JobSubmission = None,
    worker_name: str = "",
    user: User = None,
):
    # // _log.debug(f"#### I'M FLYING, JACK! ####")
    # // _log.debug(f"job_data: \n\t {pformat(job_data)}")
    #& The worker here is going to be 'maintenance'
    _log.debug(f"worker_name: {worker_name}")
    await wqm.check_config(worker_name)
    hunt_summary = {}

    job_data = {
        "db_name": job_data.db_name or user.db_name,
        "hunt_name": job_data.hunt_name,
        "plugin": job_data.plugin,
        "status": "pending",
        "user_id": user.user_id,
        "forced": job_data.forced,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "job_result_ids": [],
    }
    _log.debug(f"Processing job data: {pformat(job_data)}")
    #@ Get plugins we want to run
    plugins = []
    led_plugin_list = led.list_plugins()
    #* If we don't specify a plugin or explicitly specify 'all' then use all plugins
    if job_data['plugin'] == None or job_data['plugin'].lower() == 'all':
        for _, details in wqm.conf.items():
            plugin_name = details['_plugin_name']
            if plugin_name not in plugins:
                if plugin_name not in led_plugin_list:
                    #; Ignore invalid plugins like 'maintenance'
                    continue
                if led_plugin_list[plugin_name]['classes'][0] != "HNTR":
                    #; ignore non-HNTR plugins
                    continue
                plugins.append(plugin_name)
    #* otherwise, just use the plugin specified
    else:
        plugins.append(job_data['plugin'].lower())

    #@ Get targeted database(s)
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

    #@ Loop through HNTR plugins queues and databases to run everything
    _log.debug(f"plugins: {plugins}")
    for plugin_name in plugins:
        _log.debug(f"Getting worker for {plugin_name}")
        # await wqm.check_config(plug_worker)
        #~ Get the worker_name
        hunt_summary[plugin_name] = {}
        plug_worker = await get_available_worker(plugin_name)
        #~ Get the Queue we're going to use for each HNTR Plugin
        queue = wqm.conf[plug_worker]['queue']

        #~ Run Hunts against all databases selected
        for db_name in all_dbs:
            try:
                forced = job_data['forced']
                hunt_name = job_data['hunt_name']
                hunt_db_job = queue.enqueue_call(
                    run_hunt_job_queue,
                    args=[db_name, plug_worker, forced, hunt_name],
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
            hunt_summary[plugin_name][db_name] = {}
            hunt_summary[plugin_name][db_name]['job_id'] = hunt_db_job.id

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
    _log.setLevel('INFO')
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
    _log.setLevel('DEBUG')
    return result

#&##############################################################################
#& API Endpoint-Facing Functions
#&##############################################################################

#~##########################
#~ Add a thing to the database
#~##########################
async def add_thing_handler(
    thing: ThingSubmission,
    user: User,
):
    worker_name = await get_available_worker('typedb_client')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing add_thing_handler")

    job = queue.enqueue_call(
        add_thing_task,
        args=[thing, user],
        timeout=60,
        result_ttl=60*24,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response

#~##########################
#~ Replace Attributes of a Thing
#~##########################
async def replace_attributes_handler(
    thing: ThingUpdate,
    user: User,
):
    worker_name = await get_available_worker('typedb_client')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing add_thing_handler")

    job = queue.enqueue_call(
        replace_attributes_task,
        args=[thing, user],
        timeout=60,
        result_ttl=60*24,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response

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
    tdb.close_client()
    return results

#~###############
#~ Run a Hunt
#~###############

async def hunt_handler(
    job_data: JobSubmission = None,
    user: User = None,
    slack_format: Optional[bool] = False
):
    worker_name = await get_available_worker('maintenance')
    # // _log.debug(f"wqm.conf: {pformat(wqm.conf)}")
    await wqm.check_config(worker_name)
    # // _log.debug(f"wqm.conf: {pformat(wqm.conf)}")
    queue = wqm.conf[worker_name]['queue']
    queue: Queue

    job = queue.enqueue_call(
        run_hunt_conf,
        args=[job_data, worker_name, user],
        timeout=60*60,
        result_ttl=60*60*24,
    )

    response = await two_sec_grace(worker_name, job.id, slack_format=slack_format)

    return response





