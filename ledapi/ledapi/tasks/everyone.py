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

from ledapi.config import(
    _log,
    led,
    get_tdb,
    wqm,
)
from ledapi.helpers import (
    two_sec_grace,
    result_error_catching
)
from ledapi.models import(
    SearchObject,
)
from ledapi.user import User
from ledapi.worker_manager import(
    get_available_worker
)
import os
# _log.debug(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}")
from typedb_client import TypeDBClient

#&##############################################################################
#& INTERNAL - TASKS/SUBTASK EXECUTION
#&
#& This is where the actual functions are processed, not just job queueing.
#&##############################################################################

#~######################################
#~ list_dbs() tasks
#~######################################

async def list_dbs_task(
    worker_name: str = None,
):
    """get list of all databases

    :param worker_name: worker for processing task, defaults to None
    :type worker_name: str, optional
    :raises Exception: If failed to retrieve list of databases
    :return: list of all databases found
    :rtype: List
    """
    _log.debug(f"Getting list of all databases...")
    all_dbs = []
    temp_plugin = wqm.conf.get(worker_name)['_plugin']
    #. TypeDBClient for whatever reason is "special" and needs to be fully launched fresh
    #. at runtime, so we'll load a new version of it, copy the ['_plugin'] settings,
    #. and start fresh.
    plugin = get_tdb(temp_plugin)
    plugin: TypeDBClient
    dbs = plugin.get_all_dbs()

    for db in dbs:
        all_dbs.append(str(db))

    _log.debug(f"Found all dbs: {all_dbs}")
    plugin.close_client()

    return all_dbs

#~######################################
#~ search() tasks
#~######################################

async def search_task(
    tdb: TypeDBClient = None,
    search_thing: Union[Entity, Relation] = None,
)->List:
    """search typedb database

    :param tdb: client we're using to search the database
    :type tdb: TypeDBClient, required
    :param search_thing: Search Object we're looking for
    :type search_thing: Union[Entity, Relation], required
    :return: List of Thing objects discovered in the database
    :rtype: List
    """
    _log.debug(f"Here we go... RUNNING THE SEARCH")
    things = tdb.find_things(search_thing)
    _log.debug(f"SEARCH COMPLETE!")
    return things

#~######################################
#~ get_news() tasks
#~######################################

async def news_task(
    tdb: TypeDBClient = None,
    days_back: int = 1,
    so: Union[Entity,Relation] = None,
    results: Dict = {},
):
    min_date = datetime.now(timezone.utc) - timedelta(days=days_back)

    all_dbs = []
    dbs = result_error_catching(tdb.get_all_dbs, "Failed to fetch databases")
    if not dbs:
        return results
    for db in dbs:
        all_dbs.append(str(db))
    for db_name in all_dbs:
        if db_name not in results['new_things']:
            results['new_things'][db_name] = {}
        tdb.db_name = db_name
        rez = []
        # ent_so = Entity(label='entity')
        things = result_error_catching( #! Change to handle_response()
            tdb.find_things,
            f"Error searching for {so}",
            so,
            comp_mod=[('date-discovered', '>', min_date)]
        )
        if not things:
            continue
        for thing in things:
            simple_attrs = {}
            skip_me = ['date-seen', 'ledid']
            for attr in thing.has:
                if attr.label in skip_me:
                    continue
                # y = {attr.label: attr.value}
                # simple_attrs.append(y)
                if attr.label not in simple_attrs:
                    simple_attrs[attr.label] = [attr.value]
                else:
                    simple_attrs[attr.label].append(attr.value)
            x = {'label': thing.label, 'value': thing.keyval, 'attrs':simple_attrs}
            rez.append(x)
        for ent in rez:
            if ent['label'] not in results['new_things'][db_name]:
                results['new_things'][db_name][ent['label']] = [{ent['value']: ent['attrs']}]
            else:
                results['new_things'][db_name][ent['label']].append({ent['value']: ent['attrs']})
        '''
        for thing in things:
            dd_attr = thing.get_attributes(label='date-discovered')[0]
            if isinstance(dd_attr.value, datetime) and dd_attr.value >= min_date:
                simple_attrs = {}
                skip_me = ['date-seen', 'ledid']
                for attr in thing.has:
                    if attr.label in skip_me:
                        continue
                    # y = {attr.label: attr.value}
                    # simple_attrs.append(y)
                    if attr.label not in simple_attrs:
                        simple_attrs[attr.label] = [attr.value]
                    else:
                        simple_attrs[attr.label].append(attr.value)
                x = {'label': thing.label, 'value': thing.keyval, 'attrs':simple_attrs}
                rez.append(x)
        for ent in rez:
            if ent['label'] not in results['new_things'][db_name]:
                results['new_things'][db_name][ent['label']] = [{ent['value']: ent['attrs']}]
            else:
                results['new_things'][db_name][ent['label']].append({ent['value']: ent['attrs']})
        '''

    return results

#&##############################################################################
#& INTERNAL - COMPLEX TASKING
#&
#& Handling complex tasks that require pre-configuration and/or
#& queueing multiple jobsConfig and Job Queuing
#&##############################################################################

#~######################################
#~ get_news config
#~######################################

async def get_news_conf(
    worker_name: str = None,
    days_back: int = 1,
    user: User = None,
):
    temp = wqm.conf.get(worker_name)['_plugin']
    _log.debug(f"temp: {temp}")
    tdb = get_tdb(temp)
    tdb: TypeDBClient

    results = {
        'new_things':{},
        'count': {},
    }

    so = Entity(label='entity')
    results = await news_task(tdb, days_back, so, results)
    so = Relation(label='relation')
    results = await news_task(tdb, days_back, so, results)
    #; Calc Stats
    for db_name, labels in results['new_things'].items():
        for label, vals in labels.items():
            if label not in results['count']:
                results['count'][label]=len(vals)
            else:
                results['count'][label]+=len(vals)

    tdb.close_client()
    return results

#~######################################
#~ search config
#~######################################

async def search_conf(
    worker_name: str = None,
    search_obj: SearchObject = None,
    user: User = None,
):
    """search database

    Consumes a JSON blob matching the following optional parameters:
    {
        'db_name': '<Name of database to search if different from default>',
        'label': '<Thing Label>',
        'new_days_back': int,
        'ttype': '<Type of Thing to return>',
        'value': '<Attribute Value>',
    }

    - db_name may be passed to search a different database than the one
        currently selected and assigned to tdb.db_name

    - At least one of 'label' or 'value' is required to execute a search

    - ttype can be either 'entity' or 'relation'. If not passed, defaults to 'entity'
        this is the type of object you would like to return with your search.

    - new_days_back if set will filter your results to only return those that
        have a date-discovered date >= this number of days back.

    :param search_obj: SearchObject containing label, value, ttype, and db_name
    :type search_obj: ledapi.models.everyone.SearchObject
    :param user: User submitting the request
    :type user: UserModel, required
    :return: Returns JSON serialized objects from the database
    :rtype: List[Dict]
    """
    _log.debug(f"Configuring search...")
    temp = wqm.conf.get(worker_name)['_plugin']
    _log.debug(f"temp: {temp}")
    tdb = get_tdb(temp)
    tdb: TypeDBClient

    if search_obj.ttype == 'entity': # * If we want to return all entities...
        # * and our search label is a known entity...
        if search_obj.label in led.all_labels['entity']:
            # * start with an Entity object with that label
            so = Entity(label=search_obj.label)
            # * if we also passed a value
            if search_obj.value:
                # * values only belong to Attributes, so we add a generic attribute
                # * with that value.
                so.has.append(Attribute(label='attribute', value=search_obj.value))
        # * if our search label is not a known entity, but is instead an Attribute...
        elif search_obj.label in led.all_labels['attribute']:
            # * ...and we have a value passed...
            if search_obj.value:
                # * ...create a specific attribute + value
                attr = Attribute(label=search_obj.label, value=search_obj.value)
            # * ...otherwise just use the Attribute label...
            else:
                attr = Attribute(label=search_obj.label)
            # * ...and attach it to a generic entity to get all entites with that attribute
            so = Entity(label='entity', has=[attr])
        # * What if we want to get all entities belonging to a Relation?
        # * I'm not sure how I'd handle that just yet...
        # * I think it would either be Entity.relations or Entity.plays
        # * But I'm also trying to avoid Relations at this stage, so I'm not
        # * worried about it right now
        # elif search_obj.label in led.all_labels['relation']:
        #     so = Relation(label=search_obj.label)
        #     if search_obj.value:
        #         so.has[Attribute(label='attribute', value=search_obj.value)]
    elif search_obj.ttype == 'relation': # * If we want to return all relations...
        # * and our search label is a known relation...
        if search_obj.label in led.all_labels['relation']:
            #* start with a Relation object with that label
            so = Relation(label=search_obj.label)
            # * if we also passed a value
            if search_obj.value:
                # * values only belong to Attributes, so we add a generic attribute
                # * with that value
                so.has.append(Attribute(label='attribute', value=search_obj.value))
        # * if our search label is not a known Relation, but is instead an Attribute...
        elif search_obj.label in led.all_labels['attribute']:
            # * ...and we have a value passed...
            if search_obj.value:
                # * ...create a specific attribute + value
                attr = Attribute(label=search_obj.label, value=search_obj.value)
            # * ...otherwise just use the Attribute label...
            else:
                attr = Attribute(label=search_obj.label)
            # * ...and attach it to a generic Relation to get all Relations with that Attribute
            so = Relation(label='relation', has=[attr])
        # * there's probably a better way to let us search for Relations with specific
        # * players belonging to Entity labels, or Relations with Player Entities that
        # * own a specific Attribute, but again - I'm trying to avoid Relations in this
        # * model, and don't want to waste too much time searching Relations when all
        # * of this will inevitably have to be changed in TypeDB 3.0 anyway...

    if search_obj.db_name:
        tdb.db_name = search_obj.db_name
    elif user.db_name and user.db_name!="all":
        tdb.db_name = user.db_name
        search_obj.db_name = user.db_name
    else:
        search_obj.db_name = tdb.db_name

    _log.debug(f"Search ready to run with search object {so}")

    things = await search_task(tdb, so)

    _log.debug(f"Found {len(things)} things!")
    if not things:
        return []
    verbose_rez = []
    simple_rez = []
    for thing in things:
        if search_obj.new_days_back:
            # * If we're focusing on only new stuff, make sure we grab
            # * the things with the date-discovered within our threshold
            min_date = datetime.now(timezone.utc) - timedelta(days=search_obj.new_days_back)
            dd_attr = thing.get_attributes(label='date-discovered')[0]
            if isinstance(dd_attr.value, datetime) and dd_attr.value >= min_date:
                verbose_rez.append(thing.to_dict())
                simple = {thing.label: thing.keyval}
                simple_rez.append(simple)
        else:
            verbose_rez.append(thing.to_dict())
            simple = {thing.label: thing.keyval}
            simple_rez.append(simple)

    if search_obj.verbose:
        rez = verbose_rez
    else:
        rez = simple_rez
    tdb.close_client()
    return rez

#&##############################################################################
#& API Endpoint-Facing Functions
#&##############################################################################

#~##########################
#~ List Databases
#~ Keeping this at the top b/c it's the simplest example to follow
#~##########################

async def list_dbs(
    # // user: User = None,
):
    """List all available databases

    :return: response dictionary of worker, job_id, and either job_status or
        final response of job if completed in < 2 seconds.
    :rtype: dict
    """
    await wqm.check_config() #~ Make sure plugins and configs are loaded properly
    worker_name = await get_available_worker('typedb_client')
    queue = wqm.conf[worker_name]['queue']
    job = queue.enqueue_call(
        list_dbs_task,
        args=[worker_name],
        timeout=10,
        result_ttl=60*5,
    )

    #! Wait 2 Seconds for response - if no response, queue job.
    response = await two_sec_grace(worker_name, job.id)

    return response

#~##########################
#~ Get the News
#~##########################

async def get_news(
    days_back: int = 1,
    user: User = None,
):
    await wqm.check_config() #~ Make sure everything is loaded first
    worker_name = await get_available_worker('typedb_client')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Adding search_conf job.")
    job = queue.enqueue_call(
        get_news_conf,
        args=[worker_name, days_back, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response

#~##########################
#~ Search Databases
#~##########################

async def search(
    search_obj: SearchObject = None,
    user: User = None,
):
    await wqm.check_config() #~ Make sure everything is loaded first
    worker_name = await get_available_worker('typedb_client')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Adding search_conf job.")
    job = queue.enqueue_call(
        search_conf,
        args=[worker_name, search_obj, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response