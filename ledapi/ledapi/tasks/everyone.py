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
from ledapi.helpers import (
    two_sec_grace,
    result_error_catching
)
from ledapi.user import User
from ledapi.worker_manager import(
    get_available_worker
)
import os
_log.debug(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}")
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
    plugin = wqm.conf.get(worker_name)['_plugin']
    plugin: TypeDBClient
    _log.debug(f"plugin: {plugin}")
    _log.debug(f"configs: {pformat(plugin.config.dumpall())}")
    '''
    try:
        _log.debug(f"ATTEMPTING TO GET DBS...")
        dbs = plugin.get_all_dbs()
        _log.debug(f"dbs: {dbs}")
    except Exception as e:
        _log.error(f"Failed fetching databases")
        _log.error(f"Traceback: {traceback.format_exec()}")
        raise Exception
    '''
    _log.debug(f"Attempt number 10000...")
    _log.debug(f"session: {plugin.session}") #! There's no session, cool - look into that.
    dbs = plugin.get_all_dbs()

    for db in dbs:
        all_dbs.append(str(db))

    _log.debug(f"Found all dbs: {all_dbs}")

    return all_dbs

#&##############################################################################
#& INTERNAL - COMPLEX TASKING
#&
#& Handling complex tasks that require pre-configuration and/or
#& queueing multiple jobsConfig and Job Queuing
#&##############################################################################

#~######################################
#~ run_hunt() config & queue
#~######################################

'''
async def run_hunt_conf(
    job_data: Dict = None,
    worker_name: str = "",
):

async def run_hunt_job_queue(
    db_name: str = None,
    worker_name: str = None,
    forced: bool = False,
    hunt_name: str = None,
):
'''

#&##############################################################################
#& API Endpoint-Facing Functions
#&##############################################################################

#~##########################
#~ List Databases
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
        timeout=60*60,
        result_ttl=60*60*24,
    )

    #! Wait 2 Seconds for response - if no response, queue job.
    response = await two_sec_grace(worker_name, job.id)

    return response

#~##########################
#~ Search Databases
#~##########################