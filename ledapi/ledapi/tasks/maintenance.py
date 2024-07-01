import time
import traceback

from datetime import datetime, timedelta, timezone
from fastapi import Query
from pprint import pformat
import redis as syncredis
from redis.asyncio.client import Redis
from rq import Queue, Worker, Connection
from rq.job import Job
from rq.registry import (
    FailedJobRegistry,
    FinishedJobRegistry,
    ScheduledJobRegistry,
    StartedJobRegistry,
    DeferredJobRegistry,
)
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
    redis_manager,
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

async def clean_queues_task(
    hours_back: Optional[int] = 24,
    user: User = None,
):
    await wqm.check_config()
    await redis_manager.check_redis_conn()
    queues = {}
    # for queue_name, queue in wqm.queues.items():
    for worker_name, details in wqm.conf.items():
        queue = details['queue']
        queue_name = details['queue'].name
        queues[queue_name] = {}
        fin_reg = FinishedJobRegistry(queue_name, connection=redis_manager.syncredis)
        fail_reg = FailedJobRegistry(queue_name, connection=redis_manager.syncredis)
        def_reg = DeferredJobRegistry(queue.name, connection=redis_manager.syncredis)
        registries = [fin_reg, fail_reg, def_reg]

        # Delete jobs older than 24 hrs
        # now = int(datetime.now(timezone.utc).timestamp())
        # yesterday = now-60*60*24
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        # fin_reg.cleanup(timestamp=yesterday)
        # fail_reg.cleanup(timestamp=yesterday)
        for reg in registries:
            job_counter = 0
            queues[queue_name][reg.name] = {'deleted_jobs': 0}
            for job_id in reg.get_job_ids():
                job = Job.fetch(job_id, connection=redis_manager.syncredis)
                if job.enqueued_at is not None:
                    job.enqueued_at = job.enqueued_at.replace(tzinfo=timezone.utc)
                    if job.enqueued_at < cutoff:
                        job_counter += 1
                        job.delete_dependents()
                        job.delete()
            queues[queue_name][reg.name]['deleted_jobs'] = job_counter

    return queues


#&##############################################################################
#& INTERNAL - COMPLEX TASKING
#&
#& Handling complex tasks that require pre-configuration and/or
#& queueing multiple jobsConfig and Job Queuing
#&##############################################################################

#~######################################
#~ get_news config
#~######################################

'''
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
'''


#&##############################################################################
#& API Endpoint-Facing Functions
#&##############################################################################

#~##########################
#~ Clean Queues
#~##########################

async def clean_queues(
    hours_back: Optional[int] = 24,
    user: User = None,
):
    await wqm.check_config()
    worker_name = await get_available_worker('maintenance')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing cleanup_jobs")

    job = queue.enqueue_call(
        clean_queues_task,
        args=[hours_back, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response