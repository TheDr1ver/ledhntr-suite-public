import asyncio
import os
import time
import traceback

from datetime import datetime, timedelta, timezone
from pprint import pformat
from typing import Dict, List, Optional, Union

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
    xterm,
)
from ledapi.helpers import (
    two_sec_grace,
    result_error_catching
)
from ledapi.models import(
    SearchObject,
    JobSubmission,
)
from ledapi.tasks import(
    hunt_handler,
    slack_post_message,
    get_news_conf,
)
from ledapi.user import User
from ledapi.worker_manager import(
    get_available_worker,
    schedule_bg_task,
)

# _log.debug(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}")

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
    # ! await wqm.check_config()
    _log.debug(f"{xterm('GREEN')} Launching Cleaning Queues Task...{xterm('X')}")
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
    _log.debug(f"{xterm('GREEN')}Finished clearing queues: \n{pformat(queues)}{xterm('X')}")
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
#~######################################
#~ auto_hunt config
#~######################################

async def auto_hunt_conf(
    db_name: Optional[str] = 'all',
    hunt_name: Optional[str] = 'all',
    plugin: Optional[str] = 'all',
    forced: Optional[bool] = False,
    timeout: Optional[int] = 60*60,
    result_ttl: Optional[int] = 60*60*24,
):
    job_data = JobSubmission()
    user = User()

    job_data.db_name = db_name
    job_data.hunt_name = hunt_name
    job_data.plugin = plugin
    job_data.forced = forced
    user.user_id = "AUTOMATED"
    slack_format = False

    worker_name = await get_available_worker('maintenance')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing auto_hunt")

    job = queue.enqueue_call(
        hunt_handler,
        args=[job_data, user, slack_format],
        timeout=timeout,
        result_ttl=result_ttl,
    )

    response = await two_sec_grace(worker_name, job.id, slack_format=True)
    # TODO - POST to Slack that hunt job has begun
    # TODO - Add job_id polling loop
    # TODO - Once job is finished/failed/cancelled, post results to Slack.

    # return response
    # TODO - if success, return True. If failed, return False.
    _log.debug(f"response: \n{pformat(response)}")
    return True

#~##############################
#~ post_news config
#~##############################

async def post_news(
    hours_back: int = 24,
    verbose: bool = False,
    bot_workers: List[str] = [],
    channel: str = "#mojo-dev", # TODO - Get rid of this and roll it into a ConnectorPlugin
):
    bot_post_funcs = {
        'slackbot': slack_post_message,
    }

    text_lines = []

    interesting_things = [
        'domain',
        'hostname',
        'ip',
        'jarm',
        'ja3s',
        'ssl',
        'http',
    ]

    news_results = await get_news_conf(hours_back)
    _log.debug(f"{xterm('CYAN')}{pformat(news_results)}{xterm('X')}")
    new_things = news_results.get('new_things')
    if not new_things:
        return None
    if verbose:
        for bot in bot_workers:
            if bot not in bot_post_funcs:
                _log.error(f"No handler specified for {bot}")
                continue
            bot_worker_name = await get_available_worker(bot)
            # // _log.debug(f"{xterm('CYAN')}{bot_worker_name} configs: \n{pformat(wqm.conf[bot_worker_name])}{xterm('X')}")
            token = wqm.conf[bot_worker_name]['settings']['token']
            #; This is something else that should be specific to the chat
            #; plugin, but again... MVP... just trying to get it out the door.
            text = f"```{news_results.get('result').get('count')}```"
            blocks = [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f"```{new_things}```",
                    }
                }
            ]
            await bot_post_funcs[bot](
                token,
                channel,
                text,
                blocks,
            )
        return True

    for db, thing_types in new_things.items():
        text_lines.append(f"*{db}*")
        for tt, entries in thing_types.items():
            if tt in interesting_things:
                text_lines.append(f"_{tt}_")
            for e in entries:
                for keyval, attributes in e.items():
                    text_lines.append(f"```{keyval}")
                    for label, values in attributes.items():
                        text_lines.append(f"\t{label}")
                        for value in values:
                            text_lines.append(f"\t\t{value}")
                    text_lines.append(f"```")

    for bot in bot_workers:
        if bot not in bot_post_funcs:
            _log.error(f"No handler specified for {bot}")
            continue
        bot_worker_name = await get_available_worker(bot)
        # // _log.debug(f"{xterm('CYAN')}{bot_worker_name} configs: \n{pformat(wqm.conf[bot_worker_name])}{xterm('X')}")
        token = wqm.conf[bot_worker_name]['settings']['token']
        #; This is something else that should be specific to the chat
        #; plugin, but again... MVP... just trying to get it out the door.
        text = "\n".join(text_lines)
        blocks = []
        '''
        for line in text_lines:
            block_section = {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': line,
                }
            }
            blocks.append(block_section)
        '''
        blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': text,
                }
            }
        ]

        await bot_post_funcs[bot](
            token,
            channel,
            text,
            blocks,
        )

    return True


#&##############################################################################
#& MAIN WRAPPER
#&##############################################################################

#~##############################
#~ Check Automation Schedule
#~##############################

async def check_automation_schedules(
    bg_tasks: List[asyncio.Task] = [],
    bot_workers: List[str] = [],
    channel: str = "#mojo-dev", # TODO - Get rid of this and roll it into a ConnectorPlugin
):
    bot_post_funcs = {
        'slackbot': slack_post_message,
    }

    text_lines = []

    for bgt in bg_tasks:
        bgt: asyncio.Task
        task_key = f"{bgt.get_name()}_run_time"
        await redis_manager.check_redis_conn()
        await wqm.check_config()
        # worker_name = await get_available_worker('maintenance')
        # queue: Queue = wqm.conf[worker_name]['queue']

        next_run_time = await redis_manager.redis.get(task_key)
        if next_run_time:
            next_run_time = datetime.fromisoformat(next_run_time.decode())
            text = f"`{bgt.get_name()}` scheduled to run at `{next_run_time}`"
            text_lines.append(text)
            _log.debug(f"{xterm('MAGENTA')}{text}{xterm('RESET')}")
        else:
            text = f"`{bgt.get_name()}` not yet scheduled! Run `/mojo check-schedules` to check again."
            text_lines.append(text)
            _log.debug(f"{xterm('RED')}{text}{xterm('RESET')}")

    # TODO - This is going to need some loving. I think ultimately I'll
    # TODO - have to create each bot as an LEDHNTR Connector Plugin and
    # TODO - make sure they have the same normalized function names going
    # TODO - forward. The idea is to make it as simple as possible to have
    # TODO - multiple chat bots that post messages to different channels
    # TODO - but considering they all auth differently and handle messages
    # TODO - differently, there will have to be some normalization for each
    # TODO - individual Chat Connector Plugin.
    # TODO - Right now I'm just going to code it for Slack since that's
    # TODO - what I'm working on for MVP.
    for bot in bot_workers:
        if bot not in bot_post_funcs:
            _log.error(f"No handler specified for {bot}")
            continue
        bot_worker_name = await get_available_worker(bot)
        # // _log.debug(f"{xterm('CYAN')}{bot_worker_name} configs: \n{pformat(wqm.conf[bot_worker_name])}{xterm('X')}")
        token = wqm.conf[bot_worker_name]['settings']['token']
        #; This is something else that should be specific to the chat
        #; plugin, but again... MVP... just trying to get it out the door.
        text = "\n".join(text_lines)
        blocks = []
        for line in text_lines:
            block_section = {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': line,
                }
            }
            blocks.append(block_section)

        await bot_post_funcs[bot](
            token,
            channel,
            text,
            blocks,
        )

#~##############################
#~ Launch all Background Tasks
#~##############################

async def start_automations():
    """launches all background automations

    Loops through list of config dicts to launch automated background tasks.

    task_func - API endpoint function used for the background operation
    task_args - list of arguments passed to the task function
    interval_seconds - how often you want the task to be performed
    timeout - max runtime (seconds) the task should take
    result_ttl - max time (seconds) the result will stay in Redis

    #; NOTE - task_func, task_args, and interval_seconds are all required
    #; Any other arguments passed after that are sent to the RQ Worker.

    :return: list of background tasks
    :rtype: List[asyncio.Task]
    """
    bg_tasks = []
    all_tasks = [
        #@ Clean Abandoned Jobs from Queue
        {
            'task_func': clean_queues,
            'task_args': [24, None],
            #; Every 24 hours we're going to clean the queues
            'interval_seconds': 3600*24,
        },
        #@ Run Hunts
        {
            'task_func': auto_hunt_conf,
            'task_args': ['all', 'all', 'all', False, 60*60, 60*60*24],
            #; Every 15 min we're gonna check to run auto_hunts again
            'interval_seconds': 60*15,
        },
        #TODO @ Run Enrichments
        #TODO @ POST the news
        {
            'task_func': post_news,
            'task_args': [1, False, ['slackbot']],
            'interval_seconds': 3600,
        },
    ]

    for at in all_tasks:
        _log.debug(f"TASK: {at}")
        _log.debug(f"{xterm('BLUE')}Starting {at['task_func'].__name__} automation{xterm('RESET')}")
        task = asyncio.create_task(schedule_bg_task(**at),
        name = at['task_func'].__name__)
        bg_tasks.append(task)

    return bg_tasks

#~##############################
#~ Stop all Background Tasks
#~##############################

async def stop_automations(bg_tasks: List[asyncio.Task] = []):
    for bgt in bg_tasks:
        _log.debug(f"{xterm('RED')}Cancelling {bgt}{xterm('RESET')}")
        bgt.cancel()

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
    # ! await wqm.check_config()
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