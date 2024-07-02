import json
import os
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Depends, Query, Request, status
from pprint import pformat
import time
import traceback
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
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


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
    MOJOCMD,
    SlackAction,
    SlackEvent,
    add_user_modal,
    role_admin,
    role_dbadmin,
    role_hunter,
    role_conman,
    role_everyone,
)
from ledapi.user import User, check_role, dep_check_user_role
from ledapi.worker_manager import(
    get_available_worker
)

# _log.debug(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}")
from typedb_client import TypeDBClient

#&##############################################################################
#& INTERNAL - TASKS/SUBTASK EXECUTION
#&
#& This is where the actual functions are processed, not just job queueing.
#&##############################################################################

#~######################################
#~ Parse MOJO CMDs
#~######################################
async def mojo_addme(
    worker_name: str = None,
    mojo: MOJOCMD = None,
    user: User = None,
):
    _log.debug(f"Processing addme comand")
    _log.debug(f"mojo: {mojo}")

    admin_channel = "#mojo-dev"
    slack_token = wqm.conf[worker_name]['settings']['token']
    client = WebClient(token=slack_token)

    try:
        response = client.chat_postMessage(
            channel=admin_channel,
            text=f"User <@{mojo.user_id}> has requested an account.",
            blocks = [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f"User <@{mojo.user_id}> has requested an account."
                    },
                    'accessory': {
                        'type': 'button',
                        'text': {'type': 'plain_text', 'text': 'Add User'},
                        'action_id': 'open_add_user_modal',
                        'value': f"{mojo.user_name},{mojo.user_id},{mojo.team_id}",
                    }
                }
            ]
        )
    except SlackApiError as e:
        _log.error(f"Error sending message: {e.response['error']}")

    return {
        "response_type": "ephemeral",
        "text": f"Request for account received: {mojo.user_id}"
    }

    return mojo

async def mojo_debug(
    worker_name: str = None,
    mojo: MOJOCMD = None,
    user: User = None,
):
    _log.debug(f"Running debug endpoint")
    _log.debug(f"mojo: {mojo}")
    return mojo



#~######################################
#~ list_dbs() tasks
#~######################################

'''
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
'''

#~######################################
#~ slackaction_open_add_user_modal
#~######################################
async def slackaction_open_add_user_modal(
    worker_name: str = None,
    payload: Dict = None,
    # user: User = Depends(check_role(role_dbadmin)),
    # user: User = Depends(dep_check_user_role(role_dbadmin))
    user: User = None,
):
    _log.debug(f"Processing open_add_user_modal")
    _log.debug(f"payload: {payload}")
    _log.debug(f"user: {user.to_dict()}")

    # user = await check_role(user, role_dbadmin)

    admin_channel = "#mojo-dev" #; this isn't called here but I'm leaving it as a
    #; reminder that I can pull it from the payload if I want it dynamic.

    slack_token = wqm.conf[worker_name]['settings']['token']
    client = WebClient(token=slack_token)

    action = payload['actions'][0]

    # open the modal
    response = client.views_open(
        trigger_id=payload['trigger_id'],
        view=add_user_modal(action['value'])
    )

#~######################################
#~ slackaction_submit_add_user
#~######################################
async def slackaction_submit_add_user(
    worker_name: str = None,
    payload: Dict = None,
    # user: User = Depends(check_role(role_dbadmin)),
    user: User = None,
):
    _log.debug(f"Adding user to database...")
    _log.debug(f"payload: {payload}")
    user_data = payload['view']['state']['values']
    username = user_data['user_block']['username']['value']
    role = user_data['role_block']['role']['selected_option']['value']
    slack_id = user_data['slackid_block']['slack_id']['value']
    # add_user_to_database(username, role) # TODO
    _log.debug(f"Adding user {username} with role {role} and slack_id {slack_id} to LEDHNTR Database!")
    return {'response_action': 'clear'}


#&##############################################################################
#& INTERNAL - COMPLEX TASKING
#&
#& Handling complex tasks that require pre-configuration and/or
#& queueing multiple jobsConfig and Job Queuing
#&##############################################################################

#~######################################
#~ get_news config
#~######################################

async def mojocmd_conf(
    worker_name: str = None,
    mojo: MOJOCMD = None,
    user: User = None,
):
    opts = {
        "addme": mojo_addme,
        "debug": mojo_debug,
    }

    resp = await opts[mojo.text.split(' ')[0]](worker_name, mojo, user)
    return resp

async def slackaction_conf(
    worker_name: str = None,
    payload: Dict = None,
    user: User = None,
):

    opts = {
        'block_actions':{
            "open_add_user_modal": (slackaction_open_add_user_modal, role_dbadmin)
        },
        'view_submission':{
            'add_user_modal': (slackaction_submit_add_user, role_dbadmin) #do the add-user stuff
        }
    }


    # resp = await opts[mojo['text'].split(' ')[0]](mojo, user)
    #TODO - This can probably be multiple actions if we're using workflows.
    #TODO - Going to have to make this a better loop w/ additional sub-jobs
    #TODO - instead of just referencing the first action.
    #TODO - I'll probably loop through each action and submit as a new job to the slack queue
    if payload['type'] == 'block_actions':
        func_key = payload['actions'][0]['action_id']
    elif payload['type'] == 'view_submission':
        func_key = payload['view']['callback_id']

    if payload['type'] in opts:
        func_perms=opts[payload['type']][func_key]
        try:
            await check_role(user, func_perms[1])
        except HTTPException as e:
            raise
        except Exception as e:
            raise
        resp = await func_perms[0](worker_name, payload, user)

    else:
        _log.error(f"No scenario coded for payload['type']=={payload['type']}")
        resp = {"response_action": "clear"}
    # _log.info(pformat(request))
    return resp

async def slackevent_conf(
    worker_name: str = None,
    request: Dict = None,
    user: User = None,
):
    '''
    opts = {
        "addme": mojo_addme,
        "debug": mojo_debug,
    }
    '''

    # resp = await opts[mojo['text'].split(' ')[0]](mojo, user)
    _log.info(pformat(request))
    return request


#&##############################################################################
#& API Endpoint-Facing Functions
#&##############################################################################

#~##########################
#~ Handle MOJO Commands
#~##########################

async def mojo_handler(
    mojo: MOJOCMD = None,
    user: User = None,
):
    await wqm.check_config()
    worker_name = await get_available_worker('slackbot')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing mojo_handler")
    _log.debug(f"mojo: {mojo}")
    _log.debug(f"user: {user}")

    job = queue.enqueue_call(
        mojocmd_conf,
        args=[worker_name, mojo, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response

async def action_handler(
    request: Request = None,
    user: User = None,
):
    await wqm.check_config()
    worker_name = await get_available_worker('slackbot')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing action_handler")
    form = await request.form()
    payload = form.get('payload')
    payload = json.loads(payload)
    _log.debug(f"payload: {pformat(payload)}")
    _log.debug(f"user: {user}")

    resp = {}
    resp['payload'] = payload
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    # resp['body'] = await request.body()
    # resp['body'] = resp['body'].decode('utf-8')

    job = queue.enqueue_call(
        slackaction_conf,
        args=[worker_name, payload, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response

async def event_handler(
    request: Request = None,
    user: User = None,
):
    await wqm.check_config()
    worker_name = await get_available_worker('slackbot')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing event_handler")
    _log.debug(f"request: {request}")
    _log.debug(f"user: {user}")

    resp = {}
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    resp['body'] = await request.body()
    resp['body'] = resp['body'].decode('utf-8')

    job = queue.enqueue_call(
        slackevent_conf,
        args=[worker_name, resp, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response