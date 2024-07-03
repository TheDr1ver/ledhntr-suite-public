import asyncio
import json
import os
import httpx
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
from ledhntr.helpers import dumps
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
    UserModel,
    add_user_modal,
    role_admin,
    role_dbadmin,
    role_hunter,
    role_conman,
    role_everyone,
    role_public,
    unauthorized_modal,
    invalid_command_modal,
)
from ledapi.user import User, check_role, dep_check_user_role, get_user_by_slack_id
from ledapi.worker_manager import(
    get_available_worker,
    poll_job,
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

    rez = {
        "response_type": "ephemeral",
        "text": f"Request for account received: <@{mojo.user_id}>"
    }
    _log.debug(f"Returning rez: {rez}")

    return rez

async def mojo_debug(
    worker_name: str = None,
    mojo: MOJOCMD = None,
    user: User = None,
):
    _log.debug(f"Running debug endpoint")
    _log.debug(f"mojo: {mojo}")
    await asyncio.sleep(5)
    return mojo

#~######################################
#~ slackaction_check_job_status
#~######################################
async def slackaction_check_job_status(
    worker_name: str = None,
    payload: Dict = None,
    user: User = None,
):
    _log.debug(f"Processing check_job_status for job {payload['actions'][0]['value']}")
    _log.debug(f"payload: {pformat(payload)}")
    _log.debug(f"user: {user.to_dict()}")
    '''
    # POST to temp hook
    POST https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX
    Content-type: application/json
    {
        "text": "Oh hey, this is a marvelous message in a thread!",
        "response_type": "in_channel",
        "replace_original": false",
        "thread_ts": "1234567890"
    }

    # Payload example
    {'actions': [{'action_id': 'check_job_status',
                'action_ts': '1720014662.623072',
                'block_id': 'dPPHl',
                'text': {'emoji': True,
                        'text': 'Check Status',
                        'type': 'plain_text'},
                'type': 'button',
                'value': '7798a2da-e28d-4597-8509-ba1f719aa808'}],
    'api_app_id': '<APPID>',
    'channel': {'id': '<CHANNELID>', 'name': 'privategroup'},
    'container': {'channel_id': '<CHANNELID>',
                'is_ephemeral': True,
                'message_ts': '1720014619.003200',
                'type': 'message'},
    'enterprise': None,
    'is_enterprise_install': False,
    'response_url': 'https://hooks.slack.com/actions/<REDACTED>',
    'state': {'values': {}},
    'team': {'domain': '<YOURDOMAIN>', 'id': '<YOURTEAM>'},
    'token': '<YOURTOKEN>',
    'trigger_id': '7383253119889.2625160776.6187361c3baf56e117c01ccfc990a440',
    'type': 'block_actions',
    'user': {'id': '<YOURUSER>',
            'name': '<YOURUSERNAME>',
            'team_id': '<YOURTEAM>',
            'username': '<YOURUSERNAME>'}}

    '''
    job_id = payload['actions'][0]['value']
    rez = await poll_job(job_id)
    if not rez:
        dumprez = f"job_id {job_id} is expired"
        blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': dumprez,
                },
            }
        ]
    else:
        dumprez = dumps(rez)
        blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f"```{dumprez}```",
                },
            }
        ]
        if not rez['status'] == 'finished':
            blocks[0]['accessory'] = {
                'type': 'button',
                'text': {'type': 'plain_text', 'text': 'Check Status'},
                'action_id': 'check_job_status',
                'value': job_id,
            }
    _log.debug(f"job_details: {pformat(rez)}")

    '''
    slack_token = wqm.conf[worker_name]['settings']['token']
    client = WebClient(token=slack_token)
    client.chat_update(
        channel = payload['channel']['id'],
        ts = payload['container']['message_ts'],
        text = rez,
        blocks = blocks
    )
    '''
    resp_url = payload['response_url']
    resp_payload = {
        "response_type": "ephemeral",
        "text": dumprez,
        "blocks": blocks
    }
    async with httpx.AsyncClient() as client:
        await client.post(resp_url, json=resp_payload)

    return rez



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
    #; Add the user to the DB
    new_user = await add_user_to_db_task(username, role, slack_id)
    #; Update the reuest message
    #. At some point this should also DM the user, but that requires extra permissions
    #. and I don't have time to mess with it right now.
    slack_uid = slack_id.split(',')[0]
    slack_token = wqm.conf[worker_name]['settings']['token']
    client = WebClient(token=slack_token)
    client.chat_update(
        channel = payload['channel']['id'],
        ts = payload['message']['ts'],
        text = f"Successfully added new user <@{slack_uid}>",
        blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': f"Successfully added new user <@{slack_uid}>",
                },
            }
        ]
    )
    return {'response_action': 'clear'}

#~######################################
#~ add_user_to_db task
#~######################################
async def add_user_to_db_task(
    username: str = None,
    role: str = None,
    slack_id: str = None,
)->User:
    _log.debug(f"Checking if user exists")
    slack_id = f"({slack_id})"
    user = User.load_by_property(
        prop_type="slack_id",
        prop_value=slack_id,
    )
    if user is not None:
        _log.info(f"Updating existing user {user} slack_id to {slack_id}.")
        if user.slack_id != slack_id:
            user.slack_id = slack_id
            User.update_user(user)
        return user
    new_user = UserModel()
    new_user.user_id = username
    new_user.role = role
    new_user.slack_id = slack_id
    saved_user = User.create_user(new_user)
    _log.info(f"Added user {pformat(saved_user.to_dict())} to LEDAPI Database!")

    return saved_user



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
    slack_token = wqm.conf[worker_name]['settings']['token']
    client = WebClient(token=slack_token)
    cmd = mojo.text.split(' ')[0]
    resp = None
    opts = {
        "addme": (mojo_addme, role_public),
        "debug": (mojo_debug, role_public),
    }


    if cmd in opts:
        func_perms = opts[cmd]

        try:
            _log.debug(f"Checking user.role {user.role} against roles: {func_perms[1]}")
            await check_role(user, func_perms[1])
        except HTTPException as e:
            client.views_open(
                trigger_id=mojo.trigger_id,
                view=unauthorized_modal()
            )
        except Exception as e:
            raise
        resp = await func_perms[0](worker_name, mojo, user)
    else:
        _log.debug(f"Invalid command: {cmd}")
        client.views_open(
            trigger_id=mojo.trigger_id,
            view=invalid_command_modal(cmd=cmd)
        )

    _log.debug(f"Returning resp: {resp}")
    return resp

async def slackaction_conf(
    worker_name: str = None,
    payload: Dict = None,
    user: User = None,
):

    slack_token = wqm.conf[worker_name]['settings']['token']
    client = WebClient(token=slack_token)
    resp = None

    opts = {
        'block_actions':{
            "open_add_user_modal": (slackaction_open_add_user_modal, role_dbadmin),
            "check_job_status": (slackaction_check_job_status, role_everyone),
        },
        'view_submission':{
            'add_user_modal': (slackaction_submit_add_user, role_dbadmin), #do the add-user stuff
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
            client.views_open(
                trigger_id=payload['trigger_id'],
                view=unauthorized_modal()
            )
        except Exception as e:
            raise
        #; Finally run the function
        resp = await func_perms[0](worker_name, payload, user)

    else:
        _log.error(f"No scenario coded for payload['type']=={payload['type']}")
        # resp = {"response_action": "clear"}
        client.views_open(
            trigger_id=payload['trigger_id'],
            view=invalid_command_modal(cmd=payload['type'])
        )
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
    # ! await wqm.check_config()
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

    response = await two_sec_grace(worker_name, job.id, slack_format=True)

    return response

async def action_handler(
    request: Request = None,
    user: User = None,
):
    # ! await wqm.check_config()
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

    response = await two_sec_grace(worker_name, job.id, slack_format=True)

    return response

async def event_handler(
    request: Request = None,
    user: User = None,
):
    # ! await wqm.check_config()
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

    response = await two_sec_grace(worker_name, job.id, slack_format=True)

    return response