import argparse
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
from rq import Queue, Worker, Connection, get_current_job
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
    get_plugin,
)
from ledapi.helpers import (
    two_sec_grace,
    result_error_catching,
    xterm,
)
from ledapi.models import(
    MOJOCMD,
    SlackAction,
    SlackEvent,
    UserModel,
    add_user_modal,
    new_hits,
    role_admin,
    role_dbadmin,
    role_hunter,
    role_conman,
    role_everyone,
    role_public,
    update_thing_modal,
    # unauthorized_modal,
    # invalid_command_modal,
)
from ledapi.user import User, check_role, dep_check_user_role, get_user_by_slack_id
from ledapi.worker_manager import(
    get_available_worker,
    poll_job,
)
from ledapi.tasks import(
    get_news_conf,
)

# _log.debug(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}")
from slack_client import SlackClient
from typedb_client import TypeDBClient

#&##############################################################################
#& INTERNAL - TASKS/SUBTASK EXECUTION
#&
#& This is where the actual functions are processed, not just job queueing.
#&##############################################################################

#~######################################
#~ Post Message
#~######################################
async def slack_post_message(
    slack_token: str = None,
    channel: str = None,
    text: str = None,
    blocks: List[Dict] = [],
):
    _log.debug(f"Posting {text} to {channel}")

    client=WebClient(token=slack_token)
    try:
        response = client.chat_postMessage(
            channel=channel,
            text=text,
            blocks=blocks,
        )
    except SlackApiError as e:
        _log.error(f"Error sending message {e.response['error']}")
        return False

    _log.debug(f"Successful post! {response}")
    return True


#~######################################
#~ Parse MOJO CMDs
#~######################################

async def mojo_parse_cmd(
    cmd: str = None,
):
    parser = argparse.ArgumentParser(description="MOJO - a Slack tool for interacting with LEDHNTR")
    subparsers = parser.add_subparsers(dest='cmd', help="Available commands")

    #@ Define sub-parsers
    news = subparsers.add_parser('news', help="Get the latest findings from any given database.")
    search = subparsers.add_parser('search', help="Search information in the LEDHNTR databases and external APIs.")

    #@ Handle 'search' arguments
    search.add_argument('pos', nargs='*', help='Positional arguments: [label value verbose]')
    search.add_argument('--label', type=str, help="Label to search for (e.g. ip)")
    search.add_argument('--value', type=str, help="Value eto search for (e.g. 192.168.1.100)")
    search.add_argument('--verbose', action='store_true', help="Enable verbose output")

    #@ Handle 'news' arguments
    news.add_argument('pos', nargs="*", help='Positional arguments: [days_back database verbose]')
    news.add_argument('--days_back', type=int, default=1, help="Number of days back to retrieve news")
    news.add_argument('--hours_back', type=int, help="Number of hours back to retrieve news (overrides days_back if set)")
    news.add_argument('--database', type=str, help="Database to use for news retrieval (defaults to 'all')")
    news.add_argument('--verbose', action='store_true', help="Enable verbose output")

    args = parser.parse_args(cmd.split())

    #. Process positional arguments for 'search'
    if args.cmd == 'search':
        if args.pos:
            if args.label is None:
                args.label = args.pos[0]
            if len(args.pos) > 1:
                args.value = args.pos[1]
            if len(args.pos) > 2:
                args.verbose = args.pos[2].lower() in ['true', '1', 'yes', 'verbose']

    #. Process positional arguments for 'news'
    if args.cmd == 'news':
        if args.pos:
            #; if a positional argumet is passed, assume we're feeding it hours-back.
            args.days_back = int(args.pos[0])
            if len(args.pos) > 1:
                args.database = args.pos[1]
            if len(args.pos) > 2:
                args.verbose = args.pos[2].lower() in ['true', '1', 'yes', 'verbose']
        #. check overrides
        if args.hours_back is None:
            args.hours_back = 24*args.days_back

    _log.debug(f"{xterm('GREEN')}Parsed args: {pformat(vars(args))}{xterm('X')}")
    return args

#~######################################
#~ Addme
#~######################################
async def mojo_addme(
    mojo: MOJOCMD = None,
    user: User = None,
):
    _log.debug(f"Processing addme comand")
    _log.debug(f"mojo: {mojo}")

    '''
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

    '''
    #; Old method
    '''
    channel = "#mojo-dev"
    # slack_token = wqm.conf[worker_name]['settings']['token']
    slack_token = mojo.slackbot_token
    text = f"User <@{mojo.user_id}> has requested an account."
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

    await slack_post_message(
        slack_token,
        channel,
        text,
        blocks,
    )


    rez = {
        "response_type": "ephemeral",
        "text": f"Request for account received: <@{mojo.user_id}>"
    }
    _log.debug(f"Returning rez: {rez}")

    return rez
    '''

    text = f"User <@{mojo.user_id}> has requested an account."
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

async def mojo_debug(
    mojo: MOJOCMD = None,
    user: User = None,
):
    _log.debug(f"Running debug endpoint")
    _log.debug(f"mojo: {mojo}")
    await asyncio.sleep(5)
    return mojo

async def mojo_post_news(
    mojo: MOJOCMD = None,
    user: User = None,
):
    _log.debug(f"Running POST NEWS")
    try:
        args = await mojo_parse_cmd(mojo.text)
    except SystemExit as e:
        _log.error(f"{xterm('RED')}Error parsing cmd: {e}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")

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

    news_results = await get_news_conf(args.hours_back)
    #; _log.debug(f"{xterm('CYAN')}{pformat(news_results)}{xterm('X')}")
    new_things = news_results.get('new_things')
    if not new_things:
        _log.debug(f"{xterm('YELLOW')}no new things found..{xterm('X')}")
        return None
    #; else:
    #;     _log.debug(f"{xterm('GREEN')}new_things: {new_things}{xterm('X')}")

    plugin:SlackClient = await get_plugin()

    if args.verbose:
        #; This is something else that should be specific to the chat
        #; plugin, but again... MVP... just trying to get it out the door.
        text = f"```{new_things}```"
        _log.debug(f"{xterm('CYAN')}Posting {text} to {plugin.admin_channel}...{xterm('X')}")
        try:
            await plugin.upload_snippet(
                filename=f"{datetime.now(timezone.utc)}_news.json",
                content=dumps(new_things),
                title=f"{datetime.now(timezone.utc)}_news.json",
                snippet_type="json",
                #; channel=plugin.admin_channel, #; maybe channel_id is required?
                #; maybe it's because the channel started with #??
                #@ winner! needed to strip the # from the channel name.
                channel=mojo.channel_id,
                initial_comment="MOJO News Dump",
            )
        except Exception as e:
            _log.error(f"{xterm('RED')}Failed posting message: {e}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        _log.debug(f"MOJOCMD: {pformat(mojo)}")

        return True

    for db, thing_types in new_things.items():
        if not thing_types:
            continue
        interesting = False
        for tt in thing_types.keys():
            if tt in interesting_things:
                interesting = True
                break
            else:
                _log.debug(f"{xterm('CYAN')}{tt} not in {interesting_things}{xterm('X')}")
        if not interesting:
            _log.debug(f"{xterm('YELLOW')}nothing interesting found in {db}.{xterm('X')}")
            continue
        data = {db: thing_types}
        #; Generate pretty blocks with buttons.
        try:
            blocks = new_hits(data)
            _log.debug(f"{xterm('CYAN')}Generated blocks: \n{pformat(blocks)}{xterm('X')}")
        except Exception as e:
            _log.error(f"{xterm('RED')}Failed generating blocks: {e}{xterm('X')}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        text_lines.append(f"*{db}*")
        for tt, entries in thing_types.items():
            if tt in interesting_things:
                text_lines.append(f"*Type: {tt}*")
                for e in entries:
                    for keyval, attributes in e.items():
                        text_lines.append(f"```{keyval}")
                        for label, values in attributes.items():
                            text_lines.append(f"\t{label}")
                            for value in values:
                                text_lines.append(f"\t\t{value}")
                        text_lines.append(f"```")
            else:
                _log.debug(f"{tt} not in {interesting_things}")

        if not text_lines:
            text_lines = [f"No news from the last {args.hours_back} hours from {db}."]
        text = "\n".join(text_lines)
        if not blocks:
            blocks = None
        try:
            await plugin.post_message(
                # channel=plugin.admin_channel,
                channel=mojo.channel_id,
                text=text,
                blocks=blocks,
                blocks_verbatim=True,
            )
        except Exception as e:
            _log.error(f"{xterm('RED')}Failed posting message..: {e}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        _log.debug(f"MOJOCMD: {pformat(mojo)}")
    return True

async def mojo_clear_schedules(
    mojo: MOJOCMD = None,
    user: User = None,
):
    await redis_manager.check_redis_conn()
    #! extract pattern from MOJO command
    pattern = "*_run_time"
    cursor = '0'
    text_lines = []
    while cursor != 0:
        cursor, keys = await redis_manager.redis.scan(cursor=cursor, match=pattern)
        for key in keys:
            try:
                await redis_manager.redis.delete(key)
                text = f"<@{mojo.user_id}> successfully deleted schedule key: `{key.decode('utf-8')}`"
                text_lines.append(text)
                _log.debug(text)
            except Exception as e:
                _log.error(f"Failed removing key {key}")
                continue

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
    await slack_post_message(
        mojo.slackbot_token,
        mojo.admin_channel,
        text,
        blocks,
    )

async def mojo_check_schedules(
    mojo: MOJOCMD = None,
    user: User = None,
):
    await redis_manager.check_redis_conn()
    pattern = "*_run_time"
    cursor = '0'
    text_lines = [f"<@{mojo.user_id}> requested next schedule times..."]
    while cursor != 0:
        cursor, keys = await redis_manager.redis.scan(cursor=cursor, match=pattern)
        for key in keys:
            try:
                next_run_time = await redis_manager.redis.get(key)
                if next_run_time:
                    next_run_time = datetime.fromisoformat(next_run_time.decode())
                    text = f"`{key.decode('utf-8')}`: `{next_run_time}`"
                    text_lines.append(text)
                else:
                    text = f"`{key.decode('utf-8')}`: NOT SCHEDULED"
                    text_lines.append(text)

            except Exception as e:
                _log.error(f"Failed getting value for {key}")
                continue

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
    await slack_post_message(
        mojo.slackbot_token,
        mojo.admin_channel,
        text,
        blocks,
    )

#~######################################
#~ slackation_set_confidence_modal
#~######################################

async def slackation_set_confidence_modal(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
):
    _log.debug(f"Opening set_confidence modal...")
    # // _log.debug(f"{xterm('YELLOW')}{pformat(payload)}{xterm('X')}")#
    _log.debug(f"Sending trigger_id {payload['trigger_id']}")
    '''
    mymodal = {
        "type": "modal",
        "callback_id": "set_confidence_submit",
        "title": {"type": "plain_text", "text": "Update Thing"},
        "submit": {"type": "plain_text", "text": "Submit"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": update_thing_modal(payload),
    }'''
    mymodal = update_thing_modal(payload)
    _log.debug(f"{xterm('CYAN')}view modal:\n{pformat(mymodal)}{xterm('X')}")
    _log.debug(f"{xterm('CYAN')}modal type: {type(mymodal)}{xterm('X')}")
    try:
        await plugin.views_open(
            trigger_id=payload['trigger_id'],
            # // view=update_thing_modal(payload),
            view = mymodal,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed opening modal: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        return False

    return True

#~######################################
#~ slackaction_set_confidence
#~######################################

async def slackaction_set_confidence(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
):
    _log.debug(f"Setting confidence...")
    _log.debug(f"{xterm('YELLOW')}{pformat(payload)}{xterm('X')}")
    value_str = payload['actions'][0]['selected_option']['value']
    db_name = value_str.split('|')[0]
    iid = value_str.split('|')[1]
    value = value_str.split('|')[2]

    so = Entity(label='entity')
    so.iid = iid
    tdb:TypeDBClient = get_tdb()
    tdb.db_name = db_name

    _log.debug(f"Looking for existing thing...")
    try:
        rez = tdb.find_things(so)
        _log.debug(f"Found things{rez}")
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed finding thing {so}: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
    existing_thing = rez[0]
    _log.debug(f"Existing thing: {existing_thing}")
    if existing_thing.get_attributes('confidence'):
        _log.debug(f"Old confidence: {existing_thing.get_attributes('confidence')[0].value}")
    _log.debug(f"Replacing confidence with {value}...")
    try:
        tdb.replace_attribute(existing_thing, Attribute(label='confidence', value=int(value)))
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed replacing attribute on {existing_thing}: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
    _log.debug(f"Looking for updated thing...")
    try:
        updated_thing = tdb.find_things(so)[0]
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed finding thing {so}: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
    _log.debug(f"{xterm('GREEN')}New confidence: {updated_thing.get_attributes('confidence')[0].value}{xterm('X')}")

    #TODO - update original message with new confidence and alert group that a user changed it.

    return True

#~######################################
#~ update_thing_submit
#~######################################

async def update_thing_submit(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
):
    _log.debug(f"Updating all thing properties...")
    _log.debug(f"{xterm('YELLOW')}{pformat(payload)}{xterm('X')}")

    return True

#~######################################
#~ slackaction_check_job_status
#~######################################
async def slackaction_check_job_status(
    plugin: SlackClient = None,
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
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
)->None:
    _log.debug(f"Processing open_add_user_modal")
    _log.debug(f"payload: {payload}")
    _log.debug(f"user: {user.to_dict()}")

    #; // admin_channel = "#mojo-dev"
    #; this isn't called here but I'm leaving it as a
    #; reminder that I can pull it from the payload if I want it dynamic.


    action = payload['actions'][0]

    # open the modal
    await plugin.client.views_open(
        trigger_id=payload['trigger_id'],
        view=add_user_modal(action['value'])
    )
    return True

#~######################################
#~ slackaction_submit_add_user
#~######################################
async def slackaction_submit_add_user(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
):
    plugin:SlackClient = await get_plugin()

    _log.debug(f"Adding user to database...")
    _log.debug(f"payload: {payload}")
    user_data = payload['view']['state']['values']
    username = user_data['user_block']['username']['value']
    role = user_data['role_block']['role']['selected_option']['value']
    slack_id = user_data['slackid_block']['slack_id']['value']
    #; Add the user to the DB
    new_user = await add_user_to_db_task(username, role, slack_id)
    #; Update the request message
    #. At some point this should also DM the user, but that requires extra permissions
    #. and I don't have time to mess with it right now.
    slack_uid = slack_id.split(',')[0]
    # // slack_token = wqm.conf[worker_name]['settings']['token']
    # // client = WebClient(token=slack_token)
    blocks = [
        {
            'type': 'section',
            'text': {
                'type': 'mrkdwn',
                'text': f"Successfully added new user <@{slack_uid}>",
            },
        }
    ]
    plugin.update_message(
        channel = payload['channel']['id'],
        ts = payload['message']['ts'],
        text = f"Successfully added user <@{slack_uid}>",
        # // blocks = blocks,
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
#~ mojo_cmd config
#~######################################

async def mojocmd_conf(
    mojo: MOJOCMD = None,
    user: User = None,
):
    # TODO - Build self-documenting "help" command
    # TODO - This can probably be done using the argparse module in mojo_parse_cmd()

    plugin:SlackClient = await get_plugin()
    cmd = mojo.text.split(' ')[0]
    resp = None
    opts = {
        "addme": (mojo_addme, role_public),
        "debug": (mojo_debug, role_public),
        #; mojo clear-schedules
        #~ worker_manager.reset_schedules()
        "clear-schedules": (mojo_clear_schedules, role_admin),
        "check-schedules": (mojo_check_schedules, role_everyone),
        "news": (mojo_post_news, role_everyone),
        #; mojo add_db 20240723_MyNewDB
        #. "add_db": (mojo_add_db, role_dbadmin)
        #; mojo add_hunt #; launches modal
        #. "add_hunt": (mojo_add_hunt, role_hunter)
        #; mojo hunt --db=all --plugin=all --forced=True
        #. "hunt": (mojo_hunt, role_hunter)
        #; mojo enrich --db=all --plugin=all --forced=True
        #. "enrich": (mojo_enrich, role_hunter)
        #; mojo status --worker=censys.01
        #; mojo status --job=<jobid>
        #. "status": (mojo_status, role_everyone)
        #; mojo search ip 192.168.1.100
        #; mojo search --label=ip --value=192.168.1.100 --database=all --verbose
        #. "search": (mojo_search, role_hunter)
    }

    if cmd in opts:
        func_perms = opts[cmd]
        try:
            _log.debug(f"Checking user.role {user.role} against roles: {func_perms[1]}")
            await check_role(user, func_perms[1])
        except HTTPException as e:
            await plugin.unauthorized_resp(trigger_id=mojo.trigger_id)
        except Exception as e:
            raise
        try:
            resp = await func_perms[0](mojo, user)
        except Exception as e:
            _log.error(f"Failed running {func_perms[0]}: {e}")
            # // _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
    else:
        _log.debug(f"Invalid command: {cmd}")
        await plugin.invalid_command(
            trigger_id=mojo.trigger_id,
            cmd=cmd,
        )

    _log.debug(f"Returning resp: {resp}")
    return resp

async def slackaction_conf(
    payload: Dict = None,
    user: User = None,
):
    plugin:SlackClient = await get_plugin()

    resp = None

    opts = {
        'block_actions':{
            "open_add_user_modal": (slackaction_open_add_user_modal, role_dbadmin),
            "check_job_status": (slackaction_check_job_status, role_everyone),
            #. role_everyone can open the dialog, but only con_man can change the confidence
            "set_confidence_modal": (slackation_set_confidence_modal, role_everyone),
            "set_confidence": (slackaction_set_confidence, role_everyone),
        },
        'view_submission':{
            'add_user_modal': (slackaction_submit_add_user, role_dbadmin), #do the add-user stuff
            # // #. slackaction_update_thing() lets you set confidence, add notes and tags
            # // #; 'update_thing': (slackation_update_thing, role_conman),
            #. slackaction_set_confidence()
            "update_thing_submit": (update_thing_submit, role_conman)
        }
    }

    if not payload['type'] in opts:
        _log.error(f"No scenario coded for payload['type'] {payload['type']}")
        await plugin.invalid_command(
            trigger_id=payload['trigger_id'],
            cmd=payload['type'],
        )
        return False

    action_ids = await plugin.get_action_ids(payload)
    #. NOTE - IF USING WORKFLOWS/MULTIPLE ACTION_IDS WE MIGHT NEED TO REVISIT THIS
    #. TO INCLUDE JOB DEPENDENCIES. THAT WAY THEY DON'T ALL JUST FIRE OFF AT ONCE
    #. AS OPPOSED TO IN ORDER.
    #.
    #. FOR NOW, I'M ONLY USING ONE ACTION_ID AT A TIME SO IT DOESN'T MATTER.
    resp = []
    for action_id in action_ids:
        func_perms = opts[payload['type']][action_id]
        try:
            await check_role(user, func_perms[1])
        except HTTPException as e:
            await plugin.unauthorized_resp()
            return False
        except Exception as e:
            raise
        try:
            result = await func_perms[0](plugin, payload, user)
            resp.append(result)
        except Exception as e:
            _log.error(f"Failed running {func_perms[0]}: {e}")

    #. Will also have to figure out how to properly return a list of responses.
    #. resp will probably have to be converted to a dict w/ action_id's as the keys.
    if len(resp) == 1:
        return resp[0]
    return resp

async def slackevent_conf(
    payload: Dict = None,
    user: User = None,
):
    plugin:SlackClient = await get_plugin()
    '''
    opts = {
        "addme": mojo_addme,
        "debug": mojo_debug,
    }
    '''
    data = json.loads(payload['body'])
    """
    # Payload Body:

    {'api_app_id': 'A07A8SAPC0P',
    'authorizations': [{'enterprise_id': None,
                        'is_bot': True,
                        'is_enterprise_install': False,
                        'team_id': '<TEAM_ID>',
                        'user_id': '<USER_ID>'}],
    'context_enterprise_id': None,
    'context_team_id': '<TEAM_ID>',
    'event': {'event_ts': '1721766236.002200',
            'item': {'channel': '<CHANNEL_ITEM>',
                        'ts': '1721766231.784119',
                        'type': 'message'},
            'item_user': '<ITEM_USER>',
            'reaction': '+1',
            'type': 'reaction_added',
            'user': '<USER_ID>'},
    'event_context': '<EVENT_CONTEXT>',
    'event_id': '<EVENT_ID>',
    'event_time': 1721766236,
    'is_ext_shared_channel': False,
    'team_id': '<TEAM_ID>',
    'token': '<TOKEN>',
    'type': 'event_callback'}
    """
    event = data['event']
    resp = None

    opts = {
        # // 'reaction_added': (slackevent_reaction_added, role_conman),
    }

    '''
    if not payload['type'] in opts:
        _log.error(f"No scenario coded for payload['type'] {payload['type']}")
        await plugin.invalid_command(
            trigger_id=payload['trigger_id'],
            cmd=payload['type'],
        )
        return False
    '''
    """
    _log.debug(f"{xterm('YELLOW')}{pformat(payload)}{xterm('X')}")
    await plugin.post_message(
        channel = plugin.admin_channel,
        text=f"```{pformat(payload)}```",
    )
    await plugin.post_message(
        channel = plugin.admin_channel,
        text=f"*BODY*",
    )

    # // _log.debug(f"Attempting to json.loads {payload['body']}")
    # // _log.debug(payload['body'])
    # // _log.debug(f"body type: {type(payload['body'])}")
    # // _log.debug(f"body first bytes: {payload['body'][0:10]}")


    body_text = f"```{pformat(data)}```"
    await plugin.post_message(
        channel = plugin.admin_channel,
        text=body_text,
    )
    """

    body_text = f"<@{event['user']}> added reaction :{event['reaction']}:"
    channel = event['item']['channel']
    thread_ts = event['item']['ts']
    _log.debug(f"{xterm('YELLOW')}{pformat(data)}{xterm('X')}")
    _log.debug(f"{xterm('YELLOW')}{pformat(event)}{xterm('X')}")
    _log.debug(f"Using thread_ts: {thread_ts}")
    _log.debug(f"{xterm('CYAN')}{pformat(payload)}{xterm('X')}")

    await plugin.post_message(
        channel=channel,
        text=body_text,
        thread_ts=thread_ts,
    )

    #TODO - Do stuff with Slack Events
    return True #; this will be changed to 'response'


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
    worker_name = await get_available_worker('slack_client')
    queue = wqm.conf[worker_name]['queue']

    _log.debug(f"Enqueuing mojo_handler")
    _log.debug(f"mojo: {mojo}")
    _log.debug(f"user: {user}")

    job = queue.enqueue_call(
        mojocmd_conf,
        args=[mojo, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id, slack_format=True)

    return response

async def action_handler(
    request: Request = None,
    user: User = None,
):
    worker_name = await get_available_worker('slack_client')
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
        args=[payload, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id, slack_format=True)

    return response

async def event_handler(
    request: Request = None,
    user: User = None,
):
    worker_name = await get_available_worker('slack_client')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing event_handler")
    _log.debug(f"request: {request}")
    _log.debug(f"user: {user}")

    resp = {}
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    resp['body'] = await request.body()
    resp['body'] = resp['body'].decode('utf-8')
    # // resp['body-utf8'] = resp['body'].decode('utf-8')
    # // resp['form'] = await request.form()
    # // resp['form'] = pformat(resp['form'])

    job = queue.enqueue_call(
        slackevent_conf,
        args=[resp, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id, slack_format=True)

    return response