import argparse
import asyncio
import copy
import difflib
import json
import os
import re
import httpx
from argparse import ArgumentParser, Namespace
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Depends, Query, Request, status
from pprint import pformat
import time
import traceback
from typing import Dict, List, Optional, Union, Tuple

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)
from ledhntr.helpers import dumps, format_date
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
    ConmanObject,
    MOJOCMD,
    UserModel,
    RoleEnum,
    ThingSubmission,
    role_admin,
    role_dbadmin,
    role_hunter,
    role_conman,
    role_everyone,
    role_public,
)
from ledapi.user import User, check_role, dep_check_user_role, get_user_by_slack_id
from ledapi.worker_manager import(
    get_available_worker,
    poll_job,
)
from ledapi.tasks import(
    add_thing_task,
    get_news_conf,
    set_confidence_task,
)

from slack_sdk.web.async_client import AsyncSlackResponse

# _log.debug(f"PYTHONPATH: {os.environ.get('PYTHONPATH')}")
from slack_client import (
    SlackClient,
    ModalBuilder,
)
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
#~ Populate External Actor Opts
#~######################################

async def check_db(set_vals:Dict = None)->Union[TypeDBClient,False]:
    db_name = None
    _log.debug(f"{xterm('CYAN')}Checking DBs for actors containing {input}...{xterm('X')}")
    for _, field_dat in set_vals.items():
        if 'select_db' in field_dat:
            db_name = field_dat['select_db']['selected_option'].get('value')
        '''
        if 'add_thing_hunt-service' in field_dat:
            hunt_service = field_dat['add_thing_hunt-service']['selected_option'].get('value')
        '''
    #~ Check DB
    if db_name is None:
        _log.warning(
            f"{xterm('YELLOW')}DB selection requried for actor lookup{xterm('X')}"
        )
        return False
    #; Get TypeDB Client
    if (tdb := get_tdb(db_name=db_name)) is None:
        _log.error(f"Invalid database: {db_name}")
        return False

    tdb.db_name = db_name
    return tdb

async def opts_add_thing_get_actor(
    payload: Dict = None,
    user: User = None,
)->Dict:
    block = {
        'options': [],
    }
    view = payload['view']
    set_vals = view['state']['values']
    input = payload['value']
    #; Check if the DB is set and if set, that it's valid.
    tdb = await check_db(set_vals)
    if not tdb:
        return block

    #; Get actors from DB
    so = Entity(label='actor')
    actors = tdb.find_things(so)

    #; Parse Results
    all_names = {}
    for actor in actors:
        actor_name = actor.get_attributes('actor-name')[0].value
        if actor_name not in all_names:
            all_names[actor_name] = actor_name
        aliases = actor.get_attributes('alias')
        for alias in aliases:
            if alias.value not in all_names:
                all_names[alias.value] = actor_name
    #; Return as valid options
    _log.debug(f"{xterm('CYAN')}Found matching names: \n{pformat(all_names)}{xterm('X')}")
    for name in all_names:
        if input.lower() in name.lower():
            if name.lower() == all_names[name].lower():
                txt = f"{name}"
            else:
                txt = f"{name} ({all_names[name]})"
            opt = {
                'text': {
                    'type': 'plain_text',
                    'text': txt,
                },
                'value': all_names[name],
            }
            block['options'].append(opt)

    tdb.close_client()
    return block

async def opts_add_thing_get_tag(
    payload: Dict = None,
    user: User = None,
)->Dict:
    block = {
        'options': [],
    }
    view = payload['view']
    set_vals = view['state']['values']
    input = payload['value']
    #; Check if the DB is set and if set, that it's valid.
    tdb = await check_db(set_vals)
    if not tdb:
        return block

    #; Get actors from DB
    so = Entity(label='meta-tags')
    meta_tags = tdb.find_things(so)
    #; there SHOULD only be one meta-tags entity, but you never know...
    all_tags = []
    for mt in meta_tags:
        tagattrs = mt.get_attributes('tag')
        for ta in tagattrs:
            if ta.value not in all_tags:
                all_tags.append(ta.value)
    _log.debug(f"{xterm('CYAN')}Found tags: \n{pformat(all_tags)}{xterm('X')}")
    for tag in all_tags:
        if input.lower() in tag.lower():
            opt = {
                'text': {
                    'type': 'plain_text',
                    'text': tag,
                },
                'value': tag,
            }
            block['options'].append(opt)
    tdb.close_client()
    return block

async def opts_edit_thing_search(
    payload: Dict = None,
    user: User = None,
)->Dict:
    block = {
        'options': [],
    }
    view = payload['view']
    set_vals = view['state']['values']
    input = payload['value']
    #; Check if the DB is set and if set, that it's valid.
    tdb = await check_db(set_vals)
    if not tdb:
        return block
    #; Get matching things from DB
    label = payload['view']['title'].get('text').split(' ')[-1].lower()
    all_things = tdb.find_things(label)
    for thing in all_things:
        if input in thing.keyval:
            opt = {
                'text':{
                    'type': 'plain_text',
                    'text': thing.keyval,
                },
                'value': thing.keyval,
            }
            block['options'].append(opt)
    return block

async def opts_get_attr_labels(
    payload: Dict = None,
    user: User = None,
)->Dict:
    block = {
        'options': [],
    }
    view = payload['view']
    set_vals = view['state']['values']
    input = payload['value']
    #; Check if the DB is set and if set, that it's valid.
    tdb = await check_db(set_vals)
    if not tdb:
        return block
    tdb.close_client() #; we're not using TDB in this case
    #; Get thing we're processing from title
    title = view.get('title')
    add_thing = title.get('text').split(' ')[-1].lower()
    ent = led.schema['entity'].get(add_thing)
    if ent is None:
        ent = led.schema['relation'].get(add_thing)
    ent_obj = Entity(label=add_thing)
    all_attributes = ent['owns']
    for attr in all_attributes:
        if attr == ent_obj.keyattr:
            continue
        if input.lower() in attr.lower():
            opt = {
                'text': {
                    'type': 'plain_text',
                    'text': attr,
                },
                'value': attr,
            }
            block['options'].append(opt)
    return block

#~######################################
#~ Parse MOJO CMDs
#~######################################

async def mojo_help_to_mrkdwn(
    help_message: str = None,
)->str:
    """Parse argparse help message into pretty mrkdwn format

    :param help_message: string generated by argparse help command, defaults to None
    :type help_message: str, optional
    :return: mrkdwn pretty-formatted response
    :rtype: str
    """
    help_lines = help_message.split('\n')
    mrkdwn_lines = []
    for line in help_lines:
        if line.startswith('usage:'):
            line = line.replace('uvicorn', '/mojo')
            mrkdwn_lines.append(f"*{line.strip()}*")
        # elif line.strip() == 'positional arguments:':
        #     mrkdwn_lines.append(f"*{line.strip()}*")
        # elif line.strip() == 'optional arguments:':
        #     mrkdwn_lines.append(f"*{line.strip()}*")
        elif line.strip().endswith('arguments: '):
            mrkdwn_lines.append(f"*{line.strip()}*")
        elif line.strip() == 'Available commands':
            mrkdwn_lines.append(f"*{line.strip()}*")
        # // elif line.startswith('  ') and not line.strip().startswith('-'):
        elif line.startswith('  '):
            # // parts = line.split()
            parts = re.split(r'(\s{2,})', line)
            new_line = ""
            for part in parts:
                if part.strip().startswith('-') or part.strip().isupper():
                    new_line += f"`{part.strip()}`"
                else:
                    new_line += part
            mrkdwn_lines.append(new_line)
        else:
            mrkdwn_lines.append(line)
        '''
        if len(parts) > 1:
            argument = parts[0]
            description = ' '.join(parts[1:])
            mrkdwn_lines.append(f"`{argument}` {description}")
        else:
            mrkdwn_lines.append(f"`{line.strip()}`")
        elif line.startswith('  ') and line.strip().startswith('-'):
            mrkdwn_lines.append(f"`{line.strip()}`")
        else:
            mrkdwn_lines.append(line)
        '''
    _log.debug(f"{xterm('CYAN')}lines: {mrkdwn_lines}{xterm('X')}")
    return '\n'.join(mrkdwn_lines)

async def mojo_parse_cmd(
    cmd: str = None,
)->Tuple[ArgumentParser, Namespace]:
    parser = argparse.ArgumentParser(
        description=("`MOJO` - a chat interface for interacting with `LEDHNTR`."),
        epilog="*Example*: Try running `/mojo news -h` to see how to get the news."
    )
    subparsers = parser.add_subparsers(dest='cmd', help="Available commands")

    #@ Define sub-parsers
    add = subparsers.add_parser('add', help="Add something to a database.",
                                epilog="*Example*: `/mojo add ip 192.168.1.100`")
    edit = subparsers.add_parser('edit', help="Edit something in the database.",
                                epilog="*Example*: `/mojo edit ip 192.168.1.100`")
    epi = "*Example*: `/mojo addme` - the admins take care of the rest. It's really not that hard."
    addme = subparsers.add_parser('addme', help="Request to be added as a valid mojo user",
                                  epilog=epi)
    epi = "*Examples*:\n `/mojo news 1` `/mojo news --hours_back=48` `/mojo news 7 --verbose`"
    news = subparsers.add_parser('news', help="Get the latest findings from any given database.",
                                 epilog=epi)
    # TODO search = subparsers.add_parser('search', help="Search information in the LEDHNTR databases and external APIs.")
    help = subparsers.add_parser('help', help="Display the help message and exit.")

    #@ Handle 'add' arguments
    add.add_argument('pos', nargs='*', help='`[label value database verbose]`')
    add.add_argument('--label', type=str, help="Label to add (e.g. ip)")
    add.add_argument('--value', type=str, help="Value of that label (e.g. 192.168.1.100)")
    add.add_argument('--database', type=str, default='scratchpad', help="Database to use (defaults to 'scratchpad')")
    add.add_argument('--verbose', action='store_true', help="Enable verbose output")

    #@ Handle 'edit' arguments
    edit.add_argument('pos', nargs='*', help='`[label value database verbose]`')
    edit.add_argument('--label', type=str, help="Label to edit (e.g. ip)")
    edit.add_argument('--value', type=str, help="Value of that label (e.g. 192.168.1.100)")
    edit.add_argument('--database', type=str, default='scratchpad', help="Database to use (defaults to 'scratchpad')")
    edit.add_argument('--verbose', action='store_true', help="Enable verbose output")

    #@ Handle 'search' arguments
    # TODO
    '''
    search.add_argument('pos', nargs='*', help='`[label value database verbose]`')
    search.add_argument('--label', type=str, help="Label to search for (e.g. ip)")
    search.add_argument('--value', type=str, help="Value to search for (e.g. 192.168.1.100)")
    search.add_argument('--database', type=str, default='scratchpad', help="Database to use (defaults to 'scratchpad')")
    search.add_argument('--verbose', action='store_true', help="Enable verbose output")
    '''

    #@ Handle 'news' arguments
    news.add_argument('pos', nargs="*", help='`[days_back database verbose]`')
    news.add_argument('--days_back', type=int, default=1, help="Number of days back to retrieve news")
    news.add_argument('--hours_back', type=int, help="Number of hours back to retrieve news (overrides days_back if set)")
    news.add_argument('--database', type=str, default='all', help="Database to use for news retrieval (defaults to 'all')")
    news.add_argument('--verbose', action='store_true', help="Enable verbose output")
    news.add_argument('--con', type=str, default='0,1,2,3', help="Comma-separated confidence threshold (e.g. 0 or 1,2,3 or all)")

    try:
        args = parser.parse_args(cmd.split())
    except SystemExit as e:
        if cmd.endswith(('-h', '--help')):
            subcmd = cmd.split()[0]
            subparser = parser._subparsers._group_actions[0].choices.get(subcmd)
            if subparser:
                help_message = subparser.format_help()
            else:
                help_message = parser.format_help()
            return help_message

    #. Process positional arguments for 'search'
    #; commands with positional arguments [label value verbose]
    lvv = ['add', 'edit', 'search']
    if args.cmd in lvv:
        if args.pos:
            if args.label is None:
                args.label = args.pos[0]
            if len(args.pos) > 1:
                args.value = args.pos[1]
            if len(args.pos) > 2:
                args.database = args.pos[2]
            if len(args.pos) > 3:
                args.verbose = args.pos[3].lower() in ['true', '1', 'yes', 'verbose']

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

    #. Custom handling for 'help' command
    if args.cmd == 'help':
        help_message = parser.format_help()
        return help_message

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

    plugin:SlackClient = await get_plugin()
    await plugin.post_message(
        channel=plugin.admin_channel,
        text=text,
        blocks=blocks,
    )
    return {
        "response_type": "ephemeral",
        "text": f"Request for account received: <@{mojo.user_id}>"
    }

async def mojo_debug(
    mojo: MOJOCMD = None,
    user: User = None,
):
    _log.debug(f"Running debug endpoint")
    _log.debug(f"mojo: {mojo}")
    await asyncio.sleep(5)
    return mojo

async def mojo_add_thing(
    mojo: MOJOCMD = None,
    user: User = None,
)->bool:
    _log.debug(f"Opening add_thing modal...")

    #; parse args
    try:
        args = await mojo_parse_cmd(mojo.text)
    except SystemExit as e:
        _log.error(f"{xterm('RED')}Error parsing cmd: {e}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")

    plugin:SlackClient = await get_plugin()
    #; Check valid thing type
    # // valid_things = [thing['label'] for thing in led.schema['entity']]
    valid_things = list(led.schema['entity'].keys()) + \
        list(led.schema['relation'].keys())
    if args.label not in valid_things:
        matches = difflib.get_close_matches(
            args.label,
            valid_things,
            n=1,
            cutoff=0.6
        )
        if matches:
            txt = f"{args.label} is an invalid thing type. Did you mean {matches[0]}?"
        else:
            txt = f"{args.label} is an invalid thing type.\nValid things are: `{', '.join(valid_things)}`"
        await plugin.post_message(
            channel=mojo.channel_id,
            text=txt,
            blocks_verbatim=True,
            ephemeral=True,
            user=mojo.user_id,
        )
        return True

    #; Set user or default database
    mojo.db_name = user.db_name or plugin.default_db
    _log.debug(f"{xterm('CYAN')}Set user_db to {mojo.db_name}. user: {user.db_name} plugin: {plugin.default_db}{xterm('X')}")
    #; Open modal
    tdb:TypeDBClient = get_tdb()
    all_dbs = tdb.get_all_dbs(readable=True)
    tdb.close_client()
    try:
        mymodal = await ModalBuilder.add_thing_modal(
            db_name=mojo.db_name,
            channel_id=mojo.channel_id,
            label=args.label,
            value=args.value,
            all_dbs=all_dbs,
            ledschema=led.schema,
            plugin_list=led.list_plugins(),
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed building modal: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
    _log.debug(f"{xterm('CYAN')}view modal:\n{pformat(mymodal)}{xterm('X')}")
    _log.debug(f"{xterm('CYAN')}modal type: {type(mymodal)}{xterm('X')}")

    try:
        await plugin.views_open(
            trigger_id=mojo.trigger_id,
            view = mymodal,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed opening modal: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        return False

    return True

async def mojo_edit_thing(
    mojo: MOJOCMD = None,
    user: User = None,
)->bool:
    _log.debug(f"Opening add_thing modal...")

    #; parse args
    try:
        args = await mojo_parse_cmd(mojo.text)
    except SystemExit as e:
        _log.error(f"{xterm('RED')}Error parsing cmd: {e}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")

    plugin:SlackClient = await get_plugin()
    #; Check valid thing type
    # // valid_things = [thing['label'] for thing in led.schema['entity']]
    valid_things = list(led.schema['entity'].keys()) + \
        list(led.schema['relation'].keys())
    if args.label not in valid_things:
        matches = difflib.get_close_matches(
            args.label,
            valid_things,
            n=1,
            cutoff=0.6
        )
        if matches:
            txt = f"{args.label} is an invalid thing type. Did you mean {matches[0]}?"
        else:
            txt = f"{args.label} is an invalid thing type.\nValid things are: `{', '.join(valid_things)}`"
        await plugin.post_message(
            channel=mojo.channel_id,
            text=txt,
            blocks_verbatim=True,
            ephemeral=True,
            user=mojo.user_id,
        )
        return True

    #; Set user or default database
    mojo.db_name = user.db_name or plugin.default_db
    _log.debug(f"{xterm('CYAN')}Set user_db to {mojo.db_name}. user: {user.db_name} plugin: {plugin.default_db}{xterm('X')}")
    #; Normalize params
    db_name = args.database or mojo.db_name
    label = args.label
    value = args.value
    #; Get TypeDB Client
    if (tdb := get_tdb(db_name=db_name)) is None:
        _log.error(f"Invalid database: {db_name}")
        return False
    tdb:TypeDBClient
    all_dbs = tdb.get_all_dbs(readable=True)
    so = Entity(label=label)
    if value is None:
        things = tdb.find_things(label)
    else:
        keyattr = Attribute(label=so.keyattr, value=value)
        so.has.append(keyattr)
        things = tdb.find_things(so)
    tdb.close_client()

    #; Open modal
    try:
        mymodal = await ModalBuilder.edit_thing_modal(
            db_name=db_name,
            label=label,
            value=value,
            container={'channel_id': mojo.channel_id},
            things = things,
            all_dbs = all_dbs,
            ledschema = led.schema,
            plugin_list = led.list_plugins(),
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed building modal: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
    _log.debug(f"{xterm('CYAN')}view modal:\n{pformat(mymodal)}{xterm('X')}")
    _log.debug(f"{xterm('CYAN')}modal type: {type(mymodal)}{xterm('X')}")

    try:
        await plugin.views_open(
            trigger_id=mojo.trigger_id,
            view = mymodal,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed opening modal: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        return False

    return True

async def mojo_get_help(
    mojo: MOJOCMD = None,
    user: User = None,
)->bool:
    _log.debug(f"Generating help documents...")
    _log.debug(f"{mojo.text}")

    #; parse args
    try:
        help_message = await mojo_parse_cmd(mojo.text)
    except SystemExit as e:
        _log.error(f"{xterm('RED')}Error parsing cmd: {e}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        return False

    plugin:SlackClient = await get_plugin()

    mrkdwn_help = await mojo_help_to_mrkdwn(help_message)

    # // if not blocks:
    # //     blocks = None
    try:
        await plugin.post_message(
            # channel=plugin.admin_channel,
            channel=mojo.channel_id,
            text=mrkdwn_help,
            # // blocks=blocks,
            blocks_verbatim=True,
            ephemeral=True,
            user=mojo.user_id,
            mrkdwn=True,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed posting message..: {e}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")

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

    #; Check 'con' flag
    con_list = None
    if args.con:
        if args.con == 'all':
            con_list = [-1.0,0.0,1.0,2.0,3.0]
        else:
            con_list = list(map(float, args.con.split(',')))

    text_lines = []

    interesting_things = [
        'domain',
        'hostname',
        'ip',
        'jarm',
        'ja3s',
        'ssl',
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
        # // _log.debug(f"{xterm('CYAN')}Posting {text} to {plugin.admin_channel}...{xterm('X')}")
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
        # // _log.debug(f"MOJOCMD: {pformat(mojo)}")

        return True

    something_posted = False
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
        text_lines = []
        data = {db: thing_types}
        #; Generate pretty blocks with buttons.
        try:
            blocks = await ModalBuilder.new_hits(data, interesting_things, con_list)
            # // _log.debug(f"{xterm('CYAN')}Generated blocks: \n{pformat(blocks)}{xterm('X')}")
        except Exception as e:
            _log.error(f"{xterm('RED')}Failed generating blocks: {e}{xterm('X')}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        if not blocks:
            continue
        text_lines.append(f"*{db}*")
        for tt, entries in thing_types.items():
            if tt in interesting_things:
                text_lines.append(f"*Type: {tt}*")
                for e in entries:
                    for keyval, attributes in e.items():
                        if not con_list:
                            text_lines.append(f"```{keyval}```")
                            something_posted = True
                            '''
                            for label, values in attributes.items():
                                text_lines.append(f"\t{label}")
                                if isinstance(values, list):
                                    for value in values:
                                        text_lines.append(f"\t\t{value}")
                                elif isinstance(values, str):
                                    text_lines.append(f"\t\t{values}")
                            text_lines.append(f"```")
                            '''
                        else:
                            confidence = attributes.get('confidence')[0]
                            # _log.debug(f"con: {confidence}")
                            # _log.debug(f"con_list: {con_list}")
                            if confidence is None:
                                confidence = 0.0
                            if confidence in con_list:
                                text_lines.append(f"```{keyval}```")
                                something_posted = True
            else:
                _log.debug(f"{tt} not in {interesting_things}")

        # // if not text_lines:
        # //     text_lines = [f"No news from the last {args.hours_back} hours from {db}."]
        text = "\n".join(text_lines)
        if not blocks:
            blocks = None
        try:
            if plugin is None:
                plugin:SlackClient = await get_plugin('slack_client.01')
                _log.debug(f"plugin: {plugin}")
            # // _log.debug(f"something_posted: {something_posted}, text:{text}")
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

    if not something_posted and mojo.user_id!="AUTO-MOJO":
        await plugin.post_message(
            channel=mojo.channel_id,
            text=(f"Nothing interesting found for last `{args.hours_back} hours` "
                  f"in `{list(new_things.keys())}`")
        )

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
#~ slackaction_no_action
#~######################################
async def slackaction_no_action(plugin, payload, user): return True

async def blockaction_update_view(
    payload: Dict = None
)->Tuple[Dict, Union[str, bool]]:
    """Get updated view and selection value

    :param payload: Payload sent by block action when selection is chosen,
         defaults to None
    :type payload: Dict, required
    :return: copied view, selection value or False if invalid
    :rtype: Tuple[Dict, Union[str, bool]]
    """

    #; Clone the existing view properties
    copy_keys = [
        'blocks', 'callback_id',  'submit', 'title', 'type', 'private_metadata'
    ]
    view = {}
    for key in copy_keys:
        view[key] = payload['view'].get(key)
    #; Get the action
    actions = payload['actions']
    if not actions:
        _log.error(f"{xterm('RED')}No valid action was seen: {actions}{xterm('X')}")
        return view, False
    #; Get the value
    '''
    if actions[0].get('type') in ['static_select', 'external_select']:
        value = actions[0]['selected_option'].get('value')
    elif actions[0].get('type') in ['button']:
        value = actions[0].get('value')\
    else:
        value = False
    '''
    value = await SlackClient.get_state_vals_by_type(
        data=payload['actions'][0]
    )
    value = value[0]
    #! DEBUG
    _log.debug(
        f"{xterm('GREEN')}Updating view but keeping payload "
        f"{pformat(json.loads(view['private_metadata']))}"
    )

    if value is None:
        _log.error(f"{xterm('RED')}Invalid selected_option: "
                   f"{pformat(actions[0])}{xterm('X')}")
        return view, False
    return view, value

#~######################################
#~ slackaction_edit_thing_search
#~######################################
async def edit_thing_blocks(
    db_name: str = None,
    thing: Union[Entity, Relation] = None,
)->Dict:
    #TODO - Move me to Models.slack.py
    blocks = []

    #; Set Header
    blocks.append(await ModalBuilder.block_header(f"{thing.label.upper()}: {thing.keyval.upper()}"))
    #; Handle Date Context
    date_context = []
    fs = thing.attrs('first-seen')
    if fs:
        date_context.append(('mrkdwn', f'*first-seen*\n{await ModalBuilder.get_date(fs)}', True))
    ls = thing.attrs('last-seen')
    if ls:
        date_context.append(('mrkdwn', f'*last-seen*\n{await ModalBuilder.get_date(ls)}', True))
    disco = thing.attrs('date-discovered')
    if disco:
        date_context.append(('mrkdwn', f'*discovered*\n{await ModalBuilder.get_date(disco)}', True))

    blocks.append(await ModalBuilder.block_context(date_context, 'date-context'))

    #; Handle LEDSRC
    ledsrc = thing.attrs('ledsrc')
    if ledsrc:
        if not isinstance(ledsrc, list):
            ledsrc = [ledsrc]
        blocks.append(await ModalBuilder.block_section_mrkdwn(
            text=f"*LEDSRC*"
        ))
        for attr in ledsrc:
            blocks.append(await ModalBuilder.block_section_button(
                text=attr.value,
                button_text=":mag_right:",
                value=f"({db_name},{attr.label},{attr.value})",
                action_id="pivot_attr",
            ))

    #; Handle Hunt Names
    hunts = thing.attrs('hunt-name')
    if hunts:
        if not isinstance(hunts, list):
            hunts = [hunts]
        blocks.append(await ModalBuilder.block_section_mrkdwn(
            text=f"*HUNT-NAMES*"
        ))
        for attr in hunts:
            blocks.append(await ModalBuilder.block_section_button(
                text=attr.value,
                button_text=":mag_right:",
                value=f"({db_name},{attr.label},{attr.value})",
                action_id="pivot_attr"
            ))

    #; Add Confidence Selector

    #; Add Actors

    #; Add Tags

    #; Add Notes

    #; Populate other existing attributes

    #; Add Other Things Dropdown


    return blocks

async def slackaction_edit_thing_search(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
)->bool:
    view_id = payload['view']['id']
    hash = payload['view']['hash']
    #@ Get the update value
    view, value = await blockaction_update_view(payload)
    _log.debug(f"{xterm('CYAN')}Selected {value}...")
    _log.debug(f"View: {pformat(view)}")
    _log.debug(f"Payload: \n{pformat(payload)}{xterm('X')}")
    #@ Get thing details from TDB
    label = payload['view']['title'].get('text').split(' ')[-1].lower()
    set_vals = payload['view']['state']['values']
    tdb:TypeDBClient = await check_db(set_vals)
    if not tdb:
        return False
    so = Entity(label=label, has=[])
    so.has.append(Attribute(label=so.keyattr, value=value))
    rez = tdb.find_things(so)
    all_dbs = tdb.get_all_dbs(readable=True)
    tdb.close_client()
    #@ Modify blocks
    #; Remove DB and Keyval input blocks
    #; Just kidding... those are the only 2 blocks so we can just start from scratch
    # blocks = await edit_thing_blocks(
    #     db_name = tdb.db_name,
    #     thing = rez,
    # )
    # TODO - Move this User_UUID crap into the User object maybe
    thing = rez[0]
    user_uuids = (
        thing.attrs('user-uuid')
        if isinstance(thing.attrs('user-uuid'), list)
        else [thing.attrs('user-uuid')]
    )
    if user_uuids:
        user_ids = []
        for uuid in user_uuids:
            if uuid == '00000000-0000-0000-0000-000000000000':
                continue
                slack_id = "MOJOBOT" #TODO - FIXME
                user_ids.append(slack_id)
            else:
                slack_id = User.load_by_uuid(uuid).slack_id
                user_ids.append(slack_id)
        user_info = await plugin.users_info(user_ids=user_ids)
    else:
        user_info = None

    _log.debug(f"{xterm('GREEN')}metadata_in: {view.get('private_metadata')}")
    modal = await ModalBuilder.edit_thing_modal(
        db_name=tdb.db_name,
        label=label,
        container=payload.get('container'),
        things=rez,
        all_dbs=all_dbs,
        ledschema=led.schema,
        plugin_list=led.list_plugins(),
        user_info=user_info,
        private_metadata=view.get('private_metadata'),
    )
    _log.debug(f"Response modal:\n{pformat(modal)}")
    view['blocks'] = modal['blocks']
    view['private_metadata'] = modal['private_metadata']
    _log.debug(f"{xterm('GREEN')}metadata_out: {view.get('private_metadata')}")
    #; Add DB and Keyval as hard-coded labels
    #; Add context blocks (first/last seen, ledsrc, hunt-names)
    #; Populate changeable attribute fields
    #; Update modal view

    try:
        result = await plugin.views_update(
            view=view,
            view_id=view_id,
            hash=hash,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed updating view: {e}{xterm('X')}")
    if result:
        return True
    return False

#~######################################
#~ slackaction_get_hunt_endpoints
#~######################################
async def slackaction_get_hunt_endpoints(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
)->bool:

    view_id = payload['view']['id']
    hash = payload['view']['hash']

    view, plugin_name = await blockaction_update_view(payload)
    _log.debug(f"{xterm('CYAN')}Searching for {plugin_name} endpoints...{xterm('X')}")

    #; Get valid endpoints and URI paths for plugin_name
    try:
        myplugin = led.load_plugin(plugin_name)
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed loading plugin {plugin_name}:"
                   f" {e}{xterm('X')}")
        return False
    api_confs = list(myplugin.api_confs.keys())
    endpoints = {}
    for ac in api_confs:
        endpoints[ac] = myplugin.api_confs[ac].to_dict().get('uri')

    #; Build new block
    new_block = await ModalBuilder.get_hunt_endpoints(endpoints)
    _log.debug(f"{xterm('CYAN')}Built new_block {pformat(new_block)}{xterm('X')}")

    #; Remove block_id for hunt-endpoints if one already exists
    removed_endpoint = [d for d in view['blocks'] if d.get('block_id') != 'hunt-endpoint']
    view['blocks'] = removed_endpoint

    #; Add new hunt-endpoint block
    for index, d in enumerate(view['blocks']):
        if d.get('block_id') == 'hunt-service':
            view['blocks'].insert(index + 1, new_block)
            break

    result = None
    # // _log.debug(f"{xterm('CYAN')}Sending view: {pformat(view)}{xterm('X')}")
    try:
        result = await plugin.views_update(
            view=view,
            view_id=view_id,
            hash=hash,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed updating view: {e}{xterm('X')}")
    if result:
        return True
    return False

#~######################################
#~ slackation_get_attr_labels
#~######################################

async def slackation_get_attr_labels(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
)->bool:
    """Handle when an attribute label is selected and an input needs to be created

    :param plugin: instance of SlackClient plugin, defaults to None
    :type plugin: SlackClient, optional
    :param payload: Payload sent when selecting a label after Add New Attribute,
        defaults to None
    :type payload: Dict, optional
    :param user: User initiating the request, defaults to None
    :type user: User, optional
    :return: True if successful, False if failed
    :rtype: bool
    """
    view_id = payload['view']['id']
    hash = payload['view']['hash']

    view, label = await blockaction_update_view(payload)
    if not label:
        return False
    #; Get the value_type
    label_schema = led.schema['attribute'].get(label)
    if label_schema is None:
        _log.error(f"{xterm('RED')}No schema available for {label}{xterm('X')}")
        return False
    value_type = label_schema.get('value_type')
    if value_type is None:
        _log.error(f"{xterm('RED')}No value_type found for {label}.{xterm('X')}")
        return False
    new_input = await ModalBuilder.add_attribute_value(label=label, value_type=value_type)

    #; Update the view with a new input
    #; Remove the label we just selected and add the fresh input
    del view['blocks'][-1]
    #; Add the new input
    view['blocks'].append(new_input)
    #; Add back in the 'Add Attribute' button
    view['blocks'].append(await ModalBuilder.get_add_attribute())
    #! Check if block count is above a certain threshold, then potentially
    #! remove the 'add new attribute' button as well.
    result = None
    _log.debug(f"{xterm('CYAN')}Sending view: {pformat(view)}{xterm('X')}")
    try:
        result = await plugin.views_update(
            view=view,
            view_id=view_id,
            hash=hash,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed updating view: {e}{xterm('X')}")
    if result:
        return True
    return False

#~######################################
#~ slackaction_add_new_attribute
#~######################################

async def slackaction_add_new_attribute(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
)->bool:
    """handle when Add New Attribute button is clicked

    :param plugin: instance of SlackClient plugin, defaults to None
    :type plugin: SlackClient, optional
    :param payload: Payload sent when clicking Add New Attribute, defaults to None
    :type payload: Dict, optional
    :param user: User initiating the request, defaults to None
    :type user: User, optional
    :return: True if successful, False if failed
    :rtype: bool
    """
    #; Clone the existing view properties
    view_id = payload['view']['id']
    hash = payload['view']['hash']

    view, value = await blockaction_update_view(payload)

    #; Remove focus-on-load from all other blocks
    for block in view['blocks']:
        if block.get('element') and block.get('element').get('focus_on_load'):
            block['element']['focus_on_load'] = False
        elif block.get('accessory') and block.get('accessory').get('focus_on_load'):
            block['accessory']['focus_on_load'] = False
    #; Update the view with a new input
    label = payload['view']['title'].get('text').split(' ')[-1].lower()

    #; Get schema and meta attributes for building new_attr_label block
    schema = led.schema['entity'].get(label)
    meta_attrs = Entity(label=label).meta_attrs
    if schema is None:
        schema = led.schema['relation'].get(label)
        meta_attrs = Relation(label=label).meta_attrs
        if schema is None:
            _log.error(f"Failed obtaining schema for {label}")
            return False
    new_attr_label = await ModalBuilder.add_attribute_label(
        label=label,
        schema=schema,
        meta_attrs=meta_attrs,
    )
    view['blocks'].pop() #; Remove the 'add attribute' button
    view['blocks'].append(new_attr_label) #; Add the new label
    result = None
    _log.debug(f"{xterm('CYAN')}Sending view: {pformat(view)}{xterm('X')}")
    try:
        result = await plugin.views_update(
            view=view,
            view_id=view_id,
            hash=hash,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed updating view: {e}{xterm('X')}")
    if result:
        return True
    return False

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
    db_name = payload['actions'][0]['value'].split('|')[0]
    iid = payload['actions'][0]['value'].split('|')[1]
    container = payload['container']
    if (tdb := get_tdb(db_name=db_name)) is None:
        _log.error(f"Invalid database: {db_name}")
        return False
    tdb:TypeDBClient
    all_dbs = tdb.get_all_dbs(readable=True)
    if db_name not in all_dbs:
        _log.warning(
            f"{xterm('YELLOW')}{db_name} is an invalid DB. Must be one of:"
            f" {all_dbs}{xterm('X')}"
        )
        return False

    tdb.db_name = db_name
    so = Entity(label='entity')
    so.iid = iid
    rez = tdb.find_things(so)
    tdb.close_client()
    if not rez:
        _log.error(f"Could not find object in {db_name} with iid {iid}")
        return False
    else:
        thing = rez[0]

    things = [thing]
    label = thing.label
    ledschema = led.schema
    plugin_list = led.list_plugins()
    # TODO - Move this User_UUID crap into the User object maybe
    user_uuids = (
        thing.attrs('user-uuid')
        if isinstance(thing.attrs('user-uuid'), list)
        else [thing.attrs('user-uuid')]
    )
    if user_uuids:
        user_ids = []
        for uuid in user_uuids:
            if uuid == '00000000-0000-0000-0000-000000000000':
                continue
                slack_id = "MOJOBOT" #TODO - FIXME
                user_ids.append(slack_id)
            else:
                slack_id = User.load_by_uuid(uuid).slack_id
                user_ids.append(slack_id)
        user_info = await plugin.users_info(user_ids=user_ids)
    else:
        user_info = None

    try:
        # // mymodal = update_thing_modal(payload)
        mymodal = await ModalBuilder.edit_thing_modal(
            db_name=db_name,
            label=label,
            container=container,
            things=things,
            all_dbs=all_dbs,
            ledschema=ledschema,
            plugin_list=plugin_list,
            user_info=user_info,
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed building modal: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
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
#~ slackaction_add_thing
#~######################################

async def slackaction_add_thing(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
)->Union[Dict, False]:
    _log.debug(f"Adding thing...")
    _log.debug(f"{xterm('YELLOW')}{pformat(payload)}{xterm('X')}")
    message_failed = False
    #; Parse out important values
    label = payload['view']['title'].get('text').split(' ')[-1].lower()
    values = payload['view']['state']['values']
    #; Build Thing Object
    if label in led.schema['entity']:
        new_thing = Entity(label=label)
    elif label in led.schema['relation']:
        new_thing = Relation(label=label)
    else:
        msg = f"Invalid label: {label}"
        _log.error(xterm('RED')+msg+xterm('X'))
        message_failed = True

    for block_id, fieldvals in values.items():
        if message_failed:
            continue
        #; Get DB Name
        if fieldvals.get('select_db'):
            db_name = fieldvals.get('select_db').get('selected_option').get('value')
            continue

        #; Parse Attributes
        skip_me = ['db']
        for field, data in fieldvals.items():
            # // attr_label = field.split('_')[-1]
            if block_id in ['db_name']:
                continue
            attr_label = block_id
            if attr_label in skip_me:
                continue
            if attr_label == 'keyattr':
                attr_label = new_thing.keyattr
            '''
            data_type = data.get('type')
            if data_type in ['plain_text_input', 'number_input']:
                val = data.get('value')
                if val is None:
                    continue
                attr = Attribute(label=attr_label, value=val)
                new_thing.has.append(attr)
            elif data_type == 'static_select':
                val = data.get('selected_option').get('value')
                if val is None:
                    continue
                attr = Attribute(label=attr_label, value=val)
                new_thing.has.append(attr)
            elif data_type in ['checkboxes', 'multi_external_select']:
                opts = data.get('selected_options')
                for opt in opts:
                    val = opt.get('value')
                    if val is None:
                        continue
                    if data_type == 'checkboxes':
                        if val == 'on':
                            val = True
                    attr = Attribute(label=attr_label, value=val)
                    new_thing.has.append(attr)
            elif data_type == 'datetimepicker':
                if data.get('selected_date_time') is None:
                    continue
                val = format_date(data.get('selected_date_time'))
                attr = Attribute(label=attr_label, value=val)
                new_thing.has.append(attr)
            else:
                _log.error(
                    f"{xterm('RED')}Unknown data type: {data_type}. "
                    f"Skipping {attr_label}.{xterm('X')}"
                )
            '''
            values = await plugin.get_state_vals_by_type(data)
            for value in values:
                attr = Attribute(label=attr_label, value=value)
                new_thing.has.append(attr)

    #; Attach submitting user
    new_thing.has.append(Attribute(label='user-uuid', value=user.uuid))

    #; Set LEDSRC
    ledsrc = "Slack"
    ledsrc += f"|{payload['team'].get('id')}"
    ledsrc += f"|{payload['user'].get('id')}"
    channel = payload['view'].get('private_metadata')
    if channel is not None:
        ledsrc += f"|{channel}"
    new_thing.has.append(Attribute(label='ledsrc', value=ledsrc))

    if not message_failed:
        #; Get tdb client
        if (tdb := get_tdb(db_name=db_name)) is None:
            _log.error(f"Invalid database: {db_name}")
            return False
        tdb: TypeDBClient
        #; Validate database
        if not tdb.check_db(db_name=db_name):
            msg = f"Database {db_name} does not exist!"
            _log.error(xterm('RED')+msg+xterm('X'))
            message_failed = True

        #; Run the add_thing(thing, user) task
        try:
            _log.debug(f"{xterm('CYAN')}Attempting to add thing "
                    f"{pformat(new_thing.to_dict())}{xterm('X')}")
            rez = tdb.add_thing(new_thing, return_things=True)
            _log.debug(f"{xterm('CYAN')}Result: {rez}{xterm('X')}")
        except Exception as e:
            msg = f"Failed adding things: {e}"
            _log.error(xterm('RED')+msg+xterm('X'))
            message_failed = True

    if message_failed:
    #; Set params for successful result or ephemeral failure message
        #; Also set params if it failed
        params = dict(
            channel = payload['view']['private_metadata'].get('channel_id'),
            text = (f"Failed adding {new_thing}. "
                    f"Check error log."),
            ephemeral = True,
            blocks_verbatim = True,
            user=user.slack_id,
        )
        await plugin.post_message(**params)
        return False

    #; Otherwise, send success message to admin channel
    params = dict(
        channel = plugin.admin_channel,
        text = (f"<@{payload['user']['id']}> Successfully added `{rez}` to "
                # // f"`{db_name}`!\n```{rez.to_dict()}```"),
                f"`{db_name}`!"),
        blocks_verbatim = True,
        user=user.slack_id,
    )
    await plugin.post_message(**params)
    #; Send same message to user

    params = dict(
        channel = payload['view']['private_metadata'].get('channel_id'),
        text = (f"Successfully added `{rez}` to {db_name}!"),
                # // f"`{db_name}`!\n```{rez.to_dict()}```"),
        ephemeral = True,
        blocks_verbatim = True,
        user=payload['user']['id'],
    )

    await plugin.post_message(**params)

    return {'response_action': 'clear'}


#~######################################
#~ slackaction_edit_thing
#~######################################

async def slackaction_edit_thing(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
)->Dict:
    _log.debug(f"Editing thing...")

    state_values = payload['view']['state'].get('values')
    pmd = payload['view'].get('private_metadata')
    pmd = json.loads(pmd)
    iid = pmd.get('iid')
    db_name = pmd.get('db_name')
    if any(x is None for x in [iid, db_name]):
        _log.error(
            f"User attempted to edit thing with missing iid or db_name. "
            f"iid: {iid} db_name: {db_name}"
        )
        return {'response_action': 'clear'}
    #; Get TypeDB Client
    if (tdb := get_tdb(db_name=db_name)) is None:
        _log.error(f"Invalid database: {db_name}")
        return {'response_action': 'clear'}
    tdb:TypeDBClient
    so = Entity(label='entity')
    so.iid = iid
    #; Pull the Thing object from the DB based on private_metadata
    thing = tdb.find_things(so)[0]
    #; Loop through all state_values that were set, add them as attributes
    for block_id, actions in state_values.items():
        #TODO - Extract label from block_id
        label = block_id
        for action_id, data in actions.items():
            # // _log.debug(f"Action: {action_id} Data: {data}")
            values = await plugin.get_state_vals_by_type(data)
            if values is None:
                continue
            for value in values:
                attr = Attribute(label=label, value=value)
                if attr not in thing.has:
                    thing.has.append(attr)
    #; Call tdb.add_thing() in the ledapi/tasks/hunter.py tasks

    thingsub = ThingSubmission(
        db_name = db_name,
        label = thing.label,
        thing_type = thing.thingtype,
        attributes = thing.attrs()
    )

    #@ Actually set the confidence inside the database
    msg = None
    try:
        result = await add_thing_task(thingsub, user)
        params = dict(
            channel=plugin.admin_channel,
            text=(f"<@{payload['user']['id']}> successfully modified `{db_name} "
                  f"{result.label} {result.keyval}` to \n"
                  f"```{pformat(result)}```"),
            blocks_verbatim = True,
        )
    except SlackApiError as e:
        msg = f"Error from SlackAPI: {e}"
        msg += f"\nTraceback: \n{pformat(traceback.format_exc())}"
        _log.error(msg)
    except Exception as e:
        msg = f"Error from LEDAPI: {e}"
        msg += f"\nTraceback: \n{pformat(traceback.format_exc())}"
        _log.error(msg)
    if msg:
        params = dict(
            channel = payload['user']['id'],
            text = msg,
            ephemeral = True,
            blocks_verbatim = True,
            user=user.slack_id,
        )

    #@ Actually add the thing (this also handles updates and deconflicts meta attributes)
    _log.debug(f"Updated thing: {xterm('CYAN')}{pformat(thing.to_dict())}")
    #; Post @user updated <blah> + diff changes in channel
    # TODO - calc diff changes instead of dumping the whole Thing
    #; Print the result of this operation
    await plugin.post_message(**params)
    #; Close modal
    return {'response_action': 'clear'}

#~######################################
#~ slackaction_set_confidence
#~######################################

async def slackaction_set_confidence(
    plugin: SlackClient = None,
    payload: Dict = None,
    user: User = None,
)->Dict:
    _log.debug(f"Setting confidence...")
    _log.debug(f"{xterm('YELLOW')}{pformat(payload)}{xterm('X')}")
    # // value_str = payload['actions'][0]['selected_option']['value']

    try:
        '''
        value_str = (
            payload['view']['state']['values']
            [next(iter(payload['view']['state']['values']))]
            ['new_confidence']['selected_option']['value']
        )
        '''
        value_str = (
            payload['view']['state']['values'].get('confidence')
            ['set_confidence']['selected_option']['value']
        )
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed getting value str: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
    db_name = value_str.split('|')[0]
    iid = value_str.split('|')[1]
    value = value_str.split('|')[2]

    setcon = ConmanObject(
        db_name = db_name,
        iid = iid,
        confidence = value,
    )

    #@ Actually set the confidence inside the database
    result = await set_confidence_task(setcon, user)

    if result:
        params = dict(
            channel=plugin.admin_channel,
            text=(f"<@{payload['user']['id']}> successfully set `{db_name} "
                  f"{result.label} {result.keyval}` to "
                  f"{await ModalBuilder.get_con_format(int(value))}"),
            blocks_verbatim = True,
        )

        #@ update original message with new confidence and alert group that a user changed it.
        try:
            container = json.loads(payload['view']['private_metadata'])
            _log.debug(f"{xterm('GREEN')}container message_ts: {container['message_ts']}")
            _log.debug(f"{xterm('GREEN')}container thread_ts: {container.get('thread_ts')}")
        except Exception as e:
            _log.error(f"{xterm('RED')}{pformat(payload['view']['private_metadata'])}{xterm('X')}")
            _log.error(f"{xterm('RED')}{pformat(container)}{xterm('X')}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        #; Get the old message
        oldest = container.get('thread_ts')
        old_message = await plugin.conversations_history(
            channel=container['channel_id'],
            oldest=oldest,
            latest=container['message_ts'],
            # // limit=1,
            inclusive=True,
        )
        _log.debug(f"{xterm('GREEN')}latest: {old_message['latest']}")
        # // _log.debug(f"{xterm('CYAN')}old_message: {pformat(old_message)}")
        #; Modify the blocks
        block_id = None
        for message in old_message['messages']:
            old_blocks = message['blocks']
            updated_blocks = copy.deepcopy(old_blocks)
            for block in old_blocks:
                if 'accessory' in block:
                    if block['accessory']['value'] == f"{db_name}|{iid}":
                        block_id = block['block_id']
                        _log.debug(f"block_id={block_id}")
            if block_id:
                break

        if block_id is None:
            _log.warning(
                f"Couldn't find block_id in conversation history. Checking thread."
            )
            thread_messages = await plugin.conversations_replies(
                channel=container['channel_id'],
                ts=container.get('thread_ts'),
                inclusive=True,
            )
            for message in thread_messages['messages']:
                if message['ts'] == container['message_ts']:
                    old_blocks = message['blocks']
                    updated_blocks = copy.deepcopy(old_blocks)
                for block in old_blocks:
                    if 'accessory' in block:
                        if block['accessory']['value'] == f"{db_name}|{iid}":
                            block_id = block['block_id']
                            _log.debug(f"block_id={block_id}")
                if block_id:
                    break

        if block_id is None:
            _log.error(f"Missing block_id! old_blocks should have "
                    f"accessory|value of {db_name}|{iid}. "
                    f"old_blocks: {xterm('CYAN')}{pformat(old_blocks)}")
            return False

        for block in updated_blocks:
            if block['block_id'] == block_id:
                block['accessory']['text']['text'] = await ModalBuilder.get_con_format(int(value))

        #; Update the old message
        resp = await plugin.update_message(
            channel = container['channel_id'],
            ts = container['message_ts'],
            text = message['text'],
            blocks = updated_blocks,
        )
    else:
        params = dict(
            channel = payload['user']['id'],
            text = (f"Failed setting confidence for {db_name} {iid}. "
                    f"Check error log."),
            ephemeral = True,
            blocks_verbatim = True,
            user=user.slack_id,
        )
    #; Print the result of setting the confidence
    await plugin.post_message(**params)

    return {'response_action': 'clear'}

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
    await plugin.views_open(
        trigger_id=payload['trigger_id'],
        view=await ModalBuilder.add_user_modal(
            userval=action['value'],
            roles=[role for role in RoleEnum.valid_roles()],
        )
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
        "add": (mojo_add_thing, role_hunter),
        "edit": (mojo_edit_thing, role_hunter),
        "help": (mojo_get_help, role_everyone),
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
    if mojo.text.endswith(('-h', '--help')):
        await mojo_get_help(mojo, user)
    elif cmd in opts:
        func_perms = opts[cmd]
        try:
            _log.debug(f"Checking user.role {user.role} against roles: {func_perms[1]}")
            await check_role(user, func_perms[1])
        except HTTPException as e:
            await plugin.unauthorized_resp(trigger_id=mojo.trigger_id)
        except Exception as e:
            raise
        try:
            #; post ephemeral acknowledgement of command
            await plugin.post_message(
                channel=mojo.channel_id,
                text=f"Received `{mojo.text}`",
                ephemeral=True,
                blocks_verbatim=True,
                user=mojo.user_id,
            )
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

    _log.debug(f"Payload: \n{xterm('YELLOW')}{pformat(payload)}{xterm('X')}")

    opts = {
        'block_actions':{
            'add_new_attribute': (slackaction_add_new_attribute, role_hunter),
            'check_job_status': (slackaction_check_job_status, role_everyone),
            'edit_thing_search': (slackaction_edit_thing_search, role_hunter),
            'get_attr_labels': (slackation_get_attr_labels, role_hunter),
            'get_hunt_endpoints': (slackaction_get_hunt_endpoints, role_hunter),
            'no_action': (slackaction_no_action, role_everyone),
            'open_add_user_modal': (slackaction_open_add_user_modal, role_dbadmin),
            #. role_everyone can open the dialog, but only con_man can change the confidence
            'set_confidence': (slackaction_set_confidence, role_conman),
            'set_confidence_modal': (slackation_set_confidence_modal, role_everyone),
        },
        'view_submission':{
            # // #. slackaction_update_thing() lets you set confidence, add notes and tags
            # // #; 'update_thing': (slackation_update_thing, role_conman),
            'add_thing': (slackaction_add_thing, role_hunter),
            'add_user_modal': (slackaction_submit_add_user, role_dbadmin), #do the add-user stuff
            'edit_thing': (slackaction_edit_thing, role_hunter),
            'update_thing_submit': (update_thing_submit, role_conman)
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
        '''
        aid_trunc = action_id.rpartition('_')[0]
        if aid_trunc not in opts[payload['type']]:
        _log.error(f"{xterm('RED')}No action index called {aid_trunc}{xterm('X')}")
            continue
        func_perms = opts[payload['type']][aid_trunc]
        '''
        if action_id not in opts[payload['type']]:
            _log.error(f"{xterm('RED')}No action index called {action_id}{xterm('X')}")
            continue
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
            _log.error(f"{xterm('RED')}Failed running {func_perms[0]}: {e}")
            _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")

    #. Will also have to figure out how to properly return a list of responses.
    #. resp will probably have to be converted to a dict w/ action_id's as the keys.
    if len(resp) == 1:
        return resp[0]
    if not resp:
        resp = True
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


async def slackoptions_conf(
    req: Dict = None,
    user: User = None,
):
    plugin:SlackClient = await get_plugin()
    # data = json.loads(payload)
    # // data = req['payload']
    data = json.loads(req['payload'])
    _log.debug(f"{xterm('CYAN')}{pformat(data)}{xterm('X')}")
    action_id = data['action_id']
    # // view = data['view']
    # // state = view['state']
    _log.debug(f"{xterm('CYAN')}Received action_id: {action_id}{xterm('X')}")
    #@ populate options
    opts = {
        'add_thing_get_actor-name': (opts_add_thing_get_actor, role_hunter),
        'add_thing_get_tag': (opts_add_thing_get_tag, role_hunter),
        'edit_thing_search': (opts_edit_thing_search, role_hunter),
        #. removed in favor of static population
        # // 'get_attr_labels': (opts_get_attr_labels, role_hunter),
    }
    if action_id in opts:
        func_perms = opts[action_id]
        try:
            _log.debug(f"Checking user.role {user.role} against roles: {func_perms[1]}")
            await check_role(user, func_perms[1])
        except HTTPException as e:
            # // await plugin.unauthorized_resp(trigger_id=mojo.trigger_id)
            _log.error(
                f"{xterm('RED')}Unauthorized user: {user.slack_id} with role "
                f"{user.role}. Requires {func_perms[1]} or higher.{xterm('X')}"
            )
            raise
        except Exception as e:
            raise
        try:
            #; Run the options-getting function
            resp = await func_perms[0](data, user)
        except Exception as e:
            _log.error(
                f"{xterm('RED')}Failed running {func_perms[0]}: {e}{xterm('X')}"
            )
    else:
        _log.error(f"{xterm('RED')}No actions specified for {action_id}{xterm('X')}")
        resp = None

    return resp

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
    _log.debug(f"MOJOCMD: {pformat(mojo)}")
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
    try:
        payload = json.loads(payload)
    except TypeError as e:
        _log.error(f"{xterm('RED')}MAKE SURE YOUR PAYLOAD IS SMALL!{xterm('X')}")
        _log.error(f"{xterm('RED')}request:{pformat(form)}{xterm('X')}")
        _log.error(f"{xterm('RED')}payload:{pformat(payload)}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
        raise
    _log.debug(f"payload: {pformat(payload)}")
    _log.debug(f"user: {user}")

    resp = {}
    resp['payload'] = payload
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    # resp['body'] = await request.body() #
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

    job = queue.enqueue_call(
        slackevent_conf,
        args=[resp, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id, slack_format=True)

    return response

async def options_handler(
    request: Request = None,
    user: User = None,
):
    worker_name = await get_available_worker('slack_client')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing options_handler")
    _log.debug(f"request: {request}")
    _log.debug(f"user: {user}")
    # // _log.debug(f"form: {pformat(await request.form())}")

    resp = {}
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    # // resp['body'] = await request.body()
    # // resp['body'] = resp['body'].decode('utf-8')
    form = await request.form()
    payload = form.get('payload')
    resp['payload'] = payload

    job = queue.enqueue_call(
        slackoptions_conf,
        args=[resp, user],
        timeout=60*5,
        result_ttl=60*60,
    )

    response = await two_sec_grace(worker_name, job.id, slack_format=True)

    return response