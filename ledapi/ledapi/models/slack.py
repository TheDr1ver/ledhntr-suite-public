from argparse import Namespace
from datetime import datetime, timezone
from pprint import pformat
from pydantic import BaseModel, model_validator
from typing import Optional, Dict, List
from uuid import uuid4

from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)

from ledhntr.helpers import dumps

from ledapi.config import(
    led,
    _log,
    get_tdb,
    wqm,
    xterm,
)

from ledapi.models import RoleEnum
from slack_client import (
    block_checkbox,
    block_context,
    block_datetime_picker,
    block_divider,
    block_external_select,
    block_header,
    block_number,
    block_plain_text_input,
    block_static_select,
    get_con_format,
    get_date,
    get_link_formats,
)

from typedb_client import TypeDBClient

#@##############################################################################
#@### Pydantic API models
#@##############################################################################

class MOJOCMD(BaseModel):
    admin_channel: str = None
    api_app_id: str = None
    channel_id: str = None
    channel_name: str = None
    command: str = None
    db_name: str = None
    is_enterprise_install: bool = False
    response_url: str = None
    slackbot_token: str = None
    token: str = None
    team_id: str = None
    team_domain: str = None
    text: str = None
    trigger_id: str = None
    user_channel: str = None
    user_id: str = None
    user_name: str = None


class SlackEvent(BaseModel):
    api_app_id: str = None
    authorizations: List = None
    context_team_id: str = None
    context_enterprise_id: str = None
    event: Dict = None
    event_context: str = None
    event_id: str = None
    event_time: int = None
    is_ext_shared_channel: bool = False
    token: str = None
    team_id: str = None
    type: str = None

    '''
    # Reaction Added
    "event":
    {
        "token": "<YOURTOKEN>",
        "team_id": "<YOURTEAMID>",
        "context_team_id": "<YOURTEAMID>",
        "context_enterprise_id": null,
        "api_app_id": "<YOURAPPID>",
        "event":
        {
            "type": "reaction_added",
            "user": "<YOURUSERID>",
            "reaction": "white_check_mark",
            "item":
            {
                "type": "message",
                "channel": "<YOURCHANNELID>",
                "ts": "1719931308.079589"
            },
            "item_user": "<YOURUSERID>",
            "event_ts": "1719932161.000300"
        },
        "type": "event_callback",
        "event_id": "<YOUREVENTID>",
        "event_time": 1719932161,
        "authorizations":
        [
            {
                "enterprise_id": null,
                "team_id": "<YOURTEAMID>",
                "user_id": "<BOTUSERID>",
                "is_bot": true,
                "is_enterprise_install": false
            }
        ],
        "is_ext_shared_channel": false,
        "event_context": "<EVENT_CONTEXT>"
    }
    # Reaction Removed
    {
        "token": "<YOURTOKEN>",
        "team_id": "<YOURTEAMID>",
        "context_team_id": "<YOURTEAMID>",
        "context_enterprise_id": null,
        "api_app_id": "<YOURAPPID>",
        "event":
        {
            "type": "reaction_removed",
            "user": "<YOURUSERID>",
            "reaction": "+1",
            "item":
            {
                "type": "message",
                "channel": "<YOURCHANNELID>",
                "ts": "1719931308.079589"
            },
            "item_user": "<YOURUSERID>",
            "event_ts": "1719931739.000200"
        },
        "type": "event_callback",
        "event_id": "<EVENTID>",
        "event_time": 1719931739,
        "authorizations":
        [
            {
                "enterprise_id": null,
                "team_id": "<YOURTEAMID>",
                "user_id": "<BOTUSERID>",
                "is_bot": true,
                "is_enterprise_install": false
            }
        ],
        "is_ext_shared_channel": false,
        "event_context": "<EVENT_CONTEXT>"
    }
    '''


class SlackAction(BaseModel):
    actions: List[Dict] = None
    api_app_id: str = None
    channel: Dict = None
    container: Dict = None
    enterprise: str = None
    is_enterprise_intsall: bool = False
    message: Dict = None # This is the message that was sent to the channel to create the modal
    response_url: str = None
    state: Dict = None
    team: Dict = None
    token: str = None
    trigger_id: str = None
    type: str = None
    user: Dict = None
    '''
    # sent as URL-encoded payload
    # once decoded looks like this
    # DISPLAY MODAL
    {
        "type": "block_actions",
        "user":
        {
            "id": "<YOURUSERID>",
            "username": "driver1",
            "name": "driver1",
            "team_id": "<YOURTEAMID>"
        },
        "api_app_id": "<YOURAPPID>",
        "token": "<YOURTOKEN>",
        "container":
        {
            "type": "message",
            "message_ts": "1719936116.634509",
            "channel_id": "<CHANNEL_ID>",
            "is_ephemeral": false
        },
        "trigger_id": "7377717242017.2625160776.f3e5c5297f73a70d5844279fb4e7a26f",
        "team":
        {
            "id": "<YOURTEAMID>",
            "domain": "<YOURDOMAIN>"
        },
        "enterprise": null,
        "is_enterprise_install": false,
        "channel":
        {
            "id": "<CHANNEL_ID>",
            "name": "privategroup"
        },
        "message":
        {
            "user": "<BOTUSERID>",
            "type": "message",
            "ts": "1719936116.634509",
            "bot_id": "B07AGQB38PQ",
            "app_id": "<YOURAPPID>",
            "text": "User <@<YOURUSERID>> has requested an account.",
            "team": "<YOURTEAMID>",
            "blocks":
            [
                {
                    "type": "section",
                    "block_id": "6OIqa",
                    "text":
                    {
                        "type": "mrkdwn",
                        "text": "User <@<YOURUSERID>> has requested an account.",
                        "verbatim": false
                    },
                    "accessory":
                    {
                        "type": "button",
                        "action_id": "open_add_user_modal",
                        "text":
                        {
                            "type": "plain_text",
                            "text": "Add User",
                            "emoji": true
                        },
                        "value": "<YOURUSERID>,<YOURTEAMID>"
                    }
                }
            ]
        },
        "state":
        {
            "values":
            {}
        },
        "response_url": "https://hooks.slack.com/actions/<YOURTEAMID>/<INT>/<TOKEN>",
        "actions":
        [
            {
                "action_id": "open_add_user_modal",
                "block_id": "6OIqa",
                "text":
                {
                    "type": "plain_text",
                    "text": "Add User",
                    "emoji": true
                },
                "value": "<YOURUSERID>,<YOURTEAMID>",
                "type": "button",
                "action_ts": "1719936125.886532"
            }
        ]
    }

    # SUBMIT MODAL
    {'api_app_id': '<YOURAPPID>',
 'enterprise': None,
 'is_enterprise_install': False,
 'response_urls': [],
 'team': {'domain': '<YOURDOMAIN>', 'id': '<YOURTEAMID>'},
 'token': '<YOURTOKEN>',
 'trigger_id': '7388071797920.2625160776.5584f1ebf91550f4a16e3474f866f2d5',
 'type': 'view_submission',
 'user': {'id': '<YOURUSERID>',
          'name': 'driver1',
          'team_id': '<YOURTEAMID>',
          'username': 'driver1'},
 'view': {'app_id': '<YOURAPPID>',
          'app_installed_team_id': '<YOURTEAMID>',
          'blocks': [{'block_id': 'user_block',
                      'dispatch_action': False,
                      'element': {'action_id': 'username',
                                  'dispatch_action_config': {'trigger_actions_on': ['on_enter_pressed']},
                                  'initial_value': '<YOURUSERID>,<YOURTEAMID>',
                                  'placeholder': {'emoji': True,
                                                  'text': 'Enter the username',
                                                  'type': 'plain_text'},
                                  'type': 'plain_text_input'},
                      'label': {'emoji': True,
                                'text': 'Username',
                                'type': 'plain_text'},
                      'optional': False,
                      'type': 'input'},
                     {'block_id': 'role_block',
                      'dispatch_action': False,
                      'element': {'action_id': 'role',
                                  'options': [{'text': {'emoji': True,
                                                        'text': 'Read-only',
                                                        'type': 'plain_text'},
                                               'value': 'read-only'},
                                              {'text': {'emoji': True,
                                                        'text': 'Conman',
                                                        'type': 'plain_text'},
                                               'value': 'conman'},
                                              {'text': {'emoji': True,
                                                        'text': 'Hunter',
                                                        'type': 'plain_text'},
                                               'value': 'hunter'},
                                              {'text': {'emoji': True,
                                                        'text': 'Dbadmin',
                                                        'type': 'plain_text'},
                                               'value': 'dbadmin'},
                                              {'text': {'emoji': True,
                                                        'text': 'Admin',
                                                        'type': 'plain_text'},
                                               'value': 'admin'}],
                                  'placeholder': {'emoji': True,
                                                  'text': 'Select a role',
                                                  'type': 'plain_text'},
                                  'type': 'static_select'},
                      'label': {'emoji': True,
                                'text': 'Role',
                                'type': 'plain_text'},
                      'optional': False,
                      'type': 'input'}],
          'bot_id': '<BOTID>',
          'callback_id': 'add_user_modal',
          'clear_on_close': False,
          'close': {'emoji': True, 'text': 'Cancel', 'type': 'plain_text'},
          'external_id': '',
          'hash': '1719938427.1QQ7fjy7',
          'id': '<ID>',
          'notify_on_close': False,
          'previous_view_id': None,
          'private_metadata': '',
          'root_view_id': '<ROOTVIEWID>',
          'state': {'values': {'role_block': {'role': {'selected_option': {'text': {'emoji': True,
                                                                                    'text': 'Admin',
                                                                                    'type': 'plain_text'},
                                                                           'value': 'admin'},
                                                       'type': 'static_select'}},
                               'user_block': {'username': {'type': 'plain_text_input',
                                                           'value': '<YOURUSERID>,<YOURTEAMID>'}}}},
          'submit': {'emoji': True, 'text': 'Submit', 'type': 'plain_text'},
          'team_id': '<YOURTEAMID>',
          'title': {'emoji': True, 'text': 'Add User', 'type': 'plain_text'},
          'type': 'modal'}}
    '''


#@##############################################################################
#@### Slack Modals
#@###
#@### Consider rolling these into the SlackClient plugin - potentially with
#@### their own modals.py file that gets imported by slack_client.py
#@### it's just way easier to dev like this because the app reloads every time
#@### I save, so I don't have to keep reinstalling the damn plugin.
#@##############################################################################

def _get_actors()->Dict:

    block = {
        'type': 'section',
        'block_id': 'actor-name',
        'text': {
            'type': 'mrkdwn',
            'text': 'Actors',
        },
        'accessory': {
            'action_id': 'add_thing_get_actor-name',
            'type': 'multi_external_select',
            'placeholder': {
                'type': 'plain_text',
                'text': 'Select related actors',
            },
            'min_query_length': 3,
        }
    }

    return block

def get_hunt_endpoints(endpoints:Dict = None)->Dict:
    block = {
        'type': 'section',
        'block_id': 'hunt-endpoint',
        'text': {
            'type': 'mrkdwn',
            'text': 'Hunt Endpoint',
        },
        'accessory': {
            'action_id': 'add_thing_hunt-endpoint',
            'type': 'static_select',
            'placeholder': {
                'type': 'plain_text',
                'text': 'Select an endpoint',
                'emoji': False,
            },
            'options': [],
        }
    }
    if endpoints is None:
        opt = {
            'value': '0',
            'text': {
                'type': 'plain_text',
                'text': "Select a hunt-service first",
                'emoji': False,
            },
        },
        block['accessory']['options'].append(opt)
        return block
    for ep, uri in endpoints.items():
        opt = {
            'value': ep,
            'text': {
                'type': 'plain_text',
                'text': f"{ep} ({uri})",
                'emoji': False,
            },
        }
        block['accessory']['options'].append(opt)

    return block

def get_add_attribute()->Dict:
    block = {
        'block_id': 'add_new_attribute_block',
        'type': 'actions',
        'elements': [
            {
                'type': 'button',
                'text': {
                    'type': 'plain_text',
                    'text': ':heavy_plus_sign: Add New Attribute',
                    'emoji': True,
                },
                'value': 'add_new_attribute',
                'action_id': 'add_new_attribute',
            }
        ]
    }
    return block

def _get_hunt_services()->Dict:
    #. Populate with enabled HNTR plugins
    block = {
        'type': 'section',
        'block_id': 'hunt-service',
        'text': {
            'type': 'mrkdwn',
            'text': 'Hunt Services',
        },
        'accessory': {
            'action_id': 'get_hunt_endpoints',
            'type': 'static_select',
            'placeholder': {
                'type': 'plain_text',
                'text': 'Select a hunt service',
                'emoji': True,
            },
            'options': [],
        },
    }

    #; Get list of HNTR plugins
    plugin_list = led.list_plugins()
    hntr_plugins = []
    for plugin_name, details in plugin_list.items():
        if 'HNTR' in details['classes']:
            hntr_plugins.append(plugin_name)

    #; Populate options
    for plugin in hntr_plugins:
        opt = {
            'value': plugin,
            'text': {
                'type': 'plain_text',
                'text': plugin,
                'emoji': False,
            },
        }
        block['accessory']['options'].append(opt)

    return block

def _get_tags()->Dict:
    block = {
        'type': 'section',
        'block_id': 'tag',
        'text': {
            'type': 'mrkdwn',
            'text': 'Tags',
        },
        'accessory': {
            'action_id': 'add_thing_get_tag',
            'type': 'multi_external_select',
            'placeholder': {
                'type': 'plain_text',
                'text': 'Select related tags',
            },
            'min_query_length': 3,
        },
    }
    return block

def add_attribute_label(label:str = None)->Dict:
    block = {
        'type': 'section',
        'text': {
            'text': '*Attribute Label*',
            'type': 'mrkdwn',
        },
        'accessory': {
            'action_id': 'get_attr_labels',
            'type': 'static_select',
            'placeholder': {
                'type': 'plain_text',
                'text': 'Select a label',
                'emoji': True,
            },
            'options': [],
            'focus_on_load': True,
        }
    }
    '''
    #; old external selector
    'accessory': {
        'action_id': 'get_attr_labels',
        'type': 'external_select',
        'placeholder': {
            'type': 'plain_text',
            'text': 'Select a label',
            'emoji': True,
        },
        'min_query_length': 2,
        'focus_on_load': True,
    }
    '''
    schema = led.schema['entity'].get(label)
    meta_attrs = Entity(label=label).meta_attrs
    if schema is None:
        schema = led.schema['relation'].get(label)
        meta_attrs = Relation(label=label).meta_attrs
    if schema is None:
        return block
    for attr_label in schema.get('owns'):
        #; ignore keyattrs because it's already in the modal and HIGHLANDER
        if attr_label == schema.get('keyattr'):
            continue
        #; ignore meta_attrs because we don't want to mess with them unless
        #; explicitly stated through something like a special 'hunt' schema.
        if attr_label in meta_attrs:
            continue
        opt = {
            'text': {
                'type': 'plain_text',
                'text': attr_label,
                'emoji': True,
            },
            'value': attr_label,
        }
        block['accessory']['options'].append(opt)

    return block

def add_attribute_value(
    label: str = None,
    value_type: str = None
)->Dict:
    """Return section block based on value_type fed

    :param value_type: string, double, boolean, or datetime, defaults to None
    :type value_type: str, optional
    :return: Section block containing appropriate input widget
    :rtype: Dict
    """

    #@ Set Configs
    #; Which attributes require multi-line inputs
    multi_line_attrs = ['http-html', 'hunt-string']
    #; Which checkboxes should be True by default?
    chk_true = ['hunt-active']
    #; What should the initial value of these ints be?
    init_int = {
        'confidence': 0,
        'frequency': 24,
    }
    #; Any numbers that should have min/max values?
    min_max = {
        'confidence': (-1,3),
        'frequency': (0,None),
    }
    #; List of meta attributes that are universally required if they exist
    required = [
        'actor-name', 'confidence', 'frequency',
        'hunt-endpoint', 'hunt-service', 'hunt-string', 'date-seen',
    ]
    #; List of attributes that should default to right now
    now_dates = ['date-seen', 'date-discovered']
    #; String min/max defaults
    str_min_max = {
        'ip-address': (7,45)
    }

    #@ Set Defaults
    #; Checkbox True
    if label in chk_true:
        initial_options = [(label, 'on')]
    else:
        initial_options = []
    #; initial integer value
    if label in init_int:
        initial_value = init_int[label]
    else:
        initial_value = None
    #; min/max values
    if label in min_max:
        min_value = min_max[label][0]
        max_value = min_max[label][1]
    else:
        min_value = None
        max_value = None
    #; min/max lengths
    if label in str_min_max:
        min_length = str_min_max[label][0]
        max_length = str_min_max[label][1]
    else:
        min_length = None
        max_length = None
    #; now dates
    if label in now_dates:
        initial_date_time = int(datetime.now(timezone.utc).timestamp())
    else:
        initial_date_time = None

    if value_type == 'boolean':
        input = block_checkbox(
            block_id=label,
            action_id = f"add_attr_{label}",
            label = label,
            options = [(label, 'on')],
            initial_options = initial_options,
            optional = label not in required,
        )
    elif value_type == 'double':
        input = block_number(
            block_id=label,
            action_id = f"add_attr_{label}",
            label = label,
            initial_value = initial_value,
            min_value = min_value,
            max_value = max_value,
            optional = label not in required,
        )
    elif value_type == 'datetime':
        input = block_datetime_picker(
            block_id=label,
            action_id = f"add_attr_{label}",
            label = label,
            initial_date_time = initial_date_time,
            optional = label not in required,
        )
    else: #@ implied value_type == 'string'
        input = block_plain_text_input(
            block_id=label,
            action_id = f"add_thing_{label}",
            label = label,
            multiline = label in multi_line_attrs,
            min_length=min_length,
            max_length=max_length,
            optional = label not in required,
        )
    return input

def add_user_modal(
    userval: str = None,
):
    username = userval.split(',')[0]
    slack_id = f"{userval.split(',')[1]},{userval.split(',')[2]}"
    return {
        "type": "modal",
        "callback_id": "add_user_modal",
        "title": {"type": "plain_text", "text": "Add User"},
        "submit": {"type": "plain_text", "text": "Submit"},
        "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": [
            {
                "type": "input",
                "block_id": "user_block",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "username",
                    "placeholder": {"type": "plain_text", "text": "Enter the LEDHNTR Username"},
                    "initial_value": username,
                },
                "label": {"type": "plain_text", "text": "LEDHNTR Username"},
            },
            {
                "type": "input",
                "block_id": "slackid_block",
                "element": {
                    "type": "plain_text_input",
                    "action_id": "slack_id",
                    "placeholder": {"type": "plain_text", "text": "SlackID (SlackUserID,SlackTeamID) DO NOT MODIFY"},
                    "initial_value": slack_id,
                },
                "label": {"type": "plain_text", "text": "SlackID (SlackUserID,SlackTeamID) DO NOT MODIFY"},
            },
            {
                "type": "input",
                "block_id": "role_block",
                "element": {
                    "type": "static_select",
                    "action_id": "role",
                    "placeholder": {"type": "plain_text", "text": "Select a role"},
                    "options": [
                        {
                            "text": {"type": "plain_text", "text": role.capitalize()},
                            "value": role,
                        }
                        for role in RoleEnum.valid_roles()
                    ],
                },
                "label": {"type": "plain_text", "text": "Role"},
            },
        ],
    }

def new_hits(
    data: Dict = {},
    interesting_things: List = None,
    con_list: List = None,
):
    _log.debug(f"Building new_hits block")
    '''
        {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":collision: NEW HITS [My_DB]",
                    "emoji": true
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "<!date^1721825208^{date_num} {time_secs}|2024-07-24>"
                    }
                ]
            },
            {
                "type": "divider"
            },
            {
                "type": "rich_text",
                "elements": [
                    {
                        "type": "rich_text_section",
                        "elements": [
                            {
                                "type": "text",
                                "text": "DOMAINS",
                                "style": {
                                    "bold": true
                                }
                            }
                        ]
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "`example.com`\nVT | Censys | Shodan",
                    "verbatim": true
                },
                "accessory": {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": ":fire: High",
                        "emoji": true
                    },
                    "value": "click_me_123",
                    "action_id": "button-action"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "`example2.com`\nVT | Censys | Shodan",
                    "verbatim": true
                },
                "accessory": {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": ":shrug: Unknown",
                        "emoji": true
                    },
                    "value": "click_me_123",
                    "action_id": "button-action"
                }
            }
        ]
    }
    '''
    blocks = []
    db = next(iter(data))
    new_stuff = data[db]

    #; Format links for quick context lookups
    link_formats = get_link_formats()

    #; Check for interesting things first:
    #; If there's nothing interesting, return an empty block
    interesting = False
    for thing_type in new_stuff:
        if thing_type in interesting_things:
            interesting = True
            break
    if not interesting:
        return []

    # f":collision: NEW HITS [{db}]"
    blocks.append(block_header(f":collision: NEW HITS [{db}]"))
    blocks.append(block_divider())
    context = block_context(
        elements = [
            ('mrkdwn', get_date())
        ]
    )
    blocks.append(context)
    for thing_type, things in new_stuff.items():
        # TODO - Convert this to a rich_text function in slack_client
        if thing_type.lower() not in interesting_things:
            _log.debug(f"{xterm('RED')}{thing_type} is not interesting. Skipping.{xterm('X')}")
            continue
        blocks.append(
            {
                'type': 'rich_text',
                'elements': [
                    {
                        'type': 'rich_text_section',
                        'elements': [
                            {
                                'type': 'text',
                                'text': thing_type.upper(),
                                'style': {
                                    'bold': True
                                }
                            }
                        ]
                    }
                ]
            }
        )
        thing_added = False
        for thing in things:
            keyval = next(iter(thing))
            #! DEBUG - this should never happen normally
            if 'confidence' not in thing[keyval]:
                confidence = 0
            else:
                confidence = thing[keyval]['confidence'][0]
            if con_list and confidence not in con_list:
                continue
            iid = thing[keyval]['iid']
            lines = [
                f"`{keyval}`"
            ]
            if thing_type.lower() in link_formats:
                links = ""
                for text, link in link_formats[thing_type.lower()].items():
                    links += f"<{link.format(value=keyval)}|{text}> | "
                links = links.rstrip(" | ")
                lines.append(links)
            mrkdwn = "\n".join(lines)
            button = {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "emoji": True,
                    "text": get_con_format(int(confidence)),
                },
                "value": f"{db}|{iid}",
                # // "action_id": f"set_confidence_modal_{uuid4().hex[:8]}",
                "action_id": f"set_confidence_modal",
            }
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": mrkdwn,
                        "verbatim": True,
                    },
                    "accessory": button,
                }
            )
            thing_added = True
        #; If we didn't add anything, remove the heading.
        if not thing_added:
            blocks.pop()

    #; This means all we have is the DB header, divider, and context date
    if len(blocks) == 3:
        return []
    return blocks

def add_thing_modal(
    mojo: MOJOCMD = None,
    args: Namespace = None,
)->Dict:
    _log.debug(f"Building add_thing modal...")
    blocks = []
    # // container = dumps(payload['container'])
    # // _log.debug(f"{xterm('CYAN')}MOJO: {pformat(mojo)}{xterm('X')}")
    tdb: TypeDBClient = get_tdb()
    all_dbs = tdb.get_all_dbs(readable=True)

    db_opts = []

    #; Universal "meta" attributes that could/should apply to every entity/relation
    #; Leaving out 'ref-link' for now to save space.
    universal_meta = [
        'actor-name', 'confidence', 'date-seen', 'date-discovered', 'note', 'tag'
    ]

    #; entities/relations that should have a limited number of fields available
    special_ents = {
        'hunt': {
            'keyattr': 'hunt-name',
            'owns': ['hunt-service', 'hunt-string',
                'hunt-active', 'frequency',]
        }
    }

    #; attributes that have preset values
    special_attrs = {
        'actor-name': _get_actors(),
        'hunt-service': _get_hunt_services(),
        #; can hunt-endpoint be populated based on hunt-service value?
        'hunt-endpoint': get_hunt_endpoints(),
        'tag': _get_tags(),
    }

    #; Available Databases - Tuple of text,value
    for db in all_dbs:
        db_opts.append((db,db))

    #; Generate multi-static select from config.
    select_db_section = block_static_select(
        block_id="db_name",
        label="Database",
        placeholder="Select",
        options=db_opts,
        action_id="select_db",
        initial_option=(mojo.db_name, mojo.db_name),
    )
    #; Append them to the primary blocks
    blocks.append(select_db_section)

    schema = None
    #; If the label is a "special case", use fields defined above
    if args.label in special_ents:
        #; set keyattr and extend universal_meta
        schema = special_ents[args.label]
        universal_meta = special_ents[args.label]['owns'] + universal_meta

    if schema is None:
        #; Otherwise get the schema from led.schema
        schema = led.schema['entity'].get(args.label) or \
            led.schema['relation'].get(args.label)
    #; if it's still None, there's no schema that matches this thing.
    if schema is None:
        #! This should never happen b/c we check for valid things before getting
        #! to this point.
        _log.error(
            f"{xterm('RED')}No schema found for {args.label}. "
            f"This shouldn't happen.{xterm('X')}"
        )
        return False
    #; If the thing has a keyattr and the keyattr isn't comboid
    if not schema['keyattr'] is None and schema['keyattr'] != 'comboid':
        #; make sure the first input is for that keyattr
        input = block_plain_text_input(
            action_id = 'add_thing_keyattr',
            label = schema['keyattr'],
            initial_value = args.value,
            focus_on_load = True,
            block_id = 'keyattr',
        )
        blocks.append(input)

    for attr in universal_meta:
        #@ Check for special attributes
        if attr in special_attrs:
            input = special_attrs[attr]
            blocks.append(input)
            continue
        #@ Get value_type
        value_schema = led.schema['attribute'].get(attr)
        if value_schema is None:
            _log.error(f"{xterm('RED')}Could not find "
                       f"attribute type {attr}{xterm('X')}")
            continue
        value_type = value_schema.get('value_type')
        #@ Handle different attribute input types
        input = add_attribute_value(label=attr, value_type=value_type)
        #; add input to main blocks.
        blocks.append(input)

    #@ + Add New Attribute Block
    #! There should be a check for how long the modal can be before this is added
    blocks.append(get_add_attribute())

    mymodal = {
        "type": "modal",
        # // "callback_id": f"set_confidence_{uuid4().hex[:8]}",
        "callback_id": f"add_thing",
        "title": {"type": "plain_text", "text": f"Add {args.label.upper()}"},
        "submit": {"type": "plain_text", "text": "Submit"},
        # // "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks,
        "private_metadata": mojo.channel_id,
    }

    return mymodal

def edit_thing_modal(
    db_name: str = None,
    label: str = None,
    value: str = None,
    channel_id: str = None,
)->Dict:
    _log.debug(f"Building edit_thing modal...")
    #. There should be a translation layer before we get to edit_thing_modal
    #. that converts MOJOCMD or Payload into effectively the same object.
    #. args should also be a universal object that's populated either from
    #. the mojo command or a button being pressed.
    #.
    #. /mojo edit <label> <keyval>
    #. defaults to 'evil' db - otherwise takes --database flag to change
    #. If you run it with just the label you should get an external select box
    #. that lets you effectively search for the keyval you're interested in changing.
    #. Once you select the value from the dropdown it should populate the rest
    #. of the modal.
    blocks = []
    mymodal = {}
    # // container = dumps(payload['container'])
    # // _log.debug(f"{xterm('CYAN')}MOJO: {pformat(mojo)}{xterm('X')}")
    tdb: TypeDBClient = get_tdb()
    tdb.db_name = db_name
    if not label:
        # TODO - these errors should be sent to the user, not just logged to CLI
        _log.error(f"A thing label is required before we can edit anything.")
        return mymodal

    ent = Entity(label=label)
    keyattr = Attribute(label=ent.keyattr, value=value)
    ent.has.append(keyattr)
    if not value:
        search_rez = tdb.find_things(label)
    else:
        if ent.keyattr is None:
            _log.error(f"Cannot edit a type that doesn't have a keyattr")
            return mymodal
        search_rez = tdb.find_things(ent)

    #TODO If len(search_rez)==1 set the title, remove the keyval search input,
    #TODO and populate the rest of the modal with the result's editable attributes
    #TODO
    #TODO If len(search_rez) > 1 then we need to add the keyval search input and
    #TODO start populating it externally with select options.
    #TODO
    #TODO Before inputs, we want first/last/discovered dates, label, keyval,
    #TODO ledsrc(s) and hunt-name(s) at the top for fast context.
    #TODO
    #TODO For the Edit modal front-and-center inputs should be change confidence, existing
    #TODO Notes/Tags/Actors, and a Delete button should be available for the whole
    #TODO Thing as well as each individual attribute.
    #TODO
    #TODO Attributes that should not be editable/removable include:
    #TODO   date-seen, date-discovered, keyattr, user-uuid, ledid, ledsrc,
    #TODO   hunt-name (for anything other than hunts)
    db_opts = []
    #@ If we don't have exactly one thing that matches we need to narrow it down.
    if len(search_rez) != 1:
        all_dbs = tdb.get_all_dbs(readable=True)
        #; Available Databases - Tuple of text,value
        for db in all_dbs:
            db_opts.append((db,db))

        #; Generate multi-static select from config.
        select_db_section = block_static_select(
            block_id="db_name",
            label="Database",
            placeholder="Select",
            options=db_opts,
            action_id="select_db",
            initial_option=(tdb.db_name, tdb.db_name),
        )
        #; Append them to the primary blocks
        blocks.append(select_db_section)

        #; Append keyval input
        input = block_external_select(
            block_id='keyattr',
            action_id='edit_thing_search',
            label=ent.keyattr,
            placeholder="Enter value",
            min_query_length=2,
        )
        blocks.append(input)
        mymodal = {
            "type": "modal",
            # // "callback_id": f"set_confidence_{uuid4().hex[:8]}",
            "callback_id": f"edit_thing",
            "title": {"type": "plain_text", "text": f"Edit {label.upper()}"},
            "submit": {"type": "plain_text", "text": "Submit"},
            # // "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": blocks,
            "private_metadata": channel_id,
        }
        tdb.close_client()
        return mymodal

    #; Universal "meta" attributes that could/should apply to every entity/relation
    #; Leaving out 'ref-link' for now to save space.
    universal_meta = [
        'actor-name', 'confidence', 'date-seen', 'date-discovered', 'note', 'tag'
    ]

    #; entities/relations that should have a limited number of fields available
    special_ents = {
        'hunt': {
            'keyattr': 'hunt-name',
            'owns': ['hunt-service', 'hunt-string',
                'hunt-active', 'frequency',]
        }
    }

    #; attributes that have preset values
    special_attrs = {
        'actor-name': _get_actors(),
        'hunt-service': _get_hunt_services(),
        #; can hunt-endpoint be populated based on hunt-service value?
        'hunt-endpoint': get_hunt_endpoints(),
        'tag': _get_tags(),
    }

    schema = None
    #; If the label is a "special case", use fields defined above
    if label in special_ents:
        #; set keyattr and extend universal_meta
        schema = special_ents[label]
        universal_meta = special_ents[label]['owns'] + universal_meta

    if schema is None:
        #; Otherwise get the schema from led.schema
        schema = led.schema['entity'].get(label) or \
            led.schema['relation'].get(label)
    #; if it's still None, there's no schema that matches this thing.
    if schema is None:
        #! This should never happen b/c we check for valid things before getting
        #! to this point.
        _log.error(
            f"{xterm('RED')}No schema found for {label}. "
            f"This shouldn't happen.{xterm('X')}"
        )
        return False
    #; If the thing has a keyattr and the keyattr isn't comboid
    if not schema['keyattr'] is None and schema['keyattr'] != 'comboid':
        #; make sure the first input is for that keyattr
        input = block_plain_text_input(
            action_id = 'edit_thing_keyattr',
            label = schema['keyattr'],
            initial_value = value,
            focus_on_load = True,
            block_id = 'keyattr',
        )
        blocks.append(input)

    for attr in universal_meta:
        #@ Check for special attributes
        if attr in special_attrs:
            input = special_attrs[attr]
            blocks.append(input)
            continue
        #@ Get value_type
        value_schema = led.schema['attribute'].get(attr)
        if value_schema is None:
            _log.error(f"{xterm('RED')}Could not find "
                       f"attribute type {attr}{xterm('X')}")
            continue
        value_type = value_schema.get('value_type')
        #@ Handle different attribute input types
        input = add_attribute_value(label=attr, value_type=value_type)
        #; add input to main blocks.
        blocks.append(input)

    #@ + Add New Attribute Block
    #! There should be a check for how long the modal can be before this is added
    blocks.append(get_add_attribute())

    mymodal = {
        "type": "modal",
        # // "callback_id": f"set_confidence_{uuid4().hex[:8]}",
        "callback_id": f"edit_thing",
        "title": {"type": "plain_text", "text": f"Add {label.upper()}"},
        "submit": {"type": "plain_text", "text": "Submit"},
        # // "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks,
        "private_metadata": channel_id,
    }

    tdb.close_client()
    return mymodal

def update_thing_modal(
    payload: Dict = None,
)->Dict:
    _log.debug(f"Building update_thing modal...")

    container = dumps(payload['container'])

    # TODO - Add capability to add/remove tags and notes
    blocks = []

    tdb: TypeDBClient = get_tdb()
    _log.debug(f"{xterm('YELLOW')}action_val = {payload['actions'][0]['value']}{xterm('X')}")
    db_name = payload['actions'][0]['value'].split('|')[0]
    _log.debug(f"{xterm('YELLOW')}Set db_name to {db_name}{xterm('X')}")
    tdb.db_name = db_name
    iid = payload['actions'][0]['value'].split('|')[1]
    _log.debug(f"{xterm('YELLOW')}IID set to {iid}{xterm('X')}")

    so = Entity(label='entity')
    so.iid = iid
    thing = tdb.find_things(so)[0]

    #; Header
    # // blocks.append(block_header(f"[{db_name}]\n{thing.label}: {thing.keyval}"))
    #; Divider
    # // blocks.append(block_divider())
    #; Context
    db_type = f"db_name: {db_name} | label: {thing.label}"
    disco_time = f"discovered: {get_date(thing.get_attributes('date-discovered')[0].value)}"
    first_time = f"first_seen: {get_date(thing.get_attributes('first-seen')[0].value)}"
    last_time = f"last_seen: {get_date(thing.get_attributes('last-seen')[0].value)}"
    times = f"{db_type}\n{disco_time}\n{first_time}\n{last_time}"
    blocks.append(block_context(
        elements = [
            ('mrkdwn', times, True)
        ]
    ))
    #; LEDSRC, TAGS, NOTES
    tag_mrkdwn = None
    note_mrkdwn = None
    srcs = thing.get_attributes('ledsrc')
    src_vals = [src.value for src in srcs]
    src_string = ", ".join(src_vals)
    if src_string: #; This should always be set, but had to change for debugging
        ledsrc_mrkdwn = f"*LEDSRC*\n```{src_string}```\n"
    else:
        ledsrc_mrkdwn = None

    tags = thing.get_attributes('tags')
    tag_vals = [tag.value for tag in tags]
    tag_string = ", ".join(tag_vals)
    if tag_string:
        tag_mrkdwn = f"*TAGS*\n```{tag_string}```\n"

    notes = thing.get_attributes('notes')
    note_vals = [note.value for note in notes]
    note_string = "\n---\n".join(note_vals)
    if note_string:
        note_mrkdwn = f"*NOTES*\n```{note_string}```\n"

    # TODO - ADD OTHER IMPORTANT ATTRIBUTES FOR THINGS LIKE HTTP AND SSL THINGS

    meta_mrkdwn = ""
    if ledsrc_mrkdwn:
        meta_mrkdwn += ledsrc_mrkdwn
    if tag_mrkdwn:
        meta_mrkdwn += tag_mrkdwn
    if note_mrkdwn:
        meta_mrkdwn += note_mrkdwn
    if not meta_mrkdwn:
        meta_mrkdwn = "No metadata found. You must be debugging :trollface:"

    meta_section = {
        'type': 'section',
        'text': {
            'type': 'mrkdwn',
            'text': meta_mrkdwn,
        }
    }
    blocks.append(meta_section)

    #; Set Confidence
    #! This is just for DEBUGGING - normally Confidence should ALWAYS be set.
    if not thing.get_attributes('confidence'):
        confidence = 0
    else:
        confidence = int(thing.get_attributes('confidence')[0].value)

    set_con_section = block_static_select(
        label="Select Level of Confidence",
        placeholder=get_con_format(confidence),
        options=[
            (get_con_format(-1),f"{db_name}|{iid}|-1"),
            (get_con_format(0),f"{db_name}|{iid}|0"),
            (get_con_format(1),f"{db_name}|{iid}|1"),
            (get_con_format(2),f"{db_name}|{iid}|2"),
            (get_con_format(3),f"{db_name}|{iid}|3"),
        ],
        action_id="new_confidence"
    )
    blocks.append(set_con_section)

    # blocks.append(block_header(f"[{db_name}]\n{thing.label}: {thing.keyval}"))
    title = thing.keyval
    #; if title is 25 char or more, truncate it and add the full title to the context
    if len(title) >= 25:
        title = f"{thing.keyval[0:21]}..."
        # // _log.debug(f"{pformat(blocks[0])}")
        blocks[0]['elements'][0]['text'] = f"{thing.keyval}\n{blocks[0]['elements'][0]['text']}"
    mymodal = {
        "type": "modal",
        # // "callback_id": f"set_confidence_{uuid4().hex[:8]}",
        "callback_id": f"set_confidence",
        "title": {"type": "plain_text", "text": f"{title}"},
        "submit": {"type": "plain_text", "text": "Submit"},
        # // "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks,
        "private_metadata": container,
    }

    return mymodal