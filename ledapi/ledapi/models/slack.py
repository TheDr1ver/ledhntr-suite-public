from pydantic import BaseModel, model_validator
from typing import Optional, Dict, List

from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)

from ledapi.config import(
    led,
    _log,
    get_tdb,
    wqm,
    xterm,
)

from ledapi.models import RoleEnum
from slack_client import (
    block_context,
    block_divider,
    block_header,
    get_con_format,
    get_date,
    get_link_formats,
)

from typedb_client import TypeDBClient

#@##############################################################################
#@### Pydantic API models
#@##############################################################################

class MOJOCMD(BaseModel):
    token: str = None
    team_id: str = None
    team_domain: str = None
    channel_id: str = None
    channel_name: str = None
    user_id: str = None
    user_name: str = None
    command: str = None
    text: str = None
    api_app_id: str = None
    is_enterprise_install: bool = False
    response_url: str = None
    trigger_id: str = None
    slackbot_token: str = None
    admin_channel: str = None

class SlackEvent(BaseModel):
    token: str = None
    team_id: str = None
    context_team_id: str = None
    context_enterprise_id: str = None
    api_app_id: str = None
    event: Dict = None
    type: str = None
    event_id: str = None
    event_time: int = None
    authorizations: List = None
    is_ext_shared_channel: bool = False
    event_context: str = None

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
    type: str = None
    user: Dict = None
    api_app_id: str = None
    token: str = None
    container: Dict = None
    trigger_id: str = None
    team: Dict = None
    enterprise: str = None
    is_enterprise_intsall: bool = False
    channel: Dict = None
    message: Dict = None # This is the message that was sent to the channel to create the modal
    state: Dict = None
    response_url: str = None
    actions: List[Dict] = None
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
#@##############################################################################
'''
def invalid_command_modal(cmd: str = None):
    return {"type": "modal",
        "callback_id": "invalid_command",
        "title": {
            "type": "plain_text",
            "text": "Invalid Command"
        },
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":no_entry: You have entered an invalid command: {cmd}"
                }
            }
        ]
    }


def unauthorized_modal():
    return {"type": "modal",
        "callback_id": "unauthorized_modal",
        "title": {
            "type": "plain_text",
            "text": "Unauthorized"
        },
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ":no_entry: You are not authorized"
                }
            }
        ]
    }
'''

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
    interesting_things = [
        'domain',
        'hostname',
        'ip',
        'jarm',
        'ja3s',
        'ssl',
    ]
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
        for thing in things:
            keyval = next(iter(thing))
            #! DEBUG - this should never happen normally
            if 'confidence' not in thing[keyval]:
                confidence = 0
            else:
                confidence = thing[keyval]['confidence'][0]
                _log.debug(f"{xterm('MAGENTA')}confidence: {confidence}{xterm('X')}")
            iid = thing[keyval]['iid']
            lines = [
                f"`{keyval}`"
            ]
            if thing_type.lower() in link_formats:
                links = ""
                for text, link in link_formats[thing_type.lower()].items():
                    links += f"<{link.format(value=keyval)}|{text}> |"
                links = links.rstrip(" |")
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
                "action_id": "set_confidence_modal",
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

    return blocks

def update_thing_modal(
    payload: Dict = None,
):
    _log.debug(f"Building update_thing modal...")
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
    # TODO - Simplify this into a general function in slack_client so it's not so ugly
    #! This is just for DEBUGGING - normally Confidence should ALWAYS be set.
    if not thing.get_attributes('confidence'):
        confidence = 0
    else:
        confidence = int(thing.get_attributes('confidence')[0].value)
    set_con_section = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "Select Level of Confidence"
        },
        "accessory": {
            "type": "static_select",
            "placeholder": {
                "type": "plain_text",
                "emoji": True,
                "text": get_con_format(confidence)
            },
            "options":[
                {
                    "text": {
                        "type": "plain_text",
                        "emoji": True,
                        "text": get_con_format(-1)
                    },
                    "value": f"{db_name}|{iid}|-1",
                },
                {
                    "text": {
                        "type": "plain_text",
                        "emoji": True,
                        "text": get_con_format(0)
                    },
                    "value": f"{db_name}|{iid}|0",
                },
                {
                    "text": {
                        "type": "plain_text",
                        "emoji": True,
                        "text": get_con_format(1)
                    },
                    "value": f"{db_name}|{iid}|1",
                },
                {
                    "text": {
                        "type": "plain_text",
                        "emoji": True,
                        "text": get_con_format(2)
                    },
                    "value": f"{db_name}|{iid}|2",
                },
                {
                    "text": {
                        "type": "plain_text",
                        "emoji": True,
                        "text": get_con_format(3)
                    },
                    "value": f"{db_name}|{iid}|3",
                },
            ],
            "action_id": "set_confidence"
        }
    }
    blocks.append(set_con_section)

    # blocks.append(block_header(f"[{db_name}]\n{thing.label}: {thing.keyval}"))
    mymodal = {
        "type": "modal",
        "callback_id": "set_confidence_submit",
        "title": {"type": "plain_text", "text": f"{thing.keyval}"},
        "submit": {"type": "plain_text", "text": "Submit"},
        # // "close": {"type": "plain_text", "text": "Cancel"},
        "blocks": blocks,
    }

    return mymodal