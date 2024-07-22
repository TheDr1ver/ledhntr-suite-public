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
)

from ledapi.models import RoleEnum

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