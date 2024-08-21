from datetime import datetime, timedelta, timezone
from pprint import pformat
from typing import Optional, Dict, List

from fastapi import (
    APIRouter,
    Body,
    Depends,
    Form,
    HTTPException,
    status,
    Query,
    Request
)
from fastapi.responses import Response
from ledapi.user import(
    User,
    dep_check_user_role,
    get_user_by_api_key,
    get_user_by_slack_id,
    dep_check_user_role_by_slack,
)
from ledapi.config import(
    led,
    _log,
    get_tdb,
    redis_manager,
    xterm
)
from ledapi.helpers import handle_response

from ledapi.models import(
    DBName,
    MOJOCMD,
    SearchObject,
    UserModel,
    role_everyone,
)

from ledapi.tasks import(
    action_handler,
    event_handler,
    mojo_handler,
    options_handler,
)

from ledhntr.data_classes import Attribute, Entity, Relation, Thing
from ledhntr.helpers import dumps

router = APIRouter()

#@##############################################################################
#@### Slack ENDPOINTS
#@##############################################################################

#~##########################
#~ Slash-Command Endpoint
#~##########################

@router.post("/slack/mojo")
async def mojo_ep(
    request: Request = None,
    # user: User = Depends(dep_check_user_role_by_slack(role_everyone)),
):
    try:
        # user = Depends(dep_check_user_role_by_slack(role_everyone))
        user = await get_user_by_slack_id(request)
    except Exception as e:
        _log.error(f"Unable to load user from slack_id: {e}")
        user = None #; possibly this is a new user.
    form = await request.form()
    mojo = MOJOCMD(
        token=form.get('token'),
        team_id=form.get('team_id'),
        team_domain=form.get('team_domain'),
        channel_id=form.get('channel_id'),
        channel_name=form.get('channel_name'),
        user_id=form.get('user_id'),
        user_name=form.get('user_name'),
        command=form.get('command'),
        text=form.get('text'),
        api_app_id=form.get('api_app_id'),
        is_enterprise_install=form.get('is_enterprise_install') == 'true',
        response_url=form.get('response_url'),
        trigger_id=form.get('trigger_id'),
    )
    '''
    resp = {'headers': None, 'body': None}
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    # resp['body'] = await request.body()
    # resp['body'] = resp['body'].decode('utf-8')
    resp['mojo'] = mojo
    _log.info(pformat(resp))
    return resp
    '''
    # // _log.debug(f"Running mojo command...")
    # // _log.debug(f"{pformat(mojo)}")
    if user is not None:
        _log.debug(f"User object returned:")
        _log.debug(f"{pformat(user.to_dict())}")
    msg_400 = f"Invalid input"
    msg_500 = f"Error running mojo command"

    # user = None
    response = await handle_response(
        mojo_handler,
        msg_400,
        msg_500,
        mojo,
        user,
    )

    _log.debug(f"Sending this to slack:")
    _log.debug(f"{pformat(response)}")
    if not response:
        return Response(status_code=204)
    return response

#~##########################
#~ SlackAction Endpoint
#~##########################

@router.post("/slack/action")
async def slackaction_ep(
    request: Request,
    # // user: User = Depends(dep_check_user_role_by_slack(role_everyone)),
):
    #! IMPORTANT NOTE!!!!
    #! IF YOU'RE GETTING ZERO PAYLOAD WHEN YOUR ACTION SHOULD BE POSTING
    #! IT'S LIKELY BECAUSE YOUR BLOCKS + TEXT IS TOO DAMN LONG!
    #! THERE'S LITERALLY NO ERROR MESSAGE THAT WARNS YOU ABOUT THIS, IT JUST
    #! SENDS 0-BYTE REQUESTS TO YOUR SERVER!

    resp = {'headers': None, 'body': None}
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    _log.debug(f"{xterm('CYAN')}Headers: \n{pformat(resp['headers'])}{xterm('X')}")
    '''
    resp['body'] = await request.body()
    resp['body'] = resp['body'].decode('utf-8')
    # resp['body'] = request.json()
    # _log.info(f"Body: {pformat(await request.json())}")
    _log.info(f"{xterm('GREEN')}{pformat(resp)}{xterm('X')}")
    # return await request.json()
    '''

    # // _log.debug(f"{xterm('BLUE')}Posting request to /slack/action: \n{pformat(await request.body())}{xterm('X')}")
    try:
        # user = Depends(dep_check_user_role_by_slack(role_everyone))
        user = await get_user_by_slack_id(request)
    except Exception as e:
        _log.error(f"Unable to load user from slack_id: {e}")
        user = None #; possibly this is a new user...
    form = await request.form()

    _log.debug(f"Running slack action...")
    _log.debug(f"{pformat(request)}")
    _log.debug(f"Form: {pformat(form)}")
    msg_400 = f"Invalid input"
    msg_500 = f"Error running slack action"

    # user = None
    response = await handle_response(
        action_handler,
        msg_400,
        msg_500,
        request,
        user,
    )
    #& bypass normal endpoint response for slack-formatted response
    # // if response['status_code'] == 200:
    # //     response = response['message']['result']
    _log.debug(f"Sending this to slack:")
    _log.debug(f"{pformat(response)}")
    return response

#~##########################
#~ SlackEvent Endpoint
#~##########################

@router.post("/slack/event")
async def slackevent_ep(
    request: Request,
    # // user: User = Depends(dep_check_user_role_by_slack(role_everyone)),
):
    """Handle events (emojii etc)

    :param request: request submitted to the endpoint
    :type request: Request
    :return: Slack-friendly response
    :rtype: Dict
    """

    '''
    resp = {'headers': None, 'body': None}
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    # _log.info(f"Headers: \n{pformat(headers)}")
    resp['body'] = await request.body()
    resp['body'] = resp['body'].decode('utf-8')
    # resp['body'] = request.json()
    # _log.info(f"Body: {pformat(await request.json())}")
    _log.info(pformat(resp))
    # return await request.json()
    return resp
    '''
    _log.debug(f"{xterm('BLUE')}Posting request to /slack/event: \n{pformat(request)}{xterm('X')}")
    try:
        # user = Depends(dep_check_user_role_by_slack(role_everyone))
        user = await get_user_by_slack_id(request)
    except Exception as e:
        _log.error(f"Unable to load user from slack_id: {e}")
        user = None #; possibly this is a new user.

    # // form = await request.form()

    _log.debug(f"Running slack event...")
    _log.debug(f"{pformat(request)}")
    # // _log.debug(f"Form: {pformat(form)}")
    msg_400 = f"Invalid input"
    msg_500 = f"Error running slack event"

    # user = None
    response = await handle_response(
        event_handler,
        msg_400,
        msg_500,
        request,
        user,
    )
    #& bypass normal endpoint response for slack-formatted response
    # // if response['status_code'] == 200:
        # // response = response['message']['result']
    _log.debug(f"Sending this to slack:")
    _log.debug(f"{pformat(response)}")
    return response

#~##########################
#~ SlackEvent Options
#~##########################

@router.post("/slack/options")
async def slackoptions_ep(
    request: Request,
    # // user: User = Depends(dep_check_user_role_by_slack(role_everyone)),
):
    """Handle options (load form values)

    :param request: request submitted to the endpoint
    :type request: Request
    :return: Slack-friendly response
    :rtype: Dict
    """

    '''
    {
        "type": "block_suggestion",
        "user":
        {
            "id": "UGJE1B2MQ",
            "username": "driver1",
            "name": "driver1",
            "team_id": "T02JD4QNU"
        },
        "container":
        {
            "type": "view",
            "view_id": "V07FNG7AU2H"
        },
        "api_app_id": "A07A8SAPC0P",
        "token": "Us7eCNB0Psg0VgVUCqjqp4tE",
        "action_id": "tagtest_actionid",
        "block_id": "test-tag-section123",
        "value": "tes",
        "team":
        {
            "id": "T02JD4QNU",
            "domain": "punchcyber"
        },
        "enterprise": null,
        "is_enterprise_install": false,
        "view":
        {
            "id": "V07FNG7AU2H",
            "team_id": "T02JD4QNU",
            "type": "modal",
            "blocks":
            [
                {
                    "type": "section",
                    "block_id": "cfaFz",
                    "text":
                    {
                        "type": "mrkdwn",
                        "text": "Database",
                        "verbatim": false
                    },
                    "accessory":
                    {
                        "type": "static_select",
                        "action_id": "select_db",
                        "placeholder":
                        {
                            "type": "plain_text",
                            "text": "Select",
                            "emoji": true
                        },
                        "initial_option":
                        {
                            "text":
                            {
                                "type": "plain_text",
                                "text": "scratchpad",
                                "emoji": true
                            },
                            "value": "scratchpad"
                        },
                        "options":
                        [
                            {
                                "text":
                                {
                                    "type": "plain_text",
                                    "text": "led_hntr_dev",
                                    "emoji": true
                                },
                                "value": "led_hntr_dev"
                            },
                            {
                                "text":
                                {
                                    "type": "plain_text",
                                    "text": "scratchpad",
                                    "emoji": true
                                },
                                "value": "scratchpad"
                            }
                        ]
                    }
                },
                {
                    "type": "input",
                    "block_id": "yp6wQ",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "hunt-name",
                        "emoji": false
                    },
                    "optional": false,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "plain_text_input",
                        "action_id": "add_thing_keyattr",
                        "multiline": false,
                        "min_length": 0,
                        "max_length": 3000,
                        "focus_on_load": true,
                        "dispatch_action_config":
                        {
                            "trigger_actions_on":
                            [
                                "on_enter_pressed"
                            ]
                        }
                    }
                },
                {
                    "type": "input",
                    "block_id": "qRyi2",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "hunt-active",
                        "emoji": true
                    },
                    "optional": false,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "checkboxes",
                        "action_id": "add_thing_hunt-active",
                        "initial_options":
                        [
                            {
                                "text":
                                {
                                    "type": "plain_text",
                                    "text": "hunt-active",
                                    "emoji": true
                                },
                                "value": "hunt-active"
                            }
                        ],
                        "options":
                        [
                            {
                                "text":
                                {
                                    "type": "plain_text",
                                    "text": "hunt-active",
                                    "emoji": true
                                },
                                "value": "hunt-active"
                            }
                        ]
                    }
                },
                {
                    "type": "input",
                    "block_id": "5fnpt",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "hunt-endpoint",
                        "emoji": false
                    },
                    "optional": false,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "plain_text_input",
                        "action_id": "add_thing_hunt-endpoint",
                        "multiline": false,
                        "min_length": 0,
                        "max_length": 3000,
                        "focus_on_load": false,
                        "dispatch_action_config":
                        {
                            "trigger_actions_on":
                            [
                                "on_enter_pressed"
                            ]
                        }
                    }
                },
                {
                    "type": "input",
                    "block_id": "XtxO4",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "hunt-service",
                        "emoji": false
                    },
                    "optional": false,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "plain_text_input",
                        "action_id": "add_thing_hunt-service",
                        "multiline": false,
                        "min_length": 0,
                        "max_length": 3000,
                        "focus_on_load": false,
                        "dispatch_action_config":
                        {
                            "trigger_actions_on":
                            [
                                "on_enter_pressed"
                            ]
                        }
                    }
                },
                {
                    "type": "input",
                    "block_id": "xp/Jc",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "hunt-string",
                        "emoji": false
                    },
                    "optional": false,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "plain_text_input",
                        "action_id": "add_thing_hunt-string",
                        "multiline": true,
                        "min_length": 0,
                        "max_length": 3000,
                        "focus_on_load": false,
                        "dispatch_action_config":
                        {
                            "trigger_actions_on":
                            [
                                "on_enter_pressed"
                            ]
                        }
                    }
                },
                {
                    "type": "input",
                    "block_id": "YQCNC",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "frequency",
                        "emoji": true
                    },
                    "optional": false,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "number_input",
                        "action_id": "add_thing_frequency",
                        "initial_value": "24",
                        "min_value": "0",
                        "is_decimal_allowed": true,
                        "focus_on_load": false
                    }
                },
                {
                    "type": "input",
                    "block_id": "SD3hv",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "confidence",
                        "emoji": true
                    },
                    "optional": false,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "number_input",
                        "action_id": "add_thing_confidence",
                        "initial_value": "0",
                        "min_value": "-1",
                        "max_value": "3",
                        "is_decimal_allowed": true,
                        "focus_on_load": false
                    }
                },
                {
                    "type": "input",
                    "block_id": "O3e/3",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "note",
                        "emoji": false
                    },
                    "optional": true,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "plain_text_input",
                        "action_id": "add_thing_note",
                        "multiline": false,
                        "min_length": 0,
                        "max_length": 3000,
                        "focus_on_load": false,
                        "dispatch_action_config":
                        {
                            "trigger_actions_on":
                            [
                                "on_enter_pressed"
                            ]
                        }
                    }
                },
                {
                    "type": "section",
                    "block_id": "test-tag-section123",
                    "text":
                    {
                        "type": "mrkdwn",
                        "text": "pick items from the list",
                        "verbatim": false
                    },
                    "accessory":
                    {
                        "type": "multi_external_select",
                        "action_id": "tagtest_actionid",
                        "placeholder":
                        {
                            "type": "plain_text",
                            "text": "Select items",
                            "emoji": true
                        },
                        "min_query_length": 3
                    }
                },
                {
                    "type": "input",
                    "block_id": "7elZ4",
                    "label":
                    {
                        "type": "plain_text",
                        "text": "actor-name",
                        "emoji": false
                    },
                    "optional": false,
                    "dispatch_action": false,
                    "element":
                    {
                        "type": "plain_text_input",
                        "action_id": "add_thing_actor-name",
                        "multiline": false,
                        "min_length": 0,
                        "max_length": 3000,
                        "focus_on_load": false,
                        "dispatch_action_config":
                        {
                            "trigger_actions_on":
                            [
                                "on_enter_pressed"
                            ]
                        }
                    }
                }
            ],
            "private_metadata": "",
            "callback_id": "add_thing",
            "state":
            {
                "values":
                {
                    "cfaFz":
                    {
                        "select_db":
                        {
                            "type": "static_select",
                            "selected_option":
                            {
                                "text":
                                {
                                    "type": "plain_text",
                                    "text": "scratchpad",
                                    "emoji": true
                                },
                                "value": "scratchpad"
                            }
                        }
                    },
                    "qRyi2":
                    {
                        "add_thing_hunt-active":
                        {
                            "type": "checkboxes",
                            "selected_options":
                            [
                                {
                                    "text":
                                    {
                                        "type": "plain_text",
                                        "text": "hunt-active",
                                        "emoji": true
                                    },
                                    "value": "hunt-active"
                                }
                            ]
                        }
                    },
                    "YQCNC":
                    {
                        "add_thing_frequency":
                        {
                            "type": "number_input",
                            "value": "24"
                        }
                    },
                    "SD3hv":
                    {
                        "add_thing_confidence":
                        {
                            "type": "number_input",
                            "value": "0"
                        }
                    }
                }
            },
            "hash": "1722959532.M8Kh9DyQ",
            "title":
            {
                "type": "plain_text",
                "text": "Add HUNT",
                "emoji": true
            },
            "clear_on_close": false,
            "notify_on_close": false,
            "close": null,
            "submit":
            {
                "type": "plain_text",
                "text": "Submit",
                "emoji": true
            },
            "previous_view_id": null,
            "root_view_id": "V07FNG7AU2H",
            "app_id": "A07A8SAPC0P",
            "external_id": "",
            "app_installed_team_id": "T02JD4QNU",
            "bot_id": "B07AGQB38PQ"
        }
    }
    '''
    """
    resp = {'headers': None, 'body': None}
    resp['headers'] = {key: val for  key, val in request.headers.items()}
    # _log.info(f"Headers: \n{pformat(headers)}")
    resp['body'] = await request.body()
    resp['body'] = resp['body'].decode('utf-8')
    # resp['body'] = request.json()
    # _log.info(f"Body: {pformat(await request.json())}")
    _log.info(f"{xterm('GREEN')}{pformat(resp)}{xterm('X')}")
    # return await request.json()

    _log.debug(f"{xterm('BLUE')}Posting request to /slack/options: \n{pformat(request)}{xterm('X')}")
    """
    try:
        user = await get_user_by_slack_id(request)
    except Exception as e:
        _log.error(f"Unable to load user from slack_id: {e}")
        user = None #; possibly this is a new user.

    # // form = await request.form()

    _log.debug(f"Requesting options...")
    # // _log.debug(f"{pformat(request)}")
    # // _log.debug(f"Form: {pformat(form)}")
    msg_400 = f"Invalid input"
    msg_500 = f"Error pulling options"

    # // return resp
    # user = None
    response = await handle_response(
        options_handler,
        msg_400,
        msg_500,
        request,
        user,
    )
    #& bypass normal endpoint response for slack-formatted response
    # // if response['status_code'] == 200:
        # // response = response['message']['result']
    _log.debug(f"Sending this to slack:")
    _log.debug(f"{pformat(response)}")
    return response