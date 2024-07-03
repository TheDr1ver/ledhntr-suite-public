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
    redis_manager
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
)

from ledhntr.data_classes import Attribute, Entity, Relation, Thing

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
    _log.debug(f"Running mojo command...")
    _log.debug(f"{pformat(mojo)}")
    _log.debug(f"User object returned:")
    _log.debug(f"{user}")
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
    return response

#~##########################
#~ SlackAction Endpoint
#~##########################

@router.post("/slack/action")
async def slackaction_ep(
    request: Request,
    user: User = Depends(dep_check_user_role_by_slack(role_everyone)),
):
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
    '''

    _log.debug(f"Running slack action...")
    _log.debug(f"{pformat(request)}")
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
    user: User = Depends(dep_check_user_role_by_slack(role_everyone)),
):
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

    _log.debug(f"Running slack event...")
    _log.debug(f"{pformat(request)}")
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