"""
Overview
========

This is a connector plugin for interacting with a Slack Workspace.

"""
import asyncio
import logging

from datetime import datetime, timezone, timedelta
from functools import wraps
from pprint import pformat
from typing import(
    Dict,
    List,
    Optional,
    Union,
)

import httpx

from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.errors import SlackApiError

from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)

from ledhntr.helpers import LEDConfigParser
from ledhntr.helpers import format_date, dumps, xterm
from ledhntr.plugins.connector import ConnectorPlugin

#&##########################################################################
#& COMMON MODAL LAYOUTS
#&##########################################################################

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

#&##########################################################################
#& DECORATORS
#&##########################################################################

def check_client(func):
    @wraps(func)
    async def check_client_wrapper(self, *args, **kwargs):
        _log = self._log
        if 'channel' in kwargs and not kwargs['channel'].startswith('#'):
            kwargs['channel'] = f"#{kwargs['channel']}"
        if not self.admin_channel.startswith('#'):
            self.admin_channel = f"#{self.admin_channel}"
        if not self.user_channel.startswith('#'):
            self.user_channel = f"#{self.user_channel}"
        if not self.client:
            _log.debug(f"self.client not defined. Reloading client.")
            self.reload_web_client()
        else:
            _log.debug(f"self.client set. token: {self.client.token}")
            _log.debug(f"self.client.auth_test: {await self.client.auth_test()}")
        if not await self.client.auth_test():
            self.reload_web_client()
        return func(self, *args, **kwargs)
    return check_client_wrapper

class SlackClient(ConnectorPlugin):
    """SlackClient
    """
    def __init__(
        self,
        config: LEDConfigParser = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__(config)

        if not logger:
            self._log: logging.Logger = logging.getLogger('ledhntr')
        else:
            self._log = logger
        self.config = config

        self.token = config.get(
            'options',
            'token',
            fallback = '<YOUR_TOKEN>',
        )

        self.cmd = config.get(
            'options',
            'cmd',
            fallback='mojo',
        )

        self.admin_channel = config.get(
            'options',
            'admin_channel',
            fallback='mojo-admin',
        )
        if not self.admin_channel.startswith('#'):
            self.admin_channel = f"#{self.admin_channel}"


        self.user_channel = config.get(
            'options',
            'user_channel',
            fallback='mojo-bot',
        )
        if not self.user_channel.startswith('#'):
            self.user_channel = f"#{self.user_channel}"

        self.client = None

    def __getstate__(self):
        state = self.__dict__.copy()
        state['client'] = None
        state['log'] = None
        state['_log'] = None
        state['logger'] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.client = None

    #&##########################################################################
    #& LOAD CLIENT
    #&##########################################################################

    def reload_web_client(
        self,
        token: Optional[str] = None,
    )->AsyncWebClient:
        """reload web client

        :param token: SlackBot Token, defaults to None
        :type token: Optional[str], optional
        :return: SlackBot WebClient
        :rtype: WebClient
        """
        _log = self._log
        _log.debug(f"Reloading AsyncWebClient...")
        if not token:
            self.client = AsyncWebClient(token=self.token)
        else:
            self.client = AsyncWebClient(token=token)
        return self.client

    #&##########################################################################
    #& GLOBAL RESPONSES
    #&##########################################################################

    #~##################
    #~ Invalid Command
    #~##################

    @check_client
    async def invalid_command(
        self,
        trigger_id: str = None,
        cmd: str = None,
        **kwargs
    )->None:
        _log = self._log
        await self.client.views_open(
            trigger_id=trigger_id,
            view=invalid_command_modal(cmd=cmd),
        )
        return None

    #~##################
    #~ UNAUTHORIZED
    #~##################

    @check_client
    async def unauthorized_resp(
        self,
        trigger_id: str = None,
        **kwargs
    )->None:
        _log = self._log
        _log.debug(f"Unauthorized operation.")
        await self.client.views_open(
            trigger_id=trigger_id,
            view=unauthorized_modal(),
        )
        return None

    #&##########################################################################
    #& POST/UPDATE MESSAGES
    #&##########################################################################

    @check_client
    async def action_response(
        self,
        text: str = None,
        response_url: str = None,
        blocks: Optional[List] = None,
        blocks_verbatim: Optional[bool] = False,
        response_type: Optional[str] = "ephemeral",
        **kwargs
    )->bool:
        """Handle responses to various Slack Actions (button clicks, etc)

        :param text: Text to include in the response payload, defaults to None
        :type text: str, optional
        :param response_url: Response URL to send payload to, defaults to None
        :type response_url: str, optional
        :param blocks: Block Kit Blocks for pretty messages, defaults to None
        :type blocks: List, optional
        :param response_type: Response type, ephemeral or in_channel, defaults to "ephemeral"
        :type response_type: Optional[str], optional
        :return: True if message succeeded, False if it failed
        :rtype: Boolean
        """
        _log = self._log
        if blocks is None:
            blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'verbatim': blocks_verbatim,
                    'text': text,
                },
            }
        ]
        resp_url = response_url
        resp_payload = {
            "response_type": response_type,
            "text": text,
            "blocks": blocks
        }
        _log.debug(f"Posting {pformat(resp_payload)} to {resp_url}")
        try:
            async with httpx.AsyncClient() as client:
                await client.post(resp_url, json=resp_payload)
            return True
        except Exception as e:
            _log.error(f"Error posting to {resp_url}")
            return False

    @check_client
    async def post_message(
        self,
        channel: str = None,
        text: str = None,
        blocks: Optional[List] = None,
        blocks_verbatim: Optional[bool] = False,
        **kwargs
    )->bool:
        """Posts brand new message to a channel

        :param channel: Channel or DM ID, defaults to None
        :type channel: str, optional
        :param text: Text to post to the channel, defaults to None
        :type text: str, optional
        :param blocks: Block Kit blocks for pretty messages, defaults to None
        :type blocks: List, optional
        :return: True if successful, False if failure
        :rtype: Boolean
        """
        _log = self._log
        if blocks is None:
            blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'verbatim': blocks_verbatim,
                    'text': text,
                },
            }
        ]
        _log.debug(f"Posting {text} to {channel}")
        try:
            response = await self.client.chat_postMessage(
                channel=channel,
                text=text,
                blocks=blocks,
            )
        except SlackApiError as e:
            _log.error(f"SlackError sending message {e.response['error']}")
            '''
            _log.error(f"Full error: {e}")
            _log.error(f"channel: {channel}")
            _log.error(f"text: {text}")
            _log.error(f"blocks: {blocks}")
            _log.error(f"self.client: {self.client}")
            _log.error(f"self.client.token: {self.client.token}")
            _log.error(f"self.client.auth_test: {await self.client.auth_test()}")
            '''
            return False
        except Exception as e:
            _log.error(f"Error sending message: {e}")
            return False

        _log.debug(f"Successful post!: {pformat(response)}")
        return True

    @check_client
    async def update_message(
        self,
        channel: str = None,
        ts: str = None,
        text: str = None,
        blocks: Optional[List] = None,
        blocks_verbatim: Optional[bool] = False,
        **kwargs
    )->bool:
        """update pre-exising message

        :param channel: channel name where message resides, defaults to None
        :type channel: str, optional
        :param ts: timestamp message was sent, defaults to None
        :type ts: str, optional
        :param text: text to update message with, defaults to None
        :type text: str, optional
        :param blocks: Block Kit blocks for pretty messages, defaults to None
        :type blocks: List, optional
        :return: True if successful, False if failure
        :rtype: Boolean
        """
        _log = self._log
        if blocks is None:
            blocks = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'verbatim': blocks_verbatim,
                    'text': text,
                },
            }
        ]
        try:
            response = await self.client.chat_update(
                channel = channel,
                ts = ts,
                text = text,
                blocks = blocks,
            )
        except SlackApiError as e:
            _log.error(f"Error sending message {e.response['error']}")
            return False
        except Exception as e:
            _log.error(f"Error sending message: {e}")
            return False

        _log.debug(f"Successful update!: {pformat(response)}")

    #&##########################################################################
    #& INTERACTIVITY
    #& Slack Actions, Slack Events, and Slash-Commands
    #&##########################################################################

    async def get_action_ids(
        self,
        payload: Dict = None,
    )->Union[List[str], False]:
        _log = self._log
        action_ids = []
        if payload['type'] == 'block_actions':
            for aid in payload['actions']:
                action_id = aid['action_id']
                action_ids.append(action_id)
        elif payload['type'] == 'view_submission':
            action_id = payload['view']['callback_id']
            action_ids.append(action_id)
        else:
            return False
        _log.debug(f"Retrieved action_ids {action_ids} from payload.")
        return action_ids