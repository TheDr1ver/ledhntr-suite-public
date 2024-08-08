"""
Overview
========

This is a connector plugin for interacting with a Slack Workspace.

"""
import asyncio
import logging
import traceback

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

from slack_sdk.web.async_client import AsyncWebClient, AsyncSlackResponse
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
#& HELPER FUNCTIONS
#&##########################################################################

_log: logging.Logger = logging.getLogger('ledhntr')

#~#########################################
#~ Block Kit Helpers
#~#########################################

# TODO - Build classes for all rich_text objects:
# TODO - rich_text_section, rich_text_list, rich_text_preformatted, rich_text_quote
# TODO - Build out comprehensive Section session as well

def block_checkbox(
    action_id: str = None,
    label: str = None,
    options: List[tuple] = None,
    emoji: Optional[bool] = True,
    initial_options: List[tuple] = None,
    block_id: Optional[str] = None,
    optional: Optional[bool] = False,
)->Dict:
    block = {
        'type': 'input',
        'element': {
            'type': 'checkboxes',
            'options': [],
            'action_id': action_id,
        },
        'label': {
            'type': 'plain_text',
            'text': label,
            'emoji': emoji,
        }
    }
    for option in options:
        opt = {
            "text": {
                'type': 'plain_text',
                'emoji': emoji,
                'text': option[0]
            },
            "value": option[1]
        }
        block['element']['options'].append(opt)

    for initial_option in initial_options:
        if block['element'].get('initial_options') is None:
            block['element']['initial_options'] = []
        if isinstance(initial_option, tuple) and len(initial_option)==2:
            init = {
                'text': {
                    'type': 'plain_text',
                    'emoji': emoji,
                    'text': initial_option[0],
                },
                'value': initial_option[1],
            }
            block['element']['initial_options'].append(init)
        else:
            _log.error(
                f"{xterm('RED')}initial_option needs to be a tuple with "
                f"exactly 2 values!{xterm('X')}"
            )
    if optional:
        block['optional'] = optional
    if block_id is not None:
        block['block_id'] = block_id
    return block

def block_context(
    elements: List[tuple] = None,
    block_id: Optional[str] = None,
):
    """Generates Context Block Kit Block

    Given a list of tuples for elements, generates a context block.

    Element tuples can be for text or image elements.

    Example text tuple: ('mrkdwn', 'Location: **Dogpatch**, True)
        this sets 'type', 'text', and 'verbatim' values

    Example image tuple: ('image', 'https://example.com/favicon.png', 'favicon')
        this sets 'type', 'image_url', and 'alt_text'

    Example Slack file image: ('image', 'F0123456', 'slack file object')
        this uses a Slack file for the image.

    :param elements: List of tuples to include in the block, defaults to None
    :type elements: List[tuple], optional
    :param block_id: unique ID for this block
    :type block_id: str, optional
    :return: Context dictionary
    :rtype: Dict
    """
    block = {
        "type": "context",
        "elements": [],
    }
    if not block_id is None:
        block['block_id'] = block_id
    for element in elements:
        if len(element) < 2:
            _log.error(
                f"{xterm('RED')}Each element requires at least two tuple values."
                f" Received: {element}{xterm('X')}"
            )
            continue
        if element[0] == "image":
            e = {
                "type": "image",
            }
            if not element[1].startswith('http'):
                e['slack_file'] = {'id': element[1]}
            elif element[1].startswith('https://files.slack.com/'):
                e['slack_file'] = {'url': element[1]}
            else:
                e['image_url'] = element[1]
            if len(element) > 2:
                e['alt_text'] = element[2]
        elif element[0] == 'plain_text':
            e = {
                "type": "plain_text",
                'text': element[2],
                "emoji": True,
            }
        elif element[0] == "mrkdwn":
            e = {
                'type': 'mrkdwn',
                'text': element[1],
            }
            if len(element) > 2:
                e['verbatim'] = element[2]
        else:
            _log.error(
                f"{xterm('RED')}{element[0]} must be image, mrkdwn, or "
                f"plain_text.{xterm('X')}"
            )
            continue
        block['elements'].append(e)

    return block

def block_datetime_picker(
    action_id: str = None,
    label: str = None,
    emoji: Optional[bool] = True,
    initial_date_time: Optional[Union[int,str]] = None,
    focus_on_load: Optional[bool] = False,
    optional: Optional[bool] = False,
    block_id: Optional[str] = None,
)->Dict:

    block = {
        'type': 'input',
        'element': {
            'type': 'datetimepicker',
            'action_id': action_id,
        },
        'label': {
            'type': 'plain_text',
            'text': label,
            'emoji': emoji,
        }
    }
    if initial_date_time is not None:
        dto = format_date(initial_date_time)
        epoch = int(dto.timestamp())
        block['element']['initial_date_time'] = epoch

    block['element']['focus_on_load'] = focus_on_load
    block['optional'] = optional
    if block_id is not None:
        block['block_id'] = block_id

    return block

def block_divider():
    return {
        "type": "divider"
    }

def block_header(
    header: str = None,
    block_id: Optional[str] = None,
):
    """Generates a Header Block

    :param header: plain_text header content, defaults to None
    :type header: str, optional
    :param block_id: unique identifier for this block, defaults to None
    :type block_id: Optional[str], optional
    :return: block to be used in block_kit
    :rtype: Dict
    """
    block = {
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": header,
            "emoji": True,
        }
    }
    if not block_id is None:
        block['block_id'] = block_id

    return block

def block_number(
    action_id: str = None,
    label: str = None,
    emoji: Optional[bool] = True,
    is_decimal_allowed: Optional[bool] = True,
    initial_value: Optional[Union[int,float]] = None,
    min_value: Optional[Union[int,float]] = None,
    max_value: Optional[Union[int,float]] = None,
    dispatch_action_config: Optional[str] = None,
    focus_on_load: Optional[bool] = False,
    placeholder: Optional[str] = None,
    optional: Optional[bool] = False,
    block_id: Optional[str] = None,
)->Dict:

    block = {
        'type': 'input',
        'element': {
            'type': 'number_input',
            'action_id': action_id,
            'is_decimal_allowed': is_decimal_allowed,
        },
        'label': {
            'type': 'plain_text',
            'text': label,
            'emoji': emoji,
        },
    }
    if placeholder:
        block['element']['placeholder'] = {
            'type': 'plain_text',
            'text': placeholder,
        }
    if initial_value is not None:
        block['element']['initial_value'] = str(initial_value)
    if min_value is not None:
        block['element']['min_value'] = str(min_value)
    if max_value is not None:
        block['element']['max_value'] = str(max_value)
    if dispatch_action_config:
        block['element']['dispatch_action_config'] = \
        get_dispatch_action_config(dispatch_action_config)
    block['optional'] = optional
    block['element']['focus_on_load'] = focus_on_load
    if block_id is not None:
        block['block_id'] = block_id

    return block

def block_plain_text_input(
    action_id: str = None,
    label: str = None,
    emoji: Optional[bool] = False,
    placeholder: Optional[str] = None,
    initial_value: Optional[str] = None,
    multiline: Optional[bool] = False,
    min_length: Optional[int] = 0,
    max_length: Optional[int] = 3000,
    focus_on_load: Optional[str] = False,
    dispatch_action_config: Optional[str] = None,
    optional: Optional[bool] = False,
    block_id: Optional[str] = None,
)->Dict:

    block = {
        'type': 'input',
        'element': {
            'type': 'plain_text_input',
            'action_id': action_id,
        },
        'label': {
            'type': 'plain_text',
            'text': label,
            'emoji': emoji,
        },
    }
    if placeholder:
        block['element']['placeholder'] = {
            'type': 'plain_text',
            'text': placeholder,
        }
    if initial_value:
        block['element']['initial_value'] = str(initial_value)
    if min_length is not None:
        block['element']['min_length'] = min_length
    if max_length is not None:
        block['element']['max_length'] = max_length
    if dispatch_action_config:
        block['element']['dispatch_action_config'] = \
        get_dispatch_action_config(dispatch_action_config)

    block['element']['multiline'] = multiline
    block['element']['focus_on_load'] = focus_on_load
    block['optional'] = optional
    if block_id is not None:
        block['block_id'] = block_id

    return block

def block_static_select(
    action_id: str = None,
    label: str = None,
    options: List[tuple] = None,
    initial_option: Optional[tuple] = None,
    placeholder: Optional[str] = None,
    block_id: Optional[str] = None,
)->Dict:
    """Build static_select section

        Example call:

        block_static_select(
            label="Level of Confidence",
            placeholder="Select Level",
            options=[
                (":x: False-Positive","my_db|my_iid|-1"),
                (":+1: True-Positive","my_db|my_iid|1")
            ],
            action_id="new_confidence",
        )

    :param label: label for selection, defaults to None
    :type label: str, required
    :param placeholder: initial value for selector, defaults to None
    :type placeholder: str, required
    :param options: List of tuples to populate options, defaults to None
        tuples contain exactly 2 values, with the first value being the text
        content of the selection, and the second value being the value that
        is passed to the server when that option is selected. For example:
        (":x: False-Positive","my_db|my_iid|-1")
    :type options: List[tuple], required
    :param action_id: action_id for section submission, defaults to None
    :type action_id: str, required
    :param block_id: unique block ID for this block, defaults to None
    :type block_id: Optional[str], optional
    :return: dictionary of formatted static_select section block
    :rtype: Dict
    """
    block = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": label,
        },
        "accessory": {
            "type": "static_select",
            "placeholder": {
                "type": "plain_text",
                "emoji": True,
                "text": placeholder
            },
            "options": [],
            "action_id": action_id,
        }
    }

    for option in options:
        opt = {
            "text": {
                'type': 'plain_text',
                'emoji': True,
                'text': option[0]
            },
            "value": option[1]
        }
        block['accessory']['options'].append(opt)

    if isinstance(initial_option, tuple) and len(initial_option)==2:
        init = {
            'text': {
                'type': 'plain_text',
                'emoji': True,
                'text': initial_option[0],
            },
            'value': initial_option[1],
        }
        block['accessory']['initial_option']=init
    else:
        _log.error(
            f"{xterm('RED')}initial_option needs to be a tuple with "
            f"exactly 2 values!{xterm('X')}"
        )

    if block_id is not None:
        block['block_id'] = block_id

    _log.debug(f"Built block: {pformat(block)}")
    return block

def get_con_format(key: int = None):
    confidence_formats = {
        -1: ":x: False-Positive",
        0: ":question: Unknown",
        1: ":thinking_face: Low",
        2: ":slightly_smiling_face: Medium",
        3: ":dart: High",
    }
    return confidence_formats[key]

def get_date(date: datetime = None):
    if date is None:
        date = datetime.now(timezone.utc)
    epoch = int(date.timestamp())
    slack_format = f"<!date^{epoch}^{{date_num}} {{time_secs}}|{date}>"
    return slack_format

def get_dispatch_action_config(
    trigger:str = None,
)->Union[Dict,None]:
    """Configure dispatch action

    :param trigger: 'enter', 'char', or 'both', defaults to None
    :type trigger: str, optional
    :return: dispatch action configuration object
    :rtype: Dict
    """
    enter = ["on_enter_pressed", "enter"]
    char = ["char", "on_character_entered"]
    both = ["both"]

    if trigger in enter:
        trigger_opts = ['on_enter_pressed']
    elif trigger in char:
        trigger_opts = ['on_character_entered']
    elif trigger in both:
        trigger_opts = ['on_enter_pressed', 'on_character_entered']
    else:
        _log.error(
            f"{xterm('RED')}Invalid trigger: {trigger}. "
            f"Returning None.{xterm('X')}"
        )
        return None

    frame = {
        'dispatch_action_config': {
            'trigger_actions_on': trigger_opts
        }
    }

    return frame

def get_link_formats():
    link_formats = {
        'domain': {
            'Censys': "https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=%22{value}%22",
            'Shodan': "https://www.shodan.io/search?query=hostname%3A{value}",
            "URLScan": "https://urlscan.io/search/#domain%3A{value}",
            'VT': "https://www.virustotal.com/gui/domain/{value}",
        },
        'ip': {
            'Censys': "https://search.censys.io/hosts/{value}",
            'Shodan': "https://www.shodan.io/host/{value}",
            'URLScan': "https://urlscan.io/search/#ip%3A{value}",
            'VT': "https://www.virustotal.com/gui/ip-address/{value}",

        },
    }
    #; Duplicate values for similar entities
    link_formats['hostname'] = link_formats['domain']
    return link_formats


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
        '''
        if 'channel' in kwargs and not kwargs['channel'].startswith('#'):
            kwargs['channel'] = f"#{kwargs['channel']}"
        if not self.admin_channel.startswith('#'):
            self.admin_channel = f"#{self.admin_channel}"
        if not self.user_channel.startswith('#'):
            self.user_channel = f"#{self.user_channel}"
        '''
        if 'channel' in kwargs and kwargs['channel'].startswith('#'):
            kwargs['channel'] = kwargs['channel'].lstrip('#')
        if not self.client:
            # // _log.debug(f"self.client not defined. Reloading client.")
            self.reload_web_client()
        else:
            _log.debug(f"{xterm('YELLOW')}self.client set.")# token: {self.client.token}")
            _log.debug(f"self.client.auth_test: {await self.client.auth_test()}{xterm('X')}")
        if not await self.client.auth_test():
            self.reload_web_client()
        return await func(self, *args, **kwargs)
    return check_client_wrapper

#&##########################################################################
#& Client
#&##########################################################################

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
        # // if not self.admin_channel.startswith('#'):
        # //     self.admin_channel = f"#{self.admin_channel}"


        self.user_channel = config.get(
            'options',
            'user_channel',
            fallback='mojo',
        )
        # // if not self.user_channel.startswith('#'):
        # //     self.user_channel = f"#{self.user_channel}"

        self.default_db = config.get(
            'options',
            'default_db',
            fallback='scratchpad',
        )

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
            _log.debug(f"Explicit token not set. Using self.token") # : {self.token}")
        else:
            self.client = AsyncWebClient(token=token)
            _log.debug(f"Explicit token set: {token}.")
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
    #& HANDLE CHANNELS
    #&##########################################################################

    @check_client
    async def conversations_info(
        self,
        channel: Optional[str] = None,
        **kwargs,
    )->Dict:
        _log.debug(f"Getting channel info for channel: {channel}")
        resp = await self.client.conversations_list(types="public_channel,private_channel", limit=1000)
        convo_list = resp.data['channels']
        if channel is None:
            return convo_list
        for convo in convo_list:
            if convo['name']==channel:
                try:
                    resp = await self.client.conversations_info(
                        channel=convo['id'],
                        **kwargs,
                    )
                    return resp.data['channel']
                except SlackApiError as e:
                    _log.error(
                        f"{xterm('RED')}Error getting conversations info {e.response['error']}"
                        f"{xterm('X')}"
                    )
                    _log.error(f"{xterm('RED')}Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
                    return False
                except Exception as e:
                    _log.error(f"{xterm('RED')}Error getting conversations info: {e}{xterm('X')}")
                    _log.error(f"{xterm('RED')}Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
                    return False
        _log.debug(f"No channel found called {channel}.")
        return convo_list


    #&##########################################################################
    #& HANDLE MESSAGES AND RESPONSES
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
        :type blocks: List, optional:param blocks_verbatim: Verbatim means blocks won't do things like render links
        :type blocks_verbatim: boolean
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
        ephemeral: Optional[bool] = False,
        thread_ts: Optional[str] = None,
        **kwargs
    )->AsyncSlackResponse:
        """Posts brand new message to a channel

        :param channel: Channel or DM ID, defaults to None
        :type channel: str, optional
        :param ephemeral: If set to True, sends an ephemeral message
        :type ephemeral: bool, optional
        :param text: Text to post to the channel, defaults to None
        :type text: str, optional
        :param blocks: Block Kit blocks for pretty messages, defaults to None
        :type blocks: List, optional
        :param blocks_verbatim: Verbatim means blocks won't do things like render links
        :type blocks_verbatim: boolean
        :param thread_ts: Timestamp of original message, used for starting threads
        :type thread_ts: str
        :return: True if successful, False if failure
        :rtype: Boolean
        """
        _log = self._log
        if channel.startswith('#'):
            channel = channel.lstrip('#')
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
        # // _log.debug(f"Posting {text} to {channel}")
        if thread_ts is not None:
            thread_ts = str(thread_ts)

        if len(text) > 3000:
            _log.warning(
                f"{xterm('YELLOW')}TEXT IS {len(text)} CHARS LONG! TRUNCATING."
                f"{xterm('X')}"
            )
            text = text[0:2999]
        if len(blocks) > 50:
            _log.warning(
            f"{xterm('YELLOW')}MORE THAN 50 {len(blocks)} PARSED!"
            f"{xterm('X')}"
        )
            overflow = len(blocks)-50
            blocks = blocks[0:48]
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (f":rotating_light: {len(overflow)} TOO "
                                    "MANY BLOCKS :rotating_light:")
                    }
                ]
            })
        parse = True
        if blocks_verbatim:
            parse = False
        try:
            if ephemeral:
                response = await self.client.chat_postEphemeral(
                    channel=channel,
                    text=text,
                    blocks=blocks,
                    thread_ts=thread_ts,
                    parse=parse,
                    **kwargs,
                )
            else:
                response = await self.client.chat_postMessage(
                    channel=channel,
                    text=text,
                    blocks=blocks,
                    thread_ts=thread_ts,
                    parse=parse,
                    **kwargs,
                )
        except SlackApiError as e:
            _log.error(f"{xterm('RED')}SlackError sending message {e.response['error']}")
            # _log.error(f"Full error: {e}")
            _log.error(f"channel: {channel}")
            _log.error(f"text: {text}")
            _log.error(f"blocks: {pformat(blocks)}")
            _log.error(f"thread_ts: {thread_ts}")
            _log.error(f"parse: {parse}")
            for k, v in kwargs.items():
                _log.error(f"{k}: {v}")
            _log.error(xterm('X'))
            '''
            _log.error(f"self.client: {self.client}")
            _log.error(f"self.client.token: {self.client.token}")
            _log.error(f"self.client.auth_test: {await self.client.auth_test()}")
            '''
            return False
        except Exception as e:
            _log.error(f"Error sending message: {e}")
            return False

        _log.debug(f"Successful post!:{xterm('MAGENTA')}"
                   f"{pformat(response.data)}{xterm('X')}")
        return response

    @check_client
    async def conversations_history(
        self,
        channel: str = None,
        inclusive: Optional[bool] = None,
        latest: Optional[str] = None,
        limit: Optional[int] = None,
        oldest: Optional[str] = None,
        **kwargs
    )->bool:
        _log = self.log
        try:
            response = await self.client.conversations_history(
                channel=channel,
                inclusive=inclusive,
                latest=latest,
                limit=limit,
                oldest=oldest,
                **kwargs,
            )
        except SlackApiError as e:
            _log.error(f"{xterm('RED')}Error getting convo history {e.response['error']}")
            return False
        except Exception as e:
            _log.error(f"Error getting convo history: {e}")
            return False

        _log.debug(f"Successfully pulled history!: {pformat(response.data)}")
        return response.data

    @check_client
    async def update_message(
        self,
        channel: str = None,
        ts: str = None,
        text: str = None,
        blocks: Optional[List] = None,
        blocks_verbatim: Optional[bool] = False,
        **kwargs
    )->Union[AsyncSlackResponse, False]:
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
            # // _log.debug(f"{xterm('MAGENTA')}response: {response}")
            # // _log.debug(f"{response.data}{xterm('X')}")
        except SlackApiError as e:
            _log.error(
                f"{xterm('RED')}Error sending message {e.response['error']}"
                f"{xterm('X')}"
            )
            _log.error(f"{xterm('RED')}Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
            return False
        except Exception as e:
            _log.error(f"{xterm('RED')}Error sending message: {e}{xterm('X')}")
            _log.error(f"{xterm('RED')}Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
            return False

        _log.debug(f"Successful update!: {pformat(response)}")
        return response

    @check_client
    async def upload_snippet(
        self,
        filename:str = None,
        content:str = None,
        title: str = None,
        snippet_type:str = None,
        channel:str = None,
        initial_comment: str = None,
    )->bool:
        _log = self._log
        if channel.startswith('#'):
            channel = channel.lstrip('#')
        try:
            response = await self.client.files_upload_v2(
                channel=channel,
                content=content,
                filename=filename,
                snippet_type=snippet_type,
                title=title,
                initial_comment=initial_comment,
            )
            _log.debug(f"File {filename} successfully uploaded: {response['file']['permalink']}")
            return True
        except SlackApiError as e:
            _log.error(f"{xterm('RED')}Error uploading snippet: {e}")
            _log.error(f"filename: {filename}")
            _log.error(f"content: {content[0:100]}...")
            _log.error(f"title: {title}")
            _log.error(f"snippet_type: {snippet_type}")
            _log.error(f"channel: {channel}")
            _log.error(f"initial_comment: {initial_comment}{xterm('X')}")
            raise

    #&##########################################################################
    #& HANDLE MODALs
    #&##########################################################################

    @check_client
    async def views_update(
        self,
        view: dict = None,
        external_id: Optional[str] = None,
        view_id: Optional[str] = None,
        hash: Optional[str] = None,
        **kwargs
    )->AsyncSlackResponse:
        try:
            resp = await self.client.views_update(
                view=view,
                external_id=external_id,
                view_id=view_id,
                hash=hash,
                **kwargs
            )
        except SlackApiError as e:
            raise
        except Exception as e:
            raise
        return resp

    @check_client
    async def views_open(
        self,
        trigger_id: str = None,
        view: List = None,
        **kwargs
    )->None:
        try:
            await self.client.views_open(
                trigger_id=trigger_id,
                view=view,
                **kwargs
            )
        except SlackApiError as e:
            raise
        except Exception as e:
            raise
        return None

    @check_client
    async def delete_message(
        self,
        channel: str = None,
        ts: str = None,
        **kwargs,
    )->bool:
        _log.debug(f"Deleting message {ts} from channel {channel}")
        try:
            resp = await self.client.chat_delete(
                channel=channel,
                ts=ts,
                **kwargs
            )
        except SlackApiError as e:
            _log.error(
                f"{xterm('RED')}Error deleting message {e.response['error']}"
                f"{xterm('X')}"
            )
            _log.error(f"{xterm('RED')}Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
            return False
        except Exception as e:
            _log.error(f"{xterm('RED')}Error deleting message: {e}{xterm('X')}")
            _log.error(f"{xterm('RED')}Traceback: \n{pformat(traceback.format_exc())}{xterm('X')}")
            return False
        _log.debug(f"Successfully deleted message: {resp.data}")
        return True

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
            term = "actions:action_id"
            for aid in payload['actions']:
                action_id = aid['action_id']
                action_ids.append(action_id)
        elif payload['type'] == 'view_submission':
            action_id = payload['view']['callback_id']
            term = "view:callback_id"
            action_ids.append(action_id)
        else:
            return False
        _log.debug(f"Retrieved {term} {action_ids} from payload.")
        return action_ids