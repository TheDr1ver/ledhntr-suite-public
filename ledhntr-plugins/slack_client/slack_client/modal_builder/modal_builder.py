"""
Overview
========

This class is used to build out Modals in the Slack Client

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

# from actions import ()
from context import (
    context_block,
)
# from image import ()
from input import (
    checkbox_block,
    datetime_picker_block,
    external_select_block,
    number_block,
    static_select_block,
)
from section import (
    button_block,
    mrkdwn_block,
)
# from rich_text import ()
from helpers import (
    get_con_format,
    get_date,
    get_dispatch_action_config,
    get_link_formats,
)

class ModalBuilder():
    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
    ):
        if not logger:
            self._log: logging.Logger = logging.getLogger('ledhntr')
        else:
            self._log = logger

    #~#########################################
    #~ Block Kit Builders
    #~#########################################

    #~ Actions
    #~ Context
    #~ Divider
    def divider_block():
        return {'type': 'divider'}
    #~ Header
    def header_block(
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
    #~ Image
    #~ Input
    checkbox_block = checkbox_block
    datetime_picker_block = datetime_picker_block
    number_block = number_block
    #~ Rich Text
    #~ Section