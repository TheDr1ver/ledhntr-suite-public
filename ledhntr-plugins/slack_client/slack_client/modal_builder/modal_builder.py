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
from ledhntr import LEDHNTR
from ledhntr.helpers import LEDConfigParser
from ledhntr.helpers import format_date, dumps, xterm
from ledhntr.plugins.connector import ConnectorPlugin

#& Import Block Kit Builders
from actions import (
    action_button_block,
)
from .context import (
    context_block,
)
# from image import ()
from .input import (
    checkbox_block,
    datetime_picker_block,
    external_select_block,
    number_block,
    plain_text_input_block,
    static_select_block,
)
from .section import (
    button_block,
    mrkdwn_block,
)
# from rich_text import ()
from .helpers import (
    get_action_ids,
    get_con_format,
    get_date,
    get_dispatch_action_config,
    get_link_formats,
    get_opt,
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

    #&##########################################################################
    #& Block Kit Builders
    #&##########################################################################

    #~ Actions
    @staticmethod
    async def action_button_block(
        button_text: Optional[str] = "Click Me",
        value: str = None,
        action_id: str = None,
        block_id: Optional[str] = None
    )->Dict:
        """Generates an Action button block

        :param button_text: plain_text content that populates the button,
            defaults to 'Click Me''
        :type button_text: str, optional
        :param value: value returned when button is clicked, defaults to None
        :type value: str, required
        :param action_id: action sent to the app when button clicked, defaults to None
        :type action_id: str, required
        :param block_id: unique identifier for this block, defaults to None
        :type block_id: Optional[str], optional
        :return: block to be used in block_kit
        :rtype: Dict
        """
        return await action_button_block(
            button_text=button_text,
            value=value,
            action_id=action_id,
            block_id=block_id,
        )

    #~ Context
    @staticmethod
    async def context_block(
        elements: List[tuple] = None,
        block_id: Optional[str] = None,
    )->Dict:
        """Generates Context Block Kit Block

        Given a list of tuples for elements, generates a context block.

        Element tuples can be for text or image elements.

        Example text tuple: ('mrkdwn', 'Location: **Dogpatch**', True)
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
        return await context_block(
            elements=elements,
            block_id=block_id,
        )

    #~ Divider
    @staticmethod
    async def divider_block()->Dict:
        """Returns a divider line

        :return: {'type': 'divider'}
        :rtype: dict
        """
        return {'type': 'divider'}
    #~ Header
    @staticmethod
    async def header_block(
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
    @staticmethod
    async def checkbox_block(action_id: str = None,
        label: str = None,
        options: List[tuple] = None,
        emoji: Optional[bool] = True,
        initial_options: List[tuple] = None,
        block_id: Optional[str] = None,
        optional: Optional[bool] = False,
    )->Dict:
        return await checkbox_block(
            label=label,
            options=options,
            emoji=emoji,
            initial_options=initial_options,
            block_id=block_id,
            optional=optional,
        )

    @staticmethod
    async def datetime_picker_block(action_id: str = None,
        label: str = None,
        emoji: Optional[bool] = True,
        initial_date_time: Optional[Union[int,str]] = None,
        focus_on_load: Optional[bool] = False,
        optional: Optional[bool] = False,
        block_id: Optional[str] = None,
    )->Dict:
        return await datetime_picker_block(
            label=label,
            emoji=emoji,
            initial_date_time=initial_date_time,
            focus_on_load=focus_on_load,
            optional=optional,
            block_id=block_id,
        )

    @staticmethod
    async def external_select_block(block_id: Optional[str] = None,
        label: str = None,
        action_id: str = None,
        placeholder: Optional[str] = None,
        min_query_length: int = 3,
        multi: Optional[bool] = False,
    )->Dict:
        return await external_select_block(
            label=label,
            action_id=action_id,
            placeholder=placeholder,
            min_query_length=min_query_length,
            multi=multi,
        )

    @staticmethod
    async def number_block(action_id: str = None,
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
        return await number_block(
            label=label,
            emoji=emoji,
            is_decimal_allowed=is_decimal_allowed,
            initial_value=initial_value,
            min_value=min_value,
            max_value=max_value,
            dispatch_action_config=dispatch_action_config,
            focus_on_load=focus_on_load,
            placeholder=placeholder,
            optional=optional,
            block_id=block_id,
        )

    @staticmethod
    async def plaintext_input_block(
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
        return await plain_text_input_block(
            action_id=action_id,
            label=label,
            emoji=emoji,
            placeholder=placeholder,
            initial_value=initial_value,
            multiline=multiline,
            min_length=min_length,
            max_length=max_length,
            focus_on_load=focus_on_load,
            dispatch_action_config=dispatch_action_config,
            optional=optional,
            block_id=block_id
        )

    @staticmethod
    async def static_select_block(action_id: str = None,
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
        return await static_select_block(
            label=label,
            options=options,
            initial_option=initial_option,
            placeholder=placeholder,
            block_id=block_id,
        )

    #~ Section
    @staticmethod
    async def button_block(
        text: str = None,
        button_text: Optional[str] = "Click Me",
        value: str = None,
        action_id: str = None,
        verbatim: Optional[bool] = True,
        block_id: Optional[str] = None
    )->Dict:
        """Generates a Section button block

        :param text: mrkdwn content, defaults to None
        :type text: str, required
        :param button_text: plain_text content that populates the button,
            defaults to 'Click Me''
        :type button_text: str, optional
        :param value: value returned when button is clicked, defaults to None
        :type value: str, required
        :param action_id: action sent to the app when button clicked, defaults to None
        :type action_id: str, required
        :param verbatim: Whether or not the markdown should be treated as verbatim,
            defaults to True
        :type verbatim: Optional[bool], optional
        :param block_id: unique identifier for this block, defaults to None
        :type block_id: Optional[str], optional
        :return: block to be used in block_kit
        :rtype: Dict
        """
        return await button_block(
            text=text,
            button_text=button_text,
            value=value,
            action_id=action_id,
            verbatim=verbatim,
            block_id=block_id,
        )

    @staticmethod
    async def mrkdwn_block(
        text: str = None,
        verbatim: Optional[bool] = True,
        block_id: Optional[str] = None
    )->Dict:
        """Generates a Section mrkdwn block

        :param text: mrkdwn content, defaults to None
        :type text: str, optional
        :param verbatim: Whether or not the markdown should be treated as verbatim,
            defaults to True
        :type verbatim: Optional[bool], optional
        :param block_id: unique identifier for this block, defaults to None
        :type block_id: Optional[str], optional
        :return: block to be used in block_kit
        :rtype: Dict
        """
        return await mrkdwn_block(
            text=text,
            verbatim=verbatim,
            block_id=block_id,
        )

    #~ Rich Text

    #~ Helpers
    @staticmethod
    async def get_action_ids(
        payload: Dict = None,
    )->Union[List[str], False]:
        """Given a block_action or view_submission payload, extract the action_ids

        :param payload: Payload sent by view_submission or block_action, defaults to None
        :type payload: Dict, optional
        :return: list of action_ids passed or False if not block_actions or
            view_submission payload type
        :rtype: Union[List[str], False]
        """
        return await get_action_ids(payload=payload)

    @staticmethod
    async def get_con_format(key: int = None)->str:
        """return format of a confidence block based on its numerical index

        :param key: integer of confidence level, defaults to None
        :type key: int, required
        :return: string depiction of this confidence
        :rtype: str
        """
        return await get_con_format(key=key)

    @staticmethod
    async def get_date(date: datetime = None)->str:
        """Returns slack-friendly format of a datetime object

        :param date: datetime object, defaults to None
        :type date: datetime, optional
        :return: slack-friendly datetime string
        :rtype: str
        """
        return await get_date(date=date)

    @staticmethod
    async def get_dispatch_action_config(trigger:str = None)->Union[Dict,None]:
        """Configure dispatch action

        :param trigger: 'enter', 'char', or 'both', defaults to None
        :type trigger: str, optional
        :return: dispatch action configuration object or None if invalid trigger
        :rtype: Dict, None
        """
        return await get_dispatch_action_config(trigger=trigger)

    @staticmethod
    async def get_link_formats()->Dict:
        """Returns link formats for different Entity/Relationship types

        :return: dict of link formats
        :rtype: Dict
        """
        return await get_link_formats()

    @staticmethod
    async def get_opt(
        text: str = None,
        value: str = None,
        emoji: Optional[bool] = True,
    )->Dict:
        return get_opt(text=text, value=value, emoji=emoji)

    #&##########################################################################
    #& Selections, Buttons, and other input fields
    #&##########################################################################
    #~ Get Actors External
    @staticmethod
    async def actors_ext_opts()->Dict:
        block = await external_select_block(
            block_id='actor_name',
            label='Actors',
            action_id='add_thing_get_actor-name',
            placeholder="Select related actors",
            min_query_length=3,
            multi=True,
        )
        return block

    #~ Get hunt endpoints Selection box
    @staticmethod
    async def get_hunt_endpoints(endpoints: Dict = None)->Dict:
        block = await static_select_block(
            block_id='hunt-endpoint',
            label='Hunt Endpoint',
            action_id='add_thing_hunt-endpoint',
            placeholder="Select an endpoint",
            options=[("Select a hunt-service first", "0")],
        )
        if endpoints is None:
            return block
        #; if endpoints isn't None, populate the options
        block['accessory']['options'] = []
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

    #~ Populate Hunt Services with enabled HNTR plugins
    @staticmethod
    async def get_hunt_services(
        plugin_list:dict = None,
    )->Dict:
        block = await static_select_block(
            label="Hunt Services",
            action_id="get_hunt_endpoints",
            options=[],
            placeholder="Select a hunt service",
            block_id="hunt-service",
        )

        #; Parse active LEDHNTR plugins
        hntr_plugins = [
            plugin_name for plugin_name, details
            in plugin_list().items()
            if 'HNTR' in details['classes']
        ]

        #; Populate options
        for plugin in hntr_plugins:
            opt = await get_opt(plugin, plugin)
            block['accessory']['options'].append(opt)

        return block

    #~ Get 'Add Attribute' button
    @staticmethod
    async def get_add_attribute()->Dict:
        block = await action_button_block(
            button_text=":heavy_plus_sign: Add New Attribute",
            value="add_new_attribute",
            action_id="add_new_attribute",
            block_id="add_new_attribute_block",
        )
        return block

    #~ Get Tag selection block
    @staticmethod
    async def get_tags()->Dict:
        block = await external_select_block(
            block_id='tag',
            label='Tags',
            action_id='add_thing_get_tag',
            placeholder='Select related tags',
            min_query_length=3,
            multi=True,
        )
        return block

    #~ Add Attribute Label Selector
    @staticmethod
    async def add_attribute_label(
        label:str = None,
        schema:Dict = None,
        meta_attrs: List = None,
    )->Dict:
        block = await static_select_block(
            action_id='get_attr_labels',
            label="*Attribute Label",
            options=[],
            placeholder="Select a label",
            focus_on_load=True,
        )

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
            opt = await get_opt(attr_label, attr_label)
            block['accessory']['options'].append(opt)
        return block

    #~ Add Attribute Value Input Format
    @staticmethod
    async def add_attribute_value(
        label: str = None,
        value_type:str = None
    )->Dict:
        """Return section block with proper formatting based on value_type fed

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
            input = await checkbox_block(
                block_id=label,
                action_id = f"add_attr_{label}",
                label = label,
                options = [(label, 'on')],
                initial_options = initial_options,
                optional = label not in required,
            )
        elif value_type == 'double':
            input = await number_block(
                block_id=label,
                action_id = f"add_attr_{label}",
                label = label,
                initial_value = initial_value,
                min_value = min_value,
                max_value = max_value,
                optional = label not in required,
            )
        elif value_type == 'datetime':
            input = await datetime_picker_block(
                block_id=label,
                action_id = f"add_attr_{label}",
                label = label,
                initial_date_time = initial_date_time,
                optional = label not in required,
            )
        else: #@ implied value_type == 'string'
            input = await plain_text_input_block(
                block_id=label,
                action_id = f"add_thing_{label}",
                label = label,
                multiline = label in multi_line_attrs,
                min_length=min_length,
                max_length=max_length,
                optional = label not in required,
            )
        return input

    #&##########################################################################
    #& Modal Layouts
    #&##########################################################################
    #~ Simple Popup
    @staticmethod
    async def simple_popup(
        title: str = None,
        callback_id: str = None,
        text: str = None,
    )->Dict:
        modal = {
            'type': 'modal',
            'callback_id': callback_id,
            'title': {
                'type': 'plain_text',
                'text': title,
            },
            'blocks': [await mrkdwn_block(text=text)]
        }
        return modal

    #~ Invalid Command
    @staticmethod
    async def invalid_command_modal(cmd: str = None):
        modal = ModalBuilder.simple_popup(
            title="Invalid Command",
            callback_id="invalid_command",
            text=f":no_entry: You have entered an invalid command: {cmd}"
        )
        return modal

    #~ Unauthorized Modal
    @staticmethod
    async def unauthorized_modal():
        modal = ModalBuilder.simple_popup(
            title="Unauthorized",
            callback_id="unauthorized_modal",
            text=":no_entry: You are not authorized"
        )
        return modal

    #~ Add User Modal

    #~ New Hits

    #~ Add Thing Modal

    #~ Edit Thing Modal

    #~ Update Thing Modal (probably replaced w/ Edit Thing Modal once that's ready)