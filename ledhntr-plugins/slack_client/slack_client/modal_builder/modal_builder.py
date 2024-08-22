"""
Overview
========

This class is used to build out Modals in the Slack Client

"""
import asyncio
import json
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
from .actions import (
    action_block,
    action_button_block,
)
from .context import (
    context_block,
)
# from image import ()
from .input import (
    checkbox_block,
    confirmation_block,
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
from .rich_text import (
    basic_rich_text,
)
from .helpers import (
    get_action_ids,
    get_con_format,
    get_date,
    get_dispatch_action_config,
    get_link_formats,
    get_opt,
)
_log: logging.Logger = logging.getLogger('ledhntr')
class ModalBuilder():
    _log: logging.Logger = logging.getLogger('ledhntr')
    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
    ):
        if not logger:
            self._log: logging.Logger = logging.getLogger('ledhntr')
        else:
            self._log = logger

    #&##########################################################################
    #& Block Kit Builders and Helper functions
    #&##########################################################################

    #~ Generic Elements
    @staticmethod
    async def button_element(
        text:str = None,
        value:str = None,
        action_id: str = None,
    )->Dict:
        button = {
            'type': 'button',
            'text': {
                'type': 'plain_text',
                'text': text,
                'emoji': True,
            },
            'value': value,
            'action_id': action_id,
        }
        return button

    #~ Actions
    #; Generic Action Block
    @staticmethod
    async def action_block(
        elements: List[dict] = None,
    )->Dict:
        """Returns a generic action block with populated elements

        :param elements: list of element dicts to include in the action block, defaults to None
        :type elements: List[dict], optional
        :return: Action block dictionary
        :rtype: Dict
        """
        return await action_block(
            elements=elements,
        )

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
    async def static_select_block(
        action_id: str = None,
        label: str = None,
        options: List[Union[tuple,dict]] = None,
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
            Alternatively, you can also submit a list of properly-formatted option
            dictionaries, like one generated by ModalBuilder.get_opts().
        :type options: List[Union[tuple,dict]], required
        :param action_id: action_id for section submission, defaults to None
        :type action_id: str, required
        :param block_id: unique block ID for this block, defaults to None
        :type block_id: Optional[str], optional
        :return: dictionary of formatted static_select section block
        :rtype: Dict
        """
        return await static_select_block(
            action_id=action_id,
            label=label,
            options=options,
            initial_option=initial_option,
            placeholder=placeholder,
            block_id=block_id,
        )

    #~ Rich Text
    @staticmethod
    async def basic_rich_text(
        text: str = None,
        bold: bool = False,
    )->Dict:
        return await basic_rich_text(text=text, bold=bold)

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
        return await get_opt(text=text, value=value, emoji=emoji)

    #&##########################################################################
    #& Modal Framework
    #&##########################################################################
    #~ Build Modal Framework
    @staticmethod
    async def get_modal_framework(
        blocks: list = [],
        callback_id: str = None,
        title: str = None,
        submit: str = 'Submit',
        close: str = 'Close',
        emoji: bool = True,
        private_metadata: str = None,
    )->Dict:
        modal = {
            'type': 'modal',
            'callback_id': callback_id,
            'title': {'type': 'plain_text', 'text': title},
            'submit': {'type': 'plain_text', 'text': submit, 'emoji':emoji},
            'close': {'type': 'plain_text', 'text': close, 'emoji': emoji},
            'blocks': blocks,
        }
        if private_metadata is not None:
            modal['private_metadata'] = private_metadata
        return modal

    #&##########################################################################
    #& Selections, Buttons, and other input fields
    #&##########################################################################
    #~ Get Actors External
    @staticmethod
    async def actors_ext_opts(
        existing: Union[List[str],str] = None,
    )->Dict:
        _log.debug(f"EXISTING: {existing}")
        options = None
        if existing is not None and not isinstance(existing, list):
            existing = [existing]
        if existing is not None:
            options = [
                await get_opt(attr, attr)
                for attr in existing
                if attr is not None
            ]
        _log.debug(f"OPTIONS: {options}")
        if options:
            block = await external_select_block(
                block_id='actor-name',
                label='Actors',
                action_id='opts_get_actors',
                initial_options=options,
                min_query_length=3,
                multi=True,
            )
        else:
            block = await external_select_block(
                block_id='actor-name',
                label='Actors',
                action_id='opts_get_actors',
                placeholder="Select related actors",
                min_query_length=3,
                multi=True,
            )
        _log.debug(f"BLOCK:\n{pformat(block)}")
        return block

    #~ Get frequency input
    @staticmethod
    async def get_frequency(frequency: int = 24)->Dict:
        block = await number_block(
            block_id='frequency',
            action_id='action_edit_frequency',
            label='Frequency',
            emoji=False,
            is_decimal_allowed=True,
            initial_value=frequency,
            min_value=0,
            max_value=None,
            dispatch_action_config='enter',
        )
        return block

    #~ Get hunt-active checkbox
    @staticmethod
    async def get_hunt_active(is_active: bool = False)->Dict:
        if is_active:
            '''
            confirm = await confirmation_block(
                title="Disable Hunt?",
                text="Are you sure you want to DISABLE this hunt?",
                confirm="DISABLE HUNT",
                deny="Nevermind",
                style='danger'
            )
            '''
            block = await checkbox_block(
                block_id='hunt-active',
                label='Hunt Active',
                action_id='action_update_boolean_attribute',
                options=[('hunt-active', 'off')],
                initial_options=[('hunt-active', 'off')],
                # // confirm=confirm
            )
        else:
            '''
            confirm = await confirmation_block(
                title="Enable Hunt?",
                text="Are you sure you want to ENABLE this hunt?",
                confirm="ENABLE HUNT",
                deny="Nevermind",
                style='primary'
            )
            '''
            block = await checkbox_block(
                block_id='hunt-active',
                label='Hunt Active',
                action_id='action_update_boolean_attribute',
                options=[('hunt-active', 'on')],
                # // confirm=confirm
            )
        return block

    #~ Get hunt string multi-line input
    @staticmethod
    async def get_hunt_string(hunt_string: str = None)->Dict:
        block = await plain_text_input_block(
            action_id='action_edit_hunt_string',
            label='Hunt String',
            emoji=False,
            placeholder='Enter a hunt string',
            initial_value=hunt_string,
            multiline=True,
            optional=True,
            block_id='hunt-string',
            dispatch_action_config='enter',
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
            in plugin_list.items()
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
    async def get_tags(
        existing: Union[List[str],str] = None,
    )->Dict:
        _log.debug(f"{xterm('MAGENTA')}existing: {existing}")
        options = None
        if existing is not None and not isinstance(existing, list):
            existing = [existing]
        if existing is not None:
            options = [
                await get_opt(attr, attr)
                for attr in existing
                if attr is not None
            ]
        _log.debug(f"{xterm('MAGENTA')}options: {options}")
        if options:
            block = await external_select_block(
                block_id='tag',
                label='Tags',
                action_id='opts_get_tags',
                initial_options=options,
                min_query_length=3,
                multi=True,
            )
        else:
            block = await external_select_block(
                block_id='tag',
                label='Tags',
                action_id='opts_get_tags',
                placeholder='Select related tags',
                min_query_length=3,
                multi=True,
            )
        _log.debug(f"{xterm('MAGENTA')}block: {block}")
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
            label="*Attribute Label*",
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
        value_type:str = None,
        initial_value:Union[datetime,str,int,float,bool] = None,
        optional: bool = False,
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
        if initial_value is None and label in chk_true:
            initial_value = [(label, 'on')]
        elif label in chk_true:
            if initial_value==True:
                initial_value = [(label, 'on')]
            else:
                initial_value = None
        #; initial integer value
        if initial_value is None and label in init_int:
            initial_value = init_int.get(label)
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
        if initial_value is None and label in now_dates:
            initial_value = int(datetime.now(timezone.utc).timestamp())
        elif label in now_dates:
            initial_value = int(initial_value.timestamp())

        if value_type == 'boolean':
            input = await checkbox_block(
                block_id=label,
                action_id = f"add_attr_{label}",
                label = label,
                options = [(label, 'on')],
                initial_options = initial_value,
                optional = optional or label not in required,
            )
        elif value_type == 'double':
            input = await number_block(
                block_id=label,
                action_id = f"add_attr_{label}",
                label = label,
                initial_value = initial_value,
                min_value = min_value,
                max_value = max_value,
                optional = optional or label not in required,
            )
        elif value_type == 'datetime':
            input = await datetime_picker_block(
                block_id=label,
                action_id = f"add_attr_{label}",
                label = label,
                initial_date_time = initial_value,
                optional = optional or label not in required,
            )
        else: #@ implied value_type == 'string'
            input = await plain_text_input_block(
                block_id=label,
                action_id = f"add_thing_{label}",
                label = label,
                initial_value=initial_value,
                multiline = label in multi_line_attrs,
                min_length=min_length,
                max_length=max_length,
                optional = optional or label not in required,
            )
        return input

    @classmethod
    async def edit_attribute_display(
        cls,
        label: str = None,
        values: List[str] = None,
        parent_iid: str = None,
        counter: Optional[int]=0,
        db_name: str = None,
    )->List[Dict]:
        blocks = []
        blocks.append(await mrkdwn_block(
            text=f"*{label}*",
            verbatim=True,
            block_id=f"{label}_heading"
        ))
        for value in values:
            blocks.append(await context_block(
                elements=[('mrkdwn', f'`{value}`', True)],
                block_id=f"{label}_value_{counter}"
            ))
            pivot_button = await cls.button_element(
                text="Pivot :mag_right:",
                # value=f"({db_name},{label},{value})",
                value=f"{value}",
                action_id=f"pivot_attr"
            )
            delete_button = await cls.button_element(
                text="DELETE :wastebasket:",
                # value=f"({db_name},{label},{value},{parent_iid})",
                value=f"{value}",
                action_id=f"delete_attribute",
            )
            blocks.append(await action_block(
                elements=[pivot_button,delete_button],
                block_id=f"{label}_buttons_{counter}"
            ))
            counter += 1
        return blocks



    #&##########################################################################
    #& Message Layouts
    #&##########################################################################

    #~ New Hits
    @classmethod
    async def new_hits(
        cls,
        data: Dict = {},
        interesting_things: List = None,
        con_list: List = None,
    )->Dict:
        """Return a block format for posting a message containing New Hits
        When we run the "news" this is what generates the response.

        :param data: _description_, defaults to {}
        :type data: Dict, optional
        :param interesting_things: _description_, defaults to None
        :type interesting_things: List, optional
        :param con_list: _description_, defaults to None
        :type con_list: List, optional
        :return: _description_
        :rtype: Dict
        """
        #. This is ugly, but it works. Could probably use some freshening up
        #. now that I've got a better understanding of the layout.
        blocks = []
        db = next(iter(data))
        new_stuff = data[db]
        #; Format links for quick context lookups
        link_formats = await get_link_formats()

        #; Check for interesting things first:
        #; If there's nothing interesting, return an empty block
        if not any(thing_type in interesting_things for thing_type in new_stuff):
            return []

        blocks.append(await cls.header_block(f":collision: NEW HITS [{db}]"))
        blocks.append(await cls.divider_block())
        blocks.append(
            await context_block(elements=[('mrkdwn', await get_date())])
        )
        for thing_type, things in new_stuff.items():
            if thing_type.lower() not in interesting_things:
                cls._log.debug(f"{thing_type} is not interesting. Skipping.")
                continue
            blocks.append(await basic_rich_text(text=thing_type.upper(), bold=True))
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
                if not (hunt_names := thing[keyval].get('hunt-name')) is None:
                    hunts_string=""
                    for hunt_name in hunt_names:
                        hunts_string+=f"`{hunt_name}` "
                    hunts_string.rstrip()
                    lines.append(hunts_string)
                if thing_type.lower() in link_formats:
                    links = ""
                    for text, link in link_formats[thing_type.lower()].items():
                        links += f"<{link.format(value=keyval)}|{text}> | "
                    links = links.rstrip(" | ")
                    lines.append(links)
                mrkdwn = "\n".join(lines)
                button = await button_block(
                    text=mrkdwn,
                    button_text=await get_con_format(int(confidence)),
                    value=f"{db}|{iid}",
                    action_id='set_confidence_modal',
                    verbatim=True,
                )
                '''
                button = await cls.action_button_block(
                    text=await get_con_format(int(confidence)),
                    button_text=mrkdwn,
                    value=f"{db}|{iid}",
                    action_id='set_confidence_modal',
                    verbatim=True,
                )
                '''
                blocks.append(button)
                thing_added = True
            #; If we didn't add anything, remove the heading.
            if not thing_added:
                blocks.pop()
        #; This means all we have is the DB header, divider, and context date
        if len(blocks) == 3:
            return []
        return blocks


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
    @classmethod
    async def invalid_command_modal(cls, cmd: str = None):
        modal = cls.simple_popup(
            title="Invalid Command",
            callback_id="invalid_command",
            text=f":no_entry: You have entered an invalid command: {cmd}"
        )
        return modal

    #~ Unauthorized Modal
    @classmethod
    async def unauthorized_modal(cls):
        modal = cls.simple_popup(
            title="Unauthorized",
            callback_id="unauthorized_modal",
            text=":no_entry: You are not authorized"
        )
        return modal

    #~ Add User Modal
    @classmethod
    async def add_user_modal(
        cls,
        userval: str = None,
        roles: List[str] = None,
    )->Dict:
        username = userval.split(',')[0]
        slack_id = f"{userval.split(',')[1]},{userval.split(',')[2]}"
        modal = await cls.get_modal_framework(
            callback_id='add_user_modal',
            title='Add User',
        )
        modal['blocks'].append(
            await plain_text_input_block(
                block_id='user_block',
                action_id='username',
                placeholder='Enter the LEDHNTR Username',
                initial_value=username,
                label='LEDHNTR Username'
            )
        )
        modal['blocks'].append(
            await plain_text_input_block(
                block_id='slackid_block',
                action_id='slack_id',
                placeholder='SlackID (SlackUserID,SlackTeamID) DO NOT MODIFY',
                initial_value=slack_id,
                label='SlackID (SlackUserID,SlackTeamID) DO NOT MODIFY',
            )
        )
        options = [
            await cls.get_opt(text=role.capitalize(), value=role)
           for role in roles
        ]

        modal['blocks'].append(
            await static_select_block(
                block_id='role_block',
                action_id='role',
                placeholder='Select a role',
                options=options,
                label='Role',
            )
        )
        return modal

    #~ Add Thing Modal
    #. First we need to break out the mojo CMD and the args into individual params
    #. Then we can worry about converting the rest of the function.
    @classmethod
    async def add_thing_modal(
        cls,
        db_name: str = None,
        channel_id: str = None,
        label: str = None,
        value: str = None,
        all_dbs: List[str] = None,
        ledschema: Dict = None,
        plugin_list: Dict = None,
    )->Dict:
        blocks = []
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
        special_attrs = {
            'actor-name': await cls.actors_ext_opts(),
            'hunt-service': await cls.get_hunt_services(plugin_list),
            'hunt-endpoint': await cls.get_hunt_endpoints(),
            'hunt-active': await cls.get_hunt_active(),
            'hunt-string': await cls.get_hunt_string(),
            'frequency': await cls.get_frequency(),
            'tag': await cls.get_tags(),
        }

        #@ Stack Blocks
        #; static select from available databases
        db_opts = [(db,db) for db in all_dbs]
        blocks.append(await static_select_block(
                block_id="db_name",
                label="Database",
                placeholder="Select",
                options=db_opts,
                action_id="select_db",
                initial_option=(db_name,db_name)
            ))

        #; Handle special cases like 'hunt'
        schema = None
        if label in special_ents:
            schema = special_ents[label]
            universal_meta = special_ents[label]['owns'] + universal_meta

        #; Get schema for this specific Ent/Relation
        if schema is None:
            schema = ledschema['entity'].get(label) or \
                ledschema['relation'].get(label)

        #; if it's still None, there's no schema that matches this thing.
        if schema is None:
            #! This should never happen b/c we check for valid things before getting
            #! to this point.
            cls._log.error(
                f"{xterm('RED')}No schema found for {label}. "
                f"This shouldn't happen.{xterm('X')}"
            )
            return False

        if not schema['keyattr'] is None and schema['keyattr'] != 'comboid':
            #; Make sure the first input is for the keyattr
            blocks.append(await plain_text_input_block(
                    action_id='add_thing_keyattr',
                    label=schema['keyattr'],
                    initial_value = value,
                    focus_on_load = True,
                    block_id = 'keyattr',
                ))

        for attr in universal_meta:
            #; Check for special attributes
            if attr in special_attrs:
                blocks.append(special_attrs[attr])
                continue
            #; Get value_type
            value_schema = ledschema['attribute'].get(attr)
            if value_schema is None:
                cls._log.error(
                    f"Could not find attribute type {attr}"
                )
                continue
            value_type = value_schema.get('value_type')
            #; handle all other attribute input types
            blocks.append(await cls.add_attribute_value(
                    label=attr,
                    value_type=value_type,
                ))

        #; Finally, add the '+ Add Attribute' Block
        blocks.append(await cls.get_add_attribute())


        #@ build modal framework
        private_metadata=dumps({'channel_id': channel_id, 'label': label.lower()})
        modal = await cls.get_modal_framework(
            callback_id='add_thing',
            title=f"Add {label.upper()}",
            blocks=blocks,
            private_metadata=private_metadata,
        )
        return modal

    #~ Edit Thing Modal
    @classmethod
    async def edit_thing_modal(
        cls,
        db_name: str = None,
        label: str = None,
        value: Optional[str] = None,
        container: Dict = None,
        things: Optional[List[Union[Entity,Relation]]] = None,
        all_dbs: Optional[List[str]] = None,
        ledschema: Dict = None,
        plugin_list: Dict = None,
        user_info: Optional[Dict] = None,
        private_metadata: Optional[str] = None,
    )->Dict:
        """Builds a modal for editing an existing entity or relation.

        This method generates a modal that allows users to edit attributes of an entity or relation
        by providing a refined input interface. It will dynamically populate based on the provided
        schema and available database options.

        :param db_name: The name of the database where the entity or relation resides.
        :type db_name: str, required
        :param label: The label of the entity or relation to be edited.
        :type label: str, required
        :param value: The initial value for the key attribute of the entity or relation.
        :type value: Optional[str], optional
        :param container: A dictionary containing additional information related to the state.
        :type container: Dict, optional
        :param things: A list of existing entities or relations matching the criteria for editing.
        :type things: Optional[List[Union[Entity, Relation]]], optional
        :param all_dbs: A list of all available databases. Optional if things is provided
            and len(things) == 1.
        :type all_dbs: List[str], optional
        :param ledschema: A schema dictionary for attributes and metadata.
        :type ledschema: Dict, required
        :param plugin_list: A dictionary of active plugins that may affect modal behavior.
        :type plugin_list: Dict, required
        :param user_info: A dictionary containing user information to customize the modal.
        :type user_info: Optional[Dict], optional
        :param private_metadata: A string containing metadata for internal usage within the modal.
        :type private_metadata: Optional[str], optional
        :return: A dictionary representing the constructed modal framework for editing the entity or relation.
        :rtype: Dict
        """
        cls._log.debug(f"Building edit_thing modal...")
        blocks = []
        modal = {}
        channel_id = container.get('channel_id') if container else None
        if any(param is None for param in [db_name, label]):
            cls._log.error(f"db_name, and label are required.")
            cls._log.error(
                f"db_name: {db_name} label: {label}"
            )
            cls.simple_popup(
                title="ERROR",
                callback_id="edit_thing_error",
                text=":warning: A label is required to edit something."
            )
            cls._log.debug(f"{xterm('CYAN')}Finished Modal: \n{pformat(modal)}")
            return modal

        if things is not None:
            if not isinstance(things, list):
                if isinstance(things, (Entity, Relation)):
                    things = [things] if not isinstance(things, list) else things
                else:
                    cls._log.warning(
                        f"{things} is not a list, Entity, or Relation -"
                        " setting to None."
                    )
                    things = None

        ent = Entity(label=label)
        if ent.keyattr is None:
            msg = f":warning: {label} does not have a keyattr, so it is uneditable."
            cls._log.error(msg)
            cls.simple_popup(
                title='ERROR',
                callback_id='edit_thing_error',
                text=msg
            )
            cls._log.debug(f"{xterm('CYAN')}Finished Modal: \n{pformat(modal)}")
            return modal
        elif ent.keyattr == 'comboid':
            msg = f":warning: At this time, keyattrs of 'comboid' are uneditable."
            cls._log.error(msg)
            cls.simple_popup(
                title='ERROR',
                callback_id='edit_thing_error',
                text=msg
            )
            cls._log.debug(f"{xterm('CYAN')}Finished Modal: \n{pformat(modal)}")
            return modal
        #; Process private_metadata
        pmd = {}
        if private_metadata is not None:
            pmd = json.loads(private_metadata)
        if pmd.get('channel_id') is None:
            pmd['channel_id'] = channel_id
        pmd['label']=label

        #; We found ONE THING! GREAT! Populate the modal
        if things is not None and len(things) == 1:
            #; Let the thing iid and db_name come along for the ride
            #; this is necessary for the final "edit" operation
            #; since we're not including these values in the inputs.
            container['iid'] = things[0].iid
            container['db_name'] = db_name
            container['value']=things[0].keyval
            modal = await cls.thing_inspect_modal(
                callback_id='edit_thing',
                container=container,
                db_name=db_name,
                label=label,
                ledschema=ledschema,
                plugin_list=plugin_list,
                thing=things[0],
                user_info=user_info,
                private_metadata=dumps(pmd, compactly=True),
            )
            modal['blocks'].append(
                await cls.get_add_attribute()
            )
            cls._log.debug(f"{xterm('CYAN')}Finished Modal: \n{pformat(modal)}")
            return modal
        else:
            #; If no things have been found yet, we need to present a simple form that lets us search
            #; Get available databases
            db_opts = [(db,db) for db in all_dbs]
            blocks.append(await static_select_block(
                    block_id='db_name',
                    label='Database',
                    placeholder='Select DB',
                    options=db_opts,
                    action_id='select_db',
                    initial_option=(db_name,db_name),
                ))
            #; Append keyval input
            if things is None:
                blocks.append(await external_select_block(
                        block_id='keyattr',
                        action_id='opts_get_things',
                        label=ent.keyattr,
                        placeholder='Enter value',
                        min_query_length=2,
                    ))
            else:
                blocks.append(await external_select_block(
                        block_id='keyattr',
                        action_id='opts_get_things',
                        label=ent.keyattr,
                        placeholder=value,
                        min_query_length=2,
                    ))
            modal = await cls.get_modal_framework(
                callback_id='edit_thing',
                title=f"Edit {label.upper()}",
                blocks=blocks,
                private_metadata=dumps(pmd, compactly=True),
            )
            cls._log.debug(f"{xterm('CYAN')}Finished Modal: \n{pformat(modal)}")
            return modal

        #; Otherwise, if there's more than one thing, we need to narrow it down
        #TODO - What happens when we have more than one thing that matches the query?
        #@ elif len(things) > 1:

    #~ Thing Inspect Modal (can be called from button press or edit-thing modal)
    @classmethod
    async def thing_inspect_modal(
        cls,
        callback_id: str = "inspect_thing",
        container: Dict = None,
        db_name: str = None,
        label: str = None,
        ledschema: Dict = None,
        plugin_list: Dict = None,
        thing: Union[Entity,Relation] = None,
        user_info: Optional[Dict] = None,
        private_metadata: Optional[Dict] = None,
    )->Dict:
        cls._log.debug(f"Building update_thing modal...")
        blocks = []
        #; Universal "meta" attributes that could/should apply to every entity/relation
        #; Leaving out 'ref-link' for now to save space.
        universal_meta = [
            'actor-name', 'confidence', 'date-seen', 'date-discovered', 'note', 'tag'
        ]

        #; entities/relations that should have a limited number of fields available
        special_ents = {
            'hunt': {
                'keyattr': 'hunt-name',
                'owns': ['hunt-active', 'hunt-string',
                        'frequency',]
            },
            'enrichment': {
                'keyattr': 'hunt-name',
                'owns': ['hunt-active', 'hunt-string',
                        'frequency',]
            }
        }

        #; attributes that have preset values
        special_attrs = {
            'actor-name': await cls.actors_ext_opts(thing.attrs('actor-name')),
            'hunt-service': await cls.get_hunt_services(plugin_list),
            'hunt-endpoint': await cls.get_hunt_endpoints(),
            'hunt-active': await cls.get_hunt_active(thing.attr('hunt-active')),
            'hunt-string': await cls.get_hunt_string(thing.attr('hunt-string')),
            'frequency': await cls.get_frequency(thing.attr('frequency')),
            'tag': await cls.get_tags(thing.attrs('tag')),
        }


        schema = None
        #; If the label is a "special case", use fields defined above
        if label in special_ents:
            #; set keyattr and extend universal_meta
            schema = special_ents[label]
            universal_meta = special_ents[label]['owns'] + universal_meta

        if schema is None:
            #; Otherwise get the schema from led.schema
            schema = ledschema['entity'].get(label) or \
                ledschema['relation'].get(label)
        #; if it's still None, there's no schema that matches this thing.
        if schema is None:
            #! This should never happen b/c we check for valid things before getting
            #! to this point.
            cls._log.error(
                f"No schema found for {label}. This shouldn't happen."
            )
            return False

        '''
        #. Thanks for NOTHING, ChatGPT!
        schema = special_ents.get(label, ledschema['entity'].get(label) or ledschema['relation'].get(label))
        if not schema:
            cls._log.error(f"No schema found for {label}. This shouldn't happen.")
            return False

        universal_meta.extend(schema.get('owns', []))
        '''

        #; Header
        blocks.append(await cls.header_block(
                header=f"{thing.label.upper()}: {thing.keyval}",
                block_id="update_thing_header"
            ))

        #; Get Interactive Users Images
        if user_info:
            user_context = []
            for user, data in user_info.items():
                username = data['user']['profile']['display_name']
                avatar = data['user']['profile']['image_192']
                user_context.append(
                    ('image', avatar, username)
                )
            blocks.append(await context_block(user_context, 'user-context'))

        #; Handle Date Context
        date_context = []
        fs = thing.attr('first-seen')
        if fs:
            date_context.append(
                ('mrkdwn', f'*first-seen*\n{await get_date(fs)}', True)
            )
        ls = thing.attr('last-seen')
        if ls:
            date_context.append(
                ('mrkdwn', f'*last-seen*\n{await get_date(ls)}', True)
            )
        disco = thing.attr('date-discovered')
        if disco:
            date_context.append(
                ('mrkdwn', f'*discovered*\n{await get_date(disco)}', True)
            )
        blocks.append(await context_block(date_context, 'date-context'))

        #; Handle LEDSRC
        ledsrc = thing.attrs('ledsrc')
        if ledsrc:
            blocks.append(await mrkdwn_block(
                text=f"*LEDSRC*"
            ))
            i = 0
            for attr in ledsrc:
                blocks.append(await button_block(
                    block_id=f"ledsrc_{i}",
                    text=f"`{attr}`",
                    button_text="Pivot :mag_right:",
                    # value=f"({db_name},ledsrc,{attr})",
                    value=f"{attr}",
                    action_id="pivot_attr",
                ))
                i += 1
                #@ Reference block_id_counter to populate dynamic context after
                #@ modal has been built

        #; Handle Hunt Names
        hunts = thing.attrs('hunt-name')
        if hunts:
            if not isinstance(hunts, list):
                hunts = [hunts]
            blocks.append(await mrkdwn_block(
                text=f"*HUNT-NAMES*"
            ))
            i = 0
            for attr in hunts:
                blocks.append(await button_block(
                    block_id=f"hunt-name_{i}",
                    text=f"`{attr}`",
                    button_text="Pivot :mag_right:",
                    # value=f"({db_name},hunt-name,{attr})",
                    value=f"{attr}",
                    action_id="pivot_attr"
                ))
                i+=1

        #; Add Confidence Selector
        if isinstance(thing.attrs('confidence'), list):
            confidence = int(thing.attrs('confidence')[0])
        else:
            confidence = int(thing.attrs('confidence')) or 0
        options = [
            (await get_con_format(lvl),f"{db_name}|{thing.iid}|{lvl}")
            for lvl in range(-1,4)
        ]
        blocks.append(await static_select_block(
                block_id="confidence",
                label="Select Level of Confidence",
                placeholder=await get_con_format(confidence),
                options= options,
                action_id="set_confidence",
            ))

        #; Add Notes
        if thing.attrs('note'):
            notes = (
                thing.attrs('note')
                if isinstance(thing.attrs('note'), list)
                else [thing.attrs('note')]
            )
            blocks.append(await mrkdwn_block(
                text=f"*NOTES*"
            ))
            note_context = []
            for note in notes:
                note_context.append(
                    ('mrkdwn', f'```{note}```', True)
                )
            if note_context:
                blocks.append(await context_block(note_context))
            else:
                blocks.pop()
        blocks.append(await plain_text_input_block(
            action_id="attach_note",
            label="Add Note",
            emoji=True,
            initial_value="",
            multiline=True,
            dispatch_action_config='enter',
            optional=True,
            block_id="note",
        ))

        '''
        for note in notes:
            blocks.append(await plain_text_input_block(
                    block_id='note',
                    label='Note',
                    action_id='inspect_note',
                    placeholder='',
                    initial_value=note,
                    multiline=True,
                    optional=True,
                ))
        '''

        #; Populate other existing attributes
        always_skip = [
            'confidence', 'date-discovered', 'date-seen', 'first-hunted',
            'first-seen', 'last-hunted', 'last-seen', 'ledid',
            'ledsrc', 'note', 'user-uuid',
        ]
        skip_me = always_skip + [
            'frequency', 'hunt-endpoint',
            'hunt-service', 'hunt-string', 'hunt-name',
        ]

        if thing.label not in special_ents:
            for x in list(thing.attrs().keys()):
                if x not in universal_meta:
                    universal_meta.append(x)
            # for meta in thing.meta_attrs:
            #     if meta not in universal_meta:
            #         universal_meta.append(meta)

        counter=0
        for attr in universal_meta:
            #; Check for special attributes
            if attr in special_attrs and special_attrs[attr]:
                blocks.append(special_attrs[attr])
                continue
            #; Check if attr is skippable
            #TODO something is messed up here when editing hunts
            if attr in skip_me and thing.label not in special_ents:
                continue
            if attr in always_skip:
                continue
            #; If attr is keyval type, skip it
            if attr == thing.keyattr:
                continue
            #; Get value_type
            value_schema = ledschema['attribute'].get(attr)
            if value_schema is None:
                cls._log.error(
                    f"Could not find attribute type {attr}"
                )
                continue
            value_type = value_schema.get('value_type')
            #; handle all other attribute input types
            if thing.attrs(attr) is None:
                continue
            initial_values = (
                thing.attrs(attr)
                if isinstance(thing.attrs(attr), list)
                else [thing.attrs(attr)]
            )
            #; Add the heading
            # // blocks.append(await mrkdwn_block(
            # //     text=f"*{attr.upper()}*"
            # // ))
            blocks += await cls.edit_attribute_display(
                label=attr,
                values=initial_values,
                counter=counter,
                db_name=db_name,
            )
            counter += (len(blocks)/2)-1

        #; Process private_metadata
        pmd = {}
        if private_metadata is not None:
            pmd = json.loads(private_metadata)
        for k, v in container.items():
            pmd[k] = v

        pmd=dumps(pmd, compactly=True)

        #; Build Modal framework and return
        if len(thing.keyval) >= 25:
            title = f"{thing.keyval[0:21]}..."
        else:
            title = thing.keyval
        modal = await cls.get_modal_framework(
            title=title,
            callback_id=callback_id,
            blocks=blocks,
            private_metadata=pmd,
        )
        return modal
