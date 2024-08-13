'''
Handles Input Blocks
'''
import logging
from pprint import pformat
from typing import(
    Dict,
    List,
    Optional,
    Union,
)
from ledhntr.helpers import format_date, dumps, xterm

from modal_builder.helpers import (
    get_dispatch_action_config
)

_log: logging.Logger = logging.getLogger('ledhntr')
#~ Dispatch Action

#~ Dispatch Custom Action

#~ Multiline Plain Text Input

#~ Plain Text Input
def plain_text_input_block(
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


#~ Number Picker
def number_block(
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


#~ Multi-Users Select

#~ External Select

def external_select_block(
    block_id: Optional[str] = None,
    label: str = None,
    action_id: str = None,
    placeholder: Optional[str] = None,
    min_query_length: int = 3,
    multi: Optional[bool] = False,
)->Dict:

    block = {
        'type': 'section',
        'text': {
            'type': 'mrkdwn',
            'text': label,
        },
        'accessory': {
            'action_id': action_id,
            'type': 'external_select',
            'min_query_length': min_query_length,
        }
    }
    if multi:
        block['accessory']['type'] = 'multi_external_select'
    if placeholder:
        block['accessory']['placeholder'] = {
            'type': 'plain_text',
            'text': placeholder,
        }
    if not block_id is None:
        block['block_id'] = block_id
    return block

#~ Static Select
def static_select_block(
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


#~ Multi-Static Select

#~ Date picker

#~ Datetime picker

def datetime_picker_block(
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


#~ Checkboxes

def checkbox_block(
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

#~ Radio Buttons

#~ Timepicker