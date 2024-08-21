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

from .helpers import (
    get_dispatch_action_config
)

_log: logging.Logger = logging.getLogger('ledhntr')
#~ Dispatch Action

#~ Dispatch Custom Action

#~ Multiline Plain Text Input

#~ Plain Text Input
async def plain_text_input_block(
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
    if initial_value is not None:
        block['element']['initial_value'] = str(initial_value)
    if min_length is not None:
        block['element']['min_length'] = min_length
    if max_length is not None:
        block['element']['max_length'] = max_length
    if dispatch_action_config:
        dac = await get_dispatch_action_config(dispatch_action_config)
        block['element']['dispatch_action_config'] = dac.get('dispatch_action_config')
        block['dispatch_action']=True

    block['element']['multiline'] = multiline
    block['element']['focus_on_load'] = focus_on_load
    block['optional'] = optional
    if block_id is not None:
        block['block_id'] = block_id

    return block


#~ Number Picker
async def number_block(
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
        await get_dispatch_action_config(dispatch_action_config)
    block['optional'] = optional
    block['element']['focus_on_load'] = focus_on_load
    if block_id is not None:
        block['block_id'] = block_id

    return block


#~ Multi-Users Select

#~ External Select

async def external_select_block(
    block_id: Optional[str] = None,
    label: str = None,
    action_id: str = None,
    placeholder: Optional[str] = None,
    min_query_length: int = 3,
    multi: Optional[bool] = False,
    initial_options: Optional[List[Union[tuple,dict]]] = None,
    focus_on_load: Optional[bool] = False,
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
    if initial_options is not None and isinstance(initial_options,list):
        block['accessory']['initial_options'] = initial_options
    elif initial_options is not None and isinstance(initial_options[0],tuple):
        for io in initial_options:
            opt = {
                "text": {
                    'type': 'plain_text',
                    'emoji': True,
                    'text': io[0]
                },
                "value": io[1]
            }
            if not block['accessory'].get('initial_options'):
                block['accessory']['initial_options'] = []
            block['accessory']['initial_options'].append(opt)
    if focus_on_load:
        block['accessory']['focus_on_load'] = True
    if not block_id is None:
        block['block_id'] = block_id
    return block

#~ Static Select
async def static_select_block(
    action_id: str = None,
    label: str = None,
    options: List[Union[tuple,dict]] = None,
    initial_option: Optional[tuple] = None,
    placeholder: Optional[str] = None,
    block_id: Optional[str] = None,
    focus_on_load: Optional[bool] = False,
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
        dictionaries, like a list generated by multiple calls to
        ModalBuilder.get_opt().
    :type options: List[Union[tuple,dict]], required
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

    if options and isinstance(options[0],tuple):
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
    elif options and isinstance(options, list):
        block['accessory']['options'] = options

    if initial_option is not None:
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
        elif isinstance(initial_option, dict):
            block['accessory']['initial_option']=initial_option
        else:
            _log.error(
                f"{xterm('RED')}initial_option needs to be a tuple with "
                f"exactly 2 values!{xterm('X')}"
            )

    if block_id is not None:
        block['block_id'] = block_id
    if focus_on_load:
        block['accessory']['focus_on_load'] = True

    # // _log.debug(f"Built block: {pformat(block)}")
    return block


#~ Multi-Static Select

#~ Date picker

#~ Datetime picker

async def datetime_picker_block(
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

async def checkbox_block(
    action_id: str = None,
    label: str = None,
    options: List[Union[tuple,dict]] = None,
    emoji: Optional[bool] = True,
    initial_options: Optional[List[Union[tuple,dict]]] = None,
    block_id: Optional[str] = None,
    optional: Optional[bool] = True,
    confirm: Optional[dict] = None,
)->Dict:
    """Generates an input block that contains a checkbox element

    :param action_id: action_id called every time a box is checked/unchecked, defaults to None
    :type action_id: str, required
    :param label: label for the input, defaults to None
    :type label: str, required
    :param options: options related to checkboxes. List of tuples normally, defaults to None.
        tuples contain exactly 2 values, with the first value being the text
        content of the selection, and the second value being the value that
        is passed to the server when that option is selected. For example:
        (":x: False-Positive","my_db|my_iid|-1")
        Alternatively, you can also submit a list of properly-formatted option
        dictionaries, like a list generated by multiple calls to
        ModalBuilder.get_opt().
    :type options: List[Union[tuple,dict]], required
    :param emoji: whether or not emoji are allowed in this input, defaults to True
    :type emoji: Optional[bool], optional
    :param initial_options: list of options that will be selected when input loads, defaults to None
        can be either a list of tuples like the options section, or a list of
        preformatted options in dict format
    :type initial_options: Optional[List[Union[tuple,dict]]], optional
    :param block_id: block_id for the input, defaults to None
    :type block_id: Optional[str], optional
    :param optional: whether or not the checkbox is optional in this form, defaults to True
    :type optional: Optional[bool], optional
    :param confirm: Confirmation dialog generated by confirmation_block(), defaults to None
    :type confirm: Optional[dict], optional
    :return: final block dictionary
    :rtype: Dict
    """
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
    if options and isinstance(options[0],tuple):
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
    elif options and isinstance(options, list):
        block['element']['options'] = options

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
        elif isinstance(initial_option, dict):
            block['element']['initial_option']=initial_option
        else:
            _log.error(
                f"initial_option needs to be a tuple with exactly 2 values!"
                f"\n{pformat(initial_option)}"
            )
    if optional:
        block['optional'] = optional
    if block_id is not None:
        block['block_id'] = block_id
    if confirm:
        block['confirm'] = confirm
    return block

#~ Confirmation Block
async def confirmation_block(
    title: str = None,
    text: str = None,
    confirm: Optional[str] = 'YES',
    deny: Optional[str] = 'NO',
    style: Optional[str] = None,
)->Dict:
    """Return a confirmation dialog

    :param title: title max 100 characters, defaults to None
    :type title: str, required
    :param text: plain_text object max 300 characters, defaults to None
    :type text: str, required
    :param confirm: plain_text object max 30 chars, defaults to 'YES'
    :type confirm: str, optional
    :param deny: plain_text object max 30 characters, defaults to 'NO'
    :type deny: str, optional
    :param style: 'primary' or 'danger' to make confirm button red or green, defaults to None
    :type deny: str, optional
    :return: _description_
    :rtype: Dict
    """
    diag = {
        'title': {
            'type': 'plain_text',
            'text': title,
        },
        'text': {
            'type': 'plain_text',
            'text': text,
        },
        'confirm': {
            'type': 'plain_text',
            'text': confirm,
        },
        'deny': {
            'type': 'plain_text',
            'text': deny,
        }
    }
    if style.lower() in ['primary', 'danger']:
        diag['style'] = {
            'type': 'plain_text',
            'text': style.lower(),
        }
    return diag

#~ Radio Buttons

#~ Timepicker