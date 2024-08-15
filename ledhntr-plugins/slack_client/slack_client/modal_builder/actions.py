'''
Handles Actions Blocks
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
_log: logging.Logger = logging.getLogger('ledhntr')
#~ All Selects

#~ Filtered Conversations Select

#~ Selects with Initial Options

#~ Generic Action block
async def action_block(
    elements: List[dict] = None,
    block_id: Optional[str] = None,
)->Dict:
    """Returns a generic action block with populated elements

    :param elements: list of element dicts to include in the action block, defaults to None
    :type elements: List[dict], optional
    :return: Action block dictionary
    :rtype: Dict
    """
    if len(elements) > 25:
        _log.error(f"There is a maximum limit of 25 blocks per action.")
        return {}
    block = {
        'type': 'actions',
        'elements': elements,
    }
    if block_id:
        block['block_id'] = block_id
    return block

#~ Button
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
    block = {
        "type": "actions",
        'elements': [
            {
                'type': 'button',
                'text': {
                    'type': 'plain_text',
                    'emoji': True,
                    'text': button_text,
                },
                'value': value,
                'action_id': action_id,
            },
        ],
    }
    if not block_id is None:
        block['block_id'] = block_id

    return block

#~ Datepickers

#~ Checkboxes

#~ Radio Buttons

#~ Timepicker