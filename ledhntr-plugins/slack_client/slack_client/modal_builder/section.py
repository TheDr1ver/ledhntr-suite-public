'''
Handles Section Blocks
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
#~ Plain Text

#~ MRKDWN

def mrkdwn_block(
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
    block = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": text,
            "verbatim": verbatim,
        }
    }
    if not block_id is None:
        block['block_id'] = block_id

    return block

#~ Text Fields

#~ Users Select

#~ Static Select

#~ Multi Static Select

#~ Multi Conversations Select

#~ Button
def button_block(
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
    block = {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": text,
            "verbatim": verbatim,
        },
        'accessory': {
            'type': 'button',
            'text': {
                'type': 'plain_text',
                'text': button_text,
                'emoji': True,
            },
            'value': value,
            'action_id': action_id,
        }
    }
    if not block_id is None:
        block['block_id'] = block_id

    return block


#~ Link Button

#~ Image

#~ Slack Image

#~ Overflow

#~ Datepicker

#~ Checkboxes

#~ Radio Buttons

#~ Timepicker