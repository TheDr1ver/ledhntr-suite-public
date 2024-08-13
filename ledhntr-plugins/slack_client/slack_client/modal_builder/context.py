'''
Handles Context Blocks
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

#~ Plain Text/MRKDWN
def context_block(
    elements: List[tuple] = None,
    block_id: Optional[str] = None,
):
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

#~ Text and Images