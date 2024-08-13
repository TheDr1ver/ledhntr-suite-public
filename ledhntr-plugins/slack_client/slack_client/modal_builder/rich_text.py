'''
Handles rich text blocks
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
#~ Basic
async def basic_rich_text(
    text:str = None,
    bold:bool = False,
)->Dict:
    block = {
        'type': 'rich_text',
        'elements': [
            {
                'type': 'rich_text_section',
                'elements': [
                    {
                        'type': 'text',
                        'text': text,
                    },
                ],
            },
        ],
    }
    if bold:
        for outter_element in block['elements']:
            for element in outter_element['elements']:
                if 'style' not in element:
                    element['style'] = {}
                element['style']['bold']=True
    return block

#~ Bold

#~ Italic

#~ Strikethrough

#~ Emoji

#~ List