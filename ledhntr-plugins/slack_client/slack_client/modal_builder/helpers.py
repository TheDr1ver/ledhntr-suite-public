'''
ModalBuilder Helper Functions
'''
import copy
import json
import logging
import re
from datetime import datetime, timezone, timedelta
from pprint import pformat
from typing import(
    Dict,
    List,
    Optional,
    Union,
    Tuple,
)
from ledhntr.helpers import format_date, dumps, xterm

_log: logging.Logger = logging.getLogger('ledhntr')

async def blockaction_update_view(
    payload: Dict = None
)->Tuple[Dict, List[str], Dict]:
    """Get updated view and selection value

    :param payload: Payload sent by block action when selection is chosen,
         defaults to None
    :type payload: Dict, required
    :return: copied view, selection value or False if invalid
    :rtype: Tuple[Dict, Union[str, bool]]
    """
    # TODO - MOVE THIS TO MODALBUILDER.helpers

    #; Clone the existing view properties
    copy_keys = [
        'blocks', 'callback_id',  'submit', 'title', 'type', 'private_metadata'
    ]
    view = {}
    for key in copy_keys:
        view[key] = payload['view'].get(key)
    #; Get the action
    actions = payload['actions']
    if not actions:
        _log.error(f"{xterm('RED')}No valid action was seen: {actions}{xterm('X')}")
        return view, None
    #; Get the value
    value = await get_state_vals_by_type(
        data=payload['actions'][0]
    )
    if value is None:
        value = []
    #; Make the private_metadata friendly
    blob = view.get('private_metadata')
    if blob is None:
        pmd = None
    else:
        pmd = json.loads(blob)
    #! DEBUG
    _log.debug(
        f"{xterm('GREEN')}Updating view but keeping payload "
        f"{pformat(json.loads(view['private_metadata']))}"
    )

    if value is None:
        _log.error(f"Invalid selected_option: {pformat(actions[0])}")
        return view, None
    return view, value, pmd

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

async def get_con_format(key: int = None)->str:
    confidence_formats = {
        -1: ":x: False-Positive",
        0: ":question: Unknown",
        1: ":thinking_face: Low",
        2: ":slightly_smiling_face: Medium",
        3: ":dart: High",
    }
    return confidence_formats[key]

async def get_date(date: datetime = None)->str:
    if date is None:
        date = datetime.now(timezone.utc)
    epoch = int(date.timestamp())
    slack_format = f"<!date^{epoch}^{{date_num}} {{time_secs}}|{date}>"
    return slack_format

async def get_dispatch_action_config(
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

async def get_link_formats()->Dict:
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

async def get_opt(
    text: str = None,
    value: str = None,
    emoji: Optional[bool] = True,
)->Dict:
    opt = {
        'value': value,
        'text': {
            'type': 'plain_text',
            'emoji': emoji,
            'text': text,
        }
    }
    return opt

async def get_state_vals_by_type(
    data:Dict = None,
)->Union[None, List[str]]:
    """Retruns values set in payload.view.state.values.block_id.action_id

    :param data: dict pulled from payload.view.state.values.block_id.action_id,
        defaults to None
    :type data: Dict, required
    :return: List of values returend from that single input or None
    :rtype: Union[None, List[str]]
    """
    data_type = data.get('type')
    if data_type in ['plain_text_input', 'number_input', 'button']:
        if data.get('value') is None:
            val = None
        else:
            val = [data.get('value')]
    elif data_type in ['static_select', 'external_select']:
        if data.get('selected_option') is None:
            val = None
        elif data.get('selected_option').get('value') is None:
            val = None
        else:
            val = [data.get('selected_option').get('value')]
    elif data_type in ['checkboxes', 'multi_external_select']:
        opts = data.get('selected_options')
        val = []
        for opt in opts:
            v = opt.get('value')
            if v is None:
                continue
            if data_type == 'checkboxes':
                if v == 'on':
                    v = True
            val.append(v)
        if not val:
            val = None
    elif data_type == 'datetimepicker':
        if data.get('selected_date_time') is None:
            val = None
        else:
            val = [format_date(data.get('selected_date_time'))]
    else:
        _log.error(
            f"{xterm('RED')}Unknown data type: {data_type}. "
            f"Skipping {pformat(data)}.{xterm('X')}"
        )
        val = None
    #; Get value from db|iid|value format
    parsed_val = []
    if val is not None:
        for v in val:
            if isinstance(v,str):
                match = re.match(r".*?\|0x[0-9a-f]+\|(.*)", v)
                if match:
                    new_v = match.group(1)
                    parsed_val.append(new_v)
        if parsed_val:
            val = parsed_val
    return val

async def replace_block_by_id(
    old_blocks:List[dict] = None,
    new_block: dict = None,
)->List[Dict]:
    if new_block.get('block_id') is None:
        _log.error(f"new_block requires block_id. Leaving old blocks intact.")
    _log.debug(f"Replacing {new_block.get('block_id')} with {pformat(new_block)}")
    for i, block in enumerate(old_blocks):
        if block.get('block_id') == new_block.get('block_id'):
            old_blocks[i] = new_block
            return old_blocks