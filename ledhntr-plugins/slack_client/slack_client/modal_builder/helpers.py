'''
ModalBuilder Helper Functions
'''
import logging
from datetime import datetime, timezone, timedelta
from pprint import pformat
from typing import(
    Dict,
    List,
    Optional,
    Union,
)
from ledhntr.helpers import format_date, dumps, xterm

_log: logging.Logger = logging.getLogger('ledhntr')

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