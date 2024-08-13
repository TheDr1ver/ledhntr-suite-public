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

def get_con_format(key: int = None):
    confidence_formats = {
        -1: ":x: False-Positive",
        0: ":question: Unknown",
        1: ":thinking_face: Low",
        2: ":slightly_smiling_face: Medium",
        3: ":dart: High",
    }
    return confidence_formats[key]

def get_date(date: datetime = None):
    if date is None:
        date = datetime.now(timezone.utc)
    epoch = int(date.timestamp())
    slack_format = f"<!date^{epoch}^{{date_num}} {{time_secs}}|{date}>"
    return slack_format

def get_dispatch_action_config(
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

def get_link_formats():
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