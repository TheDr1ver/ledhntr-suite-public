"""
Analyzer Plugins
=================

Analyzer plugins are used for processing data that's been collected.

- Simple calculations:

    ## Shared Host?
    - Input: List of resolution objects
    - Processing: How many Domains resolved to the same IP at given time?
    - Output: Resolution Objects that don't appear to belong to a shared host

    ## Equals Correlation?
    - Input: Multiple lists of <Object>
    - Processing: Compare objects between lists
    - Output: Return desired correlation results (objects in all lists, 
        objects in list 1+2, 1+3, 2+3, etc..)
    

- NLP Processes:
    - Input: Two lists of Domains
    - Processing: Create list of "stem" words for each Domain List. Correlate
        matching domains
    - Output: Domains that have the same features 
        (e.g. transportdatacollection[.] and gatewaynetcollect[.]com)


"""

import logging

from abc import abstractmethod, ABC
from configparser import ConfigParser
from datetime import datetime, timezone
from pprint import pformat
from time import time, sleep
from typing import (
    DefaultDict,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from ledhntr.data_classes import Attribute, Entity, Relation
from ledhntr.plugins import BasePlugin
from ledhntr.helpers import LEDConfigParser, format_date

class AnalyzerPlugin(BasePlugin, ABC):
    def __init__(
        self,
        config: LEDConfigParser,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__(config)
        if not logger:
            self.logger: logging.Logger = logging.getLogger("ledhntr")
        _log = self.logger