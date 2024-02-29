"""
Connector Plugins
=================

Connector plugins are used for writing objects obtained from HNTR plugins
to a database. It's originally designed to work with TypeDB in mind, but the 
goal is to be able to ultimately use any graph database.

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

class ConnectorPlugin(BasePlugin, ABC):
    def __init__(
        self,
        config: LEDConfigParser,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__(config)
        if not logger:
            self.logger: logging.Logger = logging.getLogger("ledhntr")
        _log = self.logger