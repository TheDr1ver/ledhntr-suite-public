import copy
import logging
from abc import ABC
from typing import Dict, Optional

from  ledhntr import helpers
from ledhntr.helpers import LEDConfigParser

# from helpers import get_logger(logloc, verbose=False)

class BasePlugin(ABC):
    def __init__(self, config: LEDConfigParser) -> None:
        self.config = config
        self.plugin_name = config.get('Core', 'Name', fallback=self.__class__.__name__)
        self.__author__ = config.get('Documentation', 'Author', fallback='')
        self.__version__ = config.get('Documentation', 'Version', fallback='')
        self.__website__ = config.get('Documentation', 'Website', fallback='')
        self.__description__ = config.get('Documentation', 'Description', fallback='')
        self.log = logging.getLogger(f'ledhntr.{self.plugin_name}')
    