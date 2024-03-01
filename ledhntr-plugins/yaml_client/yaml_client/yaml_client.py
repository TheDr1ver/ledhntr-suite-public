import copy
import glob
import logging
import os
import time
import yaml

from pathlib import Path
from typing import Any, Optional, Dict, DefaultDict, Union, List

from ledhntr.data_classes import (
    Attribute,
    Entity,
    Relation,
    Thing,
    Query
)
from ledhntr.helpers import LEDConfigParser
from ledhntr.helpers import format_date, dumps
from ledhntr.plugins.connector import ConnectorPlugin

class YAMLClient(ConnectorPlugin):
    """Read and understand hunts from YAML files

    :param path: A string representing the full path to load yaml files from.
        Defaults to ~/.ledhntr/data/hunts
    """
    def __init__(
        self,
        config:LEDConfigParser,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__(config)

        if not logger:
            self.logger: logging.Logger = logging.getLogger('ledhntr')
        _log = self.logger
        self.config = config

        self.hunts = []

        path = config.get(
            'options',
            'path',
            fallback = './data/hunts/',
        )
        if path and not path.endswith('/'):
            path += '/'

        self.path = path

        # Set Full Path (vs relative)
        self.full_path = self.set_path()

    def set_path(
        self,
        path: Optional[str] = '',
    ):
        """ Set path to read hunts from

        :param path: Optional - if none set, defaults to whatever is in the .conf
            - main default is ~/.ledhntr/data/hunts/
        """
        _log = self.logger
        full_path = ''

        base_dir = str(
            Path(os.getenv('LEDHNTR_HOME', f"{str(Path.home())}/.ledhntr")).resolve(
                strict=True
            )
        )
        full_path = os.path.realpath(base_dir)

        path = path or self.path
        if path:
            full_path = os.path.join(full_path, path)

        full_path = os.path.abspath(full_path)

        self.full_path = full_path
        return self.full_path


    def load_hunts(
        self,
        path: Optional[str] = "",
        ext: Optional[str] = "*.yaml",
    ):
        """Load hunts from specified path

        :param path: Optional - Location of YAML files you wish to load
        :param ext: Optional - YAML file extension in glob format. Defaults to *.yaml
        :returns: List of loaded YAML files in dict form
        """

        _log = self.logger
        if path:
            path = self.set_path(path)
        else:
            path = self.full_path
        path = os.path.join(path, ext)
        _log.info(f"Loading hunts from {path}")
        for hunt in glob.glob(path):
            exists = False
            with open(hunt, 'r') as f:
                h = yaml.safe_load(f)
            for existing_hunt in self.hunts:
                if h['id'] == existing_hunt['id']:
                    exists = True
                    break
            if exists:
                continue
            if not h['enabled']:
                _log.debug(f"Hunt {h['id']} is disabled - skipping.")
                continue
            if not h.get(h['endpoint']):
                _log.error(
                    f"Missing required endpoint parameters for {h['endpoint']}."
                    " What are we supposed to search for?"
                )
                continue
            self.hunts.append(h)

        _log.info(f"Loaded {len(self.hunts)} hunt(s).")
        return self.hunts

    def check_threshold(
        self,
        hunts: Optional[list] = [],
    ):
        """Checks if hunt is scheduled to be run again

        It looks for <path>/last_run/<hunt_id> to read timestamps of the last time
        the hunt was executed. If the hunt doesn't meet the threshold, it's removed
        from the list.

        :param hunts: Optional List of hunt dictionaries loaded from YAML files.
            Defaults to self.hunts which should be loaded from load_hunts()
        :returns: List of hunts that are past their threshold and ready to run
        """
        _log = self.logger
        updated_hunts = []
        if not hunts:
            hunts = self.hunts
        start_hunts = len(hunts)
        now = int(time.time())

        last_run_path = Path(self.full_path).joinpath("./last_run/")
        os.makedirs(last_run_path, exist_ok=True)

        for hunt in hunts:
            last_run_id = last_run_path.joinpath(hunt['id'])
            last_run_id = os.path.abspath(last_run_id)
            if not os.path.exists(last_run_id):
                # _log.info(f"No file {last_run_id}")
                # _log.info(f"Hunt {hunt['id']} never run!")
                updated_hunts.append(hunt)
                continue
            with open(last_run_id, 'r') as f:
                readtime = f.read()
            delta = now-int(readtime)
            thresh = now-(hunt['frequency'] * 60 * 60) # @ hrs * min * sec
            if thresh > delta:
                # _log.info(f"Threshold NOT met for {hunt['id']}")
                continue
            else:
                # _log.info(f"Threshold met for {hunt['id']}")
                updated_hunts.append(hunt)

        self.hunts = updated_hunts
        _log.info(
            f"Trimmed {start_hunts-len(self.hunts)} hunt(s). "
            f"{len(self.hunts)} hunt(s) ready to fire!"
        )
        return self.hunts

    def delete_lastruns(
        self,
        hunts: Optional[list] = [],
    ):
        """Deletes all last_run timestamps to start from scratch

        :params hunts: Optional list of hunts to delete timestamps for
            Defaults to self.hunts
        """
        _log = self.logger
        if not hunts:
            hunts = self.hunts
        last_run_path = Path(self.full_path).joinpath("./last_run/")
        os.makedirs(last_run_path, exist_ok=True)

        for hunt in hunts:
            last_run_id = last_run_path.joinpath(hunt['id'])
            last_run_id = os.path.abspath(last_run_id)
            if os.path.exists(last_run_id):
                os.remove(last_run_id)

    def update_lastrun(
        self,
        hunts: Optional[list] = [],
    ):
        """Updates LastRun timestamps for all hunts

        :params hunts: Optional list of hunts to update timestamps for
        """
        _log = self.logger
        if not hunts:
            hunts = self.hunts
        now = int(time.time())
        last_run_path = Path(self.full_path).joinpath("./last_run/")
        os.makedirs(last_run_path, exist_ok=True)

        for hunt in hunts:
            last_run_id = last_run_path.joinpath(hunt['id'])
            last_run_id = os.path.abspath(last_run_id)
            # * overwrite the last timestamp file
            # _log.info(f"Creating timestamp {now} for {last_run_id}")
            with open(last_run_id, 'w') as f:
                f.write(str(now))