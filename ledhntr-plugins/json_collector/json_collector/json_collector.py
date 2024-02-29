"""
Overview
========

Use this plugin to save API results in raw JSON form to disk and rotate out
irrelevant ones

"""

import copy
import json
import logging
from multiprocessing.sharedctypes import Value
import os
from pprint import pformat
from datetime import datetime, timezone, timedelta
from pathlib import Path, PurePath

from ledhntr.data_classes import (
    Attribute,
    Entity,
    Relation,
)
from ledhntr.helpers import (
    LEDConfigParser,
    JsonComplexEncoder,
    dumps,
    get_hunt_name
)
from ledhntr.plugins.connector import ConnectorPlugin


from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union
)


class JSONCollector(ConnectorPlugin):
    """
    JSONCollector

    """
    def __init__(
        self,
        config:LEDConfigParser,
        logger: Optional[object] = None,
        path: Optional[str] = '',
        max_files: Optional[int] = 0,
    ) -> None:
        super().__init__(config)

        if not logger:
            self.logger: logging.Logger = logging.getLogger('ledhntr')
        _log = self.logger
        self.config = config

        if not max_files:
            self.max_files = int(config.get(
                'options',
                'max_files',
                fallback = 0
            ))

        self.client = None

        self.mindate = datetime.fromtimestamp(0).replace(tzinfo=timezone.utc)
        self.maxdate = datetime.now(timezone.utc)

    def set_client(
        self,
        client: ConnectorPlugin,
    ):
        """Set client for interacting with a file system
        :params client: This is a ConnectorPlugin used for writing to a file
            system (e.g. local storage vs AWS S3)
        """
        _log = self.logger
        # client.db_name = self.db_name
        self.client = client
        return self.client

    def write_result(
        self,
        result: Union[List,Dict] = [],
        subdir: str = '',
        compactly: Optional[bool] = True,
    ):
        """
        Converts a result (list or dict) to a raw JSON string and writes it to
            a file.

        :param result: The parsed API result (list or dict)
        :para subdir: The sub directory the JSON will be stored in.
            Should be something unique like the ip address or hostname that triggered
            the lookup. (e.g. './censys/192_168_1_100/')
        :para compactly: If set to False, writes JSON with human-readable indents.
        """
        _log = self.logger
        raw_json = dumps(result, compactly=compactly)
        path = self.client.get_search_path(label=subdir)

        dto = datetime.now(timezone.utc)
        filename = dto.strftime("%Y%m%d_%H_%M_%S_UTC")
        filename += ".json"

        first_files = []
        all_files = self.client.list_dir(path, filenames_only=True)

        # TODO look into the root cause of this, but for whatever reason sometimes
        # I'm getting all_files = [["file1.json", "file2.json"]]
        if isinstance(all_files, list):
            try:
                if isinstance(all_files[0], list):
                    all_files = all_files[0]
            except IndexError:
                _log.error(f"Error getting list of files. all_files = {all_files}")
                _log.error(f"No results written!")
                return False

        for af in all_files:
            if not isinstance(af, str):
                _log.error(f"{af} is not a string!")
                continue
            if af.startswith("_"):
                if af.endswith(".json"):
                    first_files.append(af)
                    break

        if not first_files:
            filename = f"_{filename}"

        wrj = self.client.write_raw_json(
            raw_json=raw_json,
            path=path,
            filename=filename,
        )
        # If successful, run directory cleaning
        if wrj:
            self.client.clean_dir(path=path, max_files=self.max_files)

        return True

    def load_latest(
        self,
        fullpath: Optional[str] = '',
        subdir: Optional[str] = '',
        get_filepath: Optional[bool] = False,
        mindate: Optional[datetime] = datetime.fromtimestamp(0).replace(tzinfo=timezone.utc),
        maxdate: Optional[datetime] = datetime.now(timezone.utc),
        freq: Optional[float] = 24.0,
    ):
        """
        Checks a given subdirectory for JSON files, and if one exists, return
            it as a parsed list or dict.

        :param fullpath: If provided, uses the full path of the JSON file we wish to load.
            Takes priority over subdir

        :param subdir: The sub directory the JSON will be stored in.
            Should be something unique like the ip address or hostname that triggered
            the lookup. (e.g. './censys/192_168_1_100/')

        :param get_filepath: Whether or not to simply return the full filepath
            where the JSON file resides vs returning the loaded/parsed data.

        :param mindate: datetime object of the minimum acceptable date a JSON object
            can be from.

        :param maxdate: datetime object of the maxium acceptable date a JSON object
            can be from.

        :param freq: Hunt frequency (in hours) before a cache is expired.
        """
        _log = self.logger
        # _log.setLevel('DEBUG')

        if not mindate.tzinfo:
            mindate.replace(tzinfo=timezone.utc)
        if not maxdate.tzinfo:
            maxdate.replace(tzinfo=timezone.utc)

        if fullpath:
            read_dir = fullpath
        elif subdir:
            read_dir = self.client.get_search_path(
                path=self.client.full_path,
                label=subdir,
            )
        else:
            _log.error(f"Either subdir or fullpath required!")
            return False

        files = self.client.list_dir(read_dir)

        now = datetime.now(timezone.utc)
        cache_gt_requirement = datetime.fromtimestamp(now.timestamp()-(freq*60*60)).astimezone(timezone.utc)
        latest_file = {}

        for fullpath_file in files:
            f = PurePath(fullpath_file).parts[-1]
            if f.startswith("_"):
                try:
                    dto = datetime.strptime(f, "_%Y%m%d_%H_%M_%S_UTC.json")
                    dto = dto.replace(tzinfo=timezone.utc)
                except ValueError as ex:
                    _log.debug(f"couldn't parse: {ex}")
                    continue
                _log.debug(f"{mindate} {dto} {maxdate}")
                # If the latest cache date is greater than the max date
                # (e.g. last_seen+24hrs), use the cache. Otherwise, refresh
                if mindate < cache_gt_requirement < dto:
                    _log.debug(f"success | min: {mindate} last_cached: {dto} now: {now} max: {maxdate} cache_gt_req: {cache_gt_requirement}")
                    latest_file[f] = dto
                    break
                else:
                    _log.debug(f"{f} | min: {mindate} last_cached: {dto} now: {now} max: {maxdate} cache_gt_req: {cache_gt_requirement}")

        for fullpath_file in files:
            f = PurePath(fullpath_file).parts[-1]
            try:
                dto = datetime.strptime(f, "%Y%m%d_%H_%M_%S_UTC.json")
                dto = dto.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            _log.debug(f"min: {mindate} last_cached: {dto} now: {now} max: {maxdate} cache_gt_req: {cache_gt_requirement}")
            # If the latest cache date is greater than the max date
            # (e.g. last_seen+24hrs), use the cache. Otherwise, refresh
            if mindate < cache_gt_requirement < dto:
                if not latest_file:
                    latest_file[f] = dto
                    continue
                safe_lf = copy.deepcopy(latest_file)
                for k, v in safe_lf.items():
                    if dto > v:
                        latest_file = {f:dto}

        if not latest_file:
            _log.error(f"Found no valid files in {read_dir}!")
            return False
        read_dir_path = PurePath(read_dir)
        full_path = read_dir_path.joinpath(list(latest_file.keys())[0])
        if get_filepath:
            return full_path
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                result = json.load(f)
        except Exception as ex:
            _log.error(f"Unable to load {full_path}! {ex}")
            return False

        return result

    def hunt_to_dir_map(
        self,
        active_hunts: Dict = {},
    ):
        """
        Takes  and
            returns a mapping of {hunt-name : storage_directory} after cleaning
            up any undesirable characters

        :param active_hunts: a dictionary of active hunts (generated by a
            HNTR plugin's find_active_hunts()).
            e.g. {
                '/v2/endpoint': [
                    <Relation,label=hunt)
                ]
            }
        """
        _log = self.logger
        subdirs = []
        if not active_hunts:
            _log.error(f"No active hunts were given!")
        for endpoint, hunts in active_hunts.items():
            for hunt in hunts:
                for attr in hunt.has:
                    if attr.label=="hunt-name":
                        subdirs.append(attr.value)
        # pprint(subdirs)

        huntname_subdirs = {}
        forbidden_chars = ['<','>',':','"','/','\\','|','?','*', ' ',]
        forbidden_dirs = [
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6',
            'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6',
            'LPT7', 'LPT8', 'LPT9'
        ]
        for subdir in subdirs:
            clean_dir = ""
            for letter in subdir:
                if letter in forbidden_chars:
                    clean_dir+="_"
                    continue
                clean_dir+=letter
            clean_dir.rstrip(".")
            clean_dir.rstrip(" ")
            if clean_dir in forbidden_dirs:
                clean_dir = "_"+clean_dir
            huntname_subdirs[subdir]=clean_dir
        return huntname_subdirs

    def gen_custom_min_max(
        self,
        hunt: object = None,
    ):
        _log = self.logger
        freq = None
        first_seen = None
        last_seen = None
        mindate = None
        maxdate = None
        for attr in hunt.has:
            if attr.label == 'frequency':
                freq = attr.value
            elif attr.label == 'last-seen':
                last_seen = attr.value
            elif attr.label == 'first-seen':
                first_seen = attr.value
            elif attr.label == 'hunt-name':
                hunt_name = attr.value
        # if not last_seen, it's never been generated, so ignore any caching
        if not last_seen:
            mindate=maxdate
            return mindate, maxdate
        if freq and last_seen:
            if not last_seen.tzinfo:
                last_seen.replace(tzinfo=timezone.utc)
            ls_epoch = int(last_seen.timestamp())
            maxdate = datetime.fromtimestamp(ls_epoch+(freq*60*60)).astimezone(timezone.utc)
        if first_seen:
            if not first_seen.tzinfo:
                first_seen.replace(tzinfo=timezone.utc)
            mindate = first_seen
            now = datetime.now(timezone.utc)
            yesterday = now-timedelta(days=1)
            if yesterday < mindate:
                mindate = yesterday
        # _log.setLevel('DEBUG')
        _log.debug(f"Hunt: {hunt_name}")
        _log.debug(f"first_seen: {first_seen}")
        _log.debug(f"last_seen: {last_seen}")
        _log.debug(f"Maximum date allowed for using caching: {maxdate}")
        _log.debug(f"Minium date allowed for using caching: {mindate}")
        # _log.setLevel('INFO')
        return mindate, maxdate

    def load_cached_hunts(
        self,
        active_hunts: Dict = {},
        hntr_plugin: str = '',
        parent_dir: Optional[str] = '',
        mindate: Optional[datetime] = None,
        maxdate: Optional[datetime] = None,
        db_name: Optional[str] = None,
    ):
        """

        :param active_hunts: a dictionary of active hunts (generated by a
            HNTR plugin's find_active_hunts()).
            e.g. {
                '/v2/endpoint': [
                    <Relation,label=hunt)
                ]
            }
        :param hntr_plugin: Name of the hntr plugin generating these results (e.g. censys)

        :param parent_dir: Parent directory to load results from

        :param mindate: datetime object of the minimum acceptable date a JSON object
            can be from. If no mindate provided, default will use the hunt
            first-seen attribute to generate the appropriate mindate. If first-seen
            is > the latest cached blob, the cache will not be used.

        :param maxdate: datetime object of the maximum acceptable date a JSON object
            can be from. If no maxdate provided, default will use the hunt frequency
            and last-seen attribute to generate the appropriate maxdate. If now
            is > last_seen+freq, the cache will not be used.
            # NOT HOW THIS WORKS
            # IF LATEST CACHED FILE IS < MAXDATE IT SHOULD BE REFRESHED!

        """
        _log = self.logger
        # _log.setLevel('DEBUG')

        if not mindate:
            mindate = self.mindate
        if not maxdate:
            maxdate = self.maxdate

        cached_hunts = {}

        hunt_dir_map = self.hunt_to_dir_map(active_hunts)

        if db_name:
            self.client.set_path(db_name=db_name)

        for endpoint, hunts in active_hunts.items():
            for hunt in hunts:
                new_mindate = None
                new_maxdate = None
                reset_min = False
                reset_max = False
                freq = 24.0
                for attr in hunt.has:
                    if attr.label == 'frequency':
                        freq = attr.value
                if mindate == self.mindate or maxdate == self.maxdate:
                    new_mindate, new_maxdate = self.gen_custom_min_max(hunt)
                if mindate == self.mindate and new_mindate:
                    _log.debug(f"Using customized mindate {new_mindate}...")
                    mindate = new_mindate
                    reset_min = True
                if maxdate == self.maxdate and new_maxdate:
                    _log.debug(f"Using customized maxdate: {new_maxdate}")
                    maxdate = new_maxdate
                    reset_max = True
                hunt_name = get_hunt_name(hunt)
                subdir = hunt_dir_map[hunt_name]

                label = f"{hntr_plugin}/{subdir}"
                fullpath = self.client.get_search_path(label=label)
                _log.debug(f"Loading latest files with mindate {mindate} and maxdate {maxdate}")

                # now = datetime.now(timezone.utc)
                # json_filepath=False
                # if mindate <= now <= maxdate:
                json_filepath = self.load_latest(
                    fullpath=fullpath,
                    get_filepath=True,
                    mindate=mindate,
                    maxdate=maxdate,
                    freq=freq,
                )

                if json_filepath:
                    if endpoint not in cached_hunts:
                        cached_hunts[endpoint] = {}
                    cached_hunts[endpoint][hunt_name]=json_filepath
                if reset_min:
                    mindate = self.mindate
                if reset_max:
                    maxdate = self.maxdate

        # _log.setLevel('INFO')
        return cached_hunts

    def cache_hunt_results(
        self,
        active_hunts: Dict = {},
        hunt_results: Dict = {},
        plugin: str = '',
        db_name: Optional[str] = None,
    ):
        """
        Cache hunt results returned by a HNTR plugin.
        """
        _log = self.logger

        hunt_dir_map = self.hunt_to_dir_map(active_hunts)

        if db_name:
            self.client.set_path(db_name=db_name)

        for endpoint, hunts in hunt_results.items():
            for hunt_name in hunts:
                if hunt_results[endpoint][hunt_name]['cached']:
                    continue
                if hunt_results[endpoint][hunt_name]['found']['raw']:
                    parsed_res = hunt_results[endpoint][hunt_name]['found']['raw']
                    # subdir = f"./data/json_collector/api_results/censys/{hunt_dir_map[hunt_name]}/"
                    
                    subdir = f"{plugin}/{hunt_dir_map[hunt_name]}"

                    self.write_result(
                        result=parsed_res,
                        subdir=subdir,
                    )

        return True
