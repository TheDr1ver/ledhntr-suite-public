"""
Overview
========

This is a connector plugin for interacting with the local filesystem.

"""

import copy
import dateutil.parser
import json
import logging
import os
import re

from datetime import datetime, timezone
from pathlib import Path
from pkg_resources import resource_stream
from pprint import pformat

from typing import (
    DefaultDict,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

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

class LocalFileClient(ConnectorPlugin):
    """LocalFileClient

    This is a file system client that's used to read and write files to disk.
    It can be invoked through a caching plugin like json_collector, or an
    organizer/search engine like jsonflats_client.

    Alternatively, you can use it to simply read and write local files without
    all the complicated operations of a caching plugin.
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

        path = config.get(
            'options',
            'path',
            fallback = './data/local/',
        )
        if path and not path.endswith('/'):
            path += '/'

        self.path = path

        self.db_name = config.get(
            'options',
            'db_name',
            fallback = 'dev_db',
        )

        # Set Path
        self.full_path = self.set_path()

        # adding debug flag for doing things like making sure we always print
        # the resulting ledid of a newly-added Thing
        self.debug = False

    def set_path(
        self,
        path: Optional[str] = '',
        db_name: Optional[str] = '',
    ):
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

        if db_name:
            self.db_name = db_name
        db_name = db_name or self.db_name
        if db_name:
            full_path = os.path.join(full_path, db_name)

        full_path = os.path.abspath(full_path)

        self.full_path = full_path
        return self.full_path

    def write_thing(
        self,
        thing: Thing = None,
        path: Optional[str] = '',
        return_things: Optional[bool] = False,
        unsafe: Optional[bool] = False,
    ):
        """Add Thing to db folder as a JSON file

        :param thing: Thing object to add
        :param path: Optional path to save the thing to. Defaults to self.full_path
        :param return_things: True if you want the added attribute returned,
            False to return True or invalid data
        :param unsafe: True if you want the files and directories to be created
            in chmod 777 mode.

        :returns: added Thing object if return_things=True, otherwise boolean value
            as it pertains to the write result.
        """
        _log = self.logger

        data = dumps(thing.to_dict(), compactly=True)

        if path or not self.full_path:
            full_path = self.set_path(path=path)
        else:
            full_path = self.full_path
        full_dir = self.get_search_path(path=full_path, label=thing.label)

        filename = ""
        if hasattr(thing, 'keyval') and thing.keyval:
            filename = f"{thing.keyval}-"
        if hasattr(thing, 'ledid') and thing.ledid:
            filename += f"{thing.ledid}"
        filename += ".json"

        full_path = os.path.join(full_dir, filename)
        if unsafe:
            os.makedirs(full_dir, exist_ok=True, mode=0o777)
        else:
            os.makedirs(full_dir, exist_ok=True)

        write_path = os.path.abspath(full_path)
        with open(write_path, 'w', encoding='utf-8') as f:
            try:
                f.write(data)
            except Exception as e:
                _log.error(f"Error writing JSON blob: {e}")
                return data
        if unsafe:
            os.chmod(write_path, 0o777)

        if return_things:
            json_data = self.load_json(write_path)
            if json_data['thingtype'] == 'entity':
                ent = Entity()
                rebuilt_thing = ent.from_dict(**json_data)
            elif json_data['thingtype'] == 'relation':
                rel = Relation()
                rebuilt_thing = rel.from_dict(**json_data)
            return rebuilt_thing

        return True

    def clean_dir(
        self,
        path: str = '',
        max_files: Optional[int] = 0,
    ):
        """
        Clean the specified path by deleting old files (except for the first
            one created).

        :param path: The path you want to do file cleanup on.
        :param max_files: the maximum number of files you wish to keep in path

        :returns: True if successful, False if not.
        """
        _log = self.logger

        if max_files == 0:
            _log.info(f"max_files set to zero means cleaning skipped!")
            return True

        delete_me = []
        parsed_dict = {}

        _log.debug(f"Cleaning {path}!")
        files = os.listdir(path)

        for f in files:
            try:
                dto = datetime.strptime(f, "%Y%m%d_%H_%M_%S_UTC.json")
                dto = dto.replace(tzinfo=timezone.utc)
                parsed_dict[f]=dto

            except ValueError:
                pass

        newest_files = {}

        for f, dto in parsed_dict.items():
            if len(newest_files) < max_files:
                newest_files[f] = dto
                continue
            newest_safe_copy = copy.deepcopy(newest_files)
            for nf, ndto in newest_safe_copy.items():
                if dto > ndto:
                    newest_files[f] = dto
                    if len(newest_files) > max_files:
                        newest_files.pop(nf)
                        if isinstance(path, str):
                            p = Path(path)
                        else:
                            p = path
                        full_path = p.joinpath(nf)
                        delete_me.append(full_path)

        _log.debug(f"delete list: {delete_me}")
        for f in delete_me:
            try:
                os.remove(f)
            except Exception as ex:
                _log.error(f"Failed attempting to delete {f}: {ex}")

        return True

    def write_raw_json(
        self,
        raw_json: str = "",
        path: Optional[str] = '',
        filename: Optional[str] = '',
        append_date: Optional[bool] = False,
        unsafe: Optional[bool] = False,
    ):
        """Write raw JSON to file
        Converts a result (list or dict) to a raw JSON string and writes it to
            a file.

        :param raw_json: A parsed JSON object as as string
        :para path: The full folder path the file will be written to 
            (e.g. ~/.ledhntr/data/local/test_db/api_results/)
        :para filename: The filename to write to the path (e.g. blob.json)
        :para append_date: Boolean - determines if the date should be appended
        to the filename.
        :param unsafe: True if you want the files and directories to be created
            in chmod 777 mode.
        """
        _log = self.logger

        if not path:
            path = self.full_path
        if append_date or not filename:
            dto = datetime.now(timezone.utc)
            filename += dto.strftime("%Y%m%d_%H_%M_%S_UTC")
            filename += ".json"
        if not filename.endswith(".json"):
            filename += ".json"
        if unsafe:
            os.makedirs(path, exist_ok=True, mode=0o777)
        else:
            os.makedirs(path, exist_ok=True)
        if isinstance(path, str):
            p = Path(path)
        else:
            p = path
        full_path = p.joinpath(filename)
        write_path = os.path.abspath(full_path)

        # Check if it's proper JSON
        if not isinstance(raw_json, str):
            raw_json = dumps(raw_json, compactly=True)

        try:
            with open(write_path, 'x', encoding='utf-8') as f:
                f.write(f"{raw_json}\n")
        except Exception as ex:
            _log.error(f"Failed writing {write_path}! {ex}")
            return False

        if unsafe:
            os.chmod(write_path, 0o777)

        return True

    def get_search_path(
        self,
        path: Optional[str] = "",
        label: Optional[str] = "",
    ):
        _log = self.logger
        search_path = ""

        path = path or self.full_path
        full_dir = path

        if label:
            label = label.lstrip(".")
            label = label.rstrip("/")
            label = label.lstrip("/")
            if path:
                full_dir = os.path.join(path, label)
            else:
                full_dir = f"/{label}/"

        search_path = os.path.abspath(full_dir)
        return search_path

    def list_dir(
        self,
        path: str = "",
        filenames_only: Optional[bool] = False,
    ):
        """List a directory

        :param path: A string representing the full path to search
        :param filenames_only: True/False as to whether or not to return the 
            full path for each file in a directory, or just the file name itself.

        :returns: List of all files included in the search_path
        """
        _log = self.logger

        file_list = []

        full_dir = os.path.abspath(path)
        if not os.path.isdir(full_dir):
            return file_list

        for root_dir, dirs, files in os.walk(full_dir):
            for name in files:
                if filenames_only:
                    file_list.append(name)
                else:
                    combo_path = os.path.join(root_dir,name)
                    file_list.append(os.path.abspath(combo_path))

        return file_list

    def load_json(
        self,
        file_path: str = "",
    ):
        """Reads a JSON file from a full file path
        Given the full file path of a JSON object, read the string and convert
        it to a dict.

        :param file_path: Full path location of the JSON file to read

        :returns: Dict of loaded JSON file
        """
        _log = self.logger

        data = {}

        with open(file_path, 'rb') as f:
            try:
                data = json.loads(f.read().decode('latin-1'))
            except Exception as e:
                _log.error(f"Error loading JSON Blob: {e}")
                return data

        return data

    def delete_file(
        self,
        file_path: str = "",
    ):
        """Deletes a file from a local path
        Given the full file path of a file, deletes that file remotely.

        :param file_path: Full path location of the file to delete

        :returns: True if successful, False if unsuccessful
        """
        _log = self.logger

        try:
            os.remove(file_path)
            return True
        except Exception as e:
            _log.error(f"Error deleting file {file_path}: {e}")
            return False
