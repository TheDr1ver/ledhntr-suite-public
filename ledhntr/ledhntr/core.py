#!/usr/bin/env python3
import logging, logging.handlers
import os

from pathlib import Path
from pprint import pformat

from typing import (
    Dict,
    List,
    Optional,
    Union,
)
_UNSET = object()

import ledhntr.helpers as helpers
from ledhntr.plugin_loader import PluginLoader
from ledhntr.data_classes import pretty_schema


class LEDHNTR(PluginLoader):

    def __init__(
        self,
        base_dir: Optional[str] = "",
        db_server: Optional[str] = "",
        db_name: Optional[str] = "",
        log_level: Optional[str] = "",
        log_dir: Optional[Union[str, object]] = _UNSET,
        config_file: Optional[str] = "",
        plugin_dir_list: Optional[List[str]] = [],
        plugin_opts: Optional[Dict[str, Dict]] = {},
        plugins: Optional[Dict[str, object]] = {},
        schema_load: Optional[bool] = False,
        all_plugins: Optional[bool] = False,
    ):

        # Read Configs
        if not base_dir:
            # base_dir = os.getcwd()
            base_dir = str(
            Path(os.getenv('LEDHNTR_HOME', f"{str(Path.home())}/.ledhntr")).resolve(
                strict=True
            )
        )
        base_dir = os.path.realpath(base_dir)
        self.base_dir = base_dir
        try:
            if not config_file:
                # config_file = '.secrets/ledhntr.cfg'
                # config_file = os.path.join(base_dir, '.secrets/ledhntr.cfg')
                config_file = os.path.join(base_dir, 'ledhntr.cfg')
            config = helpers.LEDConfigParser()
            config.read(config_file)
            self._ledhntr_config = config

        except Exception as ex:
            raise

        # self.verbose_logging = log_level
        if log_dir is _UNSET:
            # log_dir = "./led_hntr.log"
            log_dir = config.get(
                'core', 'log_dir',  fallback=os.path.join(base_dir, 'logs')
            )

        log_level = log_level or config.get('core', 'log_level', fallback="INFO")
        log_maxbytes = int(config.get('core', 'log_maxbytes', fallback='25000000'))
        log_backup_count = int(config.get('core', 'log_backup_count', fallback='5'))
        log_syntax = config.get('core', 'log_syntax', fallback='text')
        self._init_logger(
            log_dir,
            log_level,
            log_maxbytes,
            log_backup_count,
            log_syntax
        )
        _log = self.logger

        plugin_dir_list = plugin_dir_list or config.getlist(
            'core', 'plugin_dir_list', fallback=os.path.join(base_dir, 'plugins')
        )

        super().__init__(plugin_dir_list, plugin_opts, config)

        self.plugins = plugins

        # Additional Vars
        self.schema = pretty_schema

        # Load all active plugins
        if all_plugins:
            self.reload_all_plugins()

        _log.info(f"Successfully loaded configs!")

    def _init_logger(
        self,
        log_dir,
        log_level,
        log_maxbytes,
        log_backup_count,
        log_syntax
    ) -> None:

        self.logger = logging.getLogger('ledhntr')
        self.logger.setLevel(log_level.upper())
        self.logger.handlers=[]


        # if log_syntax == 'json':
        #     formatter = jsonlogger.JsonFormatter
        # else:
        formatter = logging.Formatter

        stderr_handler = logging.StreamHandler()

        stderr_logformat = formatter(
            u"%(asctime)s [%(levelname)s] %(name)s[%(process)d] > "
            u"%(filename)s > (%(funcName)s) [%(lineno)d] > "
            u" %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        stderr_handler.setFormatter(stderr_logformat)
        self.logger.addHandler(stderr_handler)

        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            log_file = f"ledhntr.log"
            log_path = os.path.abspath(
                os.path.join(log_dir, log_file)
            )
            rfh  = logging.handlers.RotatingFileHandler
            file_handler = rfh(
                filename=log_path,
                mode='a',
                maxBytes=log_maxbytes,
                backupCount=log_backup_count,
                encoding= 'UTF-8',
                delay = True,
            )
            file_logformat = formatter(
                u"%(asctime)s [%(levelname)s] %(name)s > "
                u"%(filename)s > (%(funcName)s) [%(lineno)d] > "
                u" %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_logformat)
            self.logger.addHandler(file_handler)
            self.logger.debug(f"Writing logs to {log_path}...")

    def reload_all_plugins(self):
        """
        Reloads all plugins

        """
        _log = self.logger
        self.unload_plugin(all=True)
        for plugin_name in self.list_plugins().keys():
            _log.info(f"Loading {plugin_name}...")
            try:
                plugin = self.load_plugin(plugin_name)
            except Exception:
                _log.error(f"Failed loading {plugin_name}", exc_info=True)
                continue
            # if not self.plugins[plugin_name]:
            if plugin_name not in self.plugins:
                self.plugins[plugin_name] = plugin
                _log.info(f"Successfully loaded {plugin_name}!")
        _log.debug(f"Loaded plugins: \n\t{pformat(self.plugins)}")

