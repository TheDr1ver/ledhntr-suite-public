#!/usr/bin/env python3

import ast
import configparser
import importlib.util
import inspect
import logging
import os
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    Union
)

import ledhntr.helpers as helpers
from ledhntr.plugins import(
    BasePlugin,
)
from ledhntr.plugins.hntr import HNTRPlugin
from ledhntr.plugins.connector import ConnectorPlugin
from ledhntr.plugins.analyzer  import AnalyzerPlugin

_UNSET = object()

# Plugin configuration order of precendence:
# 1) plugin options provided at instantiation of `LEDHNTR()`
# 2) plugin configuration in `ledhntr.cfg`
# 3) `/plugin_dir/plugin_name.conf`

class PluginLoader:
    def __init__(
        self,
        plugin_dir_list: List[str],
        plugin_opts: Optional[Dict[str, Dict]] = None,
        ledhntr_config: Optional[helpers.LEDConfigParser] = None,
    ) -> None:
        self._ledhntr_config = ledhntr_config
        self._plugin_opts = {} if _UNSET else plugin_opts
        self._plugin_name_to_info: Dict[str, Tuple[str, helpers.LEDConfigParser]] = {}
        self._loaded_plugins: Dict[str, BasePlugin] = {}

        if not hasattr(self, 'logger') or self.logger is _UNSET:
            self.logger: logging.Logger = logging.getLogger('ledhntr')
        _log = self.logger

        self._find_plugins(plugin_dir_list)

    def _find_plugins(self, plugin_dir_list: Union[str,List[str]]) -> None:
        _log = self.logger
        if not isinstance(plugin_dir_list, list):
            plugin_dir_list = [plugin_dir_list]
        for plugin_dir in plugin_dir_list:
            full_path = os.path.abspath(plugin_dir.strip())
            if not os.path.isdir(full_path):
                _log.warning(f"Invalid plugin path: skipping {full_path}")
                continue
            for root_dir, dirs, files in os.walk(full_path):
                for file in files:
                    if not file.endswith('.conf'):
                        continue
                    plugin_conf_path = os.path.join(root_dir, file)
                    plugin_config = helpers.LEDConfigParser()
                    try:
                        plugin_config.read(plugin_conf_path)
                        plugin_name = plugin_config.get('Core', 'Name')
                        module_name = plugin_config.get('Core', 'Module')
                    except Exception:
                        _log.warning(
                            f"Error loading config: {plugin_conf_path}",
                            exc_info=True
                        )
                        continue
                    module_path_py = f"{os.path.join(root_dir, module_name)}.py"
                    if os.path.isfile(module_path_py):
                        self._plugin_name_to_info[plugin_name] = (
                            module_path_py,
                            plugin_config
                        )
                    else:
                        _log.warning(
                            f"Unable to find module at {module_path_py}",
                            exc_info=True,
                        )
                        continue

    def _plugin_name_checker(self, plugin_name: str, counter: Optional[int] = 0):
        if counter:
            test_name = f"{plugin_name}{counter}"
        else:
            test_name = plugin_name
        if test_name in self._loaded_plugins:
            counter += 1
            test_name = self._plugin_name_checker(plugin_name, counter)

        return test_name

    def load_plugin(self, plugin_name: str, duplicate: Optional[bool] = False):
        plugin_name = plugin_name.strip()
        if plugin_name in self._loaded_plugins:
            if not duplicate:
                return self._loaded_plugins[plugin_name]

        if plugin_name not in self._plugin_name_to_info:
            raise Exception(
                f"Plugin {plugin_name} not found!"
            )
        module_path, plugin_config = self._plugin_name_to_info[plugin_name]
        spec = importlib.util.spec_from_file_location(
            plugin_config.get('Core', 'Module'), module_path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        plugin_classes = inspect.getmembers(
            module,
            predicate=lambda mem: inspect.isclass(mem)
            and issubclass(mem, BasePlugin)
            and mem
            not in [
                BasePlugin,
                HNTRPlugin,
                ConnectorPlugin,
                AnalyzerPlugin,
            ]
            and not inspect.isabstract(mem),
        )
        if len(plugin_classes) == 0:
            raise Exception(
                f"No valid plugin classes found in the module for {plugin_name}"
            )
        if len(plugin_classes) > 1:
            raise Exception(
                f"Multiple plugin classes found in module for {plugin_name}!\n"
                f"{plugin_classes}"
            )
        name, plugin_class = plugin_classes[0]
        # Plugin configuration order of precendence:
        # 1) plugin options provided at instantiation of `LEDHNTR()`
        # 2) plugin configuration in `ledhntr.cfg`
        # 3) `plugin_name.conf`
        if isinstance(
            self._ledhntr_config, helpers.LEDConfigParser
        ) and self._ledhntr_config.has_section(
            plugin_name
        ):
            if not plugin_config.has_section('options'):
                plugin_config.add_section('options')
            for opt in self._ledhntr_config.options(plugin_name):
                plugin_config['options'][opt] = self._ledhntr_config.get(
                    plugin_name, opt
                )
        if self._plugin_opts.get(plugin_name):
            plugin_config.read_dict(
                {'options': self._plugin_opts[plugin_name]}
            )
        plugin = plugin_class(plugin_config, logger=self.logger)
        if not duplicate:
            self._loaded_plugins[plugin_name] = plugin
            return plugin
        # if duplicate is set, then allow the plugin to be loaded more than once
        # subsequent names will appear as ['plugin', 'plugin1', 'plugin2']
        dup_plugin_name = self._plugin_name_checker(plugin_name)
        self._loaded_plugins[dup_plugin_name] = plugin
        return plugin

    def list_plugins(self) -> Dict[str, Dict[str, Any]]:
        valid_classes = [
            'HNTRPlugin',
            'ConnectorPlugin',
            'AnalyzerPlugin',
        ]
        plugins = {}
        for plugin in self._plugin_name_to_info.keys():
            plugin_classes = []
            try:
                with open(self._plugin_name_to_info[plugin][0]) as f:
                    parsed_plugin = ast.parse(f.read())
                classes = [n for n in parsed_plugin.body if isinstance(n, ast.ClassDef)]
                for c in classes:
                    for base in c.bases:
                        if base.id in valid_classes:
                            plugin_classes.append(
                                base.id.replace('Plugin', '')
                            )
            except (UnicodeDecodeError, ValueError):
                plugin_classes = ['UNKNOWN']
            plugins[plugin] = {
                'classes': plugin_classes,
                'version': self._plugin_name_to_info[plugin][1].get(
                    'Documentation', 'version', fallback=''
                ),
                'description': self._plugin_name_to_info[plugin][1].get(
                    'Documentation', 'description', fallback=''
                ),
            }
        return plugins

    def unload_plugin(
        self,
        plugin_name: Optional[Union[List[str],str]] = "",
        all: Optional[bool] = False,
    ) -> None:
        _log = self.logger
        if all:
            if self._loaded_plugins:
                _log.debug(f"Unloaded all plugins!")
            self._loaded_plugins = {}
            return True

        if isinstance(plugin_name, str):
            plugin_name = [plugin_name]

        for pn in plugin_name:
            self._loaded_plugins.pop(pn)
            _log.debug(f"Unloaded plugin {pn}!")
        return True
