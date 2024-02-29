#!/usr/bin/env python3

import os
import sys
import logging
import requests
import subprocess
from tempfile import NamedTemporaryFile

_log = logging.getLogger()


class LEDHNTRPluginInstaller:

    DEFAULT_REPO = 'git+https://github.com/TheDr1ver/ledhntr-plugins-public.git'

    @staticmethod
    def install(
        plugin_path: str, install_dir: str, upgrade: bool, github: bool
    ) -> None:
        if github:
            if plugin_path.startswith('git+http'):
                pass
            elif plugin_path.startswith('ledhntr:'):
                plugin_name = plugin_path.split(':')[1]
                plugin_path = f'{LEDHNTRPluginInstaller.DEFAULT_REPO}#egg={plugin_name}&subdirectory={plugin_name}'
            else:
                _log.error(f'Invalid Github repository specified. {plugin_path}')
                raise
        else:
            plugin_path = os.path.abspath(plugin_path)
            if not os.path.isdir(plugin_path):
                _log.error(
                    f'Given plugin directory does not exist: {plugin_path}'
                )
                raise
        install_dir = os.path.abspath(install_dir)
        if not os.path.isdir(install_dir):
            _log.error(
                f'Given install directory does not exist: {install_dir}'
            )
            raise
        LEDHNTRPluginInstaller.setup_package(plugin_path, install_dir, upgrade, github)

    @staticmethod
    def setup_package(
        plugin_path: str, install_dir: str, upgrade: bool, github: bool
    ) -> None:
        if github:
            url = (
                plugin_path.split('+')[1]
                .split('#')[0]
                .replace('.git', '')
                .replace('github.com', 'raw.githubusercontent.com')
                .replace('@', '/')
            )
            path = plugin_path.split('subdirectory=')[1]
            requirements = f'{url}/{path}/requirements.txt'
            with NamedTemporaryFile() as temp_file:
                response = requests.get(requirements)
                if response.status_code == 200:
                    temp_file.write(response.content)
                    temp_file.flush()
                    subprocess.check_call(
                        [
                            sys.executable,
                            '-m',
                            'pip',
                            'install',
                            '--quiet',
                            '-r',
                            temp_file.name,
                        ]
                    )
                elif response.status_code == 404:
                    pass
                else:
                    _log.info(f'Failed to install requirements from {requirements}')
        else:
            requirements = f'{plugin_path}/requirements.txt'
            if os.path.isfile(requirements):
                subprocess.check_call(
                    [
                        sys.executable,
                        '-m',
                        'pip',
                        'install',
                        '--quiet',
                        '-r',
                        requirements,
                    ]
                )

        cmd = [sys.executable, '-m', 'pip', 'install', plugin_path, '-t', install_dir]
        if upgrade:
            cmd.append('--upgrade')
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            if f'WARNING: Target directory {install_dir}' in output.decode():
                _log.error(
                    f'Plugin ({plugin_path}) already exists in {install_dir}'
                )
                raise
        except subprocess.CalledProcessError as err:
            if not os.getenv('VIRTUAL_ENV'):
                _log.error(
                    '[!!] Plugin install failed. Are you root or in a virtual environment?\n'
                )
            _log.error(err.output)
            raise