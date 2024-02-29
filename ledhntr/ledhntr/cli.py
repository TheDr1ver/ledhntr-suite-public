#!/usr/bin/env python3

import os
import sys
import select
import argparse
from pathlib import Path
from typing import Dict, Union

from ledhntr.installer import LEDHNTRPluginInstaller
from ledhntr import LEDHNTR, __version__

def main() -> None:
    about = f"LEDHNTR V{__version__}"
    # If $HOME/.ledhntr doesn't exist, create it
    Path(f"{str(Path.home())}/.ledhntr/plugins").mkdir(parents=True, exist_ok=True)
    # If $LEDHNTR_HOME exists, set base dir to that, otherwise use $HOME/.ledhntr
    try:
        led_home = str(
            Path(os.getenv('LEDHNTR_HOME', f"{str(Path.home())}/.ledhntr")).resolve(
                strict=True
            )
        )
    except FileNotFoundError as err:
        print(f"$LEDHNTR_HOME is invalid: {err}", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=about,
        epilog='''
Examples:

    - Install a plugin from a directory

    $ %(prog)s install path/to/plugin_directory

    - Install a plugin from github

    $ %(prog)s install --github ledhntr:PLUGIN_NAME
    ''',
    )
    subparsers = parser.add_subparsers(title='commands', dest='command')
    subparsers.required = True

    plugin_list = subparsers.add_parser('list', help='List available plugins')
    plugin_list.add_argument(
        '--plugin-dir', nargs='+', help='Directory(ies) containing LEDHNTR plugins'
    )

    install = subparsers.add_parser('install', help='Install a given plugin')
    install.add_argument(
        'plugin_path', help='Directory or Github repo of the plugin to install'
    )
    install.add_argument(
        '--install_dir',
        default=os.path.join(led_home, 'plugins'),
        help='Override the default plugin installation directory',
    )
    install.add_argument(
        '--upgrade',
        action='store_true',
        help='Force the plugin to be upgraded if it already exists',
    )
    install.add_argument(
        '--github',
        action='store_true',
        help='Install plugin from GitHub repository',
    )
    args = parser.parse_args()

    if args.command == 'list':
        led = LEDHNTR(base_dir=led_home, plugin_dir_list=args.plugin_dir)
        print(about)
        print('-' * len(about))
        for name, info in led.list_plugins().items():
            print(f'{name:<20s} v{info["version"]:<10s}{info["description"]}')
            print(f'\t\t\t\t- {", ".join(info["classes"]):<20s}')

    elif args.command == 'install':
        LEDHNTRPluginInstaller.install(
            args.plugin_path, args.install_dir, args.upgrade, args.github,
        )
        print(f"Finished installing {args.plugin_path} into {args.install_dir}")

if __name__ == '__main__':
    main()