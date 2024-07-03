import copy

from ledhntr import LEDHNTR
from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

import redis.asyncio as redis
import redis as syncredis
from pprint import pformat
from redis.asyncio.client import Redis
from rq import Queue, Worker, Connection
from typing import (Optional, Dict, List)

#@##############################################################################
#@ LOGGING TERM COLORS
#@##############################################################################

def xterm(color: str = None):
    color = color.upper()
    colors = {
        "RESET": "\033[0m",
        "RED": "\033[31m",
        "BOLD_RED": "\033[1;31m",
        "GREEN": "\033[32m",
        "BOLD_GREEN": "\033[1;32m",
        "YELLOW": "\033[33m",
        "BOLD_YELLOW": "\033[1;33m",
        "BLUE": "\033[34m",
        "BOLD_BLUE": "\033[1;34m",
        "CYAN": "\033[36m",
        "BOLD_CYAN": "\033[1;36m",
    }
    return colors[color]


#@##############################################################################
#@ LEDHNTR CONFIGS AND LOGGING
#@##############################################################################
# Load LEDHNTR
led = LEDHNTR()
def get_tdb(
    old_plugin: Optional[object] = None,
):
    #~ NOTE - I'm not sure if creating a bunch of database connections is a good idea,
    #~ but I think it's worse if we try reusing the same one for all operations/jobs
    '''
    if 'typedb_client' in led.plugins:
        tdb = led.plugins['typedb_client']
    else:
        tdb = led.load_plugin('typedb_client')
    '''
    tdb = led.load_plugin('typedb_client', duplicate=True)
    ignore_attrs = [
        'client',
        'session',
        'generic_client_counter',
        'log',
        'logger',
        'session',
        'session_timer',
        'tx',
        'tx_timer'
    ]
    if old_plugin:
        for k, v in vars(old_plugin).items():
            if k in ignore_attrs:
                continue
            setattr(tdb, k, v)
        if old_plugin.client and old_plugin.client.is_open():
            old_plugin.close_client()
    return tdb

_log = led.logger

# Set log level
_log.setLevel('DEBUG')

# load config vars
conf = led._ledhntr_config
redis_url = conf['ledapi']['redis_url']

# Organize Schema so we don't have to do it again
def org_schema(led):
    led.all_labels = {
        'thing': [],
        'attribute': [],
        'entity': [],
        'relation': [],
    }
    for ttype in led.schema.keys():
        for thing in led.schema[ttype]:
            if thing['label'] not in led.all_labels:
                led.all_labels['thing'].append(thing['label'])
            if thing['type']=='attribute':
                led.all_labels['attribute'].append(thing['label'])
            elif thing['type']=='entity':
                led.all_labels['entity'].append(thing['label'])
            elif thing['type']=='relation':
                led.all_labels['relation'].append(thing['label'])
    return led

led = org_schema(led)

#@##############################################################################
#@ REDIS MANAGEMENT
#@##############################################################################

class RedisManager(object):
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis = None
        self.syncredis = None

    async def connect(self):
        if not self.redis:
            # // _log.debug(f"Connecting to {self.redis_url}")
            self.redis = await redis.from_url(self.redis_url)
        if not self.syncredis:
            self.syncredis = syncredis.from_url(self.redis_url)

    async def disconnect(self):
        if self.redis:
            _log.debug(f"Disconnecting redis instance {self.redis}")
            await self.redis.close()
            self.redis = None
        if self.syncredis:
            self.syncredis.close()
            self.syncredis = None

    async def check_redis_conn(self):
        if self.redis is None:
            _log.debug(f"[Async] connecting to {self.redis_url}...")
            await self.connect()
        if self.syncredis is None:
            _log.debug(f"[Sync] connecting to {self.redis_url}...")
            await self.connect()

redis_manager = RedisManager(redis_url=redis_url)

#@##############################################################################
#@ WORKER MANAGEMENT
#@##############################################################################
no_plugin_workers = ["maintenance", "slackbot"] # neither of these have LEDHNTR Plugins
class WorkersQueueManager(object):
    def __init__(self):
        self.conf = None
        self.queues = None

    async def parse_value(
        self,
        value
    ):
        if value.lower() in {'true', 'false'}:
            return value.lower() == 'true'
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass

        return value

    #~ Set Conf
    async def load_config(
        self,
        explicit_worker_name: Optional[str] = None,
    ):
        #~ Parse Workers Conf
        if self.conf is None:
            self.conf = {}

        led_plugin_list = led.list_plugins()

        for key in conf['ledapi.workers']:
            #* If we pass an explicit worker_name only focus on loading that conf
            #* Otherwise we're going to just load the worker names.
            if explicit_worker_name is None:
                plugin_name = key.split('.')[0]
                worker_id = key.split('.')[1]
                worker_name = f"{plugin_name}.{worker_id}"
                if worker_name not in self.conf:
                    self.conf[worker_name] = {
                        '_plugin_name': plugin_name,
                        'settings': {},
                    }
                continue
            if explicit_worker_name and not key.startswith(explicit_worker_name):
                continue
            plugin_name = key.split('.')[0]
            #* Don't load plugin for generic workers that don't have an LEDHNTR Plugin
            if plugin_name in no_plugin_workers:
                worker_id = key.split('.')[1]
                worker_name = f"{plugin_name}.{worker_id}"
                self.conf[worker_name] = {
                    '_plugin_name': plugin_name,
                    '_plugin_class': plugin_name,
                    '_plugin': None,
                    'settings': {},
                }
            elif plugin_name not in led_plugin_list.keys():
                _log.debug(f"{plugin_name} is not a valid plugin")
                continue
            worker_name = f"{key.split('.')[0]}.{key.split('.')[1]}"
            if worker_name not in self.conf:
                self.conf[worker_name] = {
                    '_plugin_name': plugin_name,
                    '_worker_id': key.split('.')[1],
                    'settings': {},
                }
            #; Load settings
            if key.startswith(worker_name):
                setting = key.split('.')[2]
                if setting not in self.conf[worker_name]:
                    self.conf[worker_name]['settings'][setting] = await self.parse_value(conf['ledapi.workers'][key])

            details = self.conf[worker_name]
            #; we explicitly set _plugin = None for no_plugin_workers[]
            #; so anything that passes this check is just for
            #. *actual* LEDHNTR Plugins
            if '_plugin' in details:
                continue
            #. Load Plugin modules
            plugin = led.load_plugin(details['_plugin_name'], duplicate=True)
            #. Set plugin attributes based on conf file
            for k, v in details['settings'].items():
                if not hasattr(plugin, k):
                    _log.debug(f"plugin {plugin} has no attribute {k}")
                    continue
                setattr(plugin, k, v)
            #. Reload HNTR APIConf Details
            self.conf[worker_name]['_plugin_class'] = led_plugin_list[details['_plugin_name']]['classes'][0]
            if self.conf[worker_name]['_plugin_class'] == 'HNTR':
                plugin._load_api_configs()

            self.conf[worker_name]['_plugin'] = plugin
        return self.conf
        '''
        #! BREAK BREAK
        #~ if worker_name (e.g. typedb_client.01) is passed, only load those confs
        if worker_name is not None:
            plugin_name = worker_name.split('.')[0]
            if plugin_name in no_plugin_workers:
                self.conf[worker_name] = {
                    '_plugin_name': plugin_name,
                    '_plugin_class': plugin_name,
                    '_plugin': None,
                    'settings': {},
                }
            if worker_name not in self.conf:
                self.conf[worker_name] = {
                    '_plugin_name': plugin_name,
                    '_worker_id': key.split('.')[1],
                    'settings': {},
                }

        #~ Otherwise we're gonna load everything
        else:
            for key in conf['ledapi.workers']:
                plugin_name = key.split('.')[0]
                if plugin_name not in led.list_plugins().keys():
                    # Don't load plugin for generic workers that don't have an LEDHNTR Plugin
                    if plugin_name in no_plugin_workers:
                        worker_id = key.split('.')[1]
                        worker_name = f"{plugin_name}.{worker_id}"
                        self.conf[worker_name] = {
                            '_plugin_name': plugin_name,
                            '_plugin_class': plugin_name,
                            '_plugin': None,
                            'settings': {},
                        }
                        continue
                    _log.debug(f"{plugin_name} is not a valid plugin")
                    continue
                worker_name = f"{key.split('.')[0]}.{key.split('.')[1]}"
                if worker_name not in self.conf:
                    self.conf[worker_name] = {
                        '_plugin_name': plugin_name,
                        '_worker_id': key.split('.')[1],
                        'settings': {},
                    }
                #; Load settings
                if key.startsith(worker_name):
                    setting = key.split('.')[2]
                    if setting not in self.conf[worker_name]:
                        self.conf[worker_name]['settings'][setting] = await self.parse_value(conf['ledapi.workers'][key])

        #~ Get settings for each worker
        safe_dict = copy.deepcopy(self.conf)
        for worker_name, details in safe_dict.items():
            for key in conf['ledapi.workers']:
                if key.startswith(worker_name):
                    # _log.debug(f"Splitting key {key} into {key.split('.')}")
                    setting = key.split('.')[2]
                    if setting not in self.conf[worker_name]:
                        self.conf[worker_name]['settings'][setting] = await self.parse_value(conf['ledapi.workers'][key])

        #~ Load Plugin Modules For Each Worker
        safe_dict = copy.deepcopy(self.conf)
        for worker_name, details in safe_dict.items():
            # self.conf[worker_name]['_plugin'] = led.load_plugin(details['_plugin_name'], duplicate=True)
            if not '_plugin' in details: #; we explicitly set _plugin = None for maintenance
                plugin = led.load_plugin(details['_plugin_name'], duplicate=True)
                for k, v in details['settings'].items():
                    if not hasattr(plugin, k):
                        _log.debug(f"plugin {plugin} has no attribute {k}")
                        continue
                    #! FFS STOP DOING THIS!!! plugin.k = v
                    setattr(plugin, k, v)
                    # // _log.debug(f"Set {worker_name} {plugin}.{k} to {v}")
                    # // _log.debug(f"{RED}CONFIRMED{RESET}: k: {k} v: {plugin.k}")
                #* Reload API Configs
                led_plugin_list = led.list_plugins()
                self.conf[worker_name]['_plugin_class'] = led_plugin_list[details['_plugin_name']]['classes'][0]
                if self.conf[worker_name]['_plugin_class'] == 'HNTR':
                    plugin._load_api_configs()

                self.conf[worker_name]['_plugin'] = plugin
        '''

    async def test_confs(
        self,
    ):
        #~ Test results of changed settings
        for worker_name, details in self.conf.items():
            _log.debug(f"{xterm('GREEN')}{worker_name} - {details['_plugin_name']}{xterm('RESET')}")
            # _log.debug(f"{pformat(details['_plugin'].config.dumpall())}")
            for name, value in vars(details['_plugin']).items():
                _log.debug(f"{xterm('GREEN')}{name}{xterm('RESET')}:{xterm('RED')}{value}{xterm('RESET')}")
            for endpoint, ac in details['_plugin'].api_confs.items():
                _log.debug(f"{xterm('YELLOW')}{endpoint}{xterm('RESET')}")
                _log.debug(f"{pformat(ac.to_dict())}")
            _log.debug(f"{xterm('CYAN')}plugin.key: {details['_plugin'].key}{xterm('RESET')}")

    #~ Define Queues
    async def load_queues(
        self,
    ):
        await redis_manager.check_redis_conn()
        init_queues = []
        for worker_name, details in self.conf.items():
            #* Each plugin should have a single queue, regardless of how many workers
            #* are able to process it. That way if you have 2 Shodan accounts with
            #* separate rate limits they can both execute from the same queue.
            queue_name = details['_plugin_name']
            queue = Queue(queue_name, connection=redis_manager.syncredis)
            self.conf[worker_name]['queue'] = queue
            if queue not in init_queues:
                init_queues.append(queue)

        #& TODO - Add endpoints for add/enable/disable/modify hunt
        #&
        #& TODO - Add a few AutoHunter Analyzer workers to handle things like
        #& - Running hunts
        #& - Checking enrichments
        #& - Doing DB clean-up operations
        #& - Disabling "dead" hunts
        #& - Giving summaries of the day's jobs successes/failures
        #&
        #& TODO - Finally Need to write the Slack bot plugin to get to MVP

        _log.debug(f"init worker_queues: {pformat(init_queues)}")

    async def check_config(
        self,
        worker_name: Optional[str] = None,
    ):
        if self.conf is None:
            await self.load_config(worker_name)
            # _log.debug(f"{CYAN}TESTING OUTSIDE load_config(){RESET}")
            # await self.test_confs()
            await self.load_queues()

wqm = WorkersQueueManager()
# _log.debug(f"wqm: {pformat(wqm.conf)}")#