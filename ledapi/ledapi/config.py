import copy

from ledhntr import LEDHNTR
from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

import redis.asyncio as redis
import redis as syncredis
from pprint import pformat
from redis.asyncio.client import Redis
from rq import Queue, Worker, Connection
from typing import (Optional, Dict, List)

RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
BOLD_RED = "\033[1;31m"

#@##############################################################################
#@ LEDHNTR CONFIGS AND LOGGING
#@##############################################################################
# Load LEDHNTR
led = LEDHNTR()
def get_tdb():
    #~ NOTE - I'm not sure if creating a bunch of database connections is a good idea,
    #~ but I think it's worse if we try reusing the same one for all operations/jobs
    '''
    if 'typedb_client' in led.plugins:
        tdb = led.plugins['typedb_client']
    else:
        tdb = led.load_plugin('typedb_client')
    '''
    tdb = led.load_plugin('typedb_client', duplicate=True)
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
            _log.debug(f"Connecting to {self.redis_url}")
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
            _log.debug(f"Async Redis not started, connecting...")
            await self.connect()
        if self.syncredis is None:
            _log.debug(f"Synchronous Redis not started, connecting...")
            await self.connect()

redis_manager = RedisManager(redis_url=redis_url)

#@##############################################################################
#@ WORKER MANAGEMENT
#@##############################################################################

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
    ):
        #~ Parse Workers Conf
        if self.conf is None:
            self.conf = {}
        #~ Get plugin names and worker names
        for key in conf['ledapi.workers']:
            plugin_name = key.split('.')[0]
            if plugin_name not in led.list_plugins().keys():
                _log.debug(f"{plugin_name} is not a valid plugin")
                continue
            worker_name = f"{key.split('.')[0]}.{key.split('.')[1]}"
            if worker_name not in self.conf:
                self.conf[worker_name] = {
                    '_plugin_name': plugin_name,
                    '_worker_id': key.split('.')[1],
                    'settings': {},
                }

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

    async def test_confs(
        self,
    ):
        #~ Test results of changed settings
        for worker_name, details in self.conf.items():
            _log.debug(f"{GREEN}{worker_name} - {details['_plugin_name']}{RESET}")
            # _log.debug(f"{pformat(details['_plugin'].config.dumpall())}")
            for name, value in vars(details['_plugin']).items():
                _log.debug(f"{GREEN}{name}{RESET}:{RED}{value}{RESET}")
            for endpoint, ac in details['_plugin'].api_confs.items():
                _log.debug(f"{YELLOW}{endpoint}{RESET}")
                _log.debug(f"{pformat(ac.to_dict())}")
            _log.debug(f"{CYAN}plugin.key: {details['_plugin'].key}{RESET}")

    #~ Define Queues
    '''
    async def load_queues(
        self, 
        worker_name: Optional[str] = None,
    ):
        await redis_manager.check_redis_conn()
        #* If we're explicitly passing a worker name, it means we want to create
        #* a single dedicated queue for that explicit worker if it's a HNTR worker
        #* because each set of credentials has its own rate limit.
        #* However, if it's a Connector or Analyzer worker, we don't have to worry
        #* about rate limits and can share a single queue across multiple workers/processes
        if not worker_name is None:
            if self.conf[worker_name]['_plugin_class'] != 'HNTR':
                #* If it's not a hunter we just want one queue shared with all workers of that type
                
                queue_name = self.conf[worker_name]['_plugin_name']
                _log.debug(f"{worker_name} is not a HNTR worker. Changing queue name to {queue_name}.")
            else:
                #* Otherwise, we want a specific queue for each unique hunter worker_name
                #* so we'll leave queue_name as-is.
                queue_name = worker_name
            self.queues = {worker_name: Queue(queue_name, connection=redis_manager.syncredis)}
        else:
            # self.queues = {worker_name: Queue(worker_name, connection=redis_manager.syncredis) for worker_name in self.conf.keys()}
            #* If we're not passing a worker name that means we want to load all queues
            #* for the main process.
            self.queues = {}
            for worker_name, details in self.conf.items():
                if details['_plugin_class'] != 'HNTR':
                    queue_name = details['_plugin_name']
                else:
                    queue_name = worker_name
                self.queues[worker_name] = Queue(queue_name, connection=redis_manager.syncredis)

        _log.debug(f"init worker_queues: {self.queues}")
    '''
    async def load_queues(
        self,
    ):
        await redis_manager.check_redis_conn()
        for worker_name, details in self.conf.items():
            if details['_plugin_class'] != 'HNTR':
                #* If it's not a hunter we just want one queue shared with all workers of that type
                queue_name = details['_plugin_name']
            else:
                #* Otherwise, we want a specific queue for each unique hunter worker_name
                #* so we'll leave queue_name as-is.
                queue_name = worker_name
            # self.queues[worker_name] = Queue(queue_name, connection=redis_manager.syncredis)
            self.conf[worker_name]['queue'] = Queue(queue_name, connection=redis_manager.syncredis)

        _log.debug(f"init worker_queues: {self.queues}")

    async def check_config(
        self,
    ):
        if self.conf is None:
            await self.load_config()
            # _log.debug(f"{CYAN}TESTING OUTSIDE load_config(){RESET}")
            # await self.test_confs()
            await self.load_queues()

    '''
    async def check_queues(
        self,
        worker_name: Optional[str] = None
    ):
        await self.check_config()
        if self.queues is None:
            await self.load_queues(worker_name)
    '''

wqm = WorkersQueueManager()
# _log.debug(f"wqm: {pformat(wqm.conf)}")