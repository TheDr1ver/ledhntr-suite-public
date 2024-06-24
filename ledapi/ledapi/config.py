from ledhntr import LEDHNTR
from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

import redis.asyncio as redis
import redis as syncredis
from redis.asyncio.client import Redis
from rq import Queue, Worker, Connection
from typing import (Optional, Dict, List)


#@##############################################################################
#@ LEDHNTR CONFIGS AND LOGGING
#@##############################################################################
# Load LEDHNTR
led = LEDHNTR()
def get_tdb():
    if 'typedb_client' in led.plugins:
        tdb = led.plugins['typedb_client']
    else:
        tdb = led.load_plugin('typedb_client')
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
        #~ Parse Workers Conf
        self.conf = {}
        for key in conf['ledapi.workers']:
            if key.endswith('.threshold'):
                plugin_name = key.split('.')[0]
                threshold = int(conf['ledapi.workers'][key])
                self.conf[plugin_name] = {'threshold': threshold}
        # TODO - Eventually we'll want to load alternate keys/secrets from each of the plugins.
        # TODO - This way we could have multiple accounts per plugin to increase throughput.
        # TODO - For right now though I'm sticking with one worker per plugin just to get
        # TODO - something out the door.
        self.queues = None

    #~ Define Queues
    async def load_queues(
        self, 
        worker_name: Optional[str] = None,
    ):
        await redis_manager.check_redis_conn()
        if not worker_name is None:
            self.queues = {worker_name: Queue(worker_name, connection=redis_manager.syncredis)}
        else:
            self.queues = {worker_name: Queue(worker_name, connection=redis_manager.syncredis) for worker_name in self.conf}
        _log.debug(f"init worker_queues: {self.queues}")

    async def check_queues(
        self,
        worker_name: Optional[str] = None
    ):
        if self.queues is None:
            await self.load_queues(worker_name)

wqm = WorkersQueueManager()