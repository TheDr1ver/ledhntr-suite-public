from ledhntr import LEDHNTR
from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

import redis.asyncio as redis
from redis.asyncio.client import Redis

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

class RedisManager:
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis = None

    async def connect(self):
        _log.debug(f"Connecting to {self.redis_url}")
        self.redis = await redis.from_url(self.redis_url)

    async def disconnect(self):
        if self.redis:
            _log.debug(f"Disconnecting redis instance {self.redis}")
            await self.redis.close()

redis_manager = RedisManager(redis_url=redis_url)