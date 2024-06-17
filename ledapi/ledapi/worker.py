import argparse

# from config import RedisManager
import redis
from rq import Queue, Worker, Connection
from rq.registry import StartedJobRegistry
from datetime import timedelta

from ledhntr import LEDHNTR
led = LEDHNTR()

redis_url = "redis://192.168.70.10/1"
# redis_jq = RedisManager(redis_url=redis_url)

'''
class RedisJobQueueManager(redis.Redis):
    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis = None
    def connect(self):
        self.redis = redis.from_url(self.redis_url)
    def disconnect(self):
        if self.redis:
            self.redis.close()

redis_jq = RedisJobQueueManager(redis_url=redis_url)
'''
redis_jq = redis.from_url(redis_url)

def main(args: argparse.ArgumentParser = None):
    # redis_jq.connect()
    '''
    queues = {
        "censys": Queue('censys', connection=redis_jq),
        "shodan": Queue('shodan', connection=redis_jq)
    }
    '''
    hntr_plugins = []
    for plugin_name, info in led.list_plugins().items():
        if 'HNTR' in info['classes'] and plugin_name not in hntr_plugins:
            hntr_plugins.append(plugin_name)
    queues = {}
    for plugin in hntr_plugins:
        queues[plugin] = Queue(plugin, connection=redis_jq)

    def get_worker(worker_name):
        return Worker([queues[worker_name]], connection=redis_jq)

    worker_name = args.plugin
    registry = StartedJobRegistry(queue=queues[worker_name])
    if len(registry.get_job_ids()) == 0:
        worker = get_worker(worker_name)
        worker.work()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--plugin", help="plugin to name worker")
    args = parser.parse_args()
    main(args)