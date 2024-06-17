"""Hunting Process
This is for executing hunting jobs, adding the results, and handling caching.
Logic goes as follows:
- Each plugin only has one worker (this keeps API rate limits in check).
- Each worker has its own job queue.
- A job contains a database name, a status (pending|hunting|enriching|complete),
    a submitter (user), a boolean "forced" flag, a time submitted, and a time completed. 
    These jobs are stored in Redis with a 7-day expiration time.

- For each job, gather active hunts from that DB. For each hunt:
    - Check existing cache to use if "force" isn't set
    - Change job status to "hunting"
    - If cache expired or "force" set, run it and cache the results to disk
    - Write the parsed results to the database
    - Change job status to "enriching"
    - Repeat for "enrichments"
    - Change job status to "complete"
"""
#! Pick this up later. It's probably a step in the right direction, but I'm out
#! of time and don't want to mess with it too much until I can debug it.
'''
import redis
from rq import Queue, Worker, Connection
from rq.registry import StartedJobRegistry
from datetime import datetime, timedelta, UTC
import time

from ledapi.config import redis_jq, _log

# TODO - replace this with an entry in ledhntr.cfg
hntr_plugins = ['censys', 'shodan']

job_queues = {}
for plugin in hntr_plugins:
    job_queues[plugin.lower()] = Queue(plugin.lower(), connection=redis_jq)

def get_worker(worker_name):
    return Worker([job_queues[worker_name]], connection=redis_jq)

for plugin in hntr_plugins:
    registry = StartedJobRegistry(queue=job_queues[plugin.lower()])
    if len(registry.get_job_ids()) == 0:
        worker = get_worker(plugin.lower())
        worker.work()

def process_job(target_db, worker_name, user_id, forced):
    start_time = datetime.now(UTC)
    _log.debug(f"Starting job with worker {worker_name}")
    time.sleep(5)
    end_time = datetime.now(UTC)
    return {
        "start_time": start_time,
        "end_time": end_time,
        "worker_name": worker_name,
        "target_db": target_db,
        "user_id": user_id,
        "forced": forced,
        "status": "complete",
    }
'''