import asyncio
import traceback

from datetime import datetime, timedelta, timezone
from multiprocessing import Process, Manager
from pprint import pformat

import psutil
import redis as syncredis
from redis.asyncio.client import Redis
from rq import Queue, Worker, Connection
from rq.registry import (
    FailedJobRegistry,
    FinishedJobRegistry,
    ScheduledJobRegistry,
    StartedJobRegistry,
)

from ledapi.config import(
    _log,
    conf,
    redis_manager,
    wqm,
)

#@##############################################################################
#@ WORKER MANAGEMENT
#@##############################################################################

#&#######################
#& INTERNAL FUNCTIONS
#&#######################

def init_manager():
    global worker_processes
    worker_processes = Manager().dict()

async def set_worker_status(worker_name, worker_id, status):
    # await redis_manager.redis.set(f"worker_status:{worker_name}:{worker_id}", status, ex=60*60*24*7)
    await redis_manager.check_redis_conn()
    await redis_manager.redis.set(f"rq:worker:{worker_name}", status, ex=60*60*24*7)

async def clear_worker_status(worker_name):
    # await redis_manager.redis.delete(f"worker_status:{worker_name}:{worker_id}")
    await redis_manager.check_redis_conn()
    await redis_manager.redis.delete(f"rq:worker:{worker_name}")

async def get_worker(worker_name):
    running_worker = None
    await redis_manager.check_redis_conn()
    all_workers = Worker.all(connection=redis_manager.syncredis)
    if not all_workers:
        _log.debug(f"NO WORKERS CURRENTLY STARTED")
    for worker in all_workers:
        _log.debug(f"WORKER.NAME: {worker.name} ||| worker_name: {worker_name}")
        if worker.name == worker_name:
            return worker
        _log.debug(f"NOT A MATCH")

    _log.debug(f"No worker {worker_name} found!")
    return running_worker

async def async_worker_process(worker_name):
    _log.debug(f"Connecting to Redis for worker {worker_name}")
    await redis_manager.check_redis_conn()
    redis_sync_client = redis_manager.syncredis

    # Check worker queues
    _log.debug(f"Checking worker queues...")
    # await wqm.check_queues(worker_name)
    await wqm.check_config()
    loaded_queues = [details['queue'] for _, details in wqm.conf.items()]
    _log.debug(f"Queues: {loaded_queues}")

    # Check for existing workers
    _log.debug(f"Checking for existing workers {worker_name}...")
    worker = await get_worker(worker_name)
    if worker:
        _log.debug(f"FOUND EXISTING WORKER {worker_name}")
        #@ await worker.work()
        try:
            await worker.work()
        except ValueError as e:
            _log.info(f"Attempted to start Worker {worker_name} which is already running: {e}")
            pass
        return worker

    _log.debug(f"No existing workers found. Starting new process.")
    # with Connection(redis_pool.sync_client):
    with Connection(redis_sync_client):
        '''
        #* If it's not a HNTR class it shouldn't have rate-limiting we need to 
        #* worry about, so it's better for multiple workers to share a single queue.
        #* If it is a HNTR class we'll want a unique queue per worker to abide by
        #* rate limits for each account.
        if wqm.conf[worker_name]['_plugin_class'] != 'HNTR':
            queue_name = wqm.conf[worker_name]['_plugin_name']
        else:
            queue_name = worker_name
        '''
        _log.debug(f"Starting worker {worker_name}")
        # worker = Worker([wqm.queues[worker_name]], name=f"{worker_name}")
        worker = Worker([wqm.conf[worker_name]['queue']], name=worker_name)
        _log.debug(f"worker: {worker} (if shutting down this might be boolean)")
        await worker.work()

def worker_process(worker_name):
    try:
        asyncio.run(async_worker_process(worker_name))
    except Exception as e:
        _log.error(f"Failed to run async worker process {worker_name}: {e}")
        _log.error(f"Traceback: {traceback.format_exc()}")


async def start_worker(worker_name):
    _log.debug(f"Starting worker {worker_name}...")
    if await get_worker(worker_name):
        if worker_name not in worker_processes:
            _log.debug(f"Found running worker {worker_name} in Redis that wasn't in processes.")
            _log.debug(f"Adding worker {worker_name} to running processes...")
            process = Process(target=worker_process, args=(worker_name,))
            process.start()
            worker_processes[worker_name] = process.pid
            msg = f"Existing Worker {worker_name} started new process."
            _log.debug(msg)
            return msg

    _log.debug(f"Starting new process: {worker_name}")
    # process = Process(target=partial(worker_process, worker_name, worker_id))
    process = Process(target=worker_process, args=(worker_name,))
    process.start()
    # worker_processes[worker_name] = process
    worker_processes[worker_name] = process.pid
    msg = f"New Worker {worker_name} started and added to redis."
    _log.debug(msg)
    return msg

async def stop_worker(worker_name):
    _log.debug(worker_processes)
    pid = worker_processes.get(worker_name)
    if pid is not None:
        try:
            process = psutil.Process(pid)
            # process.terminate() # Or process.kill() if you want to forcefully kill the process
            process.kill()
            process.wait() # Wait for the process to terminate
            del worker_processes[worker_name]
            await clear_worker_status(worker_name)
            msg = f"Worker {worker_name} stopped."
            _log.debug(msg)
            return msg
        except psutil.NoSuchProcess:
            msg = "No such process with PID {pid}"
            _log.error(msg)
    else:
        msg = f"No running worker found with name {worker_name}.\n"
        msg += f"worker_processes: {worker_processes}"
        _log.debug(msg)
        _log.debug(f"Clearing {worker_name} anyway to make sure redis is clear")
        #! NOTE - This is probably a bad idea if I want to have the hunt queue persist
        #! after the app is restarted or crashes
        await clear_worker_status(worker_name)
    await redis_manager.disconnect()
    return msg

async def get_worker_status(worker_name):
    if await get_worker(worker_name):
        msg = f"Worker {worker_name} is running."
        _log.debug(msg)
        return msg
    msg = f"Worker {worker_name} is not running."
    _log.debug(msg)
    return msg

async def start_all_workers():
    # _log.debug(f"Initializing Multiprocess manager")
    if not "worker_processes" in globals():
        init_manager()
    # _log.debug(f"Loading Worker Queues...")
    # await wqm.check_queues()
    await wqm.check_config()
    _log.debug(f"Starting all workers...")
    responses = {}
    # for worker_name in wqm.queues.keys():
    for worker_name in wqm.conf.keys():
        _log.debug(f"Looping through {worker_name}...")
        responses[f"{worker_name}"] = await start_worker(worker_name)
    responses['worker_processes'] = pformat(worker_processes.items())
    _log.debug(responses)
    return responses

async def stop_all_workers():
    responses = {}
    # for worker_name in wqm.queues.keys():
    for worker_name in wqm.conf.keys():
        responses[f"{worker_name}"] = await stop_worker(worker_name)
    _log.debug(responses)
    return responses



#&###########################
#& API ENDPOINT FUNCTIONS
#&###########################

'''
async def get_all_workers(with_jobs: bool = False):
    await redis_manager.check_redis_conn()
    workers = []
    _log.debug(f"first wqm.queues: {pformat(wqm.queues)}")
    for worker_name, queue in wqm.queues.items():
        _log.debug(f"queue_name: {queue_name}, queue: {queue}")
        job_ids = []
        if with_jobs:
            failed_registry = FailedJobRegistry(queue_name, connection=redis_manager.syncredis)
            fin_registry = FinishedJobRegistry(queue_name, connection=redis_manager.syncredis)
            sched_registry = ScheduledJobRegistry(queue_name, connection=redis_manager.syncredis)
            start_registry = StartedJobRegistry(queue_name, connection=redis_manager.syncredis)

            job_ids += failed_registry.get_job_ids()
            job_ids += fin_registry.get_job_ids()
            job_ids += sched_registry.get_job_ids()
            # job_ids = sched_registry.get_job_ids()
            job_ids += start_registry.get_job_ids()

        for worker in Worker.all(connection=redis_manager.syncredis):
            _log.debug(f"queue_name: {queue_name} worker.queues: {worker.queues}")
            if queue_name in [q.name for q in worker.queues]:
                jobs = []
                for job_id in job_ids:
                    job = queue.fetch_job(job_id)
                    if job:
                        jobs.append({
                            'id': job.id,
                            'status': job.get_status(),
                            'description': job.description,
                            'enqueued_at': job.enqueued_at,
                            'started_at': job.started_at,
                            'ended_at': job.ended_at,
                            'result': job.result,
                        })

                workers.append({
                    'name': worker.name,
                    'all_keys': worker.all_keys,
                    'redis_key': worker.key,
                    'queues': [q.name for q in worker.queues],
                    'state': worker.get_state(),
                    'current_job_id': worker.get_current_job_id(),
                    'jobs': jobs,
                })
    return workers
'''
async def get_all_workers(with_jobs: bool = False):
    await redis_manager.check_redis_conn()
    workers = []
    for worker_name, details in wqm.conf.items():
        queue = details['queue']
        _log.debug(f"worker_name: {worker_name}, queue_name: {queue.name}, queue: {queue}")
        job_ids = []
        if with_jobs:
            failed_registry = FailedJobRegistry(queue.name, connection=redis_manager.syncredis)
            fin_registry = FinishedJobRegistry(queue.name, connection=redis_manager.syncredis)
            sched_registry = ScheduledJobRegistry(queue.name, connection=redis_manager.syncredis)
            start_registry = StartedJobRegistry(queue.name, connection=redis_manager.syncredis)

            job_ids += failed_registry.get_job_ids()
            job_ids += fin_registry.get_job_ids()
            job_ids += sched_registry.get_job_ids()
            # job_ids = sched_registry.get_job_ids()
            job_ids += start_registry.get_job_ids()

        for worker in Worker.all(queue=queue, connection=redis_manager.syncredis):
            if worker.name != worker_name:
                continue
            _log.debug(f"queue_name: {queue.name} worker.queues: {worker.queues}")
            #! if queue_name in [q.name for q in worker.queues]:
            jobs = []
            for job_id in job_ids:
                job = queue.fetch_job(job_id)
                if job:
                    jobs.append({
                        'id': job.id,
                        'status': job.get_status(),
                        'description': job.description,
                        'enqueued_at': job.enqueued_at,
                        'started_at': job.started_at,
                        'ended_at': job.ended_at,
                        'result': job.result,
                    })

            workers.append({
                'name': worker.name,
                'all_keys': worker.all_keys,
                'redis_key': worker.key,
                'queues': [q.name for q in worker.queues],
                'state': worker.get_state(),
                'current_job_id': worker.get_current_job_id(),
                'jobs': jobs,
            })
    return workers

async def restart_all_workers():
    responses = {}
    stop_resp = await stop_all_workers()
    responses['stop_responses'] = stop_resp
    start_resp = await start_all_workers()
    responses['start_responses'] = start_resp
    _log.debug(responses)
    return responses

#@##############################################################################
#@ JOB MANAGEMENT
#@##############################################################################

#&###########################
#& API ENDPOINT FUNCTIONS
#&###########################

async def poll_job(job_id):
    _log.debug(f"Polling job_id {job_id}")
    # await wqm.check_queues()
    await wqm.check_config()
    await redis_manager.check_redis_conn()
    job_details = None
    # for queue_name, queue in wqm.queues.items():
    for worker_name, details in wqm.conf.items():
        queue = details['queue']
        queue_name = queue.name
        for worker in Worker.all(queue=details['queue'], connection=redis_manager.syncredis):
            if queue_name in [q.name for q in worker.queues]:
                job = queue.fetch_job(job_id)
                if job:
                    job_details = {
                        'worker_name': worker.name,
                        'job_id': job.id,
                        'status': job.get_status(),
                        'description': job.description,
                        'enqueued_at': job.enqueued_at,
                        'started_at': job.started_at,
                        'ended_at': job.ended_at,
                        'result': job.result,
                    }
                    return job_details
    _log.debug(f"No job details found for: {job_id}")
    return False

async def cleanup_jobs():
    # TODO - I don't think this actually is working as intended.
    # await wqm.check_queues()
    await wqm.check_config()
    await redis_manager.check_redis_conn()
    queues = []
    # for queue_name, queue in wqm.queues.items():
    for worker_name, details in wqm.conf.items():
        queue = details['queue']
        queue_name = details['queue'].name
        fin_reg = FinishedJobRegistry(queue_name, connection=redis_manager.syncredis)
        fail_reg = FailedJobRegistry(queue_name, connection=redis_manager.syncredis)

        # Delete jobs older than 24 hrs
        now = int(datetime.now(timezone.utc).timestamp())
        yesterday = now-60*60*24
        # fin_reg.cleanup(timestamp=yesterday)
        # fail_reg.cleanup(timestamp=yesterday)
        fin_reg.cleanup()
        fail_reg.cleanup()
        queues.append(queue_name)

    return f"Cleaned finished and failed registries for {queues} that were older than 24 hrs."