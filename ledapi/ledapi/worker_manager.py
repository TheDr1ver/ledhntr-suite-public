import asyncio
import threading
import os
import time
import traceback

from datetime import datetime, timedelta, timezone
from multiprocessing import Process, Manager
from pprint import pformat

from fastapi import BackgroundTasks
import psutil
import redis as syncredis
from redis.asyncio.client import Redis
from rq import Queue, Worker, Connection
from rq.job import Job
from rq.registry import (
    FailedJobRegistry,
    FinishedJobRegistry,
    ScheduledJobRegistry,
    StartedJobRegistry,
    DeferredJobRegistry,
)
from rq_scheduler import Scheduler
# from rq_scheduler import Scheduler
from typing import(
    Dict,
    List,
    Optional,
    Union,
)
from ledhntr.helpers import dumps
from ledapi.config import(
    _log,
    conf,
    redis_manager,
    wqm,
    xterm,
)

#@##############################################################################
#@ WORKER MANAGEMENT
#@##############################################################################

#&#######################
#& INTERNAL FUNCTIONS
#&#######################

def log_spawn(func):
    def wrapper(*args, **kwargs):
        _log.info(f"{xterm('YELLOW')}Spawning pocess for function: {func.__name__}{xterm('RESET')}")
        return func(*args, **kwargs)
    return wrapper

def init_manager():
    global worker_processes
    worker_processes = Manager().dict()

async def set_worker_status(worker_name, worker_id, status):
    await redis_manager.check_redis_conn()
    await redis_manager.redis.set(f"rq:worker:{worker_name}", status, ex=60*60*24*7)

async def clear_worker_status(worker_name):
    await redis_manager.check_redis_conn()
    await redis_manager.redis.delete(f"rq:worker:{worker_name}")

async def get_worker(worker_name):
    running_worker = None
    await redis_manager.check_redis_conn()
    all_workers = Worker.all(connection=redis_manager.syncredis)

    for worker in all_workers:
        if worker.name == worker_name:
            return worker

    _log.debug(f"No worker {worker_name} found!")
    return running_worker

async def async_worker_process(worker_name):
    _log.debug(f"Connecting to Redis for worker {worker_name}")
    await redis_manager.check_redis_conn()
    redis_sync_client = redis_manager.syncredis

    # Check worker queues
    await wqm.check_config(worker_name)

    # Check for existing workers
    worker = await get_worker(worker_name)
    if worker:
        _log.debug(f"FOUND EXISTING WORKER {worker_name}")
        try:
            await worker.work()
        except ValueError as e:
            _log.info(f"Attempted to start Worker {worker_name} which is already running: {e}")
            pass
        return worker

    _log.debug(f"Worker {worker_name} not found. Starting new process.")
    with Connection(redis_sync_client):
        worker = Worker([wqm.conf[worker_name]['queue']], name=worker_name)
        _log.debug(f"WORKER STATE: {worker.state}")
        await worker.work()

def worker_process(worker_name):
    try:
        asyncio.run(async_worker_process(worker_name))
    except Exception as e:
        _log.error(f"Failed to run async worker process {worker_name}: {e}")
        _log.error(f"Traceback: {traceback.format_exc()}")

@log_spawn
async def start_worker(worker_name):
    if await get_worker(worker_name):
        if worker_name not in worker_processes:
            process = Process(target=worker_process, args=(worker_name,))
            process.start()
            worker_processes[worker_name] = process.pid
            msg = f"New PID for pre-existing {worker_name}: {process.pid}."
            _log.debug(msg)
            return msg

    process = Process(target=worker_process, args=(worker_name,))
    process.start()
    worker_processes[worker_name] = process.pid
    msg = f"New Worker {worker_name} started: {process.pid}"
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

async def get_available_worker(
    plugin_name: str = None,
)->str:
    """Get Available Workers Based on job_data['plugin']
    #! NOTE - THIS IS BASICALLY USELESS BECAUSE IT DOESN'T MEAN WE'RE ACTUALLY
    #! TELLING RQ WHICH WORKER TO USE. WHATEVER WORKER IS AVAILABLE IS THE WORKER
    #! THAT'S GOING TO PICK UP THE NEXT JOB.
    #! ULTIMATELY GOING TO NEED TO REFACTOR THE WHOLE get_available_worker('plugin')
    #! -> wqm.check_config(plugin) PIPELINE
    #~ Well.. maybe not entirely useless. Some of the checks are overkill, but
    #~ it's a decent way to figure out which wqm conf worker_name should be chosen
    Picks a worker to use based on worker status and queue length.

    :param plugin_name: name of the plugin you want to grab
        a worker for, defaults to None
    :type plugin_name: str, required
    :return: worker_name of available worker
    :rtype: str
    """

    chosen_worker_name = None
    chosen_queue = None
    # await wqm.check_config()
    for worker_name, details in wqm.conf.items():
        #* Pick a queue/worker to use.
        #* If a queue belongs to an idle worker, pick that queue.
        #* If no workers are idle, pick the queue with the least amount of jobs.
        # // _log.debug(f"looking through wqm.conf")
        # // _log.debug(f"worker_name: {worker_name}")
        # // _log.debug(f"details: {pformat(details)}")
        # // _log.debug(f"wqm")
        _log.debug(f"{details['_plugin_name']} || {plugin_name}")
        if details['_plugin_name'] != plugin_name:
            continue

        queue = details['queue']
        _log.debug(f"queue: {queue}")
        workers = Worker.all(queue=queue)
        _log.debug(f"workers: {workers}")
        for w in workers:
            if w.state == 'idle':
                _log.debug(f"Found idle worker {w.name}. Using queue {queue}.")
                return w.name
            if chosen_queue is None:
                chosen_queue = queue
                chosen_worker_name = worker_name
                continue
            if len(chosen_queue.jobs) > len(queue.jobs):
                _log.debug(
                    f"Found queue {queue.name} with lower job count "
                    f"{len(queue.jobs)} vs {len(chosen_queue.jobs)}"
                )
                chosen_queue = queue
                chosen_worker_name = worker_name
    if chosen_worker_name is None:
        if f"{plugin_name}.01" in wqm.conf:
            chosen_worker_name = f"{plugin_name}.01"
            _log.warning(f"chosen worker was 'NONE' so setting to default of {plugin_name}.01")
    _log.debug(f"Picked worker {chosen_worker_name}")
    await wqm.check_config(chosen_worker_name)
    return chosen_worker_name

async def start_all_workers():
    if not "worker_processes" in globals():
        init_manager()
    await wqm.check_config()
    _log.debug(f"Starting all workers...")
    responses = {}
    for worker_name in wqm.conf.keys():
        responses[f"{worker_name}"] = await start_worker(worker_name)
    responses['worker_processes'] = pformat(worker_processes.items())
    _log.debug(f"{xterm('GREEN')}Startup Worker Status:{xterm('RESET')}")
    _log.debug(pformat(responses))
    return responses

async def stop_all_workers():
    responses = {}
    for worker_name in wqm.conf.keys():
        responses[f"{worker_name}"] = await stop_worker(worker_name)
    _log.debug(f"{xterm('RED')}Shutdown Worker Status:{xterm('RESET')}")
    _log.debug(pformat(responses))
    return responses

#&##############################################################################
#& AUTOMATION SCHEDULER
#& Meant for things like running hunts, cleaning orphaned attributes, etc.
#&##############################################################################

#* Create an infinite async loop that checks Redis Async for a specific task_time
#* key. If that task_time key is past the interval set, run the function

async def schedule_task(
    task_func: callable = None,
    task_args: List = [],
    interval_seconds: int = 3600,
    **kwargs
):
    """schedules a task to be run in the background at an interval

    :param task_func: API funciton for the task you wish to run, defaults to None
    :type task_func: callable, required
    :param task_args: List of arguments to pass the API function, defaults to []
    :type task_args: List, required
    :param interval_seconds: How often the task should be re-run, defaults to 3600
    :type interval_seconds: int, required

    :return: Number of seconds to sleep before checking task again
    :rtype: int
    """
    task_key = f"{task_func.__name__}_run_time"
    await redis_manager.check_redis_conn()
    await wqm.check_config()
    worker_name = await get_available_worker('maintenance')
    queue: Queue = wqm.conf[worker_name]['queue']

    next_run_time = await redis_manager.redis.get(task_key)
    now = datetime.now(timezone.utc)
    if next_run_time:
        next_run_time = datetime.fromisoformat(next_run_time.decode())
        if now >= next_run_time:
            _log.debug(f"{xterm('GREEN')}{now} > {next_run_time}! Time to run {task_func.__name__}!{xterm('RESET')}")
            #* Enqueue the task
            queue.enqueue_call(
                task_func,
                args=task_args,
                **kwargs
            )
            #* Update next runtime
            next_run_time = now + timedelta(seconds=interval_seconds)
            await redis_manager.redis.set(task_key, next_run_time.isoformat())
        else:
            _log.debug(f"{xterm('RED')}Can't run {task_key} until {next_run_time}{xterm('RESET')}")
    else:
        #* Set initial run time
        next_run_time = now + timedelta(seconds=interval_seconds)
        _log.debug(f"{xterm('GREEN')}Running {task_func.__name__} for the first time! {xterm('RESET')}")
        queue.enqueue_call(
            task_func,
            args=task_args,
            **kwargs
        )
        await redis_manager.redis.set(task_key, next_run_time.isoformat())
        _log.debug(f"{xterm('CYAN')}Next time for {task_func.__name__} set to {next_run_time}{xterm('RESET')}")

    #; sleep_secs should make sure the task runs again 1 second after it's due.
    sleep_secs = (next_run_time - now).total_seconds() + 1
    return sleep_secs

async def schedule_bg_task(
    task_func: callable = None,
    task_args: list = [],
    interval_seconds: int = 3600,
    **kwargs,
):
    while True:
        sleep_secs = interval_seconds
        _log.debug(
            f"{xterm('BLUE')}Scheduling {task_func.__name__} with "
            f"{task_args} {interval_seconds} {kwargs}{xterm('RESET')}"
        )
        try:
            sleep_secs = await schedule_task(task_func, task_args, interval_seconds, **kwargs)
        except Exception as e:
            _log.error(f"{xterm('RED')}Error running {task_func.__name__}: {e} {xterm('RESET')}")
        _log.debug(
            f"{xterm('BLUE')}Sleeping {sleep_secs} seconds ({sleep_secs/60/60:.2f} "
            f"hours) before checking {task_func.__name__} again {xterm('RESET')}"
        )
        await asyncio.sleep(sleep_secs)

#~##############################
#~ Reset all Schedule Times
#~##############################

async def reset_schedules(
    bg_tasks: Optional[List[asyncio.Task]] = None,
    task_names: Optional[List[str]] = None,
):
    await redis_manager.check_redis_conn()
    if bg_tasks:
        for bgt in bg_tasks:
            task_key = f"{bgt.get_name()}_run_time"
            await redis_manager.redis.delete(task_key)
            _log.info(f"Cleared Schedule for {task_key}")
    if task_names:
        for tn in task_names:
            task_key = f"{tn}_run_time"
            await redis_manager.redis.delete(task_key)
            _log.info(f"Cleared Schedule for {task_key}")

#&###########################
#& API ENDPOINT FUNCTIONS
#&###########################
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
            deferred_registry = DeferredJobRegistry(queue.name, connection=redis_manager.syncredis)

            job_ids += failed_registry.get_job_ids()
            job_ids += fin_registry.get_job_ids()
            job_ids += sched_registry.get_job_ids()
            # job_ids = sched_registry.get_job_ids()
            job_ids += start_registry.get_job_ids()
            job_ids += deferred_registry.get_job_ids()

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
    workers.append({'worker_processes': worker_processes})
    # workers.append({'wqm.conf': dumps(wqm.conf)})
    _wqm = {}
    for k, v in wqm.conf.items():
        _wqm[str(k)] = str(v)
    workers.append({'wqm.conf': _wqm})
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
    await wqm.check_config() #; loads plugin names and queues only if not already loaded
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