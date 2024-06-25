import asyncio
import redis as syncredis
# from redis.asyncio.client import Redis
from datetime import datetime, timezone
from rq import Queue, Worker, Connection
from rq.registry import (
    FailedJobRegistry, 
    FinishedJobRegistry, 
    ScheduledJobRegistry, 
    StartedJobRegistry,
)
# from rq.registry import StartedJobRegistry
from multiprocessing import Process, Manager, set_start_method
from pprint import pformat
from redis.asyncio.client import Redis
import json
import psutil


from ledapi.config import(
    _log,
    conf,
    redis_manager,
    # wqm.queues,
    # wqm.conf,
    wqm,
)

# redis_url = conf['ledapi']['redis_url']
# conn = syncredis.from_url(redis_url)

#@##############################################################################
#@ WORKER MANAGEMENT
#@##############################################################################

def init_manager():
    global worker_processes
    worker_processes = Manager().dict()



# async def is_worker_running(worker_name):
async def is_worker_running(worker_name):
    # status = await redis_manager.redis.get(f"worker_status:{worker_name}:{worker_id}")
    await redis_manager.check_redis_conn()
    status = None
    # status = await redis_manager.redis.get(f"rq:worker:{worker_name}")
    _log.debug(f"GETTING STATUS OF {worker_name}")
    #& TODO - PICK THIS UP TOMORROW
    for worker in Worker.all(connection=redis_manager.syncredis):
        # if worker.name == f"{worker_name}":
        _log.debug(f"worker.name: {worker.name} vs worker_name {worker_name}")
        if worker.name == f"{worker_name}":
            return True
    return False

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
    for worker in Worker.all(connection=redis_manager.syncredis):
        if worker.name == f"{worker_name}":
            return worker

    _log.info(f"No worker {worker_name} found!")
    return running_worker

async def get_all_workers():
    await redis_manager.check_redis_conn()
    '''
    cursor = '0'
    keys = []
    while cursor != 0:
        cursor, partial_keys = await redis_manager.redis.scan(cursor=cursor, match="worker_status:*")
        keys.extend(partial_keys)
    results = {}
    for key in keys:
        status = await redis_manager.redis.get(key)
        res = status.decode()
        results[key] = res
    return results
    '''
    workers = []
    _log.debug(f"first wqm.queues: {wqm.queues}")
    for queue_name, queue in wqm.queues.items():
        _log.debug(f"queue_name: {queue_name}, queue: {queue}")
        
        failed_registry = FailedJobRegistry(queue_name, connection=redis_manager.syncredis)
        fin_registry = FinishedJobRegistry(queue_name, connection=redis_manager.syncredis)
        sched_registry = ScheduledJobRegistry(queue_name, connection=redis_manager.syncredis)
        start_registry = StartedJobRegistry(queue_name, connection=redis_manager.syncredis)
        
        job_ids = failed_registry.get_job_ids()
        job_ids += fin_registry.get_job_ids()
        job_ids += sched_registry.get_job_ids()
        job_ids += start_registry.get_job_ids()

        for worker in Worker.all(connection=redis_manager.syncredis):
            
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

    



'''# Original Setup
def get_worker(worker_name):
    return Worker([wqm.queues[worker_name]], connection=conn)

def worker_process(worker_name):
    async def main():
        await check_redis_conn()
        if await is_worker_running(worker_name):
            print(f"Worker {worker_name} with ID {worker_id} is already running. Exiting.")
        try:
            await set_worker_status(worker_name, worker_id, "running")
            worker = get_worker(worker_name)
            worker.work()
        finally:
            await clear_worker_status(worker_name)
            await redis_manager.disconnect()
    asyncio.run(main())
'''
'''# Attempt 1
def worker_process(worker_name):
    try:
        _log.debug(f"Connecting to redis for worker {worker_name}")
        conn = syncredis.from_url(redis_url)
        with Connection(conn):
            _log.debug(f"Starting worker {worker_name}")
            worker = Worker([wqm.queues[worker_name]])
            worker.work()
    except Exception as e:
        _log.error(f"Failed to start workier {worker_name}: {e}")
'''
async def async_worker_process(worker_name):
    try:
        _log.debug(f"Connecting to Redis for worker {worker_name}")
        await redis_manager.check_redis_conn()
        redis_sync_client = redis_manager.syncredis

        # Check worker queues
        _log.debug(f"Checking worker queues...")
        await wqm.check_queues(worker_name)
        _log.debug(f"Queues: {wqm.queues}")

        # Check for existing workers
        _log.debug(f"Checking for existing workers...")
        for worker in Worker.all(connection=redis_sync_client):
            if worker.name == f"{worker_name}":
                _log.debug(f"Exisitng worker {worker.name} found!")
                ##& await worker.work()
                return worker
            else:
                _log.debug(f"{worker_name} != {worker.name}")
        
        _log.debug(f"No existing workers found. Starting new process.")
        # with Connection(redis_pool.sync_client):
        with Connection(redis_sync_client):
            _log.debug(f"Starting worker {worker_name}")
            worker = Worker([wqm.queues[worker_name]], name=f"{worker_name}")
            await worker.work()
    except Exception as e:
        _log.error(f"Failed to start worker {worker_name}: {e}")

def worker_process(worker_name):
    try:
        asyncio.run(async_worker_process(worker_name))
    except Exception as e:
        _log.error(f"Failed to run async worker process {worker_name}: {e}")


async def start_worker(worker_name):
    _log.debug(f"Starting worker {worker_name}...")
    #! active_workers = [worker_id for worker_id in range(wqm.conf[worker_name]['threshold']) if await is_worker_running(worker_name)]
    active_workers = []
    for worker_name, details in wqm.conf.items():
        if await is_worker_running(worker_name):
            active_workers.append(worker_name)
    if len(active_workers) >= len(wqm.conf.keys()):
        #! running_processes = [worker_id for worker_id in range(wqm.conf[worker_name]['threshold']) if worker_name in worker_processes]
        running_processes = []
        for worker_name, details in wqm.conf.items():
            if worker_name in worker_processes:
                running_processes.append(worker_name)
        if len(running_processes) == len(active_workers):
            return f"All {wqm.conf[worker_name]['_plugin_name']} workers are already running."
        '''
        else:
            _log.error(f"Workers in Redis do not match workers in active processes. Clearing Redis and restarting worker processes")
            for worker_id in range(wqm.conf[worker_name]['threshold']):
                if worker_name not in worker_processes:
                    if await is_worker_running(worker_name):
                        await clear_worker_status(worker_name)
                        _log.debug(f"Removed ({worker_name}, {worker_id}) from Redis.")
            
            # TODO - I WANT TO GRAB EXISTING WORKERS FROM REDIS IF POSSIBLE, NOT NUKE THEM
        '''

    worker_name = None
    # worker_id = next(worker_id for worker_id in range(wqm.conf[worker_name]['threshold']) if not await is_worker_running(worker_name))
    #! for wid in range(wqm.conf[worker_name]['threshold']):
    for worker_name, details in wqm.conf.items():
        #! if not await is_worker_running(worker_name, wid):
        #!     worker_id = wid
        #!     break
        if await is_worker_running(worker_name):
            if worker_name not in worker_processes:
                _log.debug(f"Found running worker {worker_name} in Redis that wasn't in processes.")
                _log.debug(f"Adding worker to running processes...")
                process = Process(target=worker_process, args=(worker_name,))
                process.start()
                worker_processes[worker_name] = process.pid
                msg = f"Existing Worker {worker_name} started new process."
                _log.debug(msg)
                return msg
        else:
            break

    if worker_name is None:
        return f"No available worker ID space found for workers of type {worker_name}"
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
    if await is_worker_running(worker_name):
        msg = f"Worker {worker_name} is running."
        _log.debug(msg)
        return msg
    msg = f"Worker {worker_name} is not running."
    _log.debug(msg)
    return msg

async def start_all_workers():
    _log.debug(f"Initializing Multiprocess manager")
    if not "worker_processes" in globals():
        init_manager()
    _log.debug(f"Loading Worker Queues...")
    await wqm.check_queues()
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
    for worker_name in wqm.queues.keys():
        responses[f"{worker_name}"] = await stop_worker(worker_name)
    _log.debug(responses)
    return responses

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

async def create_job(job_data):
    _log.debug(f"Creating job: {job_data}")

async def update_job_status(job_id, status):
    _log.debug(f"Updating {job_id} status to {status}")
    '''
    await redis_manager.check_redis_conn()
    job_data = await redis_manager.redis.get(job_id)
    if job_data:
        job_data = json.loads(job_data.decode('utf-8'))
        job_data['status'] = status
        if status == "completed":
            job_data['completed_at'] = datetime.now(timezone.utc).isoformat()

        await redis_manager.redis
    '''

async def poll_job(job_id):
    _log.debug(f"Polling job_id {job_id}")
    await wqm.check_queues()
    await redis_manager.check_redis_conn()
    job_details = None
    for queue_name, queue in wqm.queues.items():
        for worker in Worker.all(connection=redis_manager.syncredis):
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
    await wqm.check_queues()
    await redis_manager.check_redis_conn()
    queues = []
    for queue_name, queue in wqm.queues.items():
        fin_reg = FinishedJobRegistry(queue_name, connection=redis_manager.syncredis)
        fail_reg = FailedJobRegistry(queue_name, connection=redis_manager.syncredis)

        # Delete jobs older than 24 hrs
        now = int(datetime.now().timestamp())
        yesterday = now-60*60*24
        # fin_reg.cleanup(timestamp=yesterday)
        # fail_reg.cleanup(timestamp=yesterday)
        fin_reg.cleanup()
        fail_reg.cleanup()
        queues.append(queue_name)

    return f"Cleaned finished and failed registries for {queues} that were older than 24 hrs."