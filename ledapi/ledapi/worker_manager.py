import asyncio
import redis as syncredis
# from redis.asyncio.client import Redis
from rq import Queue, Worker, Connection
# from rq.registry import StartedJobRegistry
from multiprocessing import Process, Manager, set_start_method
from redis.asyncio.client import Redis
import json
import psutil


from ledapi.config import(
    _log,
    conf,
    redis_manager,
)

redis_url = conf['ledapi']['redis_url']
conn = syncredis.from_url(redis_url)

#~ Parse Conf
workers_conf = {}
for key in conf['ledapi.workers']:
    if key.endswith('.threshold'):
        plugin_name = key.split('.')[0]
        threshold = int(conf['ledapi.workers'][key])
        workers_conf[plugin_name] = {'threshold': threshold}
# TODO - Eventually we'll want to load alternate keys/secrets from each of the plugins.
# TODO - This way we could have multiple accounts per plugin to increase throughput.
# TODO - For right now though I'm sticking with one worker per plugin just to get
# TODO - something out the door.

#~ Define Queues
queues = {queue: Queue(queue, connection=conn) for queue in workers_conf}

def init_manager():
    global worker_processes
    worker_processes = Manager().dict()

async def check_redis_conn():
    if redis_manager.redis is None:
        await redis_manager.connect()

async def is_worker_running(worker_name, worker_id):
    status = await redis_manager.redis.get(f"worker_status:{worker_name}:{worker_id}")
    return status == b"running"

async def set_worker_status(worker_name, worker_id, status):
    await redis_manager.redis.set(f"worker_status:{worker_name}:{worker_id}", status, ex=60*60*24*7)

async def clear_worker_status(worker_name, worker_id):
    await redis_manager.redis.delete(f"worker_status:{worker_name}:{worker_id}")

async def get_all_workers():
    cursor = '0'
    keys = []
    while True:
        cursor, partial_keys = await redis_manager.redis.scan(cursor=cursor, match="worker_status:*")
        keys.extend(partial_keys)
        if cursor == 0:
            break
    results = {}
    for key in keys:
        status = await redis_manager.redis.get(key)
        res = status.decode()
        results[key] = res
    return results

def get_worker(worker_name):
    return Worker([queues[worker_name]], connection=conn)

'''# Original Setup
def worker_process(worker_name, worker_id):
    async def main():
        await check_redis_conn()
        if await is_worker_running(worker_name, worker_id):
            print(f"Worker {worker_name} with ID {worker_id} is already running. Exiting.")
        try:
            await set_worker_status(worker_name, worker_id, "running")
            worker = get_worker(worker_name)
            worker.work()
        finally:
            await clear_worker_status(worker_name, worker_id)
            await redis_manager.disconnect()
    asyncio.run(main())
'''
'''# Attempt 1
def worker_process(worker_name, worker_id):
    try:
        _log.debug(f"Connecting to redis for worker {worker_name}_{worker_id}")
        conn = syncredis.from_url(redis_url)
        with Connection(conn):
            _log.debug(f"Starting worker {worker_name}_{worker_id}")
            worker = Worker([queues[worker_name]])
            worker.work()
    except Exception as e:
        _log.error(f"Failed to start workier {worker_name}_{worker_id}: {e}")
'''
async def async_worker_process(worker_name, worker_id):
    try:
        _log.debug(f"Connecting to Redis for worker {worker_name}_{worker_id}")
        await redis_manager.connect()
        redis_sync_client = redis_manager.syncredis
        
        # with Connection(redis_pool.sync_client):
        with Connection(redis_sync_client):
            _log.debug(f"Starting worker {worker_name}_{worker_id}")
            worker = Worker([queues[worker_name]])
            await worker.work()
    except Exception as e:
        _log.error(f"Failed to start worker {worker_name}_{worker_id}: {e}")

def worker_process(worker_name, worker_id):
    try:
        asyncio.run(async_worker_process(worker_name, worker_id))
    except Exception as e:
        _log.error(f"Failed to run async worker process {worker_name}_{worker_id}: {e}")


async def start_worker(worker_name):
    _log.debug(f"Starting worker {worker_name}...")
    active_workers = [worker_id for worker_id in range(workers_conf[worker_name]['threshold']) if await is_worker_running(worker_name, worker_id)]
    if len(active_workers) >= workers_conf[worker_name]['threshold']:
        running_processes = [worker_id for worker_id in range(workers_conf[worker_name]['threshold']) if (worker_name, worker_id) in worker_processes]
        if len(running_processes) == len(active_workers):
            return f"Maximum number of {workers_conf[worker_name]['threshold']} {worker_name} workers are already running."
        else:
            _log.error(f"Workers in Redis do not match workers in active processes. Clearing Redis and restarting worker processes")
            for worker_id in range(workers_conf[worker_name]['threshold']):
                if (worker_name, worker_id) not in worker_processes:
                    if await is_worker_running(worker_name, worker_id):
                        await clear_worker_status(worker_name, worker_id)
                        _log.debug(f"Removed ({worker_name}, {worker_id}) from Redis.")

    worker_id = None
    # worker_id = next(worker_id for worker_id in range(workers_conf[worker_name]['threshold']) if not await is_worker_running(worker_name, worker_id))
    for wid in range(workers_conf[worker_name]['threshold']):
        if not await is_worker_running(worker_name, wid):
            worker_id = wid
            break
    if worker_id is None:
        return f"No available worker ID found for {worker_name}"
    _log.debug(f"Starting new process: {worker_name}, {worker_id}")
    # process = Process(target=partial(worker_process, worker_name, worker_id))
    process = Process(target=worker_process, args=(worker_name, worker_id))
    process.start()
    # worker_processes[(worker_name, worker_id)] = process
    worker_processes[(worker_name, worker_id)] = process.pid
    msg = f"Worker {worker_name} with ID {worker_id} started."
    _log.debug(msg)
    return msg

async def stop_worker(worker_name, worker_id):
    _log.debug(worker_processes)
    pid = worker_processes.get((worker_name, worker_id))
    if pid is not None:
        try:
            process = psutil.Process(pid)
            # process.terminate() # Or process.kill() if you want to forcefully kill the process
            process.kill()
            process.wait() # Wait for the process to terminate
            del worker_processes[(worker_name, worker_id)]
            await clear_worker_status(worker_name, worker_id)
            msg = f"Worker {worker_name} with ID {worker_id} stopped."
            _log.debug(msg)
            return msg
        except psutil.NoSuchProcess:
            msg = "No such process with PID {pid}"
            _log.error(msg)
    else:
        msg = f"No running worker found with name {worker_name} and ID {worker_id}.\n"
        msg += f"worker_processes: {worker_processes}"
        _log.debug(msg)
        _log.debug(f"Clearing {worker_name} {worker_id} anyway to make sure redis is clear")
        #! NOTE - This is probably a bad idea if I want to have the hunt queue persist
        #! after the app is restarted or crashes
        await clear_worker_status(worker_name, worker_id)
    await redis_manager.disconnect()
    return msg

async def get_worker_status(worker_name, worker_id):
    if await is_worker_running(worker_name, worker_id):
        msg = f"Worker {worker_name} with ID {worker_id} is running."
        _log.debug(msg)
        return msg
    msg = f"Worker {worker_name} with ID {worker_id} is not running."
    _log.debug(msg)
    return msg

async def start_all_workers():
    _log.debug(f"Initializing manager")
    if not "worker_processes" in globals():
        init_manager()
    _log.debug(f"Starting all workers...")
    responses = {}
    for worker_name in queues.keys():
        for worker_id in range(workers_conf[worker_name]['threshold']):
            responses[f"{worker_name}_{worker_id}"] = await start_worker(worker_name)
    _log.debug(responses)
    return responses

async def stop_all_workers():
    responses = {}
    for worker_name in queues.keys():
        for worker_id in range(workers_conf[worker_name]['threshold']):
            responses[f"{worker_name}_{worker_id}"] = await stop_worker(worker_name, worker_id)
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