import asyncio
import time
import traceback

from fastapi import HTTPException, status
from rq.job import Job
from typing import Callable, Optional

from ledapi.config import _log, wqm

def result_error_catching(
    result_func: Callable = None,
    detail: str = None,
    *args,
    **kwargs
):
    result = None
    try:
        result = result_func(*args, **kwargs)
    except Exception as e:
        _log.error(f"{detail}: \n\t{e}")
        _log.error(f"Traceback: \n{traceback.format_exc()}")
    return result

async def handle_response(
    result_func: Callable = None,
    message_400: Optional[str] = None,
    message_500: Optional[str] = None,
    *args,
    **kwargs,
):
    """Handle Function Execution and HTTP response

    :param result_func: function to execute for this endpoint, defaults to None
    :type result_func: Callable, required
    :param message_400: Message to return if function got no results
    :type message_400: str, optional
    :param message_500: Message to return if function threw an error
    :type message_500: str, optional
    :raises HTTPException: 400 if no results, 500 if function failed due to error
    :return: response dict with 'message' and 'status_code'
    :rtype: dict
    """
    try:
        rez = await result_func(*args, **kwargs)
    except Exception as e:
        msg = f"{message_500}: \n\t{e}"
        _log.error(msg)
        _log.error(f"Traceback: \n{traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=msg,
        )

    if not rez:
        _log.error(message_400)
        _log.error(f"Traceback: \n{traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message_400,
        )
    response = {
        'message': rez,
        'status_code': status.HTTP_200_OK
    }
    return response

async def two_sec_grace(
    worker_name: str = None,
    job_id: str = None,
):
    """Waits 2 seconds for a job to finish before returning job_id

    If job isn't finished after 2 seconds of waiting, it returns the job_id,
    otherwise it returns the result of the job.

    :param worker_name: name of the worker executing the job, defaults to None
    :type worker_name: str, optional
    :param job_id: job_id being executed, defaults to None
    :type job_id: str, optional
    :return: result dict containing worker, job_id, and result. Result set to 
        job_status if 2 seconds passes and the job hasn't completed.
    :rtype: dict
    """
    result = {
        "worker": worker_name,
        "job_id": job_id,
        "result": None,
    }
    queue = wqm.conf.get(worker_name)['queue']
    last_job: Job
    last_job = queue.fetch_job(job_id)

    count=0
    if not last_job.is_finished:
        _log.debug(f"Waiting 2 seconds for {last_job.id} to finish...")
        # for _ in range(4):
        for _ in range(10):
            if not last_job.is_finished:
                await asyncio.sleep(0.5)
                _log.debug(f"...still waiting...")
            else:
                break

    if not last_job.is_finished:
        _log.debug(f"Job still not finished, returning job_id.")
        status = last_job.get_status()
        result['result'] = status
    else:
        result['result'] = last_job.result

    return result