import traceback

from fastapi import HTTPException, status
from typing import Callable, Optional

from ledapi.config import _log

def result_error_catching(
    result_func: Callable = None,
    detail: str = None,
    *args,
    **kwargs
):
    #. NOTE - this might need to be revisited because there are probably
    #. instances where I'm using this where I don't want to raise an error
    #. and instead just log it and keep churning. tasks.get_hunts() comes to mind
    #. when looping through DBs.
    try:
        result = result_func(*args, **kwargs)
    except Exception as e:
        _log.error(f"{detail}: \n\t{e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{detail}: \n\t{e}"
        )
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
        'message': response,
        'status_code': status.HTTP_200_OK
    }
    return response
