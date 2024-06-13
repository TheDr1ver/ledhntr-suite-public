from fastapi import HTTPException, status
from typing import Callable

from ledapi.config import _log

def result_error_catching(
    result_func: Callable = None,
    detail: str = None,
    *args,
    **kwargs
):
    try:
        result = result_func(*args, **kwargs)
    except Exception as e:
        _log.error(f"{detail}: \n\t{e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{detail}: \n\t{e}"
        )
    return result