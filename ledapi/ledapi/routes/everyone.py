from datetime import datetime, timedelta, timezone
from pprint import pformat
from typing import Optional, Dict, List

from fastapi import APIRouter, Body, Depends, HTTPException, status, Query

from ledapi.user import(
    User,
    dep_check_user_role,
    get_user_by_api_key
)
from ledapi.config import(
    led,
    _log,
    get_tdb,
    redis_manager
)
from ledapi.helpers import handle_response

from ledapi.models import(
    DBName,
    SearchObject,
    UserModel,
    role_everyone,
)

from ledapi.tasks import(
    list_dbs,
    search,
    get_news,
)

from ledhntr.data_classes import Attribute, Entity, Relation, Thing

router = APIRouter()

#@##############################################################################
#@### EVERYONE ENDPOINTS
#@##############################################################################

#~##########################
#~ Test Functions
#~##########################

#~ Hello World Test User
@router.get("/hello-test-user")
async def read_hello(user: User = Depends(dep_check_user_role(role_everyone))):
    return {"message": f"hello world!",
            "user": user.to_dict()}

#~ Get User info about self
@router.get("/user-info")
async def user_info(
    user = Depends(get_user_by_api_key),
):
    return user.to_dict()

#~ Test Redis
@router.get("/redis-test")
async def redis_test(
    user: User = Depends(dep_check_user_role(role_everyone)),
):
    # redis_info = await redis_pool.info()
    redis_info = await redis_manager.redis.info()
    return {"message": redis_info}

#~##########################
#~ User Functions
#~##########################

#~ Set User Database
@router.post("/set-db")
async def set_db(
    db_name: str = Query('all', description="Set database for subsequent searches. Defaults to 'all'"),
    db_name_model: DBName = Body(None),
    user: User = Depends(dep_check_user_role(role_everyone)),
):
    """Sets preferred dictionary to focus on. Defaults to 'all'

    :param user: user making the request, defaults to Depends(dep_check_user_role(role_everyone))
    :type user: User, required
    :param db_name: db_name to inspect, defaults to 'all'
    :type db_name: str, optional
    :param db_name_model: DBName model pydantic object, optional
    :type db_name_model: DBName
    :raises HTTPException: 500
    :return: new db_name result
    :rtype: Dict
    """
    if db_name_model and db_name_model.db_name:
        new_db_name = db_name_model.db_name
    else:
        new_db_name = db_name
    modified_user = UserModel(uuid=user.uuid, db_name=new_db_name)
    
    _log.debug(f"Setting DB to {new_db_name}")
    msg_400 = f"Could not update {modified_user}"
    msg_500 = f"Error updating {modified_user}"

    response = await handle_response(
        User.update_user,
        msg_400,
        msg_500,
        modified_user,
    )

    return response

#~ Get User Database
@router.get("/get-db")
async def get_db(
    user: User = Depends(dep_check_user_role(role_everyone)),
):
    """Gets the currently selected database for this user

    :param user: user making the request
    :type user: User, required
    :raises HTTPException: 500
    :return: name of selected db
    :rtype: str
    """
    return user.db_name


#~##########################
#~ Task Functions
#~##########################

#~ List Databases
@router.get("/list-dbs")
async def list_dbs_ep(
    user: User = Depends(dep_check_user_role(role_everyone))
):
    """List available databases

    :param user: User Permissions Check, defaults to Depends(dep_check_role(role_everyone))
    :type user: User, required
    :return: Dictionary of "result", "status_code", and "count"
    :rtype: Dict
    """
    _log.debug(f"Getting list of all databases...")
    msg_400 = f"No databases found"
    msg_500 = f"Error fetching databases"

    response = await handle_response(
        list_dbs,
        msg_400,
        msg_500,
    )

    return response

#~ Search database
@router.post("/search")
async def search_ep(
    search_obj: SearchObject=None,
    user: User = Depends(dep_check_user_role(role_everyone))
):
    """search database

    Consumes a JSON blob matching the following optional parameters:
    {
        'db_name': '<Name of database to search if different from default>',
        'label': '<Thing Label>',
        'new_days_back': int,
        'ttype': '<Type of Thing to return>',
        'value': '<Attribute Value>',
    }

    - db_name may be passed to search a different database than the one
        currently selected and assigned to tdb.db_name

    - At least one of 'label' or 'value' is required to execute a search

    - ttype can be either 'entity' or 'relation'. If not passed, defaults to 'entity'
        this is the type of object you would like to return with your search.

    - new_days_back if set will filter your results to only return those that
        have a date-discovered date >= this number of days back.

    :param search_obj: SearchObject containing label, value, ttype, and db_name
    :type search_obj: ledapi.models.everyone.SearchObject
    :param everyone_api_key: Confirms API Key belongs to read-only or higher roles
    :type everyone_api_key: str, optional
    :return: Returns JSON serialized objects from the database
    :rtype: List[Dict]
    """

    _log.debug(f"Searching for {search_obj}")
    # msg_400 = f"No results found" #; this isn't exactly "Bad request"
    msg_500 = f"Error fetching databases"

    response = await handle_response(
        search,
        None,
        msg_500,
        search_obj,
        user,
    )

    return response

#~ Get News
@router.get("/news")
async def news_ep(
    days_back: Optional[int] = Query(1, description="Number of days back to consider something 'new'"),
    user: User = Depends(dep_check_user_role(role_everyone))
):
    """Get the new stuff. Optionally specify days_back if you want something older than 24 hrs
    """
    _log.debug(f"Getting things newer than {days_back} days...")
    # msg_400 = f"No results found" #; this isn't exactly "Bad request"
    msg_500 = f"Error fetching databases"

    response = await handle_response(
        get_news,
        None,
        msg_500,
        days_back,
        user,
    )

    return response