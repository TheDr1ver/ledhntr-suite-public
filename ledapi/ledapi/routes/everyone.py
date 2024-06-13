from datetime import datetime, timedelta, UTC
from pprint import pformat

from fastapi import APIRouter, Depends, HTTPException, status
# from ledapi.ledapi import auth
# from ledapi.ledapi.config import led, _log, tdb
# import auth
# from config import led, _log, tdb

from redis.asyncio.client import Redis

from ledapi.auth import(
    dep_check_role,
)

from ledapi.user import(
    User,
    dep_check_user_role
)
from ledapi.config import led, _log, tdb
from ledapi.helpers import result_error_catching
from ledapi.user import get_redis_pool

# from ledapi.ledapi.models import (
#     SearchObject,
# )
# from models import(
from ledapi.models import(
    SearchObject,
    role_everyone,
)

from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

router = APIRouter()

#@##############################################################################
#@### EVERYONE ENDPOINTS
#@##############################################################################

#~ Hello World Test
@router.get("/hello-test")
async def read_hello(api_key: str = Depends(dep_check_role(role_everyone))):
    return {"message": f"hello world! api_key_header: {api_key}"}

#~ Hello World Test User
@router.get("/hello-test-user")
async def read_hello(user: User = Depends(dep_check_user_role(role_everyone))):
    return {"message": f"hello world!",
            "user": user.to_dict()}

#~ Test Redis
@router.get("/redis-test")
async def redis_test(
    # api_key: str = Depends(dep_check_role(role_everyone)),
    #& user: User = Depends(dep_check_user_role(role_everyone)),
    redis_pool: Redis = Depends(get_redis_pool)
):
    redis_info = await redis_pool.info()
    return {"message": redis_info}

#~ List Databases
@router.get("/list-dbs")
async def list_dbs(
    api_key: str = Depends(dep_check_role(role_everyone))
):
    """List available databases

    :param api_key: API Key Permissions Check, defaults to Depends(dep_check_role(role_everyone))
    :type api_key: str, optional
    :return: Dictionary of "result", "status_code", and "count"
    :rtype: Dict
    """
    all_dbs = []
    dbs = result_error_catching(tdb.get_all_dbs, "Failed to fetch databases")
    for db in dbs:
        all_dbs.append(str(db))
    results = {
        'results': [],
        'message': None,
        'status_code': None,
        'count': 0,
    }
    if all_dbs:
        results['results']=all_dbs

    return all_dbs

#~ Search database
@router.post("/search")
async def search(
    search_obj: SearchObject,
    everyone_api_key: str = Depends(dep_check_role(role_everyone))
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

    if search_obj.ttype == 'entity': # * If we want to return all entities...
        # * and our search label is a known entity...
        if search_obj.label in led.all_labels['entity']:
            # * start with an Entity object with that label
            so = Entity(label=search_obj.label)
            # * if we also passed a value
            if search_obj.value:
                # * values only belong to Attributes, so we add a generic attribute
                # * with that value.
                so.has.append(Attribute(label='attribute', value=search_obj.value))
        # * if our search label is not a known entity, but is instead an Attribute...
        elif search_obj.label in led.all_labels['attribute']:
            # * ...and we have a value passed...
            if search_obj.value:
                # * ...create a specific attribute + value
                attr = Attribute(label=search_obj.label, value=search_obj.value)
            # * ...otherwise just use the Attribute label...
            else:
                attr = Attribute(label=search_obj.label)
            # * ...and attach it to a generic entity to get all entites with that attribute
            so = Entity(label='entity', has=[attr])
        # * What if we want to get all entities belonging to a Relation?
        # * I'm not sure how I'd handle that just yet...
        # * I think it would either be Entity.relations or Entity.plays
        # * But I'm also trying to avoid Relations at this stage, so I'm not
        # * worried about it right now
        # elif search_obj.label in led.all_labels['relation']:
        #     so = Relation(label=search_obj.label)
        #     if search_obj.value:
        #         so.has[Attribute(label='attribute', value=search_obj.value)]
    elif search_obj.ttype == 'relation': # * If we want to return all relations...
        # * and our search label is a known relation...
        if search_obj.label in led.all_labels['relation']:
            #* start with a Relation object with that label
            so = Relation(label=search_obj.label)
            # * if we also passed a value
            if search_obj.value:
                # * values only belong to Attributes, so we add a generic attribute
                # * with that value
                so.has.append(Attribute(label='attribute', value=search_obj.value))
        # * if our search label is not a known Relation, but is instead an Attribute...
        elif search_obj.label in led.all_labels['attribute']:
            # * ...and we have a value passed...
            if search_obj.value:
                # * ...create a specific attribute + value
                attr = Attribute(label=search_obj.label, value=search_obj.value)
            # * ...otherwise just use the Attribute label...
            else:
                attr = Attribute(label=search_obj.label)
            # * ...and attach it to a generic Relation to get all Relations with that Attribute
            so = Relation(label='relation', has=[attr])
        # * there's probably a better way to let us search for Relations with specific
        # * players belonging to Entity labels, or Relations with Player Entities that
        # * own a specific Attribute, but again - I'm trying to avoid Relations in this
        # * model, and don't want to waste too much time searching Relations when all
        # * of this will inevitably have to be changed in TypeDB 3.0 anyway...

    if search_obj.db_name:
        tdb.db_name = search_obj.db_name
    else:
        search_obj.db_name = tdb.db_name

    results = {
        'results': [],
        'message': None,
        'status_code': None,
        'count': 0,
    }

    things = result_error_catching(tdb.find_things, f"Error searching for {so}", so)
    '''
    try:
        things = tdb.find_things(so)
    except Exception as e:
        _log.error(e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error searching for {so}: \n\t{e}"
        )
    '''
    for thing in things:
        if search_obj.new_days_back:
            # * If we're focusing on only new stuff, make sure we grab
            # * the things with the date-discovered within our threshold
            min_date = datetime.now(UTC) - timedelta(days=search_obj.new_days_back)
            dd_attr = thing.get_attributes(label='date-discovered')
            if isinstance(dd_attr.value, datetime) and dd_attr.value >= min_date:
                results['results'].append(thing.to_dict())
        else:
            results['results'].append(thing.to_dict())
    results['message'] = f"Search object: {search_obj}"
    results['status_code'] = status.HTTP_200_OK
    results['count'] = len(results['results'])
    return results
