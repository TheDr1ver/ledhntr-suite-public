import time
import traceback

from datetime import datetime, timedelta, timezone
from fastapi import Query
from pprint import pformat
from redis.asyncio.client import Redis
from rq import Queue, Worker
from rq.job import Job, Dependency
from typing import Dict, List, Optional, Union

from ledhntr.data_classes import(
    Attribute,
    Entity,
    Relation,
)
from ledhntr.plugins import (
    HNTRPlugin,
    ConnectorPlugin,
    AnalyzerPlugin
)

from ledhntr.helpers import xterm

from ledapi.config import(
    _log,
    led,
    get_tdb,
    wqm,
)
from ledapi.helpers import(
    result_error_catching,
    two_sec_grace,
)
from ledapi.user import User
from ledapi.worker_manager import(
    get_available_worker
)
from ledapi.models import(
    ConmanObject,
)

from typedb_client import TypeDBClient

#&##############################################################################
#& Internal Functions
#&##############################################################################

#~######################################
#~ set_confidence
#~######################################
#! This is probably redundant in favor of replace_attributes_task,
#! but I'm leaving it for now because I don't want to refactor it yet.
async def set_confidence_task(
    setcon: ConmanObject = None,
    user: User = None,
)->Union[Entity,Relation,False]:
    """Change the confidence level of a given Thing in TypeDB
    ConmanObject requires either an iid or a value

    :param setcon: object consisting of iid, attr.value, attr.label, db_name, \
        and confidence level, defaults to None
    :type setcon: ConmanObject, optional
    :param user: User submitting the request, defaults to None
    :type user: User, optional
    :return: Either the changed Thing or False if the change failed
    :rtype: Union[Entity,Relation,False]
    """
    _log.debug(f"Setting confidence...")
    _log.debug(f"{xterm('YELLOW')}{pformat(setcon)}{xterm('X')}")
    # value_str = payload['actions'][0]['selected_option']['value']
    # db_name = value_str.split('|')[0]
    # iid = value_str.split('|')[1]
    # value = value_str.split('|')[2]

    if setcon.iid:
        if setcon.ttype == 'entity':
            so = Entity(label='entity')
        else:
            so = Relation(label='relation')
        so.iid = setcon.iid
    else:
        if setcon.ttype == 'entity':
            if setcon.label:
                so = Entity(label=setcon.label)
            else:
                so = Entity(label='entity')
        elif setcon.ttype == 'relation':
            if setcon.label:
                so = Relation(label=setcon.label)
            else:
                so = Relation(label='relation')
        attr = Attribute(label=so.keyattr, value=setcon.value)
        so.has.append(attr)

    tdb:TypeDBClient = get_tdb()
    tdb.db_name = setcon.db_name

    _log.debug(f"Looking for existing thing...")
    try:
        rez = tdb.find_things(so)
        _log.debug(f"Found things{rez}")
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed finding thing {so}: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
        return False
    existing_thing = rez[0]
    _log.debug(f"Existing thing: {existing_thing}")
    #; If the confidence is explicitly set to 0, we're going to set it to 0.1
    #; to mark that it's at least been touched.
    if int(setcon.confidence) == 0:
        _log.debug(f"Setting confidence to 0.1")
        new_con = 0.1
    else:
        new_con = setcon.confidence
    if existing_thing.get_attributes('confidence'):
        _log.debug(f"Old confidence: {existing_thing.get_attributes('confidence')[0].value}")
    _log.debug(f"Replacing confidence with {new_con}...")
    try:
        # tdb.replace_attribute(existing_thing, Attribute(label='confidence', value=int(setcon.confidence)))
        tdb.replace_attribute(existing_thing, Attribute(label='confidence', value=float(new_con)))
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed replacing attribute on {existing_thing}: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
        return False
    _log.debug(f"Looking for updated thing...")
    try:
        updated_thing = tdb.find_things(so)[0]
    except Exception as e:
        _log.error(f"{xterm('RED')}Failed finding thing {so}: {e}{xterm('X')}")
        _log.error(f"Traceback: \n{pformat(traceback.format_exc())}")
        return False
    _log.debug(f"{xterm('GREEN')}New confidence: {updated_thing.get_attributes('confidence')[0].value}{xterm('X')}")

    return updated_thing

#&##############################################################################
#& Internal Task Config and Job Queuing
#&##############################################################################

#&##############################################################################
#& API Endpoint-Facing Functions
#&##############################################################################

#~##########################
#~ List all Active Hunts
#~##########################


#~###############
#~ Set-Confidence Handler
#~###############


# TODO - Define ConmanObject in models and write API endpoint so this can be called
# TODO - from the API itself
async def setcon_handler(
    setcon: ConmanObject = None,
    user: User = None,
):
    worker_name = await get_available_worker('typedb_client')
    queue = wqm.conf[worker_name]['queue']
    _log.debug(f"Enqueuing conman_handler")

    job = queue.enqueue_call(
        set_confidence_task,
        args=[setcon, user],
        timeout=60,
        result_ttl=60*24,
    )

    response = await two_sec_grace(worker_name, job.id)

    return response
