from fastapi import APIRouter, Depends
# from ledapi.ledapi import auth
# from ledapi.ledapi.config import led, _log, tdb
# import auth
# from config import led, _log, tdb
from ledapi.auth import(
    dep_check_role,
)
from ledapi.models import(
    role_conman,
)
from ledapi.config import led, _log, tdb

from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

router = APIRouter()

#@##############################################################################
#@### CONMAN ENDPOINTS
#@##############################################################################

