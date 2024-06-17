from fastapi import APIRouter, Depends
# from ledapi.ledapi import auth
# from ledapi.ledapi.config import led, _log, tdb
# import auth
# from config import led, _log, tdb
# from ledapi.auth import(
#     dep_check_role,
# )
from ledapi.models import(
    role_conman,
)
from ledapi.user import(
    User,
    dep_check_user_role,
)

from ledapi.config import led, _log, tdb
from ledapi.helpers import result_error_catching

from ledhntr.data_classes import Attribute, Entity, Relation

router = APIRouter()

#@##############################################################################
#@### CONMAN ENDPOINTS
#@##############################################################################

#~ Change confidence of Thing