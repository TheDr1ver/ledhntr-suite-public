from fastapi import APIRouter, Depends
# from ledapi.ledapi import auth
# from ledapi.ledapi.config import led, _log, tdb
# import auth
# from config import led, _log, tdb
# from ledapi.auth import(
#     dep_check_role,
# )
from ledapi.models import(
    ConmanObject,
    role_conman,
)
from ledapi.tasks import(
    setcon_handler,
)
from ledapi.user import(
    User,
    dep_check_user_role,
)

from ledapi.config import(
    led,
    _log,
    get_tdb
)
from ledapi.helpers import xterm, handle_response

from ledhntr.data_classes import Attribute, Entity, Relation

router = APIRouter()

#@##############################################################################
#@### CONMAN ENDPOINTS
#@##############################################################################

#~ Change confidence of Thing

@router.get('/setcon')
async def set_con_ep(
    thing: ConmanObject = None,
    user: User = Depends(dep_check_user_role(role_conman)),
):
    _log.debug(f"Changing confidence for object {thing}...")

    msg_400 = f"No results found for thing {thing}"
    msg_500 = f"Error modifying thing."

    response = await handle_response(
        setcon_handler,
        msg_400,
        msg_500,
        thing,
        user,
    )

    return response
