from fastapi import APIRouter, Depends
# from ledapi.ledapi import auth
# from ledapi.ledapi.config import led, _log, tdb
# import auth
# from config import led, _log, tdb
from ledapi.auth import(
    dep_check_role,
)
from ledapi.models import(
    role_dbadmin,
)
from ledapi.config import led, _log, tdb

from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

router = APIRouter()

#@##############################################################################
#@### DBADMIN ENDPOINTS
#@##############################################################################

@router.post("/delete-db")
async def delete_db(
    db_name: str,
    dbadmin_api_key: str = Depends(dep_check_role(role_dbadmin))
):
    try:
        tdb.delete_db(db_name)
        msg = f"Successfully deleted {db_name}!"
    except Exception as e:
        msg = f"Failed deleting {db_name}: {e}"
        _log.error(msg)
    response = {'message': msg}
    return response