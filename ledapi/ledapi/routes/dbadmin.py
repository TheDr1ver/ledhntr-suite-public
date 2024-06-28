from fastapi import APIRouter, Depends
from importlib.resources import files
# from ledapi.ledapi import auth
# from ledapi.ledapi.config import led, _log, tdb
# import auth
# from config import led, _log, tdb
# from ledapi.auth import(
#     dep_check_role,
# )
from ledapi.models import(
    DBName,
    role_dbadmin,
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
from ledapi.helpers import result_error_catching

from ledhntr.data_classes import Attribute, Entity, Relation

# from typedb_client.typedb_client.typedb_client import TypeDBClient
# tdb: TypeDBClient

router = APIRouter()

#@##############################################################################
#@### DBADMIN ENDPOINTS
#@##############################################################################

@router.post("/create-db")
async def add_db(
    dbadmin_model: DBName,
    dbadmin_api_key: str = Depends(dep_check_user_role(role_dbadmin)),
):
    tdb = get_tdb()
    msg = None
    try:
        if tdb.check_db(dbadmin_model.db_name):
            msg = f"{dbadmin_model.db_name} already exists!"
    except Exception as e:
        msg = f"Failed to check for {dbadmin_model.db_name}: {e}"
        _log.error(msg)
    if msg:
        response = {'message': msg}
        tdb.close_client()
        return response
    try:
        tdb.create_db(dbadmin_model.db_name)
        SCHEMA = str(files('ledhntr').joinpath('schemas/schema.tql'))
        tdb.write_tql_file(file=SCHEMA)
        msg = f"Successfully created {dbadmin_model.db_name}!"
    except Exception as e:
        msg = f"Failed creating {dbadmin_model.db_name}: {e}"
        _log.error(msg)
    if msg:
        response = {'message': msg}
        tdb.close_client()
        return response

@router.post("/delete-db")
async def delete_db(
    dbadmin_model: DBName,
    dbadmin_api_key: str = Depends(dep_check_user_role(role_dbadmin))
):
    tdb = get_tdb()
    try:
        tdb.delete_db(dbadmin_model.db_name)
        msg = f"Successfully deleted {dbadmin_model.db_name}!"
    except Exception as e:
        msg = f"Failed deleting {dbadmin_model.db_name}: {e}"
        _log.error(msg)
    response = {'message': msg}
    tdb.close_client()
    return response