from fastapi import APIRouter, Depends
# from ledapi.ledapi import auth
# from ledapi.ledapi.config import led, _log, tdb
# import auth
# from config import led, _log, tdb
from ledapi.auth import(
    dep_check_role,
    key_manager,
)
from ledapi.models import(
    APIKeyCreate,
    APIKeyRevoke,
    UserModel,
    role_admin,
)
from ledapi.user import(
    Redis,
    User,
    get_redis_pool,
)
from ledapi.config import led, _log, tdb

from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

router = APIRouter()

#@##############################################################################
#@### ADMIN ENDPOINTS
#@##############################################################################

@router.post("/create-user")
async def create_user(
    user: UserModel,
    redis_pool: Redis = Depends(get_redis_pool)
):
    _log.debug(f"Received: {user}")
    _log.debug(f"Redis Pool: {redis_pool}")
    new_user = await User.create_user(user, redis_pool=redis_pool)
    response = new_user.to_dict()
    return response

@router.post("/generate-key")
async def generate_key(
    api_key_create: APIKeyCreate,
    admin_api_key: str = Depends(dep_check_role(role_admin))
):
    _log.debug(f"Received: {api_key_create}")
    new_key = await key_manager.generate_key(
        api_key_create.user,
        api_key_create.role,
        api_key_create.description
    )
    response = {
        "api_key": new_key,
        "user": api_key_create.user,
        "role": api_key_create.role,
        "description": api_key_create.description
    }
    return response

@router.get("/list-users")
async def list_users(
    admin_api_key: str = Depends(dep_check_role(role_admin))
):
    users = await key_manager.list_users()
    return users

@router.post("/revoke-key")
async def revoke_key(
    api_key_revoke: APIKeyRevoke,
    admin_api_key: str = Depends(dep_check_role(role_admin))
):
    _log.debug(f"Received: {api_key_revoke}")
    results = await key_manager.revoke_key(
        api_key_revoke.user,
        api_key_revoke.key,
    )
    response = {
        "results": results,
    }
    return response