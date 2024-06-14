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
    User,
    dep_check_user_role,
    dep_check_self_or_admin,
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
    admin_rights: User = Depends(dep_check_user_role(role_admin))
):
    _log.debug(f"Received: {user}")
    new_user = await User.create_user(user)
    response = new_user.to_dict()
    return response

@router.post("/delete-user")
async def delete_user(
    user: UserModel,
    admin_rights: User = Depends(dep_check_user_role(role_admin))
):
    _log.debug(f"Received: {user}")
    await User.delete_user(user)
    response = {'message': f'Deleted {user}'}
    return response

# @router.post("/update-user", response_model=UserModel)
@router.post("/update-user")
async def update_user(
    modified_user: UserModel,
    verified: bool = Depends(dep_check_self_or_admin)
):
    _log.debug(f"Received: {modified_user}")

    updated_user = await User.update_user(user=modified_user)
    # response = UserModel(**updated_user.to_dict())
    # response = UserModel()
    response = updated_user.to_dict()
    return response

@router.get("/list-users")
async def list_users(
    admin: User = Depends(dep_check_user_role(role_admin))
):
    _log.debug(f"Received: {admin}")
    all_users = await User.list_all_users()
    return all_users


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

'''
@router.get("/list-users")
async def list_users(
    admin_api_key: str = Depends(dep_check_role(role_admin))
):
    users = await key_manager.list_users()
    return users
'''
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