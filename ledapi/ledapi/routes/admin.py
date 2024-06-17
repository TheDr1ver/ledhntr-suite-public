from fastapi import APIRouter, Depends, Query
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
    get_user_by_api_key,
)
from ledapi.config import led, _log, tdb

from ledhntr.data_classes import Attribute, Entity, Relation

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
    response = updated_user.to_dict()
    return response

@router.get("/list-users")
async def list_users(
    admin: User = Depends(dep_check_user_role(role_admin))
):
    _log.debug(f"Received: {admin}")
    all_users = await User.list_all_users()
    return all_users

@router.get("/get-user")
async def get_user(
    user_id: str = Query(None, description="The user_id of the user"),
    uuid: str = Query(None, description="The unique UUID of the user"),
    slack_id: str = Query(None, description="The Slack ID of the user"),
    keybase_id: str = Query(None, description="The Keybase ID of the user"),
    verified: bool = Depends(dep_check_user_role(role_admin))
):
    if uuid:
        user = UserModel(uuid=uuid)
    elif user_id:
        user = UserModel(user_id=user_id)
    elif slack_id:
        user = UserModel(slack_id=slack_id)
    elif keybase_id:
        user = UserModel(keybase_id=keybase_id)
    myuser = await User.get_user(user)
    return myuser.to_dict()

'''
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
'''
