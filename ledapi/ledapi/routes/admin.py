from fastapi import APIRouter, Depends, Query, status
from ledhntr.data_classes import Attribute, Entity, Relation

from ledapi.config import(
    led,
    _log,
    get_tdb
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
from ledapi.worker_manager import(
    get_all_workers,
    get_worker_status,
    restart_all_workers,
    start_all_workers,
    start_worker,
    stop_all_workers,
    stop_worker,
)



router = APIRouter()

#@##############################################################################
#@### ADMIN ENDPOINTS
#@##############################################################################

#&##############################################################################
#&### USER MANAGEMENT ENDPOINTS
#&##############################################################################

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

#&##############################################################################
#&### WORKER MANAGEMENT ENDPOINTS
#&##############################################################################

@router.get("/get-all-workers")
async def get_all_workers_ep(
    verified: bool = Depends(dep_check_user_role(role_admin))
):
    response = await get_all_workers()
    return {
        "message": response,
        "status": status.HTTP_200_OK,
    }

@router.get("/get-worker-status/{worker_name}/{worker_id}")
async def get_worker_status_ep(
    worker_name: str,
    worker_id: int,
    verified: bool = Depends(dep_check_user_role(role_admin))
):
    response = await get_worker_status(worker_name, worker_id)
    return {
        "message": response,
        "status": status.HTTP_200_OK,
    }

@router.get("/restart-all-workers")
async def restart_all_workers_ep(
    verified: bool = Depends(dep_check_user_role(role_admin))
):
    response = await restart_all_workers()
    return {
        "message": response,
        "status": status.HTTP_200_OK,
    }

@router.get("/start-all-workers")
async def start_all_workers_ep(
    verified: bool = Depends(dep_check_user_role(role_admin))
):
    response = await start_all_workers()
    return {
        "message": response,
        "status": status.HTTP_200_OK,
    }

@router.get("/start-worker/{worker_name}")
async def start_worker_ep(
    worker_name: str,
    verified: bool = Depends(dep_check_user_role(role_admin))
):
    response = await start_worker(worker_name)
    return {
        "message": response,
        "status": status.HTTP_200_OK,
    }

@router.get("/stop-all-workers")
async def stop_all_workers_ep(
    verified: bool = Depends(dep_check_user_role(role_admin))
):
    response = await stop_all_workers()
    return {
        "message": response,
        "status": status.HTTP_200_OK,
    }

@router.get("/stop-worker/{worker_name}/{worker_id}")
async def stop_worker_ep(
    worker_name: str,
    worker_id: int,
    verified: bool = Depends(dep_check_user_role(role_admin))
):
    response = await stop_worker(worker_name, worker_id)
    return {
        "message": response,
        "status": status.HTTP_200_OK,
    }