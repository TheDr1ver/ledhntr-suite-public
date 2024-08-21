import json
import pickle
import secrets
import time

from fastapi import Depends, HTTPException, Request, status
from fastapi.security.api_key import APIKeyHeader

from pprint import pformat
from typing import Optional, Dict, List
import redis.asyncio as redis
from redis.asyncio.client import Redis
from uuid import uuid4

from ledapi.config import _log, redis_manager
from ledapi.models.user import(
    UserModel,
    NOCHANGE,
    role_admin,
    role_dbadmin,
    role_hunter,
    role_conman,
    role_everyone,
)


#@##############################################################################
#@### Define Access Token/API Key Header
#@##############################################################################

API_KEY_NAME = "access-token"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

#@##############################################################################
#@### Define User Object
#@##############################################################################

class User:
    # attributes that can be changed by a user or admin
    changeable = ["api_key", "slack_id", "keybase_id", "db_name"]

    def __init__(
        self,
        uuid: Optional[str] = None,
        role: Optional[str] = None,
        user_id: Optional[str] = None,
        api_key: Optional[str] = None,
        slack_id: Optional[str] = None,
        keybase_id: Optional[str] = None,
        active_db: Optional[str] = None,

    ):
        #& Unique Identifiers
        self.uuid = uuid if uuid else str(uuid4())
        self.user_id = user_id if user_id else ""
        self.api_key = api_key if api_key else ""
        self.slack_id = slack_id if slack_id else ""
        self.keybase_id = keybase_id if keybase_id else ""
        #& RBAC
        self.role = role if role else ""
        #& Preferences
        self.db_name = active_db if active_db else "scratchpad"
        #& Metadata
        self.created_at = time.time()
        #& Internal Variables
        self._redis_key = f"ledapi_user:{self.uuid}"

        #& redis serialize/deserialize types
        self._stringify = []
        self._floatify = ['created_at']
        self._intify = []
        self._picklefy = ['role']

    def to_dict(self):
        full_dict = self.__dict__
        less_dict = {}
        for k, v in full_dict.items():
            if k.startswith("_"):
                continue
            elif v==NOCHANGE:
                continue
            less_dict[k]=v
        return less_dict

    def redisify(self):
        """Serializer for saving to Redis
        """
        init_dict = self.to_dict()

        result = {}
        for key, value in init_dict.items():
            if value == NOCHANGE:
                continue
            elif key in self._stringify:
                result[key] = str(value)
            elif key in self._floatify:
                result[key] = float(value)
            elif key in self._intify:
                result[key] = int(value)
            elif key in self._picklefy:
                result[key] = pickle.dumps(value)
            else:
                result[key] = value
        return result

    async def save_to_redis(
        self,
    ):
        #; Load redis_pool
        redis_pool: Redis = redis_manager.redis
        #; Save primary entry by user_id
        _log.debug(f"Saving to {self._redis_key}:")
        _log.debug(f"Saved Blob: \n{pformat(self.redisify())}")
        await redis_pool.hset(self._redis_key, mapping=self.redisify())
        #; Save additional index entries for other retrieval options
        if self.user_id:
            x = await redis_pool.set(f"index:user_id:{self.user_id}", self.uuid)
            _log.debug(f"Saved user_id: {self.user_id}: {x}")
        if self.api_key:
            x = await redis_pool.set(f"index:api_key:{self.api_key}", self.uuid)
            _log.debug(f"Saved api_key: {self.api_key} : {x}")
        if self.slack_id:
            x = await redis_pool.set(f"index:slack_id:{self.slack_id}", self.uuid)
            _log.debug(f"Saved slack_id: {self.slack_id} : {x}")
        if self.keybase_id:
            x = await redis_pool.set(f"index:keybase_id:{self.keybase_id}", self.uuid)
            _log.debug(f"Saved keybase_id: {self.keybase_id} : {x}")

    @staticmethod
    async def unredis(
        data: List[bytes] = None,
    ):
        """Convert Redis-stored data into Python-actionable
        """
        deserialized = {}
        user = User()
        for key, value in data.items():
            attr = key.decode()
            if attr in user._stringify:
                value = str(value)
            elif attr in user._floatify:
                value = float(value)
            elif attr in user._intify:
                value = int(value)
            elif attr in user._picklefy:
                try:
                    value = pickle.loads(value)
                except pickle.UnpicklingError as e:
                    _log.error(f"Error unpickling {value}: {e}")
                    _log.error(f"Assuming {value} is in some way corrupt,"
                                "so we're dropping it.")
                    value = ""
            else:
                value = value.decode()
            deserialized[attr] = value
        return deserialized

    @staticmethod
    async def load_by_uuid(
        uuid: str = None,
    ):
        #; Load redis_pool
        redis_pool: Redis = redis_manager.redis
        _log.debug(f"Loading user by uuid: {uuid}")
        data = await redis_pool.hgetall(f"ledapi_user:{uuid}")
        if not data:
            _log.debug(f"No data found!")
            return None
        user = User(uuid=uuid)
        deserialized = await User.unredis(data)
        for key, value in deserialized.items():
            setattr(user, key, value)
        return user

    @staticmethod
    async def load_by_property(
        prop_type: str = "",
        prop_value: str = "",
    ):
        """load user from Redis by property value

        :param prop_type: the type of user property you want to load
        :type prop_type: str, required
        :param prop_value: value of the property you want to search for
        :type prop_value: str, required
        :return: User object or None
        :rtype: User
        """
        #; Load redis_pool
        redis_pool: Redis = redis_manager.redis
        # // _log.debug(f"redis_pool: {redis_pool}")
        _log.debug(f"Searching for user with {prop_type}: {prop_value}")
        uuid = await redis_pool.get(f"index:{prop_type}:{prop_value}")
        if uuid:
            return await User.load_by_uuid(uuid.decode())
        return None

    @staticmethod
    async def get_user(
        user_search: UserModel = None,
    ):
        user = None
        if user_search.uuid and not user_search.uuid==NOCHANGE:
            user = await User.load_by_uuid(user_search.uuid)
        elif user_search.user_id and not user_search.user_id==NOCHANGE:
            user = await User.load_by_property('user_id', user_search.user_id)
        elif user_search.api_key and not user_search.api_key==NOCHANGE:
            user = await User.load_by_property('api_key', user_search.api_key)
        elif user_search.slack_id and not user_search.slack_id==NOCHANGE:
            user = await User.load_by_property('slack_id', user_search.slack_id)
        elif user_search.keybase_id and not user_search.keybase_id==NOCHANGE:
            user = await User.load_by_property('keybase_id', user_search.keybase_id)
        if user is not None:
            return user
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User not found: {user_search}",
        )

    @staticmethod
    async def create_user(
        user: UserModel = None,
    ):
        existing = await User.load_by_property(
            prop_type='user_id',
            prop_value=user.user_id,
        )
        if existing:
            _log.info(f"Attempted to create user that already exists: {user.user_id}")
            return existing
        new_user = User(
            user_id=user.user_id,
            role=user.role,
            api_key=secrets.token_urlsafe(32),
            slack_id=user.slack_id,
            keybase_id=user.keybase_id
        )
        await new_user.save_to_redis()
        _log.info(f"New user created: {new_user.user_id} | {new_user.role} | {new_user.uuid}")
        return new_user

    @staticmethod
    async def clean_index(
        redis_pool: Redis = None,
        pattern: str = None,
        old_uuid: str = None,
    ):
        cursor = '0'
        keys = []
        nuked = []

        while cursor != 0:
            cursor, keys = await redis_pool.scan(cursor=cursor, match=pattern)
            for key in keys:
                try:
                    this_uuid = await redis_pool.get(key)
                    this_uuid = this_uuid.decode('utf-8')
                    _log.debug(f"Found uuid: {this_uuid}")
                    if this_uuid == old_uuid:
                        _log.debug(f"Found matching uuid: {this_uuid}=={old_uuid}")
                        value = await redis_pool.delete(key)
                        nuked.append(key)
                except Exception as e:
                    _log.error(f"Failed getting {key}")
                    continue
        _log.debug(f"Cleaned {len(nuked)} keys.")
        return True


    @staticmethod
    async def update_user(
        user: UserModel = None,
    ):
        """Update user settings
        """
        _log.debug(f"Updating with user object: {user}")
        existing = await User.get_user(user)
        if not existing:
            _log.error(f"User {user} does not exist!")
            return False
        #; Load redis_pool
        redis_pool: Redis = redis_manager.redis
        #; Loop through all attributes looking for new values
        for attr_name in dir(existing):
            if attr_name not in User.changeable:
                # UUID and user_id cannot be changed
                # Only attributes listed in User.changeable can be changed.
                _log.debug(f"{attr_name} cannot be changed!")
                continue
            if not attr_name.startswith("_") and not callable(getattr(existing, attr_name)):
                if not hasattr(user, attr_name):
                    # Skip attributes that weren't passed to be changed
                    continue
                attr_value = getattr(user, attr_name)
                _log.debug(f"Checking {attr_name} - user value is {attr_value} {type(attr_value)}")
                if getattr(existing, attr_name, None) is None:
                    _log.error(f"Existing User does not have attribute: {attr_name}")
                    continue
                if attr_value!=NOCHANGE and getattr(existing, attr_name) != attr_value:
                    _log.debug(f"Updating {attr_name} to {attr_value}")
                    #; remove existing index
                    val = getattr(existing, attr_name, None)
                    _log.debug(f"Existing {attr_name} is {val}")
                    if val is not None:
                        if not isinstance(val, str):
                            val = val.decode('utf-8')
                        _log.debug(f"Deleting index:{attr_name}:* == {existing.uuid}")
                        # ! await redis_pool.delete(f"index:{attr_name}:{val}")
                        pattern = f"index:{attr_name}:*"
                        await User.clean_index(redis_pool, pattern, existing.uuid)
                    #; Update attribute
                    # existing.attr_name = attr_value
                    setattr(existing, attr_name, attr_value)
                    #; update index
                    _log.debug(f"Setting new index-> index:{attr_name}:{attr_value} == {existing.uuid}")
                    x = await redis_pool.set(f"index:{attr_name}:{attr_value}", existing.uuid)
                    _log.debug(f"response: {x}")
        #; Save updated object
        _log.debug(f"Saving updated user: {existing.to_dict()}")
        # Serialize
        await existing.save_to_redis()
        return existing

    @staticmethod
    async def delete_user(
        user: UserModel = None,
    ):
        existing = await User.get_user(user)
        if not existing:
            _log.info(f"Attempted to delete user that does not exist: {user}")
            return False
        #; Load redis_pool
        redis_pool: Redis = redis_manager.redis
        #; Delete reference indexes
        if existing.user_id:
            this_key = f"index:user_id:{existing.user_id}"
            this_uuid = await redis_pool.get(this_key)
            if this_uuid:
                this_uuid = this_uuid.decode('utf-8')
                if this_uuid == existing.uuid:
                    await redis_pool.delete(this_key)
        if existing.api_key:
            this_key = f"index:api_key:{existing.api_key}"
            this_uuid = await redis_pool.get(this_key)
            if this_uuid:
                this_uuid = this_uuid.decode('utf-8')
                if this_uuid == existing.uuid:
                    await redis_pool.delete(this_key)
        if existing.slack_id:
            this_key = f"index:slack_id:{existing.slack_id}"
            this_uuid = await redis_pool.get(this_key)
            if this_uuid:
                this_uuid = this_uuid.decode('utf-8')
                if this_uuid == existing.uuid:
                    await redis_pool.delete(this_key)
        if existing.keybase_id:
            this_key = f"index:keybase_id:{existing.keybase_id}"
            this_uuid = await redis_pool.get(this_key)
            if this_uuid:
                this_uuid = this_uuid.decode('utf-8')
                if this_uuid == existing.uuid:
                    await redis_pool.delete(this_key)
        #; Delete primary hex entry
        await redis_pool.delete(f"ledapi_user:{existing.uuid}")
        _log.debug(f"Finished deleting all references to {existing}")

    @staticmethod
    async def list_all_users():
        #; Load redis_pool
        redis_pool: Redis = redis_manager.redis
        all_users = []
        cursor = '0'
        keys = []
        idx = {}

        #; SCAN to find keys with specified prefix
        # patterns = ["index:user_id:*", "index:api_key:*", "index:slack_id:*", "index:keybase_id:*"]
        patterns = ["index:slack_id:*"]
        for pattern in patterns:
            idx[pattern] = {}
            while cursor != 0:
                cursor, keys = await redis_pool.scan(cursor=cursor, match=pattern)
                for key in keys:
                    try:
                        value = await redis_pool.get(key)
                    except Exception as e:
                        _log.error(f"Failed getting {key}")
                        continue
                    idx[pattern][key.decode('utf-8')] = value.decode('utf-8')
        hash_keys = []
        while True:
            cursor, partial_keys = await redis_pool.scan(cursor=cursor, match="ledapi_user:*")
            # // _log.debug(f"Cursor: {cursor}, Keys found: {partial_keys}")
            hash_keys.extend(partial_keys)
            if cursor == 0:
                break

        #; Dump the values of the keys
        for key in hash_keys:
            value = await redis_pool.hgetall(key)
            all_users.append(value)

        clean_users = []
        # // _log.debug(f"all_users bytes: {all_users}")
        for user in all_users:
            res = await User.unredis(user)
            clean_users.append(res)
        _log.debug(f"All users found: {clean_users}")
        final = {'users': clean_users, 'indices': idx}
        return final


#@##############################################################################
#@### Authentication OPERATIONS
#@##############################################################################

async def get_user_by_api_key(
    api_key_header: str = Depends(api_key_header),
):
    """Return User object based on API Key Header as long as it's valid
    """
    user = await User.load_by_property(
        prop_type='api_key',
        prop_value=api_key_header,
    )
    if user:
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Invalid credentials",
    )

async def get_user_by_slack_id(
    request: Request,
):
    """Return User object based on SlackID,TeamID as long as it's valid
    """
    try:
        # body = await request.body()
        form = await request.form()
        _log.debug(f"FORM:")
        _log.debug(f"{pformat(form)}")
        # data = json.loads(body)
        # user_id = data['user']['id']
        # team_id = data['user']['team_id']
        user_id = form.get('user_id')
        team_id = form.get('team_id')
        _log.debug(f"user_id: {user_id}")
        _log.debug(f"team_id: {team_id}")
        if not (user_id or team_id):
            _log.debug(f"Getting user info from form payload")
            payload = form.get('payload')
            _log.debug(f"PAYLOAD: {payload}")
            if payload is not None:
                payload = json.loads(payload) # serialize
                user_info = payload.get('user')
                _log.debug(f"USER_INFO:{user_info}")
                if user_info:
                    user_id = user_info.get('id')
                    team_id = user_info.get('team_id')
        slack_id = f"({user_id},{team_id})"
        user = await User.load_by_property(
            prop_type="slack_id",
            prop_value=slack_id,
        )
    except Exception as e:
        _log.error(f"Unable to load user by slack_id: {e}")
        raise
    if user:
        _log.debug(f"Successfully loaded user {user}")
        return user
    else:
        _log.debug(f"Unable to find user with slack_id {slack_id}")
        return None
    _log.debug(f"Unable to find user with slack_id {slack_id}")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Invalid credentials",
    )

async def check_role(
    user: User = None,
    roles: List = []
)->User:
    """Check the role of the user accessing the API
    """
    #; when we're using role_public that means it's okay for a non-user to submit
    #; something - like an addme request
    if None in roles:
        return user
    if hasattr(user, 'role') and user.role in roles:
        return user
    _log.error(f"{user.user_id} is not in {roles}")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"{user.user_id} is not in {roles}",
    )

#@##############################################################################
#@### Dependency wrappers
#@##############################################################################

def dep_check_user_role(roles: List=[]):
    """Check that the user belongs to one of the roles listed
    NOTE: This one needs a wrapper function while dep_check_self_or_admin
    does not because this one takes an argument (role_X) from the route, but all
    dep_check_self_or_admin takes is user- and self-generated input.
    """
    async def _dep_check_role(user: User = Depends(get_user_by_api_key)):
        return await check_role(user, roles)
    return _dep_check_role

def dep_check_user_role_by_slack(roles: List=[]):
    """Checks that a user belongs to one of the roles listed
    This is done by using the SlackID,TeamID combo for the user
    """
    async def _dep_check_role_slack(user: User = Depends(get_user_by_slack_id)):
        return await check_role(user, roles)
    return _dep_check_role_slack


async def dep_check_self_or_admin(
    modified_user: UserModel = None,
    user: User = Depends(get_user_by_api_key)
)->bool:
    """Check if user submitting change request is either self or Admin
    """
    is_admin = False
    is_self = False
    if user.role in role_admin:
        is_admin = True
    unique_values = ["user_id", "api_key", "uuid"]
    for uv in unique_values:
        if getattr(user, uv) == getattr(modified_user, uv):
            is_self = True
    if not is_admin:
        if getattr(modified_user, 'role') and \
        getattr(user, 'role') != getattr(modified_user, 'role'):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Non-admin user cannot change their own role."
            )
    if is_admin or is_self:
        return True
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"You don't have permissions to modify {modified_user}."
    )