import pickle
import secrets
import time

from fastapi import Depends, HTTPException, status
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

API_KEY_NAME = "access_token"
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
        self.db_name = active_db if active_db else "all"
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
            await redis_pool.set(f"index:user_id:{self.user_id}", self.uuid)
        if self.api_key:
            await redis_pool.set(f"index:api_key:{self.api_key}", self.uuid)
        if self.slack_id:
            await redis_pool.set(f"index:slack_id:{self.slack_id}", self.uuid)
        if self.keybase_id:
            await redis_pool.set(f"index:keybase_id:{self.keybase_id}", self.uuid)

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
                    if val is not None:
                        await redis_pool.delete(f"index:{attr_name}:{val}")
                    #; Update attribute
                    # existing.attr_name = attr_value
                    setattr(existing, attr_name, attr_value)
                    #; update index
                    await redis_pool.set(f"index:{attr_name}:{attr_value}", existing.uuid)
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
            await redis_pool.delete(f"index:user_id:{existing.user_id}")
        if existing.api_key:
            await redis_pool.delete(f"index:api_key:{existing.api_key}")
        if existing.slack_id:
            await redis_pool.delete(f"index:slack_id:{existing.slack_id}")
        if existing.keybase_id:
            await redis_pool.delete(f"index:keybase_id:{existing.keybase_id}")
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

        #; SCAN to find keys with specified prefix
        while True:
            cursor, partial_keys = await redis_pool.scan(cursor=cursor, match="ledapi_user:*")
            # // _log.debug(f"Cursor: {cursor}, Keys found: {partial_keys}")
            keys.extend(partial_keys)
            if cursor == 0:
                break

        #; Dump the values of the keys
        for key in keys:
            value = await redis_pool.hgetall(key)
            all_users.append(value)

        clean_users = []
        # // _log.debug(f"all_users bytes: {all_users}")
        for user in all_users:
            res = await User.unredis(user)
            clean_users.append(res)
        _log.debug(f"All users found: {clean_users}")
        return clean_users


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

async def check_role(
    user: User = None,
    roles: List = []
)->User:
    """Check the role of the user accessing the API
    """
    if user.role in roles:
        return user
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