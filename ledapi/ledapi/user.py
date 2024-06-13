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

from ledapi.config import _log
from ledapi.models.user import(
    UserModel,
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
        self.db_name = active_db if active_db else ""
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
            less_dict[k]=v
        return less_dict
    
    def redisify(self):
        """Serliazer for saving to Redis
        """
        init_dict = self.to_dict()

        result = {}
        for key, value in init_dict.items():
            if key in self._stringify:
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

    async def save_to_redis(self, redis_pool):
        #; Save primary entry by user_id
        _log.debug(f"Saving to {self._redis_key}:")
        _log.debug(f"\n{pformat(self.redisify())}")
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
    async def load_by_uuid(uuid, redis_pool):
        data = await redis_pool.hgetall(f"ledapi_user:{uuid}")
        if not data:
            return None
        user = User(uuid=uuid)
        for key, value in data.items():
            attr = key.decode()
            if attr in user._stringify:
                value = str(value)
            elif attr in user._floatify:
                value = float(value)
            elif attr in user._intify:
                value = int(value)
            elif attr in user._picklefy:
                value = pickle.loads(value)
            else:
                value = value.decode()
            setattr(user, attr, value)
        return user

    @staticmethod
    async def load_by_property(
        prop_type: str = "",
        prop_value: str = "",
        redis_pool: Redis = None,
    ):
        """load user from Redis by property value

        :param prop_type: the type of user property you want to load
        :type prop_type: str, required
        :param prop_value: value of the property you want to search for
        :type prop_value: str, equired
        :param redis_pool: redis client you're connecting to, defaults to None
        :type redis_pool: Redis, optional
        :return: User object or None
        :rtype: User
        """
        _log.debug(f"redis_pool: {redis_pool}")
        uuid = await redis_pool.get(f"index:{prop_type}:{prop_value}")
        if uuid:
            return await User.load_by_uuid(uuid.decode(), redis_pool)
        return None

    @staticmethod
    async def create_user(
        # user_id: str = None,
        # role: str = None,
        user: UserModel = None,
        redis_pool: Redis = None,
        # slack_id: Optional[str] = None,
        # keybase_id: Optional[str] = None,
    ):
        _log.debug(f"redis_pool: {redis_pool}")
        existing = await User.load_by_property(
            prop_type='user_id',
            prop_value=user.user_id,
            redis_pool=redis_pool,
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
        await new_user.save_to_redis(redis_pool=redis_pool)
        _log.info(f"New user created: {new_user.user_id} | {new_user.role} | {new_user.uuid}")
        return new_user

    @staticmethod
    async def delete_user(
        user_id: str = None,
        redis_pool: Redis = None,
    ):
        existing = await User.load_by_property(
            prop_type='user_id',
            prop_value=user_id,
            redis_pool=redis_pool
        )
        if not existing:
            _log.info(f"Attempted to delete user that does not exist: {user_id}")
            return False
        #; Delete reference indexes
        if existing.user_id:
            await redis_pool.delete(f"index:user_id:{existing.user_id}")
        if existing.api_key:
            await redis_pool.delete(f"index:api_key:{existing.api_key}")
        if existing.slack_id:
            await redis_pool.set(f"index:slack_id:{existing.slack_id}")
        if existing.keybase_id:
            await redis_pool.set(f"index:keybase_id:{existing.keybase_id}")
        #; Delete primary hex entry
        await redis_pool.delete(f"ledapi_user:{existing.uuid}")

    #TODO - update_user() - I want to change my role!

#@##############################################################################
#@### Setup Redis Client
#@###
#@### This should probably be loaded as its own LEDHNTR plugin, but since
#@### all we're doing at this point is loading a redis client I'm not too
#@### worried about it.
#@##############################################################################
REDIS_URL = "redis://192.168.70.10"
# redis_client = None

async def get_redis()->Redis:
    '''
    global redis_client
    if redis_client is None:
        redis_client = await redis.from_url(REDIS_URL)
        redis_client
    '''
    redis_client = await redis.from_url(REDIS_URL)
    return redis_client

async def get_user(
    uuid: str = None,
    user_id: str = None,
    api_key: str = None,
    slack_id: str = None,
    keybase_id: str = None,
    redis_pool: Redis = None,
) -> User:
    if uuid:
        user = await User.load_by_uuid(uuid, redis_pool)
    elif user_id:
        user = await User.load_by_property('user_id', user_id, redis_pool)
    elif api_key:
        user = await User.load_by_property('api_key', api_key, redis_pool)
    elif slack_id:
        user = await User.load_by_property('slack_id', slack_id, redis_pool)
    elif keybase_id:
        user = await User.load_by_property('keybase_id', keybase_id, redis_pool)

    if user is None:
        user = User(
            uuid=uuid,
            user_id=user_id,
            api_key=api_key,
            slack_id=slack_id,
            keybase_id=keybase_id,
        )
        await user.save_to_redis(redis_pool)
    return user

'''
async def main():
    redis_pool = await get_redis()
    instance = await get_testclass_instance('user1', redis_pool)
    print(instance)
    pprint(instance.to_dict())
    print(f"Is expired: {instance.is_expired()}")
    instance.set_database("new_database")
    await instance.save_to_redis(redis_pool)

    # Reload and verify
    reloaded = await get_testclass_instance('user1', redis_pool)
    pprint(reloaded.to_dict())

    # What type of object is redis_pool?
    print(redis_pool)
    print(type(redis_pool))
    print(redis_client)
    print(type(redis_client))

await main()
'''

#@##############################################################################
#@### Connect to Redis Pool
#@##############################################################################

# Dependency for accessing Redis Pool
async def get_redis_pool():
    redis_pool = await get_redis()
    try:
        yield redis_pool
    finally:
        await redis_pool.close()

#@##############################################################################
#@### Authentication OPERATIONS
#@##############################################################################

async def get_user_by_api_key(
    api_key_header: str = Depends(api_key_header),
    redis_pool: Redis = Depends(get_redis_pool),
):
    """Return User object based on API Key Header as long as it's valid
    """
    user = await User.load_by_property(
        prop_type='api_key',
        prop_value=api_key_header,
        redis_pool=redis_pool,
    )
    if user:
        return user
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Invalid credentials",
    )

async def check_role(
    user: User = Depends(get_user_by_api_key),
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
    """
    async def _dep_check_role(user: User = Depends(get_user_by_api_key)):
        return await check_role(user, roles)
    return _dep_check_role