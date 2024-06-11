import logging
import secrets

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security.api_key import APIKeyHeader

from enum import Enum
from pydantic import BaseModel, ValidationError, model_validator
from typing import Optional, Dict, List

from databases import Database
from sqlalchemy import create_engine, MetaData, Table, Column, String
from sqlalchemy.sql import select


# Set Logger
logging.basicConfig(level=logging.DEBUG)

#@##############################################################################
#@### Load the APIKey Database
#@##############################################################################

DATABASE_URL = "sqlite:///./api_keys.db"
database = Database(DATABASE_URL)
metadata = MetaData()
api_keys_table = Table(
    "api_keys",
    metadata,
    Column("key", String),
    Column("user", String, primary_key=True),
    Column("role", String),
    Column("description", String, nullable=True),
)
engine = create_engine(DATABASE_URL)
metadata.create_all(engine)

#@##############################################################################
#@### Define Access Token/API Key Header
#@##############################################################################

API_KEY_NAME = "access_token"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

#@##############################################################################
#@### Build Key Manager
#@##############################################################################

class APIKeyManager:
    def __init__(self, database: Database):
        self.database = database

    async def generate_key(
            self,
            user: str = None,
            role: str = None,
            description: Optional[str] = "",
    ) -> str:
        key = secrets.token_urlsafe(32)
        query = api_keys_table.insert().values(
            key=key,
            user=user,
            role=role,
            description=description,
        )
        await self.database.execute(query)
        return key

    async def revoke_key(
        self,
        user: Optional[str] = None,
        key: Optional[str] = None,
    ) -> List[str]:
        results = []
        if user:
            query = api_keys_table.delete().where(api_keys_table.c.user == user)
            res = await self.database.execute(query)
            results.append(res)
        if key:
            query = api_keys_table.delete().where(api_keys_table.c.key == key)
            await self.database.execute(query)
            results.append(res)
        return results

    async def validate_key(self, key: str) -> bool:
        # query = select([api_keys_table.c.key]).where(api_keys_table.c.key == key)
        query = select(api_keys_table.c.key).where(api_keys_table.c.key == key)
        result = await self.database.fetch_one(query)
        return result is not None

    async def get_key_role(self, key: str) -> Optional[str]:
        # query = select([api_keys_table.c.role]).where(api_keys_table.c.key == key)
        query = select(api_keys_table.c.role).where(api_keys_table.c.key == key)
        result = await self.database.fetch_one(query)
        if result:
            return result["role"]
        return None

    async def get_key_from_user(self, user: str) -> Optional[str]:
        query = select(api_keys_table.c.key).where(api_keys_table.c.user == user)
        result = await self.database.fetch_one(query)
        if result:
            return result['key']
        return None

    async def get_user_role(self, user: str) -> Optional[str]:
        query = select(api_keys_table.c.role).where(api_keys_table.c.user == user)
        result = await self.database.fetch_one(query)
        if result:
            return result['role']
        return None

    async def list_users(self) -> List[Dict[str, str]]:
        query = select(api_keys_table)
        result = await self.database.fetch_all(query)
        return [dict(row) for row in result]

key_manager = APIKeyManager(database)

async def get_api_key(api_key_header: str = Depends(api_key_header)):
    """Return API Key from the header as long as it's valid.
    """
    if await key_manager.validate_key(api_key_header):
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials",
    )

async def check_role(
    api_key_header: str = Depends(api_key_header),
    roles: List = []
):
    """Check the role of the user accessing the API
    """
    if await key_manager.validate_key(api_key_header):
        role = await key_manager.get_key_role(api_key_header)
        if role in roles:
            return api_key_header
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User is not in {roles}",
        )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials",
    )

#@##############################################################################
#@### Dependency wrappers
#@##############################################################################

def dep_check_role(roles: List=[]):
    """Checks that the api_key_header belongs to one of the roles listed
    """
    async def _dep_check_role(api_key_header: str = Depends(api_key_header)):
        return await check_role(api_key_header, roles)
    return _dep_check_role

#@##############################################################################
#@### Pydantic API models
#@##############################################################################

class RoleEnum(str, Enum):
    read_only = "read-only" # Read-only access to the DB
    conman = "conman" # Allowed to post confidence levels
    hunter = "hunter" # Allowed to create/enable/disable hunts
    dbadmin = "dbadmin" # Allowed to create new databases
    admin = "admin" # handles generating/revoking auth

role_everyone = [
    RoleEnum.read_only,
    RoleEnum.conman,
    RoleEnum.hunter,
    RoleEnum.dbadmin,
    RoleEnum.admin,
]

role_conman = [
    RoleEnum.conman,
    RoleEnum.hunter,
    RoleEnum.dbadmin,
    RoleEnum.admin,
]

role_hunter = [
    RoleEnum.hunter,
    RoleEnum.dbadmin,
    RoleEnum.admin,
]

role_dbadmin = [
    RoleEnum.dbadmin,
    RoleEnum.admin,
]

role_admin = [
    RoleEnum.admin,
]

class APIKeyCreate(BaseModel):
    user: str
    role: RoleEnum
    description: Optional[str] = None

class APIKeyRevoke(BaseModel):
    user: Optional[str] = None
    key: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def check_values(cls, values):
        if not values.get('user') and not values.get('key'):
            raise ValueError('A "user" or "key" must be provided.')
        return values