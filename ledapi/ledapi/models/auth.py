from enum import Enum
from pydantic import BaseModel, model_validator
from typing import Optional, Dict

# from ledapi.ledapi.config import led, _log
# from config import led, _log
from ledapi.config import led, _log

#@##############################################################################
#@### Pydantic API models
#@##############################################################################

class RoleEnum(str, Enum):
    read_only = "read-only" # Read-only access to the DB
    conman = "conman" # Allowed to post confidence levels
    hunter = "hunter" # Allowed to create/enable/disable hunts
    dbadmin = "dbadmin" # Allowed to create new databases
    admin = "admin" # handles generating/revoking auth

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

#@##############################################################################
#@### Role Groups
#@##############################################################################

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



