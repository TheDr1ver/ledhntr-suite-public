from enum import Enum
from pydantic import BaseModel, model_validator
from typing import Optional, List, Dict, get_type_hints

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

    @staticmethod
    def is_valid_role(role_str: str) -> bool:
        return role_str in RoleEnum.__members__.values()

class UserModel(BaseModel):
    uuid: Optional[str] = None,
    user_id: Optional[str] = None,
    # role: Optional[str] = None,
    role: RoleEnum = None,
    api_key: Optional[str] = None,
    slack_id: Optional[str] = None,
    keybase_id: Optional[str] = None,
    active_db: Optional[str] = None,

    #~ Check that at least one of the following is included when submitting
    #~ a User object
    @model_validator(mode="before")
    @classmethod
    def check_values(cls, values):
        req_keys = ['uuid', 'user_id', 'api_key', 'slack_id', 'keybase_id']
        if not any(values.get(key) for key in req_keys):
            raise ValueError(f'One of the following keys must be provided: {req_keys}')
        return values
    
    #~ Convert any None values to empty strings
    @model_validator(mode="before")
    @classmethod
    def no_none(cls, values):
        type_hints = get_type_hints(cls)
        for field, field_type in type_hints.items():
            if values.get(field) is None:
                if field_type == Optional[str]:
                    values[field] = ""
                elif field_type == Optional[List]:
                    values[field] = []
                elif field_type == Optional[Dict]:
                    values[field] = {}
        return values
    
    #~ Validate role
    '''
    @model_validator(mode="before")
    @classmethod
    def validate_role(cls, values):
        values['role'] = values['role'].lower()
        role_val = values.get('role')
        valid = RoleEnum.is_valid_role(role_val)
        if not valid:
            raise ValueError(f"Invalid role {role_val}")
        return values
    '''

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



