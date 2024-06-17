from enum import Enum
from pydantic import BaseModel, Field, model_validator
from typing import Optional, Union, Any, List, Dict, get_type_hints

from ledapi.config import led, _log

NOCHANGE = object()

#@##############################################################################
#@### Pydantic API models
#@##############################################################################

class RoleEnum(str, Enum):
    READ_ONLY = "read-only" # Read-only access to the DB
    CONMAN = "conman" # Allowed to post confidence levels
    HUNTER = "hunter" # Allowed to create/enable/disable hunts
    DBADMIN = "dbadmin" # Allowed to create new databases
    ADMIN = "admin" # handles generating/revoking auth

    @staticmethod
    def is_valid_role(role_str: str) -> bool:
        return role_str in RoleEnum.__members__.values()

class UserModel(BaseModel):
    uuid: Optional[Union[str, Any]] = Field(default=NOCHANGE)
    user_id: Optional[Union[str, Any]] = Field(default=NOCHANGE)
    # role: Optional[str] = None,
    role: Optional[Union[RoleEnum, Any]] = Field(default=NOCHANGE)
    api_key: Optional[Union[str, Any]] = Field(default=NOCHANGE)
    slack_id: Optional[Union[str, Any]] = Field(default=NOCHANGE)
    keybase_id: Optional[Union[str, Any]] = Field(default=NOCHANGE)
    db_name: Optional[Union[str, Any]] = Field(default=NOCHANGE)

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
        _log.debug(f"VALUES: {values}")
        type_hints = get_type_hints(cls)
        for field, field_type in type_hints.items():
            if values.get(field) == "":
                if field_type == Optional[str]:
                    _log.debug(f"CONVERTING {field} from {values[field]} to empty string")
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
    RoleEnum.READ_ONLY,
    RoleEnum.CONMAN,
    RoleEnum.HUNTER,
    RoleEnum.DBADMIN,
    RoleEnum.ADMIN,
]

role_conman = [
    RoleEnum.CONMAN,
    RoleEnum.HUNTER,
    RoleEnum.DBADMIN,
    RoleEnum.ADMIN,
]

role_hunter = [
    RoleEnum.HUNTER,
    RoleEnum.DBADMIN,
    RoleEnum.ADMIN,
]

role_dbadmin = [
    RoleEnum.DBADMIN,
    RoleEnum.ADMIN,
]

role_admin = [
    RoleEnum.ADMIN,
]



