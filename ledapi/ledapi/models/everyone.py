from pydantic import BaseModel, model_validator
from typing import Optional, Dict

# from ledapi.ledapi.config import led, _log
# from config import led, _log
from ledapi.config import(
    led,
    _log,
    get_tdb,
)


#@##############################################################################
#@### Pydantic API models
#@##############################################################################
class DBName(BaseModel):
    db_name: Optional[str] = None

class SearchObject(BaseModel):
    db_name: Optional[str] = None
    label: Optional[str] = None
    new_days_back: Optional[int] = None
    ttype: Optional[str] = None
    value: Optional[str] = None

    #* Make sure we have at least one value or label
    @model_validator(mode="before")
    @classmethod
    def check_values(cls, values):
        if not values.get('label') and not values.get('value'):
            raise ValueError('A "label" or "value" must be provided.')
        return values

    #* Make sure the ttype (if provided) is either entity or relation
    #* Defaults to "entity"
    @model_validator(mode="before")
    @classmethod
    def check_ttype(cls, values):
        ttype = values.get('ttype')
        if ttype is None:
            ttype = 'entity'
        else:
            ttype = ttype.lower()
        values['ttype'] = ttype
        if not ttype=='entity' and not ttype=='relation':
            raise ValueError('ttype must be set to "entity" or "relation"')
        return values

    #* Make sure if there was a label provided that it's actually a valid thing
    @model_validator(mode="before")
    @classmethod
    def check_label(cls, values):
        label = values.get('label')
        if not label is None and label not in led.all_labels['thing']:
            raise ValueError(f"Label type {label} is not a valid label for this schema.")
        return values

    #* If db_name is passed, make sure it's a valid database name
    @model_validator(mode="before")
    @classmethod
    def check_db(cls, values):
        db_name = values.get('db_name')
        tdb = get_tdb()
        if db_name:
            all_dbs = tdb.get_all_dbs(readable=True)
            if db_name not in all_dbs:
                raise ValueError(f"Database {db_name} does not exist!")
        return values

    #* If new_days_back is set, make sure it's > 0
    @model_validator(mode="before")
    @classmethod
    def ndb_gt_zero(cls, values):
        ndb = values.get('new_days_back')
        if not ndb is None:
            if ndb < 1:
                raise ValueError(f"new_days_back must be an integer > 0.")
        return values
