from pydantic import BaseModel, model_validator
from typing import Optional, Dict, Union

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
class ConmanObject(BaseModel):
    db_name: str = None
    label: Optional[str] = None
    value: Optional[str] = None
    confidence: Union[str, int] = None
    iid: Optional[str] = None
    ttype: Optional[str] = None

    #* Make sure we have a label, confidence, and a value
    @model_validator(mode="before")
    @classmethod
    def check_values(cls, values):
        if ((not values.get('label') and not values.get('iid')) or
        not values.get('confidence')):
            raise ValueError(
                '("iid" OR "value") AND "confidence" must be provided.'
            )
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

    #* If provided, make sure label is actually a valid thing
    @model_validator(mode="before")
    @classmethod
    def check_label(cls, values):
        label = values.get('label')
        if label is not None and label not in led.all_labels['thing']:
            raise ValueError(f"Label type {label} is not a valid label for this schema.")
        return values

    #* Make sure db_name is a valid database name
    @model_validator(mode="before")
    @classmethod
    def check_db(cls, values):
        db_name = values.get('db_name')
        if not db_name:
            raise ValueError(f"db_name is required!")
        tdb = get_tdb()
        all_dbs = tdb.get_all_dbs(readable=True)
        tdb.close_client()
        if db_name not in all_dbs:
            raise ValueError(f"Database {db_name} does not exist!")
        return values
