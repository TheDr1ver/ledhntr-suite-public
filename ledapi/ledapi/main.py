import logging

from fastapi import FastAPI, Depends, HTTPException, status
from contextlib import asynccontextmanager

from pydantic import BaseModel, model_validator
from typing import Optional, Dict

from ledhntr import LEDHNTR
from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

# from auth import APIKeyCreate, api_key_header, key_manager
import auth

# Set Logger
logging.basicConfig(level=logging.DEBUG)

# Load LEDHNTR
led = LEDHNTR()
tdb = led.load_plugin('typedb_client')

# Load FastAPI
app = FastAPI()

#@##############################################################################
#@### Pydantic API models
#@##############################################################################
class SearchObject(BaseModel):
    label: Optional[str] = None
    value: Optional[str] = None
    ttype: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def check_values(cls, values):
        if not values.get('label') and not values.get('value'):
            raise ValueError('A "label" or "value" must be provided.')
        return values

    @model_validator(mode="before")
    @classmethod
    def check_ttype(cls, values):
        ttype = values.get('ttype').lower()
        if ttype is None:
            ttype = 'entity'
        values['ttype'] = ttype
        if not ttype=='entity' and not ttype=='relation':
            raise ValueError('ttype must be set to "entity" or "relation"')
        return values

    @model_validator(mode="before")
    @classmethod
    def check_label(cls, values):
        label = values.get('label')
        all_labels = []
        for ttype in led.schema.keys():
            for thing in led.schema[ttype]:
                if thing.label not in all_labels:
                    all_labels.append(thing.label)
        if label not in all_labels:
            raise ValueError(f"Label type {label} is not a valid label for this schema.")
        return values

#@##############################################################################
#@### EVERYONE ENDPOINTS
#@##############################################################################

@app.get("/hello-test")
async def read_hello(api_key: str = Depends(auth.dep_check_role(auth.role_everyone))):
    return {"message": f"hello world! api_key_header: {api_key}"}

@app.post("/search")
async def search(
    search_obj: SearchObject,
    everyone_api_key: str = Depends(auth.dep_check_role(auth.role_everyone))
):
    results = []
    # & NEED TO THINK THIS OUT - BASED ON THE LABEL THAT'S SENT, THE SEARCH
    # & OBJECTS WILL BE DIFFERENT
    if search_obj.ttype == 'entity':
        if search_obj.label:
            # so = Entity(label='entity', has=)
            so = None
    return results

#@##############################################################################
#@### CONMAN ENDPOINTS
#@##############################################################################

@app.get("/list-dbs")
async def list_dbs(
    api_key: str = Depends(auth.dep_check_role(auth.role_everyone))
):
    all_dbs = []
    dbs = tdb.get_all_dbs()
    for db in dbs:
        all_dbs.append(str(db))
    return all_dbs

#@##############################################################################
#@### HUNTER ENDPOINTS
#@##############################################################################

#@##############################################################################
#@### DBADMIN ENDPOINTS
#@##############################################################################

@app.post("/delete-db")
async def delete_db(
    db_name: str,
    dbadmin_api_key: str = Depends(auth.dep_check_role(auth.role_dbadmin))
):
    try:
        tdb.delete_db(db_name)
        msg = f"Successfully deleted {db_name}!"
    except Exception as e:
        msg = f"Failed deleting {db_name}: {e}"
        logging.error(msg)
    response = {'message': msg}
    return response

#@##############################################################################
#@### ADMIN ENDPOINTS
#@##############################################################################

@app.post("/generate-key")
async def generate_key(
    api_key_create: auth.APIKeyCreate,
    admin_api_key: str = Depends(auth.dep_check_role(auth.role_admin))
):
    logging.debug(f"Received: {api_key_create}")
    new_key = await auth.key_manager.generate_key(
        api_key_create.user,
        api_key_create.role,
        api_key_create.description
    )
    response = {
        "api_key": new_key,
        "user": api_key_create.user,
        "role": api_key_create.role,
        "description": api_key_create.description
    }
    return response

@app.get("/list-users")
async def list_users(
    admin_api_key: str = Depends(auth.dep_check_role(auth.role_admin))
):
    users = await auth.key_manager.list_users()
    return users

@app.post("/revoke-key")
async def revoke_key(
    api_key_revoke: auth.APIKeyRevoke,
    admin_api_key: str = Depends(auth.dep_check_role(auth.role_admin))
):
    logging.debug(f"Received: {api_key_revoke}")
    results = await auth.key_manager.revoke_key(
        api_key_revoke.user,
        api_key_revoke.key,
    )
    response = {
        "results": results,
    }
    return response

#;##############################################################################
#;### CONTEXT MANAGER
#;##############################################################################

@asynccontextmanager
async def lifespan(app: FastAPI):
    await auth.database.connect()
    yield
    await auth.database.disconnect()

app.router.lifespan_context = lifespan

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)