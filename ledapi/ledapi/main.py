from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKeyHeader
from typing import Optional
from pydantic import BaseModel

from ledhntr import LEDHNTR
from ledhntr.data_classes import Attribute, Entity, Relation, Thing, Query

led = LEDHNTR()
tdb = led.load_plugin('typedb_client')

app = FastAPI()

security = HTTPBasic()

# Replace these with your actual username and password
USERNAME = "user"
PASSWORD = "password"

# APIKey Example
API_KEY = "abcdef123456"
API_KEY_NAME = "token"

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username == USERNAME and credentials.password == PASSWORD:
        return True
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Basic"},
    )

def get_api_key(api_key_header: str = Depends(api_key_header)):
    if api_key_header == API_KEY:
        return api_key_header
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Could not validate credentials",
    )

@app.get("/hello-test2")
async def read_hello2(api_key: str = Depends(get_api_key)):
    return {"message": f"hello world! api_key_header: {api_key}"}

@app.get("/hello-test")
async def read_hello(credentials: HTTPBasicCredentials = Depends(verify_credentials)):
    return {"message": "hello world"}

@app.get("/list-dbs")
async def list_dbs(api_key: str = Depends(get_api_key)):
    all_dbs = []
    dbs = tdb.get_all_dbs()
    for db in dbs:
        all_dbs.append(str(db))
    return {"message": all_dbs}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)