import logging

from fastapi import FastAPI, Depends, HTTPException, status
from contextlib import asynccontextmanager

# from auth import APIKeyCreate, api_key_header, key_manager
# import ledapi.ledapi.auth.auth as auth
# import auth
from ledapi import auth
from ledapi.config import led, _log
from ledapi.routes import (
    everyone,
    conman,
    hunter,
    dbadmin,
    admin
)

# Set Logger
# logging.basicConfig(level=logging.DEBUG)

# Load FastAPI
app = FastAPI()
app.include_router(everyone.router, tags=["everyone"])
app.include_router(conman.router, tags=["conman"])
app.include_router(hunter.router, tags=["hunter"])
app.include_router(dbadmin.router, tags=["dbadmin"])
app.include_router(admin.router, tags=["admin"])

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