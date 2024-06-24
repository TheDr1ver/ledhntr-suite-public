from pydantic import BaseModel, model_validator
from typing import Optional, Dict


#@##############################################################################
#@### Pydantic API models
#@##############################################################################
class JobSubmission(BaseModel):
    db_name: Optional[str] = None
    hunt_name: Optional[str] = None
    plugin: Optional[str] = None
    forced: Optional[bool] = False
    sleep_time: Optional[int] = 15