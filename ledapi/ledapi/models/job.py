from pydantic import BaseModel

class JobSubmission(BaseModel):
    target_db: str
    worker_name: str
    user_id: str
    forced: bool