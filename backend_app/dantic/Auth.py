from pydantic import BaseModel


class UserLogin(BaseModel):
    username: str
    password: str

class UserCreate(BaseModel):
    username: str
    password: str

class UploadContent(BaseModel):
    content: str
    filename: str 

class DecryptContetn(BaseModel):
    upload_id: int