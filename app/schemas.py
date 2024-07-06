from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

### User 스키마 ###
class UserBase(BaseModel):
    name: str
    email: str

class UserCreate(UserBase):
    picture: Optional[str] = None

class User(UserBase):
    id: int

    class Config:
        orm_mode = True

### Prompt 스키마 ###
class PromptBase(BaseModel):
    content: str
    user_id: int

class PromptCreate(PromptBase):
    pass

class Prompt(PromptBase):
    id: int
    created_at: datetime
    user: User

    class Config:
        orm_mode = True

### Result 스키마 ###
class ResultBase(BaseModel):
    created_at: datetime
    image_data: bytes
    user_id: int
    prompt_id: int

class ResultCreate(ResultBase):
    user_id: int
    prompt_id: int
    pass

class Result(ResultBase):
    id: int
    user: User
    prompt: Prompt

    class Config:
        orm_mode = True

### Collection 스키마 ###
class CollectionBase(BaseModel):
    collection_id: int
    created_at: datetime
    user_id: int
    result_id: Optional[int] = None
    prompt_id: Optional[int] = None
    user: Optional[dict] = None
    result: Optional[dict] = None
    prompt: Optional[dict] = None

    class Config:
        orm_mode = True


class CollectionCreate(CollectionBase):
    created_at: datetime
    result_id: Optional[int] = None
    prompt_id: Optional[int] = None
    pass

class Collection(CollectionBase):
    collection_id: int
    user: User
    results: List[int] = []
    prompt: Prompt

    class Config:
        orm_mode = True

#class AddResultToCollection(BaseModel):
   # result_id: int