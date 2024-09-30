from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import LONGBLOB
from app.database import Base

### User 모델 ###
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)  # Added length
    email = Column(String(255), index=True, nullable=False, unique=True)  # Added length
    profileimg = Column(String(255))  # Added length

    prompts = relationship("Prompt", back_populates="user")
    results = relationship("Result", back_populates="user")
    collections = relationship("Collection", back_populates="user")
    
    hashed_password = Column(String, nullable=False)
    reset_token = Column(String, unique=True, index=True, nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)

### Prompt 모델 ###
class Prompt(Base):
    __tablename__ = "prompts"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, nullable=False)
    content = Column(String(255), nullable=False)  # Added length
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)

    user = relationship("User", back_populates="prompts")
    results = relationship("Result", back_populates="prompt")
    collections = relationship("Collection", back_populates="prompt")

### Result 모델 ###
class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, nullable=False)
    image_data = Column(LONGBLOB, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    prompt_id = Column(Integer, ForeignKey('prompts.id', ondelete='CASCADE'), nullable=False)

    user = relationship("User", back_populates="results")
    prompt = relationship("Prompt", back_populates="results")
    collections = relationship("Collection", back_populates="result")

### Collection 모델 ###
class Collection(Base):
    __tablename__ = "collections"

    collection_id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, nullable=True)
   # user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=True)
    #result_id = Column(Integer, ForeignKey('results.id', ondelete='CASCADE'), nullable=False)
    result_id = Column(Integer, ForeignKey('results.id', ondelete='CASCADE'), nullable=True)
    #prompt_id = Column(Integer, ForeignKey('prompts.id', ondelete='CASCADE'), nullable=False)
    prompt_id = Column(Integer, ForeignKey('prompts.id', ondelete='CASCADE'), nullable=True)
    user = relationship("User", back_populates="collections")
    result = relationship("Result", back_populates="collections")
    prompt = relationship("Prompt", back_populates="collections")

    
    
