from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import LONGBLOB
from app.database import Base

### User 모델 ###
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)  # Added length
    email = Column(String(255), nullable=False, unique=True)  # Added length
    profileimg = Column(String(255))  # Added length

    prompts = relationship("Prompt", back_populates="user")
    results = relationship("Result", back_populates="user")
    collections = relationship("Collection", back_populates="user")

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

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    result_id = Column(Integer, ForeignKey('results.id', ondelete='CASCADE'), nullable=False)
    prompt_id = Column(Integer, ForeignKey('prompts.id', ondelete='CASCADE'), nullable=False)

    user = relationship("User", back_populates="collections")
    result = relationship("Result", back_populates="collections")
    prompt = relationship("Prompt", back_populates="collections")
