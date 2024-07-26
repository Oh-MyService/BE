from pydantic import BaseModel, create_model
from sqlalchemy.orm import class_mapper
import logging
import jwt
from datetime import datetime, timedelta
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"

logging.basicConfig(level=logging.DEBUG)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logging.debug(f"JWT Token created: {encoded_jwt}")
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logging.debug(f"JWT Token decoded: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logging.error("JWT Token expired")
        return None
    except jwt.JWTError:
        logging.error("JWT Token error")
        return None

def is_token_expired(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
            logging.debug("JWT Token is expired")
            return True
        logging.debug("JWT Token is not expired")
        return False
    except jwt.ExpiredSignatureError:
        logging.debug("JWT Token is expired")
        return True
    except jwt.JWTError:
        logging.debug("JWT Token is invalid")
        return True

def sqlalchemy_to_pydantic(model, name=None):
    mapper = class_mapper(model)
    fields = {
        column.key: (column.type.python_type, ...)
        for column in mapper.columns
    }
    pydantic_model = create_model(name or model.__name__, **fields)
    return pydantic_model
