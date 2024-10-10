from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File, status
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict
from pydantic import create_model, BaseModel
from dotenv import load_dotenv
import redis
import json
from .crud import get_record, get_user_by_reset_token, update_user_password
import os
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
import logging
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from app.database import get_db
from . import crud
from .models import User, Prompt, Result, Collection, CollectionResult
from .utils import sqlalchemy_to_pydantic, create_access_token, decode_access_token, is_token_expired
import requests
import os
import uuid
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from passlib.context import CryptContext
from dotenv import load_dotenv
from .database import SessionLocal
from datetime import datetime, timezone
import pika
from urllib.parse import urlparse
from pydantic import BaseModel
from minio import Minio

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Define origins
origins = [
    "http://118.67.128.129:28282",
    "http://118.67.128.129:25252",
    "http://118.67.128.129:27272",
    "http://112.152.14.116:27272",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_cors_headers(request, call_next):
    logging.debug(f"Request origin: {request.headers.get('origin')}")
    response = await call_next(request)
    origin = request.headers.get('origin')
    if origin in origins:
        response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    logging.debug(f"Response headers: {response.headers}")
    return response

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT secret and algorithm
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 180  # 나중에 수정 필요


### MinIO 클라이언트 설정
minio_client = Minio(
    "118.67.128.129:9000",
    access_key="minio",
    secret_key="minio1234",
    secure=False
)
bucket_name = "test"


# MinIO에서 이미지 삭제
def delete_image_from_minio(image_url: str, user_id: int, prompt_id: int):
    try:
        parsed_url = urlparse(image_url)
        image_name = parsed_url.path.split('/')[-1] 

        object_name = f"{user_id}/{prompt_id}/{image_name}"
        minio_client.remove_object(bucket_name, object_name)
        print(f"MinIO에서 이미지 {object_name}가 성공적으로 삭제되었습니다.")
    except Exception as e:
        print(f"MinIO에서 이미지 삭제 중 오류 발생: {e}")
        raise HTTPException(status_code=500, detail=f"MinIO에서 이미지 삭제 중 오류 발생: {e}")

### users ###
def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

UserCreate = create_model('UserCreate', username=(str, ...), password=(str, ...), email=(str, ...))

@app.post("/register")
def register_user(username: str = Form(...), password: str = Form(...), email: str = Form(...), db: Session = Depends(get_db)):
    db_user = get_user_by_username(db, username=username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    db_email = db.query(User).filter(User.email == email).first()
    if db_email:
        raise HTTPException(status_code=400, detail="Email already registered")

    try:
        hashed_password = pwd_context.hash(password)
        user_data = {"username": username, "hashed_password": hashed_password, "email": email}
        new_user = crud.create_record(db=db, model=User, **user_data)
        return {column.name: getattr(new_user, column.name) for column in new_user.__table__.columns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user: {e}")

def authenticate_user(username: str, password: str, db: Session):
    user = get_user_by_username(db, username)
    if not user or not pwd_context.verify(password, user.hashed_password):
        return False
    return user
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "user_id": user.id}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "user_id": user.id}
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=403, detail="Token is invalid or expired")
        return payload
    except JWTError:
        raise HTTPException(status_code=403, detail="Token is invalid or expired")

@app.get("/verify-token/{token}")
async def verify_user_token(token: str):
    if is_token_expired(token):
        raise HTTPException(status_code=403, detail="Token is expired")
    verify_token(token=token)
    return {"message": "Token is valid"}
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
        logging.debug(f"Decoded token payload: {payload}")
        if payload is None:
            raise credentials_exception
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    logging.debug(f"Authenticated user: {user.username}, ID: {user.id}")
    return user


# 비밀번호 번경
@app.put("/change-password")
def change_password(
    new_password: str = Form(...), 
    token: str = Depends(verify_token), 
    db: Session = Depends(get_db)
):
    user_id = token.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    # 새 비밀번호 해싱
    hashed_password = pwd_context.hash(new_password)

    # 사용자 비밀번호 업데이트
    user.hashed_password = hashed_password
    db.commit()

    return {"message": "비밀번호가 성공적으로 변경되었습니다."}

### prompts ###
# 이미지 생성 요청을 보낼 다른 FastAPI의 URL
SECOND_API_URL = "http://118.67.128.129:27272/generate-image"

@app.post("/api/prompts")
def create_prompt(
    positive_prompt: str = Form(...),  
    negative_prompt: Optional[str] = Form(None),  
    width: Optional[int] = Form(...),  
    height: Optional[int] = Form(...),  
    background_color: Optional[str] = Form(...),  
    pattern: Optional[int] = Form(...),  
    mood: Optional[str] = Form(...),  
    cfg_scale: Optional[float] = Form(...),  
    sampling_steps: Optional[int] = Form(...),  
    seed: Optional[int] = Form(...),  
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logging.debug(f"Received request to create prompt with positive prompt: {positive_prompt} for user ID: {current_user.id}")
    try:
        ai_option = {
            "width": int(width) if width is not None else None,
            "height": int(height) if height is not None else None,
            "background_color": str(background_color) if background_color is not None else None,
            "pattern": int(pattern) if pattern is not None else None,
            "mood": str(mood) if mood is not None else None,
            "cfg_scale": float(cfg_scale) if cfg_scale is not None else None, 
            "sampling_steps": int(sampling_steps) if sampling_steps is not None else None,
            "seed": int(seed) if seed is not None else None
        }

        # None 값 제거
        ai_option = {k: v for k, v in ai_option.items() if v is not None}

        # positive_prompt와 negative_prompt를 content에 JSON 형태로 저장
        content = json.dumps({
            "positive_prompt": positive_prompt,
            "negative_prompt": negative_prompt
        })

        prompt_data = {
            "content": content,
            "ai_option": ai_option,
            "user_id": current_user.id,
            "created_at": datetime.now()
        }

        new_prompt = crud.create_record(db=db, model=Prompt, **prompt_data)
        logging.debug(f"Created new prompt: {new_prompt}")

        # 외부 FastAPI로 프롬프트 전송
        ai_input_data = {
            "user_id": current_user.id,
            "prompt_id": new_prompt.id,
            "content": content,
            "ai_option": ai_option
        }
        logging.debug(f"ai_option: {ai_input_data['ai_option']}")
        response = requests.post(SECOND_API_URL, json=ai_input_data)

        if response.status_code != 200:
            logging.error(f"Failed to send data to second API: {response.text}")
            raise HTTPException(status_code=500, detail="Failed to send data to second API")

        logging.debug(f"Successfully sent data to second API: {response.json()}")

        return {column.name: getattr(new_prompt, column.name) for column in new_prompt.__table__.columns}

    except Exception as e:
        logging.error(f"Error creating prompt: {e}")
        raise HTTPException(status_code=500, detail=f"Error creating prompt: {e}")


# 특정 user id에 대한 프롬프트 모두 보기
@app.get("/api/prompts/user/{user_id}")
def get_user_prompts(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        logging.error("Not authorized to access this user's prompts")
        raise HTTPException(status_code=403, detail="Not authorized to access this user's prompts")
    try:
        return db.query(Prompt).filter(Prompt.user_id == user_id).all()
    except Exception as e:
        logging.error(f"Error fetching user prompts: {e}")
        raise HTTPException.status_code(500, detail=f"Error fetching user prompts: {e}")

# 특정 prompt id에 대한 프롬프트 보기
@app.get("/api/prompts/{prompt_id}")
def get_prompt(prompt_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        prompt = crud.get_record(db=db, model=Prompt, record_id=prompt_id)
        if not prompt or prompt.user_id != current_user.id:
            raise HTTPException.status_code(404, detail="Prompt not found or not authorized")
        return prompt
    except Exception as e:
        raise HTTPException.status_code(500, detail=f"Error fetching prompt: {e}")


### results ###
# result 올리기 -> 테스트용 
# @app.post("/api/results")
# async def create_result(prompt_id: int = Form(...), image: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
#     try:
#         image_data = await image.read()
#         result_data = {"prompt_id": prompt_id, "user_id": current_user.id, "image_data": image_data, "created_at": datetime.now()}
#         db_result = crud.create_record(db=db, model=Result, **result_data)
#         db_result.image_data = base64.b64encode(db_result.image_data).decode('utf-8')
#         ResultResponse = sqlalchemy_to_pydantic(Result)
#         return ResultResponse.from_orm(db_result)
#     except Exception as e:
#         raise HTTPException.status_code(500, detail=f"Error creating result: {e}")


# 특정 prompt id에 대한 이미지 결과 모두 보기
@app.get("/api/results/{prompt_id}")
def get_prompt_results(prompt_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        prompt = crud.get_record(db=db, model=Prompt, record_id=prompt_id)
        if not prompt or prompt.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Prompt not found or not authorized")

        results = db.query(Result).filter(Result.prompt_id == prompt_id).all()

        # 이미지의 개수가 4개인지 확인
        if len(results) != 4:
            return {"message": f"Expected 4 images, but found {len(results)} images", "results": results}

        for result in results:
            result.image_data = result.image_data  # MinIO URL

        return {"message": "Successfully fetched all images for the prompt", "results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching prompt results: {e}")


# 특정 user id에 대한 이미지 결과 모두 보기
@app.get("/api/results/user/{user_id}")
def get_user_results(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this user's results")

    try:
        results = db.query(Result).filter(Result.user_id == user_id).all()

        for result in results:
            result.image_data = result.image_data  # MinIO URL

        return {"results": results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user results: {e}")


# 최근 생성 삭제
@app.delete("/api/results/{result_id}", status_code=status.HTTP_200_OK)
def delete_result(result_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # 삭제할 result 조회
    result = crud.get_record(db=db, model=Result, record_id=result_id)
    if not result or result.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Result를 찾을 수 없거나 권한이 없습니다.")

    try:
        # MinIO에서 이미지 삭제
        if result.image_data:
            delete_image_from_minio(result.image_data, result.user_id, result.prompt_id)  

        # 데이터베이스에서 result 삭제
        crud.delete_record(db=db, model=Result, record_id=result_id)

        return {"message": "Result 및 MinIO 이미지가 성공적으로 삭제되었습니다."}
    except Exception as e:
        logging.error(f"Result 삭제 중 오류 발생: {e}")
        raise HTTPException(status_code=500, detail=f"Result 삭제 중 오류 발생: {e}")



# result_id 로 옵션값 가져오기
@app.get("/api/results/{result_id}/prompt")
def get_prompt_by_result_id(result_id: int, db: Session = Depends(get_db)):
    # result_id로 Result 테이블에서 prompt_id 가져오기
    result = get_record(db=db, model=Result, record_id=result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result를 찾을 수 없습니다.")

    prompt_id = result.prompt_id

    # prompt_id로 Prompt 테이블에서 해당 데이터 가져오기
    prompt = get_record(db=db, model=Prompt, record_id=prompt_id)
    if not prompt:
        raise HTTPException(status_code=404, detail="Prompt를 찾을 수 없습니다.")

    # prompt의 content와 ai_option 반환
    return {
        "content": prompt.content,
        "ai_option": prompt.ai_option
    }

### collections ###
# 컬랙션 만들기
@app.post("/api/collections")
def create_collection_endpoint(collection_name: str = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        # Create a new collection
        new_collection = Collection(
            created_at=datetime.now(),
            user_id=current_user.id,
            collection_name=collection_name
        )
        db.add(new_collection)
        db.commit()
        db.refresh(new_collection)
        new_collection_result = CollectionResult(
            collection_id=new_collection.collection_id,
            result_id=None
        )
        db.add(new_collection_result)
        db.commit()
        db.refresh(new_collection_result)
        return {
            "collection": {column.name: getattr(new_collection, column.name) for column in new_collection.__table__.columns},
            "collection_result": {column.name: getattr(new_collection_result, column.name) for column in new_collection_result.__table__.columns}
        }
    except Exception as e:
        logging.error(f"Error creating collection: {e}")
        raise HTTPException(status_code=500, detail=f"Error creating collection: {e}")

# 특정 user id에 대한 컬랙션 모두 보기
@app.get("/api/collections/user/{user_id}")
def get_user_collections(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        logging.error(f"User {current_user.id} not authorized to access collections of user {user_id}")
        raise HTTPException(status_code=403, detail="Not authorized to access this user's collections")
    try:
        logging.debug(f"Fetching collections for user_id: {user_id}")
        collections = db.query(Collection).filter(Collection.user_id == user_id).all()
        logging.debug(f"Fetched collections: {collections}")
        if not collections:
            logging.debug(f"No collections found for user_id: {user_id}")
            return {"message": "No collections found"}
        collection_list = [
            {
                "collection_id": collection.collection_id,
                "user_id": collection.user_id,
                "collection_name": collection.collection_name,
                "created_at": collection.created_at.isoformat()
            }
            for collection in collections
        ]
        logging.debug(f"Collection list to be returned: {collection_list}")
        return {"collection_list": collection_list}
    except Exception as e:
        logging.error(f"Error fetching collections: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching collections: {e}")

# 특정 이미지 컬랙션에 추가
@app.post("/api/collections/{collection_id}/add_result")
def add_result_to_collection(collection_id: int, result_id: int = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    collection = db.query(Collection).filter(Collection.collection_id == collection_id).first()
    if not collection or collection.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found or not authorized")

    result = db.query(Result).filter(Result.id == result_id).first()
    if not result or result.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Result not found or not authorized")

    # 중복된 이미지인지 확인
    duplicate_result = db.query(CollectionResult).filter(
        CollectionResult.collection_id == collection_id,
        CollectionResult.result_id == result_id
    ).first()

    if duplicate_result:
        raise HTTPException(status_code=400, detail="Image is already in the collection")

    try:
        new_collection_result = CollectionResult(collection_id=collection_id, result_id=result_id)
        db.add(new_collection_result)
        db.commit()
        db.refresh(new_collection_result)
        return {
            "collection_result_id": new_collection_result.id,
            "collection_id": new_collection_result.collection_id,
            "result_id": new_collection_result.result_id
        }
    except Exception as e:
        logging.error(f"Error adding result to collection: {e}")
        raise HTTPException(status_code=500, detail=f"Error adding result to collection: {e}")

# 컬랙션 목록 불러오기 -> 아카이브    
@app.get("/api/collections/user/{user_id}")
def get_user_collections(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this user's collections")

    try:
        collections = db.query(Collection).filter(Collection.user_id == user_id).all()
        collection_list = []

        for collection in collections:
            collection_data = {column.name: getattr(collection, column.name) for column in collection.__table__.columns}
            collection_results = db.query(CollectionResult).filter(CollectionResult.collection_id == collection.collection_id).all()
            images = []

            for collection_result in collection_results:
                result = db.query(Result).filter(Result.id == collection_result.result_id).first()
                if result:
                    result_data = {column.name: getattr(result, column.name) for column in result.__table__.columns}
                    result_data["image_data"] = result.image_data  # MinIO URL
                    images.append(result_data)

            collection_data["images"] = images
            collection_list.append(collection_data)

        return {"collection_list": collection_list}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching collections: {e}")

# 특정 컬렉션 안의 이미지 결과 불러오기
@app.get("/api/collections/{collection_id}/images")
def get_collection_images(collection_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    logging.debug(f"Fetching images for collection_id: {collection_id} by user_id: {current_user.id}")

    # 사용자가 해당 컬렉션의 소유자인지 확인
    collection = db.query(Collection).filter(Collection.collection_id == collection_id, Collection.user_id == current_user.id).first()
    if not collection:
        logging.error(f"Collection not found or not authorized for user_id: {current_user.id}")
        raise HTTPException(status_code=404, detail="Collection not found or not authorized")

    try:
        collection_results = db.query(CollectionResult).filter(CollectionResult.collection_id == collection_id).all()
        images = []

        for collection_result in collection_results:
            result = db.query(Result).filter(Result.id == collection_result.result_id).first()
            if result:
                result_data = {column.name: getattr(result, column.name) for column in result.__table__.columns}
                result_data["image_data"] = result.image_data  # MinIO URL
                images.append(result_data)

        return {"images": images}

    except Exception as e:
        logging.error(f"Error fetching collection images: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching collection images: {e}")


# 컬랙션 삭제
@app.delete("/api/collections/{collection_id}", status_code=status.HTTP_200_OK)
def delete_collection(collection_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    collection = db.query(Collection).filter(Collection.collection_id == collection_id).first()
    if not collection or collection.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found or not authorized")
    try:
        db.query(CollectionResult).filter(CollectionResult.collection_id == collection_id).delete()
        db.query(Collection).filter(Collection.collection_id == collection_id).delete()
        db.commit()
        return {"message": "Collection deleted successfully"}
    except Exception as e:
        logging.error(f"Error deleting collection: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting collection: {e}")

# 컬렉션 이름 변경
@app.put("/api/collections/{collection_id}", status_code=status.HTTP_200_OK)
def update_collection_name(collection_id: int, new_name: str = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    collection = db.query(Collection).filter(Collection.collection_id == collection_id).first()
    if not collection or collection.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found or not authorized")
    crud.update_record(db=db, model=Collection, record_id=collection_id, collection_name=new_name)
    return {"message": "Collection name updated successfully"}

# 컬렉션 안에 있는 이미지 삭제
@app.delete("/api/collections/{collection_id}/results/{result_id}", status_code=status.HTTP_200_OK)
def delete_image_from_collection(collection_id: int, result_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    logging.debug(f"Deleting result_id: {result_id} from collection_id: {collection_id} by user_id: {current_user.id}")
    collection = db.query(Collection).filter(Collection.collection_id == collection_id, Collection.user_id == current_user.id).first()
    if not collection:
        logging.error(f"Collection not found or not authorized for user_id: {current_user.id}")
        raise HTTPException(status_code=404, detail="Collection not found or not authorized")
    collection_result = db.query(CollectionResult).filter(CollectionResult.collection_id == collection_id, CollectionResult.result_id == result_id).first()
    if not collection_result:
        logging.error(f"CollectionResult not found for collection_id: {collection_id} and result_id: {result_id}")
        raise HTTPException(status_code=404, detail="CollectionResult not found")

    try:
        # collection_result 삭제
        crud.delete_record(db=db, model=CollectionResult, record_id=collection_result.id)
        logging.debug(f"Deleted CollectionResult with ID: {collection_result.id}")
        return {"message": "Image successfully removed from collection"}
    except Exception as e:
        logging.error(f"Error deleting image from collection: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting image from collection: {e}")

### AI 진척도 ###
## 이미지 생성 진척도 반환
# Redis 클라이언트 설정
redis_client = redis.Redis(host='118.67.128.129', port=6379, db=0)
@app.get("/progress/{task_id}")
def get_task_progress(task_id: str):
    try:
        redis_key = f"task_progress:{task_id}"
        progress_data = redis_client.get(redis_key)

        if not progress_data:
            raise HTTPException(status_code=404, detail="Progress data not found")

        progress_info = json.loads(progress_data)
        return {
            "task_id": task_id,
            "progress": progress_info.get("progress"),
            "estimated_remaining_time": progress_info.get("estimated_remaining_time")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving progress: {e}")


# RabbitMQ 관리 API를 통해 큐 상태 가져오기
def get_rabbitmq_queue_status(queue_name: str):
    url = f"http://118.67.128.129:15672/api/queues/%2F/{queue_name}"  # %2F는 기본 vhost를 의미
    try:
        response = requests.get(url, auth=HTTPBasicAuth('guest', 'guest'))  # RabbitMQ 관리 API에 접근
        if response.status_code == 200:
            data = response.json()
            ready_count = data.get("messages_ready", 0)  
            unacked_count = data.get("messages_unacknowledged", 0)  
            total_count = data.get("messages", 0)  
            return ready_count, unacked_count, total_count
        else:
            raise Exception(f"Failed to retrieve queue status: {response.status_code} {response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving RabbitMQ queue status: {e}")

# 큐 상태 반환 API
@app.get("/rabbitmq/queue_status")
def get_queue_status(queue_name: str = 'celery'):  # 기본 큐 이름을 'celery'로 설정
    try:
        ready_count, unacked_count, total_count = get_rabbitmq_queue_status(queue_name)
        return {
            "queue_name": queue_name,
            "ready_count": ready_count,
            "unacked_count": unacked_count,
            "total_count": total_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 내 task_id 기준 남은 상황 반환
@app.get("/tasks/{task_id}/position")
def get_task_position(task_id: str):
    try:
        # Redis에서 대기 중인 작업 목록
        task_queue = redis_client.lrange('celery_task_queue', 0, -1)
        task_queue = [task.decode('utf-8') for task in task_queue]

        if task_id not in task_queue:
            raise HTTPException(status_code=404, detail="Task not found in the queue")

        # 내 task_id의 위치
        task_position = task_queue.index(task_id) + 1

        return {
            "task_id": task_id,
            "position_in_queue": task_position,
            "total_tasks_in_queue": len(task_queue)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving task position: {e}")     


##### password  ####
# Gmail SMTP 설정
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = os.getenv("GMAIL_USER")  # .env에서 가져옴
SMTP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")  # 앱 비밀번호
# 비밀번호 해시화 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# 데이터베이스 연결을 위한 세션
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# 이메일 전송 함수
def send_reset_email(to_email: str, reset_token: str):
    sender_email = SMTP_USER
    subject = "비밀번호 재설정 링크"
    reset_link = f"http://118.67.128.129:25252/change-pw?token={reset_token}"
    # 이메일 내용 구성
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = to_email
    message['Subject'] = subject
    body = f"비밀번호를 재설정하려면 아래 링크를 클릭하세요:\n\n{reset_link}"
    message.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # TLS 보안
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(SMTP_USER, to_email, message.as_string())
        server.quit()
        print(f"이메일 전송 성공: {to_email}")
    except Exception as e:
        print(f"이메일 전송 실패: {e}")
# 비밀번호 재설정 요청 (사용자가 이메일을 입력하여 토큰 요청)

# 이메일 요청을 위한 Pydantic 모델 정의
class EmailRequest(BaseModel):
    email: str

@app.post("/api/find-account")
def password_reset_request(email: str = Form(...), db: Session = Depends(get_db)):
    # 사용자 이메일로 사용자 조회
    user = get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    
    # 비밀번호 재설정 토큰 생성 및 만료 시간 설정 (1시간 유효)
    reset_token = str(uuid.uuid4())
    reset_token_expires = datetime.now(timezone.utc) + timedelta(hours=1)
    
    # 토큰을 사용자 정보에 저장
    crud.save_password_reset_token(db, user.id, reset_token, reset_token_expires)
    
    # 이메일로 재설정 링크 전송
    send_reset_email(user.email, reset_token)
    
    return {"message": "비밀번호 재설정 이메일이 전송되었습니다."}


# 패스워드 해시화를 위한 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pydantic 모델 정의
class PasswordResetRequest(BaseModel):
    token: str
    new_password: str

# 비밀번호 재설정 (토큰을 사용하여 새 비밀번호 설정)
@app.post("/api/change-password")
async def reset_password(request: PasswordResetRequest, db: Session = Depends(get_db)):
    # 로그를 추가하여 요청 데이터를 확인
    logging.info(f"Received token: {request.token}")
    logging.info(f"Received new password: {request.new_password}")

    # 토큰을 이용하여 사용자 찾기
    user = crud.get_user_by_reset_token(db, reset_token=request.token)
    if not user:
        raise HTTPException(status_code=400, detail="유효하지 않은 토큰입니다.")
    
    # 토큰이 만료되었는지 확인
    if user.reset_token_expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="토큰이 만료되었습니다.")
    
    # 새 비밀번호 해시화
    hashed_password = pwd_context.hash(request.new_password)
    
    # 비밀번호 업데이트 및 토큰 무효화
    crud.update_user_password(db, user.id, hashed_password)

if __name__ == "__main__":
       import uvicorn
       uvicorn.run(app, host="0.0.0.0", port=8000)
