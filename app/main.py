from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File, status
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
from pydantic import create_model
from dotenv import load_dotenv
import base64
import os
from datetime import datetime, timedelta
import logging
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from app.database import get_db
from . import crud
from .models import User, Prompt, Result, Collection, CollectionResult
from .utils import sqlalchemy_to_pydantic, create_access_token, decode_access_token, is_token_expired
import requests

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Define origins
origins = [
    "http://43.202.57.225:29292",
    "https://43.202.57.225:29292",
    "http://43.202.57.225:28282",
    "https://43.202.57.225:28282",
    "http://43.202.57.225:25252",
    "http://223.194.20.119:27272",
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
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 나중에 수정 필요

### users ###
def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

UserCreate = create_model('UserCreate', username=(str, ...), password=(str, ...))

@app.post("/register")
def register_user(username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    db_user = get_user_by_username(db, username=username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    try:
        hashed_password = pwd_context.hash(password)
        user_data = {"username": username, "hashed_password": hashed_password}
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


### prompts ###
# 이미지 생성 요청을 보낼 다른 FastAPI의 URL
SECOND_API_URL = "http://112.152.14.116:27272/generate-image"

# prompt 입력하기

@app.post("/api/prompts")
def create_prompt(content: str = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    logging.debug(f"Received request to create prompt with content: {content} for user ID: {current_user.id}")
    try:
        # 데이터베이스에 프롬프트 저장
        prompt_data = {"content": content, "user_id": current_user.id, "created_at": datetime.now()}
        new_prompt = crud.create_record(db=db, model=Prompt, **prompt_data)
        logging.debug(f"Created new prompt: {new_prompt}")

        # 프롬프트 ID를 포함하여 데이터 전송
        ai_input_data = {
            "user_id": current_user.id, 
            "prompt_id": new_prompt.id,  # new_prompt.id 사용
            "content": content
        }
        response = requests.post(SECOND_API_URL, json=ai_input_data)
        
        if response.status_code != 200:
            logging.error(f"Failed to send data to second API: {response.text}")
            raise HTTPException(status_code=500, detail="Failed to send data to second API")

        logging.debug(f"Successfully sent data to second API: {response.json()}")
        
        # 저장된 프롬프트 데이터 반환
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
@app.post("/api/results")
async def create_result(prompt_id: int = Form(...), image: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        image_data = await image.read()
        result_data = {"prompt_id": prompt_id, "user_id": current_user.id, "image_data": image_data, "created_at": datetime.now()}
        db_result = crud.create_record(db=db, model=Result, **result_data)
        db_result.image_data = base64.b64encode(db_result.image_data).decode('utf-8')
        ResultResponse = sqlalchemy_to_pydantic(Result)
        return ResultResponse.from_orm(db_result)
    except Exception as e:
        raise HTTPException.status_code(500, detail=f"Error creating result: {e}")
    

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
            raise HTTPException(status_code=400, detail=f"Expected 4 images, but found {len(results)} images")
        
        for result in results:
            result.image_data = base64.b64encode(result.image_data).decode('utf-8')
        
        return results

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching prompt results: {e}")


# 특정 user id에 대한 이미지 결과 모두 보기
@app.get("/api/results/user/{user_id}")
def get_user_results(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException.status_code(403, detail="Not authorized to access this user's results")
    try:
        results = db.query(Result).filter(Result.user_id == user_id).all()
        for result in results:
            result.image_data = base64.b64encode(result.image_data).decode('utf-8')
        return results
    except Exception as e:
        raise HTTPException.status_code(500, detail=f"Error fetching user results: {e}")
    
# 최근 생성 삭제
@app.delete("/api/results/{result_id}", status_code=status.HTTP_200_OK)
def delete_result(result_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    result = crud.get_record(db=db, model=Result, record_id=result_id)
    if not result or result.user_id != current_user.id:raise HTTPException(status_code=404, detail="Result not found or not authorized")
    crud.delete_record(db=db, model=Result, record_id=result_id)
    return {"message": "Result deleted successfully"}


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
                result = db.query(Result).filter(Result.result_id == collection_result.result_id).first()
                if result:
                    result_data = {column.name: getattr(result, column.name) for column in result.__table__.columns}
                    result_data["image_data"] = base64.b64encode(result.image_data).decode('utf-8')
                    images.append(result_data)
            collection_data["images"] = images
            collection_list.append(collection_data)
        return {"collection_list": collection_list}
    except Exception as e:
        raise HTTPException.status_code(500, detail=f"Error fetching collections: {e}")
    
 # 해당 컬렉션 눌렀을 때 이미지 불러오기
@app.get("/api/collections/{collection_id}/images")
def get_collection_images(collection_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    logging.debug(f"Fetching images for collection_id: {collection_id} by user_id: {current_user.id}")
    # Ensure the user owns the collection
    collection = db.query(Collection).filter(Collection.collection_id == collection_id, Collection.user_id == current_user.id).first()
    if not collection:
        logging.error(f"Collection not found or not authorized for user_id: {current_user.id}")
        raise HTTPException(status_code=404, detail="Collection not found or not authorized")
    
    try:

        collection_results = db.query(CollectionResult).filter(CollectionResult.collection_id == collection_id).all()
        logging.debug(f"Collection results: {collection_results}")
        images = []

        for collection_result in collection_results:
            result = db.query(Result).filter(Result.id == collection_result.result_id).first()
            logging.debug(f"Fetched result: {result}")
            if result:
                result_data = {column.name: getattr(result, column.name) for column in result.__table__.columns}
                result_data["image_data"] = base64.b64encode(result.image_data).decode('utf-8')
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



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
