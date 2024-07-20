from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
from typing import List
from dotenv import load_dotenv
import base64
import os
from datetime import datetime
import json
import logging

from . import crud
from .database import get_db
from .models import User, Prompt, Result, Collection, CollectionResult
from .utils import sqlalchemy_to_pydantic

# .env 파일에서 환경 변수 로드
load_dotenv()

# 로깅 설정
logging.basicConfig(level=logging.DEBUG)

app = FastAPI()

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://43.202.57.225:29292",
        "http://43.202.57.225:25252",
        "http://inkyong.com",
        "https://inkyong.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 세션 미들웨어 설정
app.add_middleware(SessionMiddleware, 
    secret_key=os.getenv("SESSION_SECRET_KEY"),
    session_cookie="session",
    max_age=3600,
    same_site="None",
    https_only=False  # HTTP 환경에서는 False로 설정
)

# .env 파일에서 Google OAuth 환경 변수 읽기
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://inkyong.com/auth")
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

@app.get("/api/login")
async def login():
    try:
        return RedirectResponse(
            f"{AUTHORIZATION_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=openid%20email%20profile"
        )
    except Exception as e:
        logging.error(f"Error during login: {e}")
        raise HTTPException(status_code=500, detail=f"Error during login: {e}")

@app.get("/auth")
async def auth(request: Request, code: str, db: Session = Depends(get_db)):
    try:
        logging.debug("Received code: %s", code)
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                TOKEN_URL,
                data={
                    "code": code,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "redirect_uri": REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            )
            logging.debug("Token response status: %s", token_response.status_code)
            token_response.raise_for_status()
            token_response_data = token_response.json()
            logging.debug("Token response data: %s", token_response_data)
            access_token = token_response_data.get("access_token")
            if not access_token:
                logging.error("Invalid client credentials")
                raise HTTPException(status_code=401, detail="Invalid client credentials")

            user_info_response = await client.get(
                USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            logging.debug("User info response status: %s", user_info_response.status_code)
            user_info_response.raise_for_status()
            user_info = user_info_response.json()
            logging.debug("User info data: %s", user_info)
            email = user_info.get("email")
            name = user_info.get("name")
            picture = user_info.get("picture")

            # 데이터베이스에서 사용자 조회
            db_user = db.query(User).filter(User.email == email).first()
            if not db_user:
                # 사용자 데이터가 없으면 새 사용자 생성
                user_data = {"email": email, "name": name, "profileimg": picture}
                db_user = crud.create_record(db=db, model=User, **user_data)

            # 세션에 사용자 정보 저장 (JSON 문자열로 저장)
            user_info_str = json.dumps({"user_id": db_user.id, "email": email, "name": name, "picture": picture}, ensure_ascii=False)
            request.session['user_info'] = user_info_str
            logging.debug(f"세션에 저장된 사용자 정보: {user_info_str}")  # 세션에 저장된 정보 출력

            # 세션이 제대로 설정되었는지 확인하기 위한 디버깅
            response = RedirectResponse(url="http://43.202.57.225:29292/login-complete")
            return response
    except HTTPException as e:
        logging.error(f"HTTP Exception during authentication: {e}")
        raise e
    except Exception as e:
        logging.error(f"Error during authentication: {e}")
        raise HTTPException(status_code=500, detail=f"Error during authentication: {e}")

@app.get("/api/user_info")
async def get_user_info(request: Request):
    logging.debug(f"세션이 존재하나요?: {bool(request.session)}")
    user_info_str = request.session.get('user_info')
    logging.debug(f"세션에서 가져온 사용자 정보: {user_info_str}")  # 세션에서 가져온 정보 출력
    if user_info_str:
        user_info = json.loads(user_info_str)
        return JSONResponse(content=user_info)
    else:
        raise HTTPException(status_code=401, detail="User not authenticated")

# 나머지 엔드포인트는 동일하게 유지

### prompts ###
# 입력한 프롬프트 저장
@app.post("/api/prompts/")
def create_prompt(prompt_data: dict, db: Session = Depends(get_db)):
    try:
        prompt_data['created_at'] = datetime.now()
        return crud.create_record(db=db, model=Prompt, **prompt_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating prompt: {e}")

# 해당 유저 id의 프롬프트 전체 불러오기
@app.get("/api/prompts/user/{user_id}")
def get_user_prompts(user_id: int, db: Session = Depends(get_db)):
    try:
        prompts = db.query(Prompt).filter(Prompt.user_id == user_id).all()
        return prompts
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user prompts: {e}")

# 해당 프롬프트 id의 프롬프트 전체 불러오기
@app.get("/api/prompts/{prompt_id}")
def get_prompt(prompt_id: int, db: Session = Depends(get_db)):
    try:
        prompt = db.query(Prompt).filter(Prompt.id == prompt_id).first()
        if not prompt:
            raise HTTPException(status_code=404, detail="Prompt not found")
        return prompt
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching prompt: {e}")

### results ###
# 결과 이미지 업로드    
@app.post("/api/results/")
async def create_result(prompt_id: int = Form(...), user_id: int = Form(...), image: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        image_data = await image.read()
        result_data = {"prompt_id": prompt_id, "user_id": user_id, "image_data": image_data, "created_at": datetime.now()}
        db_result = crud.create_record(db=db, model=Result, **result_data)
        db_result.image_data = base64.b64encode(db_result.image_data).decode('utf-8')
        ResultResponse = sqlalchemy_to_pydantic(Result)
        return ResultResponse.from_orm(db_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating result: {e}")

# 해당 프롬프트 id의 결과 이미지 전체 불러오기
@app.get("/api/results/{prompt_id}")
def get_prompt_results(prompt_id: int, db: Session = Depends(get_db)):
    try:
        results = db.query(Result).filter(Result.prompt_id == prompt_id).all()
        for result in results:
            result.image_data = base64.b64encode(result.image_data).decode('utf-8')
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching prompt results: {e}")

# 해당 유저 id의 결과 이미지 전체 불러오기    
@app.get("/api/results/user/{user_id}")
def get_user_results(user_id: int, db: Session = Depends(get_db)):
    try:
        results = db.query(Result).filter(Result.user_id == user_id).all()
        for result in results:
            result.image_data = base64.b64encode(result.image_data).decode('utf-8')
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user results: {e}")


@app.get("/api/user_results/")
def get_user_results(request: Request, db: Session = Depends(get_db)):
    user_info = request.session.get('user_info')
    if not user_info:
        raise HTTPException(status_code=401, detail="User not authenticated")

    try:
        user_id = user_info['user_id']
        results = db.query(Result).filter(Result.user_id == user_id).all()
        collections = db.query(Collection).filter(Collection.user_id == user_id).all()

        results_data = []
        for result in results:
            result_dict = {column.name: getattr(result, column.name) for column in result.__table__.columns}
            result_dict["image_data"] = base64.b64encode(result_dict["image_data"]).decode('utf-8')
            results_data.append(result_dict)

        collections_data = []
        for collection in collections:
            collection_dict = {column.name: getattr(collection, column.name) for column in collection.__table__.columns}
            collections_data.append(collection_dict)

        if not collections_data:
            collections_data = [{"message": "컬렉션이 비었습니다"}]

        return {
            "results": results_data,
            "collections": collections_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user results and collections: {e}")

@app.post("/api/collections/")
def create_collection(collection_name: str = Form(...), user_id: int = Form(...), db: Session = Depends(get_db)):
    try:
        collection_data = {"created_at": datetime.now(), "user_id": user_id, "collection_name": collection_name}
        new_collection = crud.create_record(db=db, model=Collection, **collection_data)
        return {column.name: getattr(new_collection, column.name) for column in new_collection.__table__.columns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating collection: {e}")

@app.post("/api/collections/{collection_id}/add_result")
def add_result_to_collection(collection_id: int, result_id: int, db: Session = Depends(get_db)):
    try:
        collection_result_data = {"collection_id": collection_id, "result_id": result_id}
        new_collection_result = crud.create_record(db=db, model=CollectionResult, **collection_result_data)
        return {column.name: getattr(new_collection_result, column.name) for column in new_collection_result.__table__.columns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error adding result to collection: {e}")

@app.get("/api/user_collections/")
def get_user_collections(request: Request, db: Session = Depends(get_db)):
    user_info = request.session.get('user_info')
    if not user_info:
        raise HTTPException(status_code=401, detail="User not authenticated")

    try:
        user_id = user_info['user_id']
        collections = db.query(Collection).filter(Collection.user_id == user_id).all()

        if not collections:
            return [{"message": "컬렉션이 비었습니다"}]

        collections_data = []
        for collection in collections:
            collection_dict = {column.name: getattr(collection, column.name) for column in collection.__table__.columns}
            collections_data.append(collection_dict)

        return collections_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user collections: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
