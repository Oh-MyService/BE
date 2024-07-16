from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse, FileResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
from typing import List, Optional
from dotenv import load_dotenv
import base64
import os
from datetime import datetime

from . import crud
from .database import get_db
from .models import User, Prompt, Result, Collection, CollectionResult
from .utils import sqlalchemy_to_pydantic

# .env 파일에서 환경 변수 로드
load_dotenv()

app = FastAPI()

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://43.202.57.225:29292", "http://43.202.57.225:25252", "http://inkyong.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 세션 미들웨어 설정
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY"))

# .env 파일에서 Google OAuth 환경 변수 읽기
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://inkyong.com/auth")
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

@app.get("/login")
async def login():
    try:
        return RedirectResponse(
            f"{AUTHORIZATION_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=openid%20email%20profile"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during login: {e}")

@app.get("/auth")
async def auth(request: Request, code: str, db: Session = Depends(get_db)):
    try:
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
            token_response.raise_for_status()
            token_response_data = token_response.json()
            access_token = token_response_data.get("access_token")
            if not access_token:
                raise HTTPException(status_code=401, detail="Invalid client credentials")

            user_info_response = await client.get(
                USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_info_response.raise_for_status()
            user_info = user_info_response.json()
            email = user_info.get("email")
            name = user_info.get("name")
            picture = user_info.get("picture")

            # 데이터베이스에서 사용자 조회
            db_user = db.query(User).filter(User.email == email).first()
            if not db_user:
                # 사용자 데이터가 없으면 새 사용자 생성
                user_data = {"email": email, "name": name, "profileimg": picture}
                db_user = crud.create_record(db=db, model=User, **user_data)

            # 세션에 사용자 정보 저장
            request.session['user_info'] = {"user_id": db_user.id, "email": email, "name": name, "picture": picture}
            print(f"세션에 저장된 사용자 정보: {request.session['user_info']}")  # 세션에 저장된 정보 출력


            return RedirectResponse(url="http://43.202.57.225:29292/login-complete")
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during authentication: {e}")

@app.get("/user_info")
async def get_user_info(request: Request):
    user_info = request.session.get('user_info')
    if user_info:
        return JSONResponse(content=user_info)
    else:
        raise HTTPException(status_code=401, detail="User not authenticated")

@app.post("/prompts/")
def create_prompt(prompt_data: dict, db: Session = Depends(get_db)):
    try:
        prompt_data['created_at'] = datetime.now()
        return crud.create_record(db=db, model=Prompt, **prompt_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating prompt: {e}")

@app.get("/prompts/{prompt_id}")
def read_prompt(prompt_id: int, db: Session = Depends(get_db)):
    try:
        db_prompt = crud.get_record(db, Prompt, prompt_id)
        if db_prompt is None:
            raise HTTPException(status_code=404, detail="Prompt not found")
        PromptResponse = sqlalchemy_to_pydantic(Prompt)
        return PromptResponse.from_orm(db_prompt)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading prompt: {e}")

@app.post("/results/")
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

@app.get("/results/")
def get_all_results(request: Request, db: Session = Depends(get_db)):
    user_info = request.session.get('user_info')
    if not user_info:
        raise HTTPException(status_code=401, detail="User not authenticated")

    try:
        user_id = user_info['user_id']
        results = db.query(Result).filter(Result.user_id == user_id).all()
        results_data = []

        for result in results:
            result_dict = {column.name: getattr(result, column.name) for column in result.__table__.columns}
            result_dict["image_data"] = base64.b64encode(result_dict["image_data"]).decode('utf-8')
            results_data.append(result_dict)

        return results_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching results: {e}")

@app.get("/user_results/")
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

@app.post("/collections/")
def create_collection(collection_name: str = Form(...), user_id: int = Form(...), db: Session = Depends(get_db)):
    try:
        collection_data = {"created_at": datetime.now(), "user_id": user_id, "collection_name": collection_name}
        new_collection = crud.create_record(db=db, model=Collection, **collection_data)
        return {column.name: getattr(new_collection, column.name) for column in new_collection.__table__.columns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating collection: {e}")

@app.post("/collections/{collection_id}/add_result")
def add_result_to_collection(collection_id: int, result_id: int, db: Session = Depends(get_db)):
    try:
        collection_result_data = {"collection_id": collection_id, "result_id": result_id}
        new_collection_result = crud.create_record(db=db, model=CollectionResult, **collection_result_data)
        return {column.name: getattr(new_collection_result, column.name) for column in new_collection_result.__table__.columns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error adding result to collection: {e}")

@app.get("/user_collections/")
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
