from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File, Cookie
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse, JSONResponse
import httpx
from typing import List
from dotenv import load_dotenv
import base64
import os
from datetime import datetime, timedelta
import json
import logging
from typing import Optional
from fastapi import Cookie

from . import crud
from .database import get_db
from .models import User, Prompt, Result, Collection, CollectionResult
from .utils import sqlalchemy_to_pydantic, create_access_token, decode_access_token

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)

app = FastAPI()

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://43.202.57.225:29292", "http://43.202.57.225:29292", "http://43.202.57.225:25252", "http://inkyong.com", "https://inkyong.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Read Google OAuth environment variables
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://inkyong.com/auth")
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

def get_current_user(access_token: str = Cookie(None), db: Session = Depends(get_db)):
    if not access_token:
        logging.error("No token found in cookies")
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = access_token.split("Bearer ")[1]  # 'Bearer ' 문자열 제거
    payload = decode_access_token(token)
    if payload is None:
        logging.error("Invalid or expired token")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user_id = payload.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        logging.error("User not found or token invalid")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    logging.debug(f"Authenticated user: {user.email}")
    
    return user

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
            token_response.raise_for_status()
            token_response_data = token_response.json()
            access_token = token_response_data.get("access_token")
            if not access_token:
                logging.error("Invalid client credentials")
                raise HTTPException(status_code=401, detail="Invalid client credentials")

            user_info_response = await client.get(
                USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            user_info_response.raise_for_status()
            user_info = user_info_response.json()
            email = user_info.get("email")
            name = user_info.get("name")
            
            # picture = user_info.get("picture")

            logging.debug(f"User info: {user_info}")

            db_user = db.query(User).filter(User.email == email).first()
            if not db_user:
                user_data = {"email": email, "name": name, "profileimg": picture}
                db_user = crud.create_record(db=db, model=User, **user_data)
                logging.debug(f"Created new user: {user_data}")

                request.session['user_info'] = {"user_id": db_user.id, "email": email, "name": name} # "picture": picture}
        # 세션에 저장된 사용자 정보 로그 출력

            access_token_expires = timedelta(minutes=60)
            access_token = create_access_token(
                data={"user_id": db_user.id, "email": email}, expires_delta=access_token_expires
            )

            response = RedirectResponse(url="http://43.202.57.225:29292/login-complete")
            response.set_cookie(
                key="access_token",
                value=f"Bearer {access_token}",
                httponly=False,
                secure=True,
                samesite="Lax"
            )
            return response

    except HTTPException as e:
        logging.error(f"HTTP Exception during authentication: {e}")
        raise e
    except Exception as e:
        logging.error(f"Error during authentication: {e}")
        raise HTTPException(status_code=500, detail=f"Error during authentication: {e}")
    
@app.get("/api/user_info")
async def user_info(access_token: Optional[str] = Cookie(None), db: Session = Depends(get_db)):
    logging.debug("Received access_token: %s", access_token)
    
    if not access_token:
        logging.error("No access token found in cookies")
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    if access_token.startswith("Bearer "):
        access_token = access_token[len("Bearer "):]

    payload = decode_access_token(access_token)
    if payload is None:
        logging.error("Invalid or expired token")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    user_id = payload.get("user_id")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        logging.error("User not found or token invalid")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    logging.debug(f"Returning user info: {user.email}")
    return JSONResponse(content = {"user_id": user.id, "email": user.email, "name": user.name} )


@app.get("/user_info")
async def get_user_info(request: Request):
    user_info = request.session.get('user_info')
    if user_info:
        return JSONResponse(content=user_info)
    else:
        raise HTTPException(status_code=401, detail="User not authenticated")        


@app.post("/api/prompts/")
def create_prompt(prompt_data: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        prompt_data['user_id'] = current_user.id
        prompt_data['created_at'] = datetime.now()
        return crud.create_record(db=db, model=Prompt, **prompt_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating prompt: {e}")


@app.get("/api/prompts/user/{user_id}")
def get_user_prompts(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        logging.error("Not authorized to access this user's prompts")
        raise HTTPException(status_code=403, detail="Not authorized to access this user's prompts")
    try:
        prompts = db.query(Prompt).filter(Prompt.user_id == user_id).all()
        logging.debug(f"User prompts: {prompts}")
        return prompts
    except Exception as e:
        logging.error(f"Error fetching user prompts: {e}")
        raise HTTPException(status_code=500, detail=f"Error fetching user prompts: {e}")


@app.get("/api/prompts/{prompt_id}")
def get_prompt(prompt_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        prompt = db.query(Prompt).filter(Prompt.id == prompt_id).first()
        if not prompt or prompt.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Prompt not found or not authorized")
        return prompt
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching prompt: {e}")

@app.post("/api/results/")
async def create_result(prompt_id: int = Form(...), image: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        image_data = await image.read()
        result_data = {"prompt_id": prompt_id, "user_id": current_user.id, "image_data": image_data, "created_at": datetime.now()}
        db_result = crud.create_record(db=db, model=Result, **result_data)
        db_result.image_data = base64.b64encode(db_result.image_data).decode('utf-8')
        ResultResponse = sqlalchemy_to_pydantic(Result)
        return ResultResponse.from_orm(db_result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating result: {e}")

@app.get("/api/results/{prompt_id}")
def get_prompt_results(prompt_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        prompt = db.query(Prompt).filter(Prompt.id == prompt_id).first()
        if not prompt or prompt.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Prompt not found or not authorized")
        results = db.query(Result).filter(Result.prompt_id == prompt_id).all()
        for result in results:
            result.image_data = base64.b64encode(result.image_data).decode('utf-8')
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching prompt results: {e}")

@app.get("/api/results/user/{user_id}")
def get_user_results(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this user's results")
    try:
        results = db.query(Result).filter(Result.user_id == user_id).all()
        for result in results:
            result.image_data = base64.b64encode(result.image_data).decode('utf-8')
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user results: {e}")

@app.get("/api/user_results/")
def get_user_results(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        user_id = current_user.id
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
def create_collection(collection_name: str = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        collection_data = {"created_at": datetime.now(), "user_id": current_user.id, "collection_name": collection_name}
        new_collection = crud.create_record(db=db, model=Collection, **collection_data)
        return {column.name: getattr(new_collection, column.name) for column in new_collection.__table__.columns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating collection: {e}")

@app.post("/api/collections/{collection_id}/add_result")
def add_result_to_collection(collection_id: int, result_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    collection = db.query(Collection).filter(Collection.id == collection_id).first()
    if not collection or collection.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Collection not found or not authorized")
    try:
        collection_result_data = {"collection_id": collection_id, "result_id": result_id}
        new_collection_result = crud.create_record(db=db, model=CollectionResult, **collection_result_data)
        return {column.name: getattr(new_collection_result, column.name) for column in new_collection_result.__table__.columns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error adding result to collection: {e}")

@app.get("/api/user_collections/")
def get_user_collections(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        user_id = current_user.id
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
