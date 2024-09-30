from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form, Request
from sqlalchemy.orm import Session, joinedload
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse, FileResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
from typing import List, Optional
from dotenv import load_dotenv
from . import crud, models, schemas
from .database import SessionLocal, engine
import base64
from datetime import datetime, timedelta
from pydantic import BaseModel
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from passlib.context import CryptContext
import uuid


# Load environment variables from .env file
load_dotenv()

# Initialize the FastAPI app
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY", "supersecretkey"))

# OAuth2 settings
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/auth"
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

current_dir = os.path.dirname(os.path.abspath(__file__))
index_file = os.path.join(current_dir, "index.html")
login_complete_file = os.path.join(current_dir, "login_complete.html")

class AddResultToCollection(BaseModel):
    result_id: int

@app.get("/")
async def read_root():
    return FileResponse(index_file)

@app.get("/login")
async def login():
    return RedirectResponse(
        f"{AUTHORIZATION_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=openid%20email%20profile"
    )

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/auth")
async def auth(request: Request, code: str, db: Session = Depends(get_db)):
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
        token_response_data = token_response.json()
        access_token = token_response_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=401, detail="Invalid client credentials")

        user_info_response = await client.get(
            USER_INFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        user_info = user_info_response.json()
        email = user_info.get("email")
        name = user_info.get("name")
        picture = user_info.get("picture")

        # 사용자 정보 저장 로직
        db_user = crud.get_user_by_email(db, email=email)
        if not db_user:
            user_data = schemas.UserCreate(email=email, name=name, picture=picture)
            db_user = crud.create_user(db=db, user=user_data)

        # 사용자 정보 세션에 저장
        request.session['user_info'] = {"user_id": db_user.id, "email": email, "name": name, "picture": picture}

        # Redirect to login complete page
        return RedirectResponse(url="/login-complete")

@app.get("/login-complete")
async def login_complete():
    return FileResponse(login_complete_file)

@app.get("/user_info")
async def get_user_info(request: Request):
    user_info = request.session.get('user_info')
    if user_info:
        return JSONResponse(content=user_info)
    else:
        raise HTTPException(status_code=401, detail="User not authenticated")

@app.post("/prompts/", response_model=schemas.Prompt)
def create_prompt(prompt_data: schemas.PromptCreate, db: Session = Depends(get_db)):
    return crud.create_prompt(db=db, prompt_content=prompt_data.content, user_id=prompt_data.user_id)

@app.get("/prompts/{prompt_id}", response_model=schemas.Prompt)
def read_prompt(prompt_id: int, db: Session = Depends(get_db)):
    db_prompt = crud.get_prompt(db, prompt_id=prompt_id)
    if db_prompt is None:
        raise HTTPException(status_code=404, detail="Prompt not found")
    return db_prompt

@app.post("/results/", response_model=schemas.Result)
async def create_result(prompt_id: int = Form(...), user_id: int = Form(...), image: UploadFile = File(...), db: Session = Depends(get_db)):
    image_data = await image.read()
    db_result = crud.create_result(db=db, prompt_id=prompt_id, image_data=image_data, user_id=user_id)
    db_result.image_data = base64.b64encode(db_result.image_data).decode('utf-8')
    return db_result

@app.get("/results/", response_model=List[schemas.Result])
def get_all_results(db: Session = Depends(get_db)):
    results = crud.get_all_results(db)
    for result in results:
        result.image_data = base64.b64encode(result.image_data).decode('utf-8')
    return results

@app.get("/my-page")
async def my_page():
    return FileResponse(os.path.join(current_dir, "my_page.html"))

@app.get("/user_results/")
def get_user_results(request: Request, db: Session = Depends(get_db)):
    user_info = request.session.get('user_info')
    if not user_info:
        raise HTTPException(status_code=401, detail="User not authenticated")

    user_id = user_info['user_id']
    results = db.query(models.Result).filter(models.Result.user_id == user_id).options(
        joinedload(models.Result.user),
        joinedload(models.Result.prompt)
    ).all()

    collections = db.query(models.Collection).filter(models.Collection.user_id == user_id).all()

    # 결과를 사전 형태로 변환
    results_data = []
    for result in results:
        result_data = {
            "id": result.id,
            "created_at": result.created_at,
            "prompt_id": result.prompt_id,
            "image_data": base64.b64encode(result.image_data).decode('utf-8'),
            "user_id": result.user_id,
        }
        results_data.append(result_data)

    # 컬렉션을 사전 형태로 변환
    collections_data = []
    for collection in collections:
        collection_data = {
            "collection_id": collection.collection_id,
            "created_at": collection.created_at,
            "user_id": collection.user_id,
            "result_id": collection.result_id,
            "prompt_id": collection.prompt_id,
        }
        collections_data.append(collection_data)

    # 컬렉션이 비어있는 경우 메시지 추가
    if not collections_data:
        collections_data = [{"message": "컬렉션이 비었습니다"}]

    return {
        "results": results_data,
        "collections": collections_data
    }




@app.post("/collections/", response_model=dict)
def create_collection(request: Request, user_id: int = Form(...), result_id: Optional[int] = Form(None), prompt_id: Optional[int] = Form(None), db: Session = Depends(get_db)):
    created_at = datetime.now()
    new_collection = models.Collection(created_at=created_at, user_id=user_id, result_id=result_id, prompt_id=prompt_id)
    db.add(new_collection)
    db.commit()
    db.refresh(new_collection)
    
    # 컬렉션을 사전 형태로 변환
    collection_data = {
        "collection_id": new_collection.collection_id,
        "created_at": new_collection.created_at,
        "user_id": new_collection.user_id,
        "result_id": new_collection.result_id,
        "prompt_id": new_collection.prompt_id,
        "result": None,
        "prompt": None
    }
    
    if new_collection.result_id:
        result = db.query(models.Result).filter(models.Result.id == new_collection.result_id).first()
        collection_data["result"] = {
            "id": result.id,
            "created_at": result.created_at,
            "prompt_id": result.prompt_id,
            "image_data": base64.b64encode(result.image_data).decode('utf-8'),
            "user_id": result.user_id,
        }
    
    if new_collection.prompt_id:
        prompt = db.query(models.Prompt).filter(models.Prompt.id == new_collection.prompt_id).first()
        collection_data["prompt"] = {
            "id": prompt.id,
            "created_at": prompt.created_at,
            "content": prompt.content,
            "user_id": prompt.user_id,
        }

    return collection_data


@app.post("/collections/{collection_id}/add_result")
def add_result_to_collection(collection_id: int, data: AddResultToCollection, db: Session = Depends(get_db)):
    collection = db.query(models.Collection).filter(models.Collection.collection_id == collection_id).first()
    if not collection:
        raise HTTPException(status_code=404, detail="Collection not found")

    # 결과 ID 업데이트
    collection.result_id = data.result_id
    db.commit()
    db.refresh(collection)

    return {"message": "Result added to collection successfully"}


@app.get("/user_collections/", response_model=List[schemas.Collection])
def get_user_collections(request: Request, db: Session = Depends(get_db)):
    user_info = request.session.get('user_info')
    if not user_info:
        raise HTTPException(status_code=401, detail="User not authenticated")

    user_id = user_info['user_id']
    collections = db.query(models.Collection).filter(models.Collection.user_id == user_id).all()

    if not collections:
        return [{"message": "컬렉션이 비었습니다"}]

    collections_data = []
    for collection in collections:
        collections_data.append({
            "collection_id": collection.collection_id,
            "created_at": collection.created_at,
            "user_id": collection.user_id,
            "result_id": collection.result_id,
            "prompt_id": collection.prompt_id,
        })

    return collections_data


#비밀번호 재설정
load_dotenv()
# Gmail SMTP 서버 설정
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587  # TLS 포트
SMTP_USER = os.getenv("GMAIL_USER")  # Gmail 계정 이메일 주소
SMTP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")  # 앱 비밀번호 또는 Gmail 비밀번호

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 이메일 전송 함수
def send_reset_email(to_email: str, reset_token: str):
    sender_email = SMTP_USER
    subject = "비밀번호 재설정 링크"
    reset_link = f"http://118.67.128.129:25252/reset-password?token={reset_token}"

    # 이메일 내용 구성
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = to_email
    message['Subject'] = subject
    body = f"비밀번호를 재설정하려면 아래 링크를 클릭하세요:\n\n{reset_link}"
    message.attach(MIMEText(body, 'plain'))

    try:
        # SMTP 서버에 연결
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  # TLS 보안 활성화
        server.login(SMTP_USER, SMTP_PASSWORD)  # SMTP 서버에 로그인
        server.sendmail(SMTP_USER, to_email, message.as_string())  # 이메일 전송
        server.quit()  # 서버 연결 종료
        print(f"이메일 전송 성공: {to_email}")
    except Exception as e:
        print(f"이메일 전송 실패: {e}")

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

#@app.post("/password-reset-request/")
@app.post("/find-account/")
async def password_reset_request(email: str, db: Session = Depends(get_db)):
    # 입력된 이메일로 사용자 정보 확인
    user = crud.get_user_by_email(db, email=email)
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    # 비밀번호 재설정 토큰 생성 (고유한 UUID)
    reset_token = str(uuid.uuid4())
    reset_token_expiration = datetime.utcnow() + timedelta(hours=1)  # 토큰 만료 시간 설정 (1시간)

    # 토큰을 사용자 정보에 저장
    crud.save_password_reset_token(db, user.id, reset_token, reset_token_expiration)

    # 사용자에게 이메일 발송
    send_reset_email(user.email, reset_token)

    return {"message": "비밀번호 재설정 이메일이 전송되었습니다."}

@app.post("/reset-password/")
async def reset_password(token: str, new_password: str, db: Session = Depends(get_db)):
    # 토큰으로 사용자 찾기
    user = crud.get_user_by_reset_token(db, reset_token=token)
    if not user:
        raise HTTPException(status_code=400, detail="유효하지 않은 토큰입니다.")

    # 토큰 만료 여부 확인
    if user.reset_token_expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="토큰이 만료되었습니다.")

    # 새 비밀번호 해시화
    hashed_password = pwd_context.hash(new_password)

    # 비밀번호 업데이트 및 토큰 무효화
    crud.update_user_password(db, user.id, hashed_password)

    return {"message": "비밀번호가 성공적으로 변경되었습니다."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
