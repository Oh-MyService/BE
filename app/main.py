from fastapi import FastAPI, Depends, HTTPException, File, UploadFile, Form
from sqlalchemy.orm import Session
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse, FileResponse
from starlette.middleware.sessions import SessionMiddleware
import httpx
from typing import List
from dotenv import load_dotenv
from . import crud, models, schemas
from .database import SessionLocal, engine
import base64
import os

# Load environment variables from .env file
load_dotenv()

# Initialize the database
models.Base.metadata.create_all(bind=engine)

# Initialize the FastAPI app
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 모든 도메인에서의 요청을 허용
    allow_credentials=True,
    allow_methods=["*"],  # 모든 HTTP 메서드를 허용
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

# User 검사 관련
@app.get("/auth")
async def auth(code: str, db: Session = Depends(get_db)):
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

        # Check if user already exists
        db_user = crud.get_user_by_email(db, email=email)
        if not db_user:
            user_data = schemas.UserCreate(email=email, name=name, picture=picture)
            db_user = crud.create_user(db=db, user=user_data)

        # Redirect to login complete page
        return RedirectResponse(url="/login-complete")

@app.get("/login-complete")
async def login_complete():
    return FileResponse(login_complete_file)

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
    results_encoded = []
    for result in results:
        result_dict = {
            "id": result.id,
            "created_at": result.created_at,
            "prompt_id": result.prompt_id,
            "image_data": base64.b64encode(result.image_data).decode('utf-8'),
            "user_id": result.user_id,
            "user": result.user,
            "prompt": result.prompt
        }
        results_encoded.append(result_dict)
    return results_encoded


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
