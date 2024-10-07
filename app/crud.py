# crud.py
from sqlalchemy.orm import Session
from .models import User

# 레코드 생성 함수
def create_record(db: Session, model, **kwargs):
    db_obj = model(**kwargs)
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj

# 레코드 조회 함수
def get_record(db: Session, model, record_id: int):
    return db.query(model).filter(model.id == record_id).first()

# 레코드 업데이트 함수
def update_record(db: Session, model, record_id: int, **kwargs):
    db.query(model).filter(model.collection_id == record_id).update(kwargs)
    db.commit()

# 레코드 삭제 함수
def delete_record(db: Session, model, record_id: int):
    db.query(model).filter(model.id == record_id).delete()
    db.commit()

## 비밀번호 재설정 ##
# 1. 이메일로 사용자 조회
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

# 2. 사용자 생성
def create_user(db: Session, email: str, name: str, hashed_password: str):
    new_user = User(email=email, name=name, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# 3. 비밀번호 재설정 토큰 저장
def save_password_reset_token(db: Session, user_id: int, reset_token: str, reset_token_expires):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.reset_token = reset_token
        user.reset_token_expires = reset_token_expires
        db.commit()
        db.refresh(user)

# 4. 비밀번호 재설정 토큰으로 사용자 조회
def get_user_by_reset_token(db: Session, reset_token: str):
    return db.query(User).filter(User.reset_token == reset_token).first()

# 5. 비밀번호 업데이트
def update_user_password(db: Session, user_id: int, hashed_password: str):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.hashed_password = hashed_password
        user.reset_token = None  # 토큰 무효화
        user.reset_token_expires = None  # 토큰 만료시간 제거
        db.commit()
        db.refresh(user)
    return user