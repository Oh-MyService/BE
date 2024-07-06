from sqlalchemy.orm import Session, joinedload
from datetime import datetime
from app import models, schemas

def get_prompt(db: Session, prompt_id: int):
    return db.query(models.Prompt).filter(models.Prompt.id == prompt_id).first()

def create_prompt(db: Session, prompt_content: str, user_id: int):
    created_at = datetime.now()
    db_prompt = models.Prompt(content=prompt_content, created_at=created_at, user_id=user_id)
    db.add(db_prompt)
    db.commit()
    db.refresh(db_prompt)
    return db_prompt

def get_result(db: Session, result_id: int):
    return db.query(models.Result).filter(models.Result.id == result_id).first()

def create_result(db: Session, prompt_id: int, image_data: bytes, user_id: int):
    created_at = datetime.now()
    db_result = models.Result(image_data=image_data, created_at=created_at, prompt_id=prompt_id, user_id=user_id)
    db.add(db_result)
    db.commit()
    db.refresh(db_result)
    return db_result

def get_results_by_prompt(db: Session, prompt_id: int):
    return db.query(models.Result).filter(models.Result.prompt_id == prompt_id).all()

def get_all_results(db: Session):
    return db.query(models.Result).options(
        joinedload(models.Result.user),
        joinedload(models.Result.prompt)
    ).all()

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(email=user.email, name=user.name, profileimg=user.picture)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def add_result_to_collection(db: Session, collection_id: int, result_id: int):
    collection = db.query(models.Collection).filter(models.Collection.collection_id == collection_id).first()
    result = db.query(models.Result).filter(models.Result.id == result_id).first()
    if not collection or not result:
        return None
    collection.results.append(result)
    collection.prompt_id = result.prompt_id  # result_id에 따른 prompt_id 설정
    db.commit()
    return collection
