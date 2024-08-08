# crud.py
from sqlalchemy.orm import Session

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
    primary_key_column = getattr(model, 'collection_id', 'id')  
    db.query(model).filter(primary_key_column == record_id).delete()
    db.commit()