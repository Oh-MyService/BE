from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine.url import URL

# MySQL 데이터베이스 연결 URL 설정
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://root:1234@localhost:3306/test"

# SQLAlchemy 엔진 생성
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# 세션 생성을 위한 세션팩토리 생성
# 수정 필요
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base 클래스 설정
Base = declarative_base()
