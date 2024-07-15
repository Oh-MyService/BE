from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy import create_engine
import os
from dotenv import load_dotenv

# .env 파일에서 환경 변수 로드
load_dotenv()

# .env 파일에서 DATABASE_URL 읽기
DATABASE_URL = os.getenv("DATABASE_URL")

# DATABASE_URL 출력하여 확인
print(f"DATABASE_URL: {DATABASE_URL}")

# 데이터베이스 엔진 생성
engine = create_engine(DATABASE_URL, echo=True)
Base = automap_base()

# 테이블 구조 반영
Base.prepare(engine, reflect=True)

# 자동으로 생성된 클래스들 가져오기
User = Base.classes.users
Prompt = Base.classes.prompts
Result = Base.classes.results
Collection = Base.classes.collections
CollectionResult = Base.classes.collection_results
