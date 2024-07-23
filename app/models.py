from sqlalchemy import Column, Integer, String
from database import Base
from database import engine

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)  # Specify length for VARCHAR
    hashed_password = Column(String(128))  # Specify length for VARCHAR

# Create the database tables if they don't exist
User.metadata.create_all(bind=engine)
