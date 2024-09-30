# models.py
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine, MetaData
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Read DATABASE_URL from .env file
DATABASE_URL = os.getenv("DATABASE_URL")

# Create database engine
engine = create_engine(DATABASE_URL, echo=True)
Base = automap_base()

# Reflect the tables
metadata = MetaData()
metadata.reflect(engine, only=['users', 'prompts', 'results', 'collections', 'collection_results'])

Base.prepare(engine, reflect=True)

# Automatically generated classes
User = Base.classes.users
Prompt = Base.classes.prompts
Result = Base.classes.results
Collection = Base.classes.collections
CollectionResult = Base.classes.collection_results