import os
from dotenv import load_dotenv

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

DATABASE_URL = os.environ["DATABASE_URL"]

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=1800,
)

session_local = sessionmaker(autocommit=False, bind=engine)


def get_db():
    '''Returns a session used to communicate with the database with Object
    Relation Mapper (ORM) Objects.'''
    db = session_local()
    try:
        yield db
    finally:
        db.close()