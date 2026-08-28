import os
from dotenv import load_dotenv

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

DATABASE_URL = 'mysql+pymysql://{}:{}@{}:{}/{}'.format(
    os.environ['MYSQL_USER'],
    os.environ['MYSQL_PASSWORD'],
    os.environ['MYSQL_HOST'],
    os.environ['MYSQL_PORT'],
    os.environ['MYSQL_DATABASE']
)

# Get the absolute path to the CA certificate
cert_path = os.path.join(os.path.dirname(__file__), '..', 'certs', 'DigiCertGlobalRootCA.crt.pem')


connect_args = {}

# Only enable SSL if explicitly requested
if os.getenv("MYSQL_SSL", "false").lower() == "true":
    connect_args["ssl_ca"] = cert_path

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
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
