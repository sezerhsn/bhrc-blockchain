from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from bhrc_blockchain.database.models import Base

DATABASE_URL = "sqlite:///bhrc_blockchain.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Session = SessionLocal

Base.metadata.create_all(bind=engine)

