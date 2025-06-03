from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from bhrc_blockchain.database.models import Base

engine = create_engine("sqlite:///bhrc_blockchain.db")
Session = sessionmaker(bind=engine)
session = Session()

Base.metadata.create_all(engine)

