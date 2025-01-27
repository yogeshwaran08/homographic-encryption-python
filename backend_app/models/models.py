from sqlalchemy import Column, Integer, String, ForeignKey, BLOB
from sqlalchemy.orm import relationship
from backend_app.database import Base, engine

class Uploads(Base):    
    __tablename__ = "uploads"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    contents = Column(BLOB)  
    type = Column(String)
    owner = relationship("User")
    fileName = Column(String)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

