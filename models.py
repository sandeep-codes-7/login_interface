from sqlalchemy import Column, String, Integer
from database import Base

class UserDetails(Base):
    """
    UserDetails schema for the table userDetails
    _id: Integer, primary_key | username: String, unique | hashedPassword: String
    """
    __tablename__ = "userDetails"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashedPassword = Column(String,nullable=False)