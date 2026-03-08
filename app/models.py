from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, ForeignKey, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    
    # MFA Fields
    totp_secret = Column(String, nullable=True) # The 32-char base32 secret
    is_totp_enabled = Column(Boolean, default=False) # Only require TOTP if setup is finished
    
    # Relationship to credentials
    credentials = relationship("UserCredential", back_populates="owner")

class UserCredential(Base):
    __tablename__ = "credentials"
    # WebAuthn Credential ID (Bytes)
    id = Column(LargeBinary, primary_key=True) 
    # Public Key (Bytes) - used to verify the biometric signature
    public_key = Column(LargeBinary, nullable=False) 
    # Counter to detect/prevent cloned authenticators (Replay Protection)
    sign_count = Column(Integer, default=0) 
    
    # Link to the User table
    username = Column(String, ForeignKey("users.username"), nullable=False)
    owner = relationship("User", back_populates="credentials")

# Create the tables
Base.metadata.create_all(bind=engine)