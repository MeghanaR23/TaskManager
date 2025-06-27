from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from passlib.context import CryptContext
# app = FastAPI()

DATABASE_URL = "sqlite:///./taskmanager.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password = Column(String, nullable=False)
   
class RegisterUser(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str    

app = FastAPI()
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
@app.post("/register")
async def register(user: RegisterUser,db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.username == user.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        hashed_password = pwd_context.hash(user.password)
        db_user = User(username=user.username, password=hashed_password)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return {"message": "User registered successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/token")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.username == user.username).first()
        if not existing_user or not pwd_context.verify(user.password, existing_user.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {"message": "Login successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))