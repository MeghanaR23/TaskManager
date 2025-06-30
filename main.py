from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import ForeignKey, create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import jwt,JWTError
from typing import Optional


DATABASE_URL = "sqlite:///./taskmanager.db"
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password = Column(String, nullable=False)
    tasks = relationship("Task", back_populates="user", cascade="all, delete-orphan")
    
class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    description = Column(String(255), nullable=True)
    done = Column(Boolean, default=0)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    user = relationship("User", back_populates="tasks")
   
class RegisterUser(BaseModel):
    username: str
    password: str
 
class Token(BaseModel):
    message: str
    access_token: str
    token_type: str
    
class TaskCreate(BaseModel):
    title: str
    description: str = None
    done: Optional[bool] = False 
       

app = FastAPI()
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
        
@app.post("/register",response_model=Token)
async def register(user: RegisterUser, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.username == user.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already exists")
        hashed_password = pwd_context.hash(user.password)
        db_user = User(username=user.username, password=hashed_password)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        access_token = create_access_token(data={"sub": db_user.username})
        return Token(message="User registered successfully", access_token=access_token, token_type="bearer")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/token",response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter(User.username == form_data.username).first()
        if not existing_user or not pwd_context.verify(form_data.password, existing_user.password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        access_token = create_access_token(data={"sub": existing_user.username})
        return Token(message="Login successful", access_token=access_token, token_type="bearer")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.post("/tasks", response_model=TaskCreate)
def create_task(task: TaskCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        new_task = Task(title=task.title, description=task.description, owner_id=current_user.id)
        db.add(new_task)
        db.commit()
        db.refresh(new_task)
        return new_task
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/tasks", response_model=list[TaskCreate])
def get_tasks(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        tasks = db.query(Task).filter(Task.owner_id == current_user.id).all()
        return tasks
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/tasks/{task_id}", response_model=TaskCreate)
def update_task(task_update:TaskCreate, task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        task= db.query(Task).filter(Task.id == task_id, Task.owner_id == current_user.id).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        task.title = task_update.title
        task.description = task_update.description
        db.commit()
        db.refresh(task)
        return task
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.delete("/tasks/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        task = db.query(Task).filter(Task.id == task_id, Task.owner_id == current_user.id).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        db.delete(task)
        db.commit()
        return {"message": "Task deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.patch("/tasks/{task_id}/done")
def mark_task(task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        task = db.query(Task).filter(Task.id == task_id, Task.owner_id == current_user.id).first()
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        task.done = not task.done
        db.commit()
        # db.refresh(task)
        status_msg = "done" if task.done else "undone"
        return {"message": f"Task marked as {status_msg}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))