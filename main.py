from database import engine, Base
from models import UserDetails
from fastapi import FastAPI, HTTPException, Header, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from utils import verifyHashPassword, create_access_token, decode_access_token, generateHashPassword, create_refresh_token, refresh_access_token
from database import SessionLocal
from jose import jwt, JWTError
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()
Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
app.mount("/static",StaticFiles(directory="static"), name="static")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Verify token and return current user"""
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    username = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(UserDetails).filter(UserDetails.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


class CreateUser(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str


class User(BaseModel):
    id: int
    username: str
    
# class TokenRefresh(BaseModel):
#     refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    # refresh_token: str
    token_type: str

@app.get("/")
async def home():
    return "hey sandeep"

# @app.get("/home",response_model=User)
# async def home():
#     return FileResponse("static/hello.html")

@app.post("/signup")
def signup(user: CreateUser, db: Session = Depends(get_db)):
    exist = db.query(UserDetails).filter(UserDetails.username == user.username).first()
    if exist:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="user already exists")
    hash_password = generateHashPassword(user.password)
    new_user = UserDetails(username=user.username, hashedPassword=hash_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"username": new_user.username, "id": new_user.id}

@app.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(UserDetails).filter(UserDetails.username == form_data.username).first()
    if not db_user or not verifyHashPassword(form_data.password, db_user.hashedPassword):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": db_user.username})
    # refresh_token = create_refresh_token(data={"sub": db_user.username})
    print({ "access_token": access_token, "token_type": "bearer" })
    return {
        "access_token": access_token,
        # "refresh_token": refresh_token,
        "token_type": "bearer",
    }

# @app.post("/refresh", response_model=Token)
# def refresh(request: TokenRefresh, db: Session = Depends(get_db)):
#     """Refresh access token using refresh token"""
#     new_access_token = refresh_access_token(request.refresh_token)
#     if new_access_token is None:
#         raise HTTPException(status_code=401, detail="Invalid refresh token")
#     return {
#         "access_token": new_access_token,
#         "token_type": "bearer",
#     }

# response_model=User
@app.get("/home")
async def read_me(current_user: UserDetails = Depends(get_current_user)):
    return {"hello":current_user.username}