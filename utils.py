
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import timedelta, datetime


ACCESS_TOKEN_EXPIRY_MINUTES = 5
ALGORITHM = "HS256"
SECRET = "59e24ba4af94c0128330fc11f1b78874ef0a8ed6f1a10510b0ff989d013dd28b"


pwd_context = CryptContext(schemes=['argon2'], deprecated="auto")


def generateHashPassword(password: str):
    return pwd_context.hash(password)

def verifyHashPassword(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password,hashed_password)

def create_access_token(data: dict, expiry_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES)
    to_encode.update({"exp":expire})
    encoded_jwt = jwt.encode(to_encode,SECRET,ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token=token,key=SECRET,algorithms=ALGORITHM)
        return payload
    except JWTError:
        return None
