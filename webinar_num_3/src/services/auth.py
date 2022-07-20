from datetime import datetime
from fastapi import (
    HTTPException,
    status,
)
from jose import JWTError, jwt
from passlib.hash import bcrypt
from pydantic import ValidationError

import models
from api.v1.schemas import auth

from src.core import config

class AuthService:
    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return bcrypt.verify(plain_password, hashed_password)
    
    @classmethod
    def hash_password(cls, password: str) -> str:
        return bcrypt.hash(password)
    
    @classmethod
    def validate_token(cls, token: str) -> auth.User:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={
                "WWW-Authenticate": "Bearer",
            },
        )

        try:
            payload = jwt.decode(
                token=token,
                key=config.JWT_SECRET_KEY,
                algorithms=[config.JWT_ALGORITHM],
            )
        except JWTError:
            raise exception from None

        user_data = payload.get("user")

        try:
            user = auth.User.parse_obj(user_data)
        except ValidationError:
            raise exception from None

        return user

    @classmethod
    def create_token(cls, user: models.User) -> auth.Token:
        user_data = auth.User.from_orm(user)

        now = datetime.now()

        payload = {

        }