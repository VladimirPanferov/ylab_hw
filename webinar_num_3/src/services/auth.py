from datetime import datetime, timedelta
from fastapi import (
    Depends,
    HTTPException,
    status,
)
from fastapi.security import OAuth2PasswordBearer
from jose import (
    JWTError,
    jwt,
)
from passlib.hash import bcrypt
from pydantic import ValidationError
from sqlmodel import Session

from src.api.v1.schemas import auth
from ..core import config

from .. import models
from ..db import get_session


oauth_scheme = OAuth2PasswordBearer(tokenUrl="/auth/signin/")


def get_current_user(token: str = Depends(oauth_scheme)) -> auth.User:
    return AuthService.validate_token(token)


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
            "iat": now,
            "nbf": now,
            "exp": now + timedelta(seconds=config.JWT_EXPIRATION),
            "sub": str(user_data.id),
            "user": user_data.dict(),

        }
        token = jwt.encode(
            claims=payload,
            key=config.JWT_SECRET_KEY,
            algorithm=config.JWT_ALGORITHM,
        )
        return auth.Token(access_token=token)

    def __init__(self, session: Session = Depends(get_session)):
        self.session = session

    def register_new_user(self, user_data: auth.UserCreate) -> auth.Token:
        user = models.User(
            email=user_data.email,
            username=user_data.username,
            password_hash=self.hash_password(user_data.password),
        )

        self.session.add(user)
        self.session.commit()

        return self.create_token(user)

    def authenticate_user(self, username: str, password: str) -> auth.Token:
        exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="UIncorrect username or password",
            headers={
                "WWW-Authenticate": "Bearer",
            }
        )

        user = (
            self.session
            .query(models.User)
            .filter(models.User.username == username)
            .first()
        )

        if not user:
            raise exception
        if not self.verify_password(password, user.password_hash):
            raise exception

        return self.create_token(user)
