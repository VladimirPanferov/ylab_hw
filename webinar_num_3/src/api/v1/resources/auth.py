from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm

from api.v1.schemas.auth import (
    UserCreate,
    Token,
)


router = APIRouter(
    prefix="/auth"
)


@router.post("/signup", response_model=Token)
def singup(user_data: UserCreate):
    pass


@router.post("/signin", response_model=Token)
def signin(form_data: OAuth2PasswordRequestForm = Depends()):
    pass
