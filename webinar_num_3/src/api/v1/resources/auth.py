from fastapi import (
    APIRouter,
    Depends,
)
from fastapi.security import OAuth2PasswordRequestForm

from src.services import (
    AuthService,
    get_current_user,
)

from ..schemas.auth import (
    User,
    UserCreate,
    Token,
)


router = APIRouter()


@router.post("/signup", response_model=Token)
def singup(
    user_data: UserCreate,
    service: AuthService = Depends(),
):
    return service.register_new_user(user_data)


@router.post("/signin", response_model=Token)
def signin(
    form_data: OAuth2PasswordRequestForm = Depends(),
    service: AuthService = Depends(),
):
    return service.authenticate_user(
        username=form_data.username,
        password=form_data.password,
    )


@router.get("/user", response_model=User)
def get_user(user: User = Depends(get_current_user)):
    return user

