from typing import Optional

from sqlmodel import Field, SQLModel

__all__ = ("User",)


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(nullable=False)
    username: str = Field(nullable=False)
    password_hash: str = Field(nullable=False)
