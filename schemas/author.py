from uuid import UUID

from fastapi import HTTPException
from pydantic import field_validator, EmailStr
from sqlmodel import Field

from .base.author import AuthorBase
from utilities.field_validator import validate_password_value


class AuthorPublic(AuthorBase):
    id: UUID


class AuthorCreate(AuthorBase):
    password: str = Field(
        description="The password for the user account. It must be at least 16 characters long and contain at least "
                    "one uppercase letter, one lowercase letter, one digit, and one special character (e.g., "
                    r"!@#$%^&*(),.?\":{}|<>)."
    )

    @field_validator("password")
    def validate_password(cls, value: str) -> str | HTTPException:
        # Validate the password using the external validation function
        return validate_password_value(value)


class AuthorUpdate(AuthorBase):
    email: EmailStr | None = Field(
        default=None,
        unique=True,
        index=True,
        description="The email address of the author. Must be in a valid email format"
    )

    password: str | None = Field(
        default=None,
        description="The password for the user account. It must be at least 16 characters long and contain at least "
                    "one uppercase letter, one lowercase letter, one digit, and one special character (e.g., "
                    r"!@#$%^&*(),.?\":{}|<>)."
    )

    @field_validator("password")
    def validate_password(cls, value: str) -> str | HTTPException:
        # Validate the password using the external validation function
        return validate_password_value(value)
