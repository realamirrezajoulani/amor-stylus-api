from fastapi import HTTPException
from pydantic import field_validator
from sqlmodel import SQLModel, Field

from schemas.base.admin import AdminBase
from utilities.field_validator import validate_password_value


class AdminCreate(AdminBase):
    pass


class AdminUpdate(SQLModel):
    username: str | None = Field(
        default=None,
        min_length=3,
        max_length=50,
        schema_extra={"pattern": r"^[a-z][a-z0-9._]{1,48}[a-z]$"},
        unique=True,
        index=True,
        description="The unique username for the author. Must start and end with a lowercase letter, "
                    "and can include lowercase letters, numbers, periods, and underscores."""
    )

    password: str | None= Field(
        default=None,
        description="The password for the user account. It must be at least 16 characters long and contain at least "
                    "one uppercase letter, one lowercase letter, one digit, and one special character (e.g., "
                    r"!@#$%^&*(),.?\":{}|<>)."
    )

    @field_validator("password")
    def validate_password(cls, value: str) -> str | HTTPException:
        # Validate the password using the external validation function
        return validate_password_value(value)
