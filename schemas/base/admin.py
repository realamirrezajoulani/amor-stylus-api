from fastapi import HTTPException
from pydantic import field_validator
from sqlmodel import SQLModel, Field

from utilities.enums import UserRole
from utilities.field_validator import validate_password_value


class AdminBase(SQLModel):
    username: str = Field(
        min_length=3,
        max_length=50,
        schema_extra={"pattern": r"^[a-z][a-z0-9._]{1,48}[a-z]$"},
        unique=True,
        index=True,
        description="The unique username for the author. Must start and end with a lowercase letter, "
                    "and can include lowercase letters, numbers, periods, and underscores."""
    )

    password: str = Field(
        description="The password for the user account. It must be at least 16 characters long and contain at least "
                    "one uppercase letter, one lowercase letter, one digit, and one special character (e.g., "
                    r"!@#$%^&*(),.?\":{}|<>)."
    )

    role: UserRole = Field(
        index=True,
        description="Field representing the different roles a admin can have in the system (full or admin)"
    )

    @field_validator("password")
    def validate_password(cls, value: str) -> str | HTTPException:
        # Validate the password using the external validation function
        return validate_password_value(value)

    @field_validator("role")
    def check_role(cls, v: UserRole):
        if v == UserRole.AUTHOR:
            # Raise an exception if a admin trying to create an author in the admin table (with full or admin role)
            raise HTTPException(status_code=404, detail=f"You cannot create an author in the admin table")
        return v
