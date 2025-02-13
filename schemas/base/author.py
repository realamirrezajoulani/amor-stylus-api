from re import match
from datetime import datetime

from fastapi import HTTPException
from pydantic import EmailStr, field_validator
from sqlalchemy import Column
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlmodel import SQLModel, Field

from utilities.enums import Gender


class AuthorBase(SQLModel):
    first_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        index=True,
        description="The first name of the author. Must be between 1 and 100 characters"
    )

    last_name: str | None = Field(
        default=None,
        min_length=1,
        max_length = 100,
        index=True,
        description="The last name of the author. Must be between 1 and 100 characters"
    )

    display_name: str | None = Field(
        default=None,
        min_length = 1,
        max_length = 150,
        description="The public display name of the author. This can be a nickname or a combination of first and last "
                    "names"
    )

    username: str | None = Field(
        default=None,
        min_length=3,
        max_length=50,
        schema_extra={"pattern": r"^[a-z][a-z0-9._]{1,48}[a-z]$"},
        unique=True,
        index=True,
        description="The unique username for the author. Must start and end with a lowercase letter, "
                    "and can include lowercase letters, numbers, periods, and underscores."
    )

    email: EmailStr = Field(
        unique=True,
        index=True,
        description="The email address of the author. Must be in a valid email format"
    )

    phone_number: str | None = Field(
        default=None,
        min_length=12,
        max_length=12,
        schema_extra={"pattern": r"^\+1\d{10}$"},
        description="The phone number of the author in the format +1XXXXXXXXXX, where X represents digits"
    )

    biography: str | None = Field(
        default=None,
        max_length=1000,
        description="A short biography of the author, outlining their background, interests, or other relevant "
                    "information"
    )

    picture_base64: str | None = Field(
        default=None,
        description="The author's profile picture encoded in base64 format. The maximum allowed size is "
                    "approximately 1 MB",
        sa_column=Column(
            MEDIUMTEXT,
            nullable=True
        )
    )

    gender: Gender | None = Field(
        default=None,
        description="The gender of the author. Options include 'male', 'female', or 'others'"
    )

    birthday: str | None = Field(
        default=None,
        description="The birthday of the author in YYYY-MM-DD format. Must be a valid date between the years 1900 and "
                    "2099"
    )

    @field_validator("first_name", "last_name", "display_name", "biography")
    def trim_whitespace(cls, value: str) -> str:
        """
        Validator to remove leading and trailing whitespace from string fields.

        This validator is applied to the 'first_name', 'last_name', 'display_name', and 'biography'
        fields. If the input string is not empty, it returns the string stripped of any leading or
        trailing whitespace. Otherwise, it returns the value unchanged.

        :param value: The input string to be cleaned.
        :return: The cleaned string without extra whitespace.
        """
        return value.strip() if value else value

    @field_validator("birthday")
    def validate_birthday(cls, value: str) -> str:
        """
        Validates that the birthday is in the correct format and represents a valid date.

        The format must be "YYYY-MM-DD", where:
        - YYYY is a four-digit year between 1900 and 2099.
        - MM is a two-digit month between 01 and 12.
        - DD is a two-digit day between 01 and 31.

        If the value doesn't match the required format or isn't a valid date,
        an HTTPException with a 400 status code is raised.
        """

        # Define the regex pattern to check if the birthday is in the correct format (YYYY-MM-DD)
        pattern = r"^(19[0-9]{2}|20[0-9]{2})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$"

        # Check if the value matches the expected format using regex
        if not match(pattern, value):
            raise HTTPException(status_code=400, detail="Birthday must be in format YYYY-MM-DD. Example: 1990-05-15")

        try:
            # Try to parse the date using strptime to ensure it's a valid date
            datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            # Raise a personalized exception if the date is invalid (e.g., 2021-02-30)
            raise HTTPException(status_code=400,
                                detail=f"Invalid date: '{value}' is not a valid date. Please check the day and month.")

        # Return the validated value if no errors were raised
        return value
