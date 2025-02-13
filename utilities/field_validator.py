from re import search

from fastapi import HTTPException


def validate_password_value(value: str) -> str | HTTPException:
    # Check if password meets minimum length (e.g., at least 16 characters)
    if len(value) < 16:
        raise HTTPException(status_code=400, detail="Password must be at least 16 characters long")

    # Check if password contains at least one uppercase letter
    if not search(r'[A-Z]', value):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")

    # Check if password contains at least one lowercase letter
    if not search(r'[a-z]', value):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter")

    # Check if password contains at least one digit
    if not search(r'[0-9]', value):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit")

    # Check if password contains at least one special character (e.g., !@#$%^&*)
    if not search(r'[!@#$%^&*(),.?":{}|<>]', value):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character")

    # If password passes all checks, return the value
    return value
