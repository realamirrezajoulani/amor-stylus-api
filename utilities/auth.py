from datetime import timedelta, timezone, datetime
import jwt
from secrets import token_urlsafe
from os import urandom
from typing import Any

from passlib.context import CryptContext
from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette import status
from starlette.middleware.base import BaseHTTPMiddleware

from models.admin import Admin
from models.author_and_post import Author
from schemas.auth import LoginRequest
from utilities.enums import UserRole

# Constants for token expiration times
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Access token lifetime (15 minutes)
REFRESH_TOKEN_EXPIRE_MINUTES = 7 * 24 * 60  # Refresh token lifetime (7 days)

# Generate a secure random salt
salt = urandom(16)

# Key Derivation Function (KDF) using PBKDF2-HMAC with SHA-512
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,  # Derived key length (256-bit)
    salt=salt,
    iterations=100_000,
)

# Generate a secure secret key
SECRET_KEY = kdf.derive(urandom(32)).hex()

# Algorithm used for JWT signing
ALGORITHM = "HS512"

# Password hashing context using PBKDF2-HMAC-SHA512
pwd_context = CryptContext(schemes=["pbkdf2_sha512"], deprecated="auto")

# OAuth2 password flow for authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Generates a JSON Web Token (JWT) containing the provided data and expiration time.

    Args:
        data (dict): A dictionary containing the data to be encoded in the JWT.
        expires_delta (Optional[timedelta]): The duration for which the token will be valid.
                                             If not provided, a default expiration time is used.

    Returns:
        str: The encoded JWT as a string.
    """

    # Create a copy of the input data to avoid mutating the original object
    to_encode = data.copy()

    # Calculate the expiration time by adding the expiration delta (if provided)
    # to the current time, otherwise use the default expiration time.
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))

    # Add the expiration time to the data to be encoded
    to_encode.update({"exp": expire})

    # Encode the JWT using the secret key and specified algorithm
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decodes a given JWT access token and returns its payload.

    Args:
        token (str): The JWT access token to be decoded.

    Returns:
        Dict[str, Any]: The decoded payload if the token is valid.

    Raises:
        HTTPException: If the token is expired or invalid.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Error decoding JWT: {e}"
        )


def get_password_hash(password: str) -> str:
    """
    Hashes the provided password using the bcrypt algorithm.

    Args:
        password (str): The plain password to be hashed.

    Returns:
        str: The hashed version of the provided password.

    This function hashes the provided password using the `hash` method from
    passlib's CryptContext. It's commonly used for securely storing passwords.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies whether the provided plain password matches the hashed password.

    Args:
        plain_password (str): The password in plain text to be verified.
        hashed_password (str): The hashed version of the password to compare against.

    Returns:
        bool: True if the plain password matches the hashed password, otherwise False.

    This function uses the `verify` method from passlib's CryptContext to compare
    the plain password with the stored hashed password. It handles exceptions gracefully
    and ensures the function always returns a boolean result.
    """
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as _:
        # Log the exception or handle the error in a more meaningful way
        return False


async def authenticate_user(credentials: LoginRequest, session: AsyncSession):
    username = credentials.username
    password = credentials.password
    role = credentials.role

    if role in (UserRole.ADMIN.value, UserRole.FULL.value):
        query = select(Admin).where(Admin.username == username).where(Admin.role == role)
        result = await session.exec(query)
        admin_user = result.one_or_none()

        if not admin_user or not verify_password(password, admin_user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Username or password incorrect",
            )
        return admin_user

    elif role == UserRole.AUTHOR.value:
        query = select(Author).where(Author.username == username)
        result = await session.exec(query)
        author_user = result.one_or_none()

        if not author_user or not verify_password(password, author_user.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Username or password incorrect",
            )
        return author_user

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role provided."
        )


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Middleware for CSRF (Cross-Site Request Forgery) protection.

    - Ensures that state-changing HTTP methods (POST, PUT, DELETE, PATCH) include a valid CSRF token.
    - Validates the token sent in the request header against the token stored in cookies.
    - If a CSRF token is missing or invalid, the request is denied with a 403 error.
    - Generates and sets a new CSRF token in cookies for requests that do not have one.
    """

    async def dispatch(self, request: Request, call_next):

        if request.url.hostname == "localhost":
            return await call_next(request)

        # Define HTTP methods that require CSRF protection
        csrf_protected_methods = {"POST", "PUT", "DELETE", "PATCH"}

        # Check if the request method requires CSRF validation
        if request.method in csrf_protected_methods:
            csrf_cookie = request.cookies.get("csrf_token")
            csrf_header = request.headers.get("X-CSRF-Token")

            # Deny the request if either the cookie or header token is missing
            if not csrf_cookie or not csrf_header:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "CSRF token missing"}
                )

            # Deny the request if the tokens do not match
            if csrf_cookie != csrf_header:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "CSRF token mismatch"}
                )

        # Proceed with the request processing
        response: Response = await call_next(request)

        # If the CSRF token is not present in cookies, generate and set a new one
        if "csrf_token" not in request.cookies:
            new_csrf_token = token_urlsafe(32)
            response.set_cookie(
                key="csrf_token",
                value=new_csrf_token,
                httponly=False,  # Allow JavaScript to access the token for inclusion in headers
                secure=True,  # Ensure the cookie is only transmitted over HTTPS
                samesite="strict"  # Prevent CSRF attacks by restricting cross-site requests
            )

        return response
