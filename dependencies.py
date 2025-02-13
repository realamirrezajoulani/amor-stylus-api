from typing import Callable, Any, AsyncGenerator

import jwt
from fastapi import Depends, HTTPException, Request
from starlette import status
from sqlmodel.ext.asyncio.session import AsyncSession

from database import async_engine
from utilities.auth import decode_access_token


def require_roles(*required_roles: str) -> Callable:
    """
    Dependency function to enforce role-based access control.

    Args:
        required_roles (str): The roles that are allowed to access the endpoint.

    Returns:
        Callable: An async dependency function that checks user role.

    Raises:
        HTTPException: If the user does not have the required role.
    """

    async def dependency(_user: dict = Depends(get_current_user)) -> dict:
        """
        Validates if the current user has the required role.

        Args:
            _user (dict): The authenticated user's information.

        Returns:
            dict: The authenticated user object if access is granted.

        Raises:
            HTTPException: If the user's role is not in `required_roles`.
        """
        if _user["role"] not in required_roles:
            allowed_roles = ", ".join(required_roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access requires one of the following roles: {allowed_roles}"
            )
        return _user

    return dependency


def get_current_user(request: Request) -> dict[str, Any]:
    """
    Extracts and verifies the current user's authentication token.

    Args:
        request (Request): The incoming HTTP request object.

    Returns:
        Dict[str, Any]: The decoded token payload containing user details.

    Raises:
        HTTPException:
            - 401 Unauthorized if the token is missing or invalid.
            - 403 Forbidden if the token does not contain a role.
    """

    # Retrieve the access token from cookies
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    # Remove 'Bearer ' prefix if present
    token = token.removeprefix("Bearer ")

    try:
        # Decode the token to extract user information
        payload = decode_access_token(token)

        # Ensure the role exists in the payload
        role = payload.get("role")
        if not role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Role not found"
            )

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}"
        )

    return payload


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Asynchronous dependency to provide a database session.

    This function creates and manages an asynchronous database session using SQLAlchemy's AsyncSession.
    It ensures proper session handling, including cleanup after use.

    Yields:
        AsyncSession: A database session that can be used for queries.

    Example:
        async with get_session() as session:
            result = await session.execute(statement)
            data = result.scalars().all()

    Raises:
        Exception: If session creation fails (unlikely, but can be handled for logging).
    """
    try:
        async with AsyncSession(async_engine) as session:
            yield session  # Provide the session to the caller
    except Exception as e:
        # Log the error if necessary (logging module can be used)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(e))
