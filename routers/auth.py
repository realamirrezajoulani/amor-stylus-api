import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette import status

from config_limiter import limiter
from dependencies import get_session
from schemas.auth import LoginRequest
from utilities.auth import authenticate_user, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES, \
    REFRESH_TOKEN_EXPIRE_MINUTES, decode_access_token


router = APIRouter()


@router.post("/refresh-token/",
             summary="Refreshes the access token and rotates the refresh token while verifying CSRF protection.",
             description="This endpoint refreshes the user's access token and rotates the refresh token securely. It "
                         "validates the CSRF token, decodes and verifies the refresh token, and then issues new "
                         "tokens with updated expiration times. A new CSRF token is also generated for enhanced "
                         "security.")
@limiter.limit("10/hour")
async def refresh_token(request: Request,
                        response: Response) -> dict[str, str]:
    # Retrieve the refresh token from the cookie
    refresh_token_cookie = request.cookies.get("refresh_token")
    if not refresh_token_cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token missing")

    # Verify the CSRF token: it must be present both in the cookie and in the header, and they must match
    csrf_token_cookie = request.cookies.get("csrf_token")
    csrf_token_header = request.headers.get("X-CSRF-Token")
    if not csrf_token_cookie or not csrf_token_header or csrf_token_cookie != csrf_token_header:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")

    # Decode and verify the refresh token (ensuring it is a refresh token)
    payload = decode_access_token(refresh_token_cookie)
    user_id = payload.get("id")
    role = payload.get("role")
    if not user_id or not role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token data")

    # Issue a new access token (with token_type "access")
    new_access_token = create_access_token(data={"id": user_id, "role": role})
    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    # Rotate the refresh token: create a new refresh token
    new_refresh_token = create_access_token(
        data={"id": user_id, "role": role},
        expires_delta=timedelta(days=7)
    )
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_MINUTES * 60,
    )

    # Generate and set a new CSRF token
    new_csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key="csrf_token",
        value=new_csrf_token,
        httponly=False,
        secure=True,
        samesite="strict",
    )

    return {"message": "Access token refreshed"}


@router.post("/login/",
             summary="Authenticate user and set authentication tokens",
             description="Authenticates a user by validating credentials, generates an access token, a refresh token, "
                         "and a CSRF token. The tokens are securely sent as cookies with appropriate flags to ensure "
                         "security.")
@limiter.limit("10 per 10 minute")
async def login(
    *,
    session: AsyncSession = Depends(get_session),
    response: Response,  # The HTTP response object
    credentials: LoginRequest
) -> dict[str, str]:
    """
    Endpoint for logging in a user. This route authenticates the user, generates access and refresh tokens,
    and returns them as HttpOnly cookies for secure authentication.
    """
    # Authenticate the user with the provided credentials
    user = await authenticate_user(credentials, session)

    # Create a payload containing the user's role and ID for the token
    token_payload = {"role": credentials.role.value, "id": str(user.id)}

    # Generate the access token with a short expiry time
    access_token = create_access_token(data=token_payload)

    # Set the access token as an HttpOnly, secure cookie with an expiration time
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,  # Prevents JavaScript access
        secure=True,  # Ensures the cookie is only sent over HTTPS
        samesite="strict",  # Prevents CSRF by restricting cookie sending to same-site requests
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Token expiration duration in seconds
    )

    # Generate a refresh token with a longer expiry (7 days)
    refresh_access_token = create_access_token(data=token_payload, expires_delta=timedelta(days=7))

    # Set the refresh token as an HttpOnly, secure cookie with a longer expiration time
    response.set_cookie(
        key="refresh_token",
        value=refresh_access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_MINUTES * 60,
    )

    # Generate a CSRF token for added security in future requests
    csrf_token = secrets.token_urlsafe(32)

    # Set the CSRF token as a non-HttpOnly cookie to be accessible by JavaScript
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  # Allows JavaScript access to the token
        secure=True,
        samesite="strict",
    )

    # Return a success message after login
    return {"message": "Login successful"}


@router.post("/logout/",
             summary="Logs the user out by deleting the authentication cookies.",
             description="This endpoint logs the user out by removing the `access_token`, `refresh_token`, "
                         "and `csrf_token` cookies from the client's browser, ensuring the session is terminated.")
@limiter.limit("10/minute")
@limiter.limit("100/day")
async def logout(response: Response) -> dict[str, str]:
    # Delete the authentication cookies
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    response.delete_cookie("csrf_token")
    return {"message": "Logout successful"}
