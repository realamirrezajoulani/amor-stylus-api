from fastapi import FastAPI, Request
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from database import lifespan
from routers import authors, auth, admins, posts, redirect
from routers.authors import limiter
from utilities.auth import CSRFMiddleware


description = """
A lightweight RESTful API for a simple blog application using FastAPI and SQLModel 🚀
"""


app = FastAPI(lifespan=lifespan,
              title="Amor Stylus API",
              description=description,
              version="0.0.1",
              contact={
                  "name": "Amirreza Joulani",
                  "email": "realamirrezajoulani@gmail.com",
              },
              license_info={
                  "name": "MIT",
                  "url": "https://opensource.org/license/MIT",
              },
              docs_url=None,
              redoc_url=None)


@app.get("/docs", include_in_schema=False)
async def swagger_ui_html(req: Request) -> HTMLResponse:
    """
    Custom Swagger UI documentation page.

    This endpoint serves the Swagger UI with appropriate settings, including:
    - Correct OpenAPI schema path
    - OAuth2 redirect URL (if configured)
    - Custom favicon for branding

    Args:
        req (Request): Incoming HTTP request to determine root path.

    Returns:
        HTMLResponse: Customized Swagger UI page.
    """

    root_path = req.scope.get("root_path", "").rstrip("/")
    openapi_url = root_path + app.openapi_url
    oauth2_redirect_url = app.swagger_ui_oauth2_redirect_url

    if oauth2_redirect_url:
        oauth2_redirect_url = root_path + oauth2_redirect_url

    return get_swagger_ui_html(
        openapi_url=openapi_url,
        title=f"{app.title} - Swagger UI",  # Dynamic title for the documentation
        oauth2_redirect_url=oauth2_redirect_url,
        init_oauth=app.swagger_ui_init_oauth,
        swagger_favicon_url="./static/favicon.ico",  # Custom favicon path
        swagger_ui_parameters=app.swagger_ui_parameters,  # Additional UI parameters
    )


app.add_middleware(GZipMiddleware, minimum_size=1000, compresslevel=4)
app.add_middleware(CSRFMiddleware)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Expect-CT"] = "max-age=86400, enforce"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# app.add_middleware(HTTPSRedirectMiddleware)


app.state.limiter = limiter
app.mount("/static", StaticFiles(directory="static"), name="static")


app.include_router(auth.router, tags=["authentication"])
app.include_router(posts.router, tags=["posts"])
app.include_router(authors.router, tags=["authors"])
app.include_router(admins.router, tags=["admins"])
app.include_router(redirect.router)
