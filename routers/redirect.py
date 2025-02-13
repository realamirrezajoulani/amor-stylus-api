from fastapi import APIRouter
from fastapi.responses import RedirectResponse


router = APIRouter()


@router.get("/", include_in_schema=False)
def home():
    """
    Redirects the root URL (`/`) to the Swagger UI documentation (`/docs`).
    This ensures users land on the API documentation when accessing the base URL.
    """
    return RedirectResponse(url="/docs", status_code=308)
