from uuid import UUID

from fastapi import APIRouter, Depends, Query, HTTPException, Request
from fastapi_cache.decorator import cache
from pydantic import EmailStr
from sqlalchemy.exc import IntegrityError
from sqlmodel import select, and_, or_, not_
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette import status

from config_limiter import limiter
from dependencies import get_session, require_roles
from models.author_and_post import Author
from schemas.author_posts import AuthorPublicWithPosts
from schemas.author import  AuthorCreate, AuthorUpdate
from utilities.auth import get_password_hash
from utilities.enums import UserRole, Gender, LogicalOperator
from utilities.link_generator import generate_author_links


router = APIRouter()


@router.get(
    "/authors/",
    response_model=list[AuthorPublicWithPosts],
    summary="Retrieve a list of authors",
    description="Fetches a paginated list of authors, enriched with additional links and posts data."
)
@cache(expire=900)
@limiter.limit("3/minute")
async def get_authors(
    *,
    session: AsyncSession = Depends(get_session),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, le=100),
    request: Request
) -> list[AuthorPublicWithPosts]:
    # Execute the query to fetch authors with pagination support
    authors_query = select(Author).offset(offset).limit(limit)
    authors = await session.exec(authors_query)  # Execute the query asynchronously

    # Convert the result into a list of authors
    author_list = authors.all()

    # Initialize a list to store enriched author data
    authors_with_links = []

    # Process each author and add relevant links
    for author in author_list:
        # Map author data to the response model
        author_data = AuthorPublicWithPosts.model_validate(author)

        # Generate additional links for the author
        author_data.links = generate_author_links(author_data)

        # Add the enriched author data to the result list
        authors_with_links.append(author_data)

    # Return the enriched list of authors
    return authors_with_links


@router.post(
    "/authors/",
    response_model=AuthorPublicWithPosts,
    summary="Create a new author",
    description="Creates a new author with required permissions and returns enriched author data including generated "
                "resource links."
)
@limiter.limit("3 per day")
async def create_author(
        *,
        session: AsyncSession = Depends(get_session),
        _user: dict = Depends(
            require_roles(
                UserRole.FULL.value,
                UserRole.ADMIN.value,
                UserRole.AUTHOR.value
            )
        ),
        author_create: AuthorCreate,
        request: Request
) -> AuthorPublicWithPosts:
    """
    Creates a new author in the system with proper security controls and data validation.

    Args:
        session: Asynchronous database session dependency
        _user: Authenticated user with required roles (FULL, ADMIN, or AUTHOR)
        author_create: Validated author creation payload from request body

    Returns:
        AuthorPublicWithPosts: Complete author data with posts and HATEOAS links

    Raises:
        HTTPException 500: If database operation fails
    """
    # Securely hash password before persistence
    hashed_password = get_password_hash(author_create.password)

    try:
        # Create database model with validated data and hashed credentials
        db_author = Author.model_validate(
            author_create,
            update={"password": hashed_password}
        )

        # Persist to database with explicit transaction control
        session.add(db_author)
        await session.commit()
        await session.refresh(db_author)  # Acquire DB-generated fields

        # Prepare enriched response with HATEOAS links
        response_data = AuthorPublicWithPosts.model_validate(db_author)
        response_data.links = generate_author_links(response_data)

        return response_data

    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email is already used, please choose another another username or email."
        )
    except Exception as e:
        # Critical error handling with transaction rollback
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Author creation failed: {e}"
        )


@router.get(
    "/authors/{author_id}",
    response_model=AuthorPublicWithPosts,
    summary="Get Author Details by ID",
    description=(
            "This endpoint allows authenticated users with appropriate roles (FULL, ADMIN, or AUTHOR) "
            "to retrieve detailed information about a specific author, including their associated posts. "
            "You need to provide the unique identifier (ID) of the author to fetch their data."
    )
)
@cache(expire=900)
@limiter.limit("30/minute")
async def get_author(
        *,
        session: AsyncSession = Depends(get_session),
        _user: dict = Depends(
            require_roles(
                UserRole.FULL.value,
                UserRole.ADMIN.value,
                UserRole.AUTHOR.value
            )
        ),
        author_id: UUID,
        request: Request
) -> AuthorPublicWithPosts:
    """
    Retrieves the detailed information of a specific author, including their associated posts.

    This endpoint allows authenticated users with appropriate roles (FULL, ADMIN, or AUTHOR) to retrieve
    an author's public information and their posts by providing the author's unique ID.

    - **author_id**: The unique identifier of the author.
    """

    # Attempt to retrieve the author record from the database
    result = await session.get(Author, author_id)

    # If the author is found, process the data and add necessary links
    if result:
        author_data = AuthorPublicWithPosts.model_validate(result)  # Validate and format the author data
        author_data.links = generate_author_links(author_data)  # Add links to the author's information
        return author_data
    else:
        # If the author is not found, raise a 404 Not Found error
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Author not found")


@router.patch(
    "/authors/{author_id}",
    response_model=AuthorPublicWithPosts,
    summary="Update Author Details",
    description="Allows an authenticated user with appropriate roles (ADMIN, AUTHOR) to update an author's details. "
                "Authors can only modify their own information. Admins can edit any author's information."
)
@limiter.limit("2 per day")
async def patch_author(
        *,
        session: AsyncSession = Depends(get_session),
        _user: dict = Depends(
            require_roles(
                UserRole.FULL.value,
                UserRole.ADMIN.value,
                UserRole.AUTHOR.value
            )
        ),
        author_id: UUID,
        author_update: AuthorUpdate,
        request: Request
) -> AuthorPublicWithPosts:
    # Retrieve the author record from the database using the provided ID.
    result = await session.get(Author, author_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Author not found.")

    # If the user has the 'AUTHOR' role, ensure they can only update their own information.
    if _user["role"] == UserRole.AUTHOR.value and author_id != UUID(_user["id"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You cannot edit another author's information.")

    # Prepare the update data, excluding unset fields.
    author_data = author_update.model_dump(exclude_unset=True)
    extra_data = {}

    # If the password is being updated, hash it before saving.
    if "password" in author_data:
        password = author_data["password"]
        hashed_password = get_password_hash(password)
        extra_data["password"] = hashed_password

    # Apply the update to the author record.
    result.sqlmodel_update(author_data, update=extra_data)

    # Commit the transaction and refresh the instance to reflect the changes.
    session.add(result)
    await session.commit()
    await session.refresh(result)

    # Prepare the updated author data for the response.
    author_out = AuthorPublicWithPosts.model_validate(result)

    # Generate links associated with the updated author for the response.
    author_out.links = generate_author_links(author_out)

    return author_out


@router.delete(
    "/authors/{author_id}",
    response_model=AuthorPublicWithPosts,
    summary="Delete an author from the database",
    description=(
        "This endpoint allows users with certain roles (FULL, ADMIN, AUTHOR) to delete an author. "
        "If the requesting user is an AUTHOR, they can only delete themselves. "
        "If the author does not exist, a 404 error is returned. "
        "If the user does not have permission, a 403 error is returned."
    )
)
@limiter.limit("2 per day")
async def delete_author(
    *,
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(
        require_roles(
            UserRole.FULL.value,
            UserRole.ADMIN.value,
            UserRole.AUTHOR.value
        )
    ),
    author_id: UUID,
    request: Request
) -> AuthorPublicWithPosts:
    # Fetch the author record from the database using the provided ID.
    author_to_delete = await session.get(Author, author_id)

    # If the author is not found, raise a 404 Not Found error.
    if not author_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Author not found")

    # Check if the user is trying to delete themselves or is an admin/authorized full role.
    if _user["role"] == UserRole.AUTHOR.value and author_id != UUID(_user["id"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="You do not have permission to delete other authors")

    # Convert the deleted author object into a response model with the associated posts.
    author_out = AuthorPublicWithPosts.model_validate(author_to_delete)

    # Add relevant links to the response model.
    author_out.links = generate_author_links(author_out)

    # Proceed to delete the author if the above conditions are met.
    await session.delete(author_to_delete)
    await session.commit()  # Commit the transaction to apply the changes

    # Return the author information after deletion.
    return author_out


@router.get(
    "/authors/search/",
    response_model=list[AuthorPublicWithPosts],
    summary="Search for authors based on filter criteria",
    description=(
            "This endpoint allows users to search for authors by their first name, "
            "last name, username, email, or gender. Filters can be combined using "
            "logical operators (AND, OR, NOT), and the result can be paginated with "
            "offset and limit parameters. It returns a list of authors, including "
            "relevant information such as their associated posts and links."
    )
)
@cache(expire=60)
@limiter.limit("50/minute")
async def search_authors(
        *,
        session: AsyncSession = Depends(get_session),
        _user: dict = Depends(
            require_roles(
                UserRole.FULL.value,
                UserRole.ADMIN.value,
                UserRole.AUTHOR.value
            )
        ),
        first_name: str | None = None,
        last_name: str | None = None,
        username: str | None = None,
        email: EmailStr | None = None,
        gender: Gender | None = None,
        operator: LogicalOperator,  # Logical operator (AND, OR, NOT) to apply on filters
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, le=100),
        request: Request
) -> list[AuthorPublicWithPosts]:
    """
    Search for authors based on given filter criteria.

    Filters authors by first name, last name, username, email, and gender.
    The logical operator ('AND', 'OR', 'NOT') can be applied to combine filters.
    Pagination is supported with the ability to set an offset and limit.

    - **first_name**: Optional filter by author's first name (case-insensitive partial match).
    - **last_name**: Optional filter by author's last name (case-insensitive partial match).
    - **username**: Optional filter by author's username (exact match).
    - **email**: Optional filter by author's email (exact match).
    - **gender**: Optional filter by author's gender (exact match).
    - **operator**: Logical operator ('AND', 'OR', 'NOT') to combine conditions.
    - **offset**: The starting point for pagination.
    - **limit**: The maximum number of results to return (up to 100).

    Returns a list of authors with their associated posts and relevant links.
    """

    conditions = []  # Initialize the list of filter conditions

    # Start building the query to fetch authors with pagination.
    query = select(Author).offset(offset).limit(limit)

    # Add filters to the conditions list if the corresponding arguments are provided.
    if username:
        conditions.append(Author.username == username)
    if first_name:
        conditions.append(Author.first_name.ilike(f"%{first_name}%"))
    if last_name:
        conditions.append(Author.last_name.ilike(f"%{last_name}%"))
    if email:
        conditions.append(Author.email == email)
    if gender:
        conditions.append(Author.gender == gender)

    # If no conditions are provided, raise an error.
    if not conditions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No condition specified")

    # Apply the logical operator (AND, OR, or NOT) to combine the conditions.
    if operator == LogicalOperator.AND:
        query = query.where(and_(*conditions))
    elif operator == LogicalOperator.OR:
        query = query.where(or_(*conditions))
    elif operator == LogicalOperator.NOT:
        query = query.where(and_(not_(*conditions)))
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid operator specified")

    # Execute the query asynchronously.
    result = await session.exec(query)
    authors = result.all()  # Retrieve all authors that match the conditions

    # If no authors are found, raise a "not found" error.
    if not authors:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No authors found")

    # Prepare the response data: for each author, retrieve public information and associated posts.
    authors_with_links = []
    for author in authors:
        # Validate and serialize the author data
        author_data = AuthorPublicWithPosts.model_validate(author)
        # Generate links for each author's data
        author_data.links = generate_author_links(author_data)
        authors_with_links.append(author_data)

    # Return the list of authors along with their posts and links.
    return authors_with_links
