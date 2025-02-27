from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi_cache.decorator import cache
from sqlalchemy.exc import IntegrityError
from sqlmodel import select, and_, or_, not_
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette import status

from config_limiter import limiter
from dependencies import get_session, require_roles
from models.author_and_post import Post, Author
from schemas.author import AuthorPublic
from schemas.author_posts import PostPublicWithAuthor
from schemas.post import PostCreate, PostUpdate
from utilities.enums import UserRole, PostPublicationStatus, LogicalOperator
from utilities.link_generator import generate_post_links, prepare_posts_with_author_and_links

router = APIRouter()


@router.get(
    "/posts/",
    response_model=list[PostPublicWithAuthor],
    summary="Retrieve a List of Posts",
    description="This endpoint retrieves a list of posts with detailed information about their authors. Supports "
                "pagination through offset and limit."
)
@cache(expire=300)
@limiter.limit("100/minute")
async def get_posts(
        *,
        session: AsyncSession = Depends(get_session),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, le=100),
        request: Request
) -> list[PostPublicWithAuthor]:
    """
    Fetch a paginated list of posts along with their respective authors' details.
    Pagination is handled via 'offset' and 'limit' parameters. If an author is associated with a post,
    their information is also included in the response.

    Parameters:
    - offset (int): The number of records to skip (default is 0).
    - limit (int): The number of posts to return, with a maximum value of 100 (default is 100).
    - session (AsyncSession): The database session, injected via the dependency.

    Returns:
    - list[PostPublicWithAuthor]: A list of posts with the corresponding author details.

    Raises:
    - HTTPException: If an error occurs in retrieving the posts.
    """

    # Execute the database query to fetch the posts with pagination
    result = await session.exec(select(Post).offset(offset).limit(limit))

    # Get all posts from the query result
    posts = result.all()

    return prepare_posts_with_author_and_links(posts)


@router.post(
    "/posts/",
    response_model=PostPublicWithAuthor,
    summary="Create a New Post",
    description=(
        "Creates a new post with the provided details and associates it with an author. "
        "If the authenticated user has the 'AUTHOR' role, the post is automatically linked "
        "to their user ID; otherwise, the author ID supplied in the request payload is used. "
        "After creation, the post is returned along with the public author details and generated hypermedia links."
    ),
)
@limiter.limit("5/hour")
async def create_post(
    *,
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(
        require_roles(
            UserRole.FULL.value,
            UserRole.ADMIN.value,
            UserRole.AUTHOR.value
        )
    ),
    post_create: PostCreate,
    request: Request
) -> PostPublicWithAuthor:
    """
    Create a new post with the specified details.

    Args:
        session (AsyncSession): Database session for committing and refreshing data.
        _user (dict): Authenticated user information, including role and ID.
        post_create (PostCreate): Data payload containing post details such as title, content, thumbnail,
                                  publication status, like count, and (optionally) an author ID.

    Returns:
        PostPublicWithAuthor: The newly created post enriched with author details and hypermedia links.

    Raises:
        HTTPException: If an error occurs during the post creation process.
    """
    # Determine the final author ID based on the user's role.
    # If the user is an AUTHOR, use their own user ID; otherwise, use the author ID provided in the payload.
    if _user["role"] == UserRole.AUTHOR.value:
        final_author_id = UUID(_user["id"])
    else:
        final_author_id = post_create.author_id

    try:
        # Instantiate a new Post object with data from the post_create payload and the resolved author ID.
        db_post = Post(
            thumbnail_base64=post_create.thumbnail_base64,
            title=post_create.title,
            content=post_create.content,
            publication_status=post_create.publication_status,
            like_count=post_create.like_count,
            author_id=final_author_id,
        )

        # Add the new post to the database session and commit the transaction.
        session.add(db_post)
        await session.commit()

        # Refresh the instance to load any auto-generated fields (e.g., ID, timestamps).
        await session.refresh(db_post)

        # Validate and convert the database model to the response schema.
        post_data = PostPublicWithAuthor.model_validate(db_post)

        # If the author information is missing from the validated data but exists on the database model,
        # validate and attach the public author details.
        if post_data.author is None and db_post.author:
            post_data.author = AuthorPublic.model_validate(db_post.author)

        # Generate hypermedia links related to the post (e.g., self, edit, delete).
        post_data.links = generate_post_links(post_data)

        # Return the enriched post data as the response.
        return post_data

    except IntegrityError:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The provided author ID is invalid or does not exist. Please check and try again."
        )
    except Exception as e:
        # In case of any error, rollback the session to avoid partial commits,
        # then raise an HTTPException with a 500 Internal Server Error.
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get(
    "/posts/{post_id}",
    response_model=PostPublicWithAuthor,
    summary="Retrieve a Post by ID",
    description="This endpoint fetches a specific post by its ID, including detailed information about the post's "
                "author, if available."
)
@cache(expire=600)
@limiter.limit("60/minute")
async def get_post(
    *,
    session: AsyncSession = Depends(get_session),
    post_id: UUID,
    request: Request
) -> PostPublicWithAuthor:
    """
    Retrieve a specific post from the database by its ID, along with the author's information.
    If the post is found, the response includes the post's details and its author.
    If no such post is found, a 404 Not Found exception is raised.

    Parameters:
    - post_id (UUID): The ID of the post to retrieve.
    - session (AsyncSession): The database session injected by the dependency.

    Returns:
    - PostPublicWithAuthor: A response model containing the post and author information.

    Raises:
    - HTTPException: If the post is not found, a 404 error is raised.
    """

    # Attempt to retrieve the post by ID from the database
    result = await session.get(Post, post_id)

    if not result:
        # Raise a 404 error if the post is not found
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post Not Found")

    # Validate and prepare the post data for the response
    post_data = PostPublicWithAuthor.model_validate(result)

    # If the post has an associated author, validate and attach author data
    if post_data.author:
        post_data.author = AuthorPublic.model_validate(result.author)

    # Generate and attach any necessary links related to the post
    post_data.links = generate_post_links(post_data)

    return post_data


@router.patch(
    "/posts/{post_id}",
    response_model=PostPublicWithAuthor,
    summary="Update an Existing Post",
    description=(
        "This endpoint allows an authorized user (ADMIN, FULL, or AUTHOR) to update the details "
        "of an existing post. The user must be the post's author to make modifications unless they "
        "have administrative privileges. The post details are updated based on the provided data, and "
        "the updated post is returned along with the public author information and associated hypermedia links."
    ),
)
@limiter.limit("5 per day")
async def patch_post(
    *,
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(
        require_roles(
            UserRole.FULL.value,
            UserRole.ADMIN.value,
            UserRole.AUTHOR.value
        )
    ),
    post_id: UUID,
    post_update: PostUpdate,
    request: Request
) -> PostPublicWithAuthor:
    """
    Update an existing post based on the provided update payload.

    Args:
        session (AsyncSession): Database session for committing and refreshing data.
        _user (dict): Authenticated user information, including role and ID.
        post_id (uuid.UUID): The ID of the post to be updated.
        post_update (PostUpdate): Data payload containing the updated post details.

    Returns:
        PostPublicWithAuthor: The updated post with the public author details and hypermedia links.

    Raises:
        HTTPException: If the post is not found (404) or if the user is not authorized (403).
    """
    # Retrieve the post by its ID. If the post does not exist, return a 404 error.
    result = await session.get(Post, post_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # Check if the user is authorized to edit the post. Authors can only edit their own posts.
    if _user["role"] == UserRole.AUTHOR.value:
        if result.author_id != UUID(_user["id"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You can't edit someone else's post")

    # Prepare the update data by excluding any unset fields (only updating provided fields).
    post_data = post_update.model_dump(exclude_unset=True)

    # Update the post's data in the database.
    result.sqlmodel_update(post_data)
    session.add(result)

    # Commit the transaction and refresh the instance to get the updated values.
    await session.commit()
    await session.refresh(result)

    # Validate and convert the updated post to the response schema.
    post_out = PostPublicWithAuthor.model_validate(result)

    # If the author information is missing in the response, but exists in the post, attach it.
    if post_out.author is None and result.author:
        post_out.author = AuthorPublic.model_validate(result.author)

    # Generate hypermedia links related to the post (e.g., self, edit, delete).
    post_out.links = generate_post_links(post_out)

    # Return the updated post with links and author details.
    return post_out


@router.delete(
    "/posts/{post_id}",
    response_model=PostPublicWithAuthor,
    summary="Delete a Post",
    description=(
        "This endpoint allows an authorized user (ADMIN, FULL, or AUTHOR) to delete an existing post. "
        "The user must be the post's author to delete it unless they have administrative privileges. "
        "Upon successful deletion, the deleted post is returned along with the public author information."
    ),
)
@limiter.limit("5 per day")
async def delete_post(
    *,
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(
        require_roles(
            UserRole.FULL.value,
            UserRole.ADMIN.value,
            UserRole.AUTHOR.value
        )
    ),
    post_id: UUID,
    request: Request
) -> PostPublicWithAuthor:
    """
    Delete an existing post by its ID.

    Args:
        session (AsyncSession): Database session for committing and refreshing data.
        _user (dict): Authenticated user information, including role and ID.
        post_id (uuid.UUID): The ID of the post to be deleted.

    Returns:
        PostPublicWithAuthor: The deleted post, returned with public author details and hypermedia links.

    Raises:
        HTTPException: If the post is not found (404) or if the user is not authorized to delete it (403).
    """
    # Retrieve the post by its ID. If the post does not exist, return a 404 error.
    result = await session.get(Post, post_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")

    # Check if the user is authorized to delete the post. Authors can only delete their own posts.
    if _user["role"] == UserRole.AUTHOR.value:
        if result.author_id != UUID(_user["id"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You can't delete someone else's post")

    # Return the deleted post along with author details and hypermedia links.
    post_out = PostPublicWithAuthor.model_validate(result)
    if post_out.author is None and result.author:
        post_out.author = AuthorPublic.model_validate(result.author)
    post_out.links = generate_post_links(post_out)

    # Delete the post from the database session.
    await session.delete(result)

    # Commit the transaction to finalize the deletion.
    await session.commit()

    return post_out


@router.get(
    "/posts/search/",
    response_model=list[PostPublicWithAuthor],
    summary="Search for Posts",
    description=(
            "This endpoint allows searching for posts based on various filters, such as title, publication status, "
            "content, and like count. The search supports both 'AND' and 'OR' logical operators, allowing flexible search queries. "
            "Pagination is supported with an offset and a limit parameter, with a maximum limit of 100 results per query."
    ),
)
@cache(expire=60)
@limiter.limit("50/minute")
async def search_posts(
        *,
        session: AsyncSession = Depends(get_session),
        _user: dict = Depends(
            require_roles(
                UserRole.FULL.value,
                UserRole.ADMIN.value,
                UserRole.AUTHOR.value
            )
        ),
        title: str | None = None,
        publication_status: PostPublicationStatus | None = None,
        content: str | None = None,
        like_count: int | None = None,
        operator: LogicalOperator,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, le=100),
        request: Request
) -> list[PostPublicWithAuthor]:
    """
    Search for posts based on various filters.

    Args:
        session (AsyncSession): Database session for querying posts.
        _user (dict): Authenticated user information (role and ID).
        title (str | None): Title filter for the search.
        publication_status (PublicationStatus | None): Filter posts by publication status.
        content (str | None): Content filter for the search.
        like_count (int | None): Filter posts by exact like count.
        operator (OperatorEn): Logical operator to combine filters ('AND', 'OR', 'NOT').
        offset (int): The number of posts to skip (used for pagination).
        limit (int): The maximum number of posts to return (used for pagination, default is 100).

    Returns:
        list[PostPublicWithAuthor]: List of posts matching the search criteria, along with author details and hypermedia links.

    Raises:
        HTTPException: If no valid conditions are provided (400), invalid operator is specified (400), or no posts are found (404).
    """

    # Initialize an empty list to hold the conditions for filtering.
    conditions = []

    # Start building the query with pagination parameters.
    query = select(Post).offset(offset).limit(limit)

    # Add conditions based on provided query parameters.
    if title:
        conditions.append(Post.title.ilike(f"%{title}%"))
    if publication_status:
        conditions.append(Post.publication_status == publication_status)
    if content:
        conditions.append(Post.content.ilike(f"%{content}%"))
    if like_count:
        conditions.append(Post.like_count == like_count)

    # If no conditions are provided, raise a 400 error indicating that conditions are required.
    if not conditions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No condition specified")

    # Apply logical operators (AND, OR, NOT) to combine the conditions.
    if operator == LogicalOperator.AND:
        query = query.where(and_(*conditions))
    elif operator == LogicalOperator.OR:
        query = query.where(or_(*conditions))
    elif operator == LogicalOperator.NOT:
        query = query.where(not_(and_(*conditions)))
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid operator")

    # Execute the query to retrieve posts that match the conditions.
    result = await session.exec(query)
    posts = result.all()

    # If no posts are found, raise a 404 error.
    if not posts:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No posts found")

    return prepare_posts_with_author_and_links(posts)


@router.get("/authors/{author_id}/posts/",
            response_model=list[Post],
            summary="Fetches a list of posts written by a specific author identified by author_id",
            description="This endpoint allows you to retrieve all the posts associated with a specific author using "
                        "their unique author_id. It is restricted to users with the roles FULL, ADMIN, or AUTHOR to "
                        "ensure only authorized users can access the posts. The author is first checked against the "
                        "database to ensure their existence; if no matching author is found, a 404 Not Found response "
                        "will be returned.")
@limiter.limit("20 per day")
async def get_posts_from_author(
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
) -> list[Post]:
    """
    Retrieve a list of posts written by a specific author.

    This endpoint fetches all posts associated with a particular author using their unique ID.
    Access to this endpoint is restricted to users with roles 'FULL', 'ADMIN', or 'AUTHOR'.

    **Parameters:**
    - `author_id`: The UUID of the author whose posts are being requested.

    **Response:**
    - A list of posts by the specified author, represented as instances of the `PostPublic` schema.

    **Roles required:**
    - `FULL`, `ADMIN`, or `AUTHOR`
    """

    # Fetch the author from the database using the provided author ID
    result = await session.get(Author, author_id)

    # If the author is not found, return a 404 Not Found error
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Author not found")

    # Return the posts associated with the author
    return result.posts
