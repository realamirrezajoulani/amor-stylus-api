from typing import Sequence, Type
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import select, and_, or_, not_
from sqlmodel.ext.asyncio.session import AsyncSession
from starlette import status

from config_limiter import limiter
from dependencies import get_session, require_roles
from models.admin import Admin
from schemas.admin import AdminCreate, AdminUpdate
from utilities.auth import get_password_hash
from utilities.enums import UserRole, LogicalOperator

router = APIRouter()


@router.get(
    "/admins/",
    response_model=list[Admin],
    summary="Retrieve Admins",
    description="This endpoint fetches the list of admins. If the user has an admin role, it returns only the admin "
                "data associated with that user. If the user has a 'FULL' or 'ADMIN' role, it returns all the admins."
)
@limiter.limit("20/minute")
async def get_admins(
        session: AsyncSession = Depends(get_session),
        _user: dict = Depends(
            require_roles(
                UserRole.FULL.value,
                UserRole.ADMIN.value
            )
        )
) -> Sequence[Admin]:
    """
    Endpoint to retrieve admin information based on user roles.
    - Users with role 'ADMIN' will only be able to view their own admin record.
    - Users with role 'FULL' or 'ADMIN' can view all admin records.
    """

    if _user["role"] == UserRole.ADMIN.value:
        # If the user is an admin, fetch only the admin record of the authenticated user
        result = await session.exec(select(Admin).where(Admin.id == UUID(_user["id"])))
    else:
        # If the user is a 'FULL' role or any other authorized role, fetch all admin records
        result = await session.exec(select(Admin))

    admins = result.all()  # Retrieve the list of admins from the query result
    return admins


@router.post(
    "/admins/",
    response_model=Admin,
    summary="Create a New Admin",
    description="This endpoint allows a user with 'FULL' role to create a new admin. The admin password is hashed "
                "before being stored in the database."
)
@limiter.limit("1 per day")
async def create_admin(
        *,
        session: AsyncSession = Depends(get_session),
        _user: dict = Depends(
            require_roles(
                UserRole.FULL.value
            )
        ),
        admin_create: AdminCreate
) -> Admin | HTTPException:
    """
    Endpoint to create a new admin.
    - This endpoint can only be accessed by users with the 'FULL' role.
    - The password provided for the new admin will be securely hashed before storage.
    - If an error occurs during the process, a 500 Internal Server Error is raised.
    """

    # Hash the password before storing it in the database
    hashed_password = get_password_hash(admin_create.password)

    try:
        # Create an Admin instance and apply the hashed password
        db_admin = Admin.model_validate(admin_create, update={"password": hashed_password})

        # Add the new admin to the session
        session.add(db_admin)

        # Commit the transaction to the database
        await session.commit()

        # Refresh the object to get the latest data from the database
        await session.refresh(db_admin)

        # Return the created admin
        return db_admin
    except Exception as e:
        # Rollback in case of any error during the transaction
        await session.rollback()

        # Raise an HTTP exception with a 500 status code and error details
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/admins/{admin_id}",
    response_model=Admin,
    summary="Retrieve an Admin by ID",
    description=(
        "This endpoint retrieves an admin record by its unique identifier. Users with the 'FULL' role "
        "are allowed to access any admin record, whereas users with the 'ADMIN' role can only view their own record."
    )
)
@limiter.limit("10/minute")
async def get_admin(
    *,
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(
        require_roles(
            UserRole.FULL.value,
            UserRole.ADMIN.value
        )
    ),
    admin_id: UUID
) -> Type[Admin]:
    # Retrieve the admin record from the database using the provided unique identifier.
    admin_record = await session.get(Admin, admin_id)

    # If no admin record is found, return a 404 Not Found error.
    if not admin_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin record not found")

    # If the authenticated user has the 'ADMIN' role, ensure they are accessing only their own record.
    if _user["role"] == UserRole.ADMIN.value and UUID(_user["id"]) != admin_record.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You are not allowed to view other admin's information")

    # Return the retrieved admin record.
    return admin_record


@router.patch(
    "/admins/{admin_id}",
    response_model=Admin,
    summary="Update an Admin's Information",
    description=(
            "This endpoint allows updating an admin's details. "
            "Users with the 'FULL' role can update any admin, while 'ADMIN' role users "
            "can only update their own record. If a password update is requested, it will be securely hashed."
    )
)
@limiter.limit("1 per day")
async def patch_admin(
        *,
        session: AsyncSession = Depends(get_session),
        _user: dict = Depends(
            require_roles(
                UserRole.FULL.value,
                UserRole.ADMIN.value
            )
        ),
        admin_id: UUID,
        admin_update: AdminUpdate
) -> Type[Admin]:
    """
    Update an admin's information based on their role:
    - Users with the 'ADMIN' role can only update their own profile.
    - Users with the 'FULL' role can update any admin's details.
    - If a password is updated, it will be hashed before storing.
    """

    # Fetch the admin record by ID
    admin_record = await session.get(Admin, admin_id)

    # If no admin record is found, return a 404 Not Found error
    if not admin_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin record not found")

    # Ensure 'ADMIN' role users can only edit their own profile
    if _user["role"] == UserRole.ADMIN.value and UUID(_user["id"]) != admin_record.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You are not allowed to edit other admin's information")

    # Extract only the provided (non-null) fields to update
    update_data = admin_update.model_dump(exclude_unset=True)

    # Handle password hashing if password update is requested
    extra_data = {}
    if "password" in update_data:
        hashed_password = get_password_hash(update_data["password"])
        extra_data["password"] = hashed_password

    # Update the admin record with new values
    admin_record.sqlmodel_update(update_data, update=extra_data)
    await session.commit()
    await session.refresh(admin_record)

    # Commit changes to the database
    session.add(admin_record)
    await session.commit()
    await session.refresh(admin_record)

    return admin_record  # Return the updated admin record


@router.delete(
    "/admins/{admin_id}",
    response_model=Admin,
    summary="Delete an Admin Account",
    description=(
        "This endpoint allows the deletion of an admin account. "
        "Users with the 'FULL' role can delete any admin, while 'ADMIN' role users "
        "can only delete their own account."
    )
)
@limiter.limit("1 per day")
async def delete_admin(
    *,
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(
        require_roles(
            UserRole.FULL.value,
            UserRole.ADMIN.value)
    ),
    admin_id: UUID
) -> Type[Admin]:
    """
    Delete an admin record based on the following rules:
    - Users with the 'ADMIN' role can only delete their own account.
    - Users with the 'FULL' role can delete any admin account.
    - If the specified admin does not exist, return a 404 error.
    """

    # Fetch the admin record by ID
    admin_record = await session.get(Admin, admin_id)

    # If no admin record is found, return a 404 Not Found error
    if not admin_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin record not found")

    # Ensure 'ADMIN' role users can only delete their own account
    if _user["role"] == UserRole.ADMIN.value and UUID(_user["id"]) != admin_record.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You are not allowed to delete other admin accounts")

    # Delete the admin record
    await session.delete(admin_record)
    await session.commit()

    return admin_record  # Return the deleted admin record


@router.get(
    "/admins/search/",
    response_model=list[Admin],
    summary="Search Admins",
    description=(
        "This endpoint allows searching for admin users based on username and/or role. "
        "The search conditions can be combined using logical operators (AND, OR, NOT). "
        "Only users with the 'FULL' role can perform this search."
    )
)
@limiter.limit("10/minute")
async def search_admins(
    *,
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(require_roles(UserRole.FULL.value)),
    username: str | None = None,
    role: UserRole | None = None,
    operator: LogicalOperator
):
    """
    Search for admin records based on given criteria:
    - Users can filter by `username` (partial match) and/or `role`.
    - The `operator` parameter determines how multiple conditions are combined:
        - `AND`: Match all specified conditions.
        - `OR`: Match any of the specified conditions.
        - `NOT`: Exclude results matching the conditions.
    - At least one search condition (username or role) must be provided.
    - Only users with the 'FULL' role can access this search.
    """

    conditions = []
    query = select(Admin)

    # Add search conditions if provided
    if username:
        conditions.append(Admin.username.ilike(f"%{username}%"))  # Case-insensitive search
    if role:
        conditions.append(Admin.role == role)

    # Ensure at least one search condition is provided
    if not conditions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="At least one search condition (username or role) must be specified")

    # Apply logical operator to conditions
    if operator == LogicalOperator.AND:
        query = query.where(and_(*conditions))
    elif operator == LogicalOperator.OR:
        query = query.where(or_(*conditions))
    elif operator == LogicalOperator.NOT:
        query = query.where(not_(and_(*conditions)))
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid operator specified")

    # Execute the query and retrieve results
    result = await session.exec(query)
    admins = result.all()

    # Handle case where no matching admins are found
    if not admins:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No matching admins found")

    return admins  # Return the list of matched admin records
