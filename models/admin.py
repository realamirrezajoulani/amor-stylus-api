from uuid import UUID, uuid4

from sqlmodel import Field

from schemas.base.admin import AdminBase


class Admin(AdminBase, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
