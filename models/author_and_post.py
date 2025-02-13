from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Column, DateTime, func
from sqlmodel import Field, Relationship

from schemas.base.author import AuthorBase
from schemas.base.post import PostBase


class Author(AuthorBase, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    password: str
    posts: list["Post"] = Relationship(back_populates="author", sa_relationship_kwargs={"lazy": "selectin"})


class Post(PostBase, table=True):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    author_id: UUID = Field(foreign_key="author.id", ondelete="CASCADE")
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), server_default=func.now()),
        description="The date and time when the content was first created"
    )
    updated_at: datetime | None = Field(
        sa_column=Column(DateTime(timezone=True), onupdate=func.now()),
        description="The date and time when the content was last updated"
    )
    author: Author = Relationship(back_populates="posts", sa_relationship_kwargs={"lazy": "selectin"})
