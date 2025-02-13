from uuid import UUID
from datetime import datetime

from sqlmodel import Field

from .base.post import PostBase
from utilities.enums import PostPublicationStatus


class PostPublic(PostBase):
    created_at: datetime
    updated_at: datetime | None
    id: UUID


class PostCreate(PostBase):
    author_id: UUID


class PostUpdate(PostBase):
    title: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        index=True,
        description="A short yet descriptive name or heading for the content, helping users quickly understand the "
                    "topic"
    )

    content: str | None = Field(
        default=None,
        min_length=1,
        max_length=10000,
        index=True,
        description="The main body of the post or article, containing detailed information, descriptions, "
                    "or discussions"
    )

    publication_status: PostPublicationStatus | None = Field(
        default=None,
        index=True,
        description="Indicates the current state of the content, such as whether it is published, in draft mode, "
                    "in pending mode, or archived"
    )
    like_count: int | None = Field(
        default=None,
        index=True,
        description="A numeric count of how many users have liked or reacted positively to the content"
    )
