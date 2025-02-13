from sqlalchemy import Column
from sqlmodel import SQLModel, Field
from sqlalchemy.dialects.mysql import MEDIUMTEXT

from utilities.enums import PostPublicationStatus


class PostBase(SQLModel):
    thumbnail_base64: str | None = Field(
        default=None,
        description="A small preview image or thumbnail representing the content, usually stored as a base64 "
                    "encoded string The maximum allowed size is approximately 1 MB",
        sa_column=Column(
            MEDIUMTEXT,
            nullable=True
        )
    )

    title: str = Field(
        min_length=1,
        max_length=255,
        index=True,
        description="A short yet descriptive name or heading for the content, helping users quickly understand the "
                    "topic"
    )

    content: str = Field(
        min_length=1,
        max_length=10000,
        description="The main body of the post or article, containing detailed information, descriptions, "
                    "or discussions"
    )

    publication_status: PostPublicationStatus = Field(
        default=PostPublicationStatus.DRAFT,
        index=True,
        description="Indicates the current state of the content, such as whether it is published, in draft mode, "
                    "in pending mode, or archived"
    )
    like_count: int = Field(
        default=0,
        index=True,
        description="A numeric count of how many users have liked or reacted positively to the content"
    )
