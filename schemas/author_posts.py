from sqlmodel import Field

from schemas.author import AuthorPublic
from schemas.post import PostPublic


class AuthorPublicWithPosts(AuthorPublic):
    posts: list[PostPublic] = []
    links: dict = Field(default_factory=dict)


class PostPublicWithAuthor(PostPublic):
    author: AuthorPublic
    links: dict = Field(default_factory=dict)

AuthorPublicWithPosts.model_rebuild()
PostPublicWithAuthor.model_rebuild()
