from enum import Enum


class Gender(str, Enum):
    MALE = "male"
    FEMALE = "female"
    OTHERS = "others"


class LogicalOperator(str, Enum):
    """
    Enum representing the logical operators used in search endpoints.

    - AND: Used to combine multiple search conditions where all must be true.
    - OR: Used to combine multiple search conditions where at least one must be true.
    - NOT: Used to exclude certain conditions from the search.
    """
    AND = "and"
    OR = "or"
    NOT = "not"


class PostPublicationStatus(str, Enum):
    """
    Enum representing the different publication statuses of a post.

    - DRAFT: The post is in draft state and has not been published yet.
    - PENDING: The post is under review or awaiting approval.
    - PUBLISHED: The post has been published and is visible to the public.
    - REJECTED: The post has been rejected and will not be published.
    """
    DRAFT = "draft"
    PENDING = "pending"
    PUBLISHED = "published"
    REJECTED = "rejected"


class UserRole(str, Enum):
    """
    Enum representing the different roles a user can have in the system.

    - FULL: A user with full access to the system, including the ability to perform CRUD operations on posts
      and users. They can also view posts from other authors, view other users, delete their own account,
      but they have no access to the admin model.
    - ADMIN: A user with administrative privileges, capable of performing CRUD operations on users and posts.
      In the admin model, they can only edit their own information and delete their own account, with no access
      to other admin functionalities.
    - AUTHOR: A user with administrative access to perform CRUD operations on users, posts, and admins.
    """
    FULL = "full"
    ADMIN = "admin"
    AUTHOR = "author"
