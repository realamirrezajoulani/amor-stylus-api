from typing import Sequence

from models.author_and_post import Post
from schemas.author import AuthorPublic
from schemas.author_posts import AuthorPublicWithPosts, PostPublicWithAuthor


def generate_author_links(author: AuthorPublicWithPosts) -> dict:
    """
    Generates a dictionary of HATEOAS links related to the given author.

    Parameters:
    - author (AuthorPublicWithPosts): The author object containing id and related posts.

    Returns:
    - dict: A dictionary containing URLs for self, update, delete, and posts of the author.
    """
    return {
        "self": f"/authors/{author.id}",  # Link to the author's profile
        "update": f"/authors/{author.id}",  # Link to update the author's details
        "delete": f"/authors/{author.id}",  # Link to delete the author's profile
        "posts": f"/authors/{author.id}/posts"  # Link to view the posts written by the author
    }


def generate_post_links(post: PostPublicWithAuthor) -> dict:
    """
    Generates a dictionary of HATEOAS links related to the given post.

    Parameters:
    - post (PostPublicWithAuthor): The post object containing id and related author.

    Returns:
    - dict: A dictionary containing URLs for self, update, delete, and author details of the post.
    """
    return {
        "self": f"/posts/{post.id}",  # Link to the post itself
        "update": f"/posts/{post.id}",  # Link to update the post details
        "delete": f"/posts/{post.id}",  # Link to delete the post
        "author": f"/authors/{post.author.id}"  # Link to view the author who wrote the post
    }


def prepare_posts_with_author_and_links(posts: Sequence[Post]) -> list[PostPublicWithAuthor]:
    """
    Iterates over a list of posts and enriches them by adding author details
    (if missing) and generating relevant links for each post. Returns a list
    of enriched posts.

    Args:
        posts (Sequence[Post]): A Sequence of posts to be enriched. Each post is expected
                                to be a dictionary containing post data.

    Returns:
        List[PostPublicWithAuthor]: A list of posts enriched with author details and links.
    """
    posts_with_links = []

    for post in posts:
        # Validate and prepare the post data with author details and links
        post_data = PostPublicWithAuthor.model_validate(post)

        # Check if the post data is missing an author, and if so, attach author details
        if post_data.author is None and post.author:
            post_data.author = AuthorPublic.model_validate(post.author)

        # Generate any necessary links related to the post
        post_data.links = generate_post_links(post_data)

        # Append the enriched post data to the results list
        posts_with_links.append(post_data)

    return posts_with_links

