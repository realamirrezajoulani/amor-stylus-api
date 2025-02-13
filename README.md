![Image](https://github.com/user-attachments/assets/dfe9abf6-5fff-454f-9c67-34c2e466d8a6)

## Features of the amor-stylus-api

# Implementation of Author and Admin Roles:
Designed models for posts, authors and admins with defined relationships and access controls.

# Model Validation for Author and Admin:
Robust Validation mechanisms that ensure data security and integrity.

# Custom JWT-Based Authentication Mechanism:
A secure, customized authentication flow built around JSON Web Tokens (JWT), While this approach utilizes Access and Refresh Tokens for session management, it does not follow the full OAuth2 standard..

# Advanced Search System with Logical Operators:
A combined search system that supports logical operators, allowing complex and precise queries.

# Role-Based Access Control for Endpoints:
Access to endpoints is governed by roles, ensuring that users can only access resources according to their assigned roles.

# Request Throttling:
Request rate limiting to prevent abuse and ensure the system's stability under heavy load. (Special thanks to [slowapi](https://github.com/laurentS/slowapi) and [redis](https://github.com/redis/redis))

# Async Architecture:
The entire project is designed using asynchronous programming principles, optimizing performance and responsiveness.

# Clean Code Principles:
The codebase follows ensuring readability, maintainability, and scalability.
