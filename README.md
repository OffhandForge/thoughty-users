# **Users Service**

Microservice for providing authentication, authorization and token renewal

## 1. **Project Setup**

The Users Service created with the following main dependencies:

- Spring Data JPA
- Spring Data Redis
- Spring Security
- Spring Testcontainers
- Spring Web
- Docker Compose
- JWT (`jjwt`)
- Lombok
- Mockito
- PostgreSQL
- Redis

- Set up schema migrations using Flyway. (To be implemented)

## 2. **Data Model**

- **`users` table**: `id`, `username`, `password`, `email`, `role`.
- **`refresh_tokens` table**: `id`, `username`, `issuer`, `audience`, `issuedAt`, `expiration`.

## 3. **Security**

- Spring Security configured for authentication and authorization.
- JWT (`access token`) is used for user authorization.
- UUID (`refresh token`) is used for renewal access token.
- BCrypt is used for password hashing.

## 4. **Access and Refresh tokens**

- Access token (`jwt`) contains issuer, subject(username), audience, issued date, expiration date, scopes.
- RSA256 algorithm is used for signing and verification of access token.
- Access token has 15 min expiration time and can be refreshed using refresh token.
- Refresh token (`uuid`) has 7 days expiration time and can be obtained by registration/login.

## 5. **Login Attempt Limiting**

- Redis used to store the number of failed login attempts.
- Lock a user account after exceeding the limit (e.g., 5 attempts within 10 minutes).

## 6. **Event Logging**

To be implemented.

- Log successful and failed login attempts.
- Record password changes and user logouts.

## 7. **Testing**

- Unit tests created using JUnit 5 and Mockito.
- Integration tests created using Testcontainers and MockMvc.

## 8. **API Documentation**

To be implemented.

- Use Swagger/OpenAPI to document API endpoints.
- Include example requests and responses.

## 9. **Deployment and CI/CD**

To be implemented.

- Create `Dockerfile` and `docker-compose.yml`.
- Set up CI/CD pipelines using GitHub Actions for automated deployment.
