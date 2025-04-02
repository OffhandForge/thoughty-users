# **Users Service**

Microservice for providing authentication, authorization and token renewal

## 1. **Project Setup**
- Create a Spring Boot project with the following dependencies:
  - Spring Web
  - Spring Security
  - Spring Data JPA
  - PostgreSQL
  - JWT (`jjwt`)
  - BCrypt
  - Lombok
- Configure the connection to a PostgreSQL database.
- Set up schema migrations using Flyway.

## 2. **Data Model**
- **`users` table**: `id`, `email`, `password`, `roles`, `created_at`, `updated_at`.
- **`roles` table**: `id`, `name`.
- **`refresh_tokens` table**: `id`, `user_id`, `token`, `expiry_date`.

## 3. **Security Implementation**
- Configure Spring Security for authentication and authorization.
- Implement `UserDetailsService` to load user details.
- Set up BCrypt for password hashing.

## 4. **JWT Implementation**
- Create `JwtTokenProvider` for token generation and validation.
- Configure `JwtAuthenticationFilter` to intercept requests and validate tokens.
- Implement `AuthenticationController` with the following endpoints:
  - `/register`
  - `/login`
  - `/refresh-token`

## 5. **Login Attempt Limiting**
- Use Redis to store the number of failed login attempts.
- Lock a user account after exceeding the limit (e.g., 5 attempts within 10 minutes).

## 6. **Event Logging**
- Log successful and failed login attempts.
- Record password changes and user logouts.

## 7. **Testing**
- Write unit tests using JUnit 5 and Mockito.
- Implement integration tests using Testcontainers and MockMvc.

## 8. **API Documentation**
- Use Swagger/OpenAPI to document API endpoints.
- Include example requests and responses.

## 9. **Deployment and CI/CD**
- Create `Dockerfile` and `docker-compose.yml`.
- Set up CI/CD pipelines using GitHub Actions for automated deployment.
