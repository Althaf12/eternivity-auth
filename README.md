# Eternivity Auth

A Spring Boot authentication backend with JWT token support for the Eternivity platform.

## Features

- User registration and login with BCrypt password hashing
- JWT-based authentication with customizable expiration (10-15 minutes)
- User subscription management
- OAuth account linking support
- RESTful API endpoints

## Database Schema

The application uses PostgreSQL with the following tables:

### `users`
- `user_id` (UUID, Primary Key)
- `username` (VARCHAR, Unique, Not Null)
- `email` (VARCHAR, Unique, Not Null)
- `password_hash` (VARCHAR, Not Null)
- `created_at` (TIMESTAMP, Not Null)

### `oauth_accounts`
- `id` (BIGINT, Primary Key, Auto-increment)
- `user_id` (UUID, Foreign Key → users.user_id)
- `provider` (VARCHAR, Not Null)
- `provider_user_id` (VARCHAR, Not Null)

### `user_subscriptions`
- `id` (BIGINT, Primary Key, Auto-increment)
- `user_id` (UUID, Foreign Key → users.user_id)
- `service_code` (VARCHAR, Not Null)
- `plan` (VARCHAR, Not Null)
- `status` (VARCHAR, Not Null)
- `start_date` (DATE, Not Null)
- `end_date` (DATE)

## Prerequisites

- Java 17 or higher
- Maven 3.6+
- PostgreSQL 12+

## Setup

### 1. Database Setup

Create a PostgreSQL database named `eternivity_auth`:

```sql
CREATE DATABASE eternivity_auth;
```

### 2. Configuration

Update the database credentials in `src/main/resources/application.properties`:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/eternivity_auth
spring.datasource.username=your_username
spring.datasource.password=your_password
```

Update the JWT secret (use a secure random string in production):

```properties
jwt.secret=your-secure-secret-key-here
jwt.expiration=900000  # 15 minutes in milliseconds
```

**IMPORTANT:** For production environments, use environment variables or secure configuration management instead of hardcoding sensitive values:

```bash
# Example using environment variables
export SPRING_DATASOURCE_URL=jdbc:postgresql://localhost:5432/eternivity_auth
export SPRING_DATASOURCE_USERNAME=your_username
export SPRING_DATASOURCE_PASSWORD=your_password
export JWT_SECRET=your-secure-random-secret-key-with-at-least-256-bits
export JWT_EXPIRATION=900000
```

Or update application.properties to reference environment variables:

```properties
spring.datasource.url=${SPRING_DATASOURCE_URL:jdbc:postgresql://localhost:5432/eternivity_auth}
spring.datasource.username=${SPRING_DATASOURCE_USERNAME:postgres}
spring.datasource.password=${SPRING_DATASOURCE_PASSWORD:postgres}
jwt.secret=${JWT_SECRET:change-this-in-production}
jwt.expiration=${JWT_EXPIRATION:900000}
```

### 3. Build the Application

```bash
mvn clean package
```

### 4. Run the Application

```bash
java -jar target/eternivity-auth-1.0.0.jar
```

Or using Maven:

```bash
mvn spring-boot:run
```

The application will start on `http://localhost:8080`.

## API Endpoints

### 1. Register a New User

**Endpoint:** `POST /api/auth/register`

**Request Body:**
```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "type": "Bearer",
  "username": "johndoe",
  "email": "john@example.com"
}
```

### 2. Login

**Endpoint:** `POST /api/auth/login`

**Request Body:**
```json
{
  "username": "johndoe",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "type": "Bearer",
  "username": "johndoe",
  "email": "john@example.com"
}
```

### 3. Get Current User Information

**Endpoint:** `GET /api/auth/me`

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "username": "johndoe",
  "email": "john@example.com",
  "services": {
    "SERVICE_A": {
      "plan": "premium",
      "status": "active"
    },
    "SERVICE_B": {
      "plan": "basic",
      "status": "active"
    }
  }
}
```

## JWT Token Structure

The JWT access token includes the following claims:

- `sub`: User ID (UUID)
- `username`: User's username
- `email`: User's email address
- `services`: Map of service subscriptions with plan and status
  ```json
  {
    "SERVICE_CODE": {
      "plan": "plan_name",
      "status": "status_value"
    }
  }
  ```
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp (10-15 minutes from issue time)

## Testing with cURL

### Register a new user:
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "password123"
  }'
```

### Login:
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123"
  }'
```

### Get current user info:
```bash
curl -X GET http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN_HERE"
```

## Technology Stack

- **Spring Boot 3.2.0** - Application framework
- **Spring Security** - Authentication and authorization
- **Spring Data JPA** - Database access
- **PostgreSQL** - Database
- **JJWT 0.12.3** - JWT token generation and validation
- **BCrypt** - Password hashing
- **Lombok** - Reduce boilerplate code
- **Jakarta Validation** - Input validation

## Security Features

- Passwords are hashed using BCrypt before storage
- JWT tokens are signed using HS256 algorithm
- Stateless authentication (no server-side session storage)
- Token-based authentication for protected endpoints
- CSRF protection is intentionally disabled for this stateless REST API as it uses JWT tokens in the Authorization header (not cookies), making CSRF attacks not applicable

**Security Note:** This application is designed as a stateless REST API backend. CSRF protection is disabled because:
1. The API uses JWT tokens sent in the Authorization header, not cookies
2. It's intended for programmatic access (mobile apps, SPAs) rather than traditional form-based web applications
3. For stateless JWT authentication, CSRF attacks are not applicable

If you plan to use this API with browser-based clients that store tokens in cookies, you should re-enable CSRF protection.

## Project Structure

```
src/main/java/com/eternivity/auth/
├── EternivityAuthApplication.java    # Main application class
├── config/
│   └── SecurityConfig.java           # Spring Security configuration
├── controller/
│   └── AuthController.java           # REST API endpoints
├── dto/
│   ├── AuthResponse.java             # Authentication response DTO
│   ├── LoginRequest.java             # Login request DTO
│   ├── RegisterRequest.java          # Registration request DTO
│   └── UserInfoResponse.java         # User info response DTO
├── entity/
│   ├── OAuthAccount.java             # OAuth account entity
│   ├── User.java                     # User entity
│   └── UserSubscription.java         # User subscription entity
├── repository/
│   ├── OAuthAccountRepository.java   # OAuth account repository
│   ├── UserRepository.java           # User repository
│   └── UserSubscriptionRepository.java # User subscription repository
├── security/
│   ├── JwtAuthenticationFilter.java  # JWT authentication filter
│   └── JwtTokenProvider.java         # JWT token utility
└── service/
    └── AuthService.java               # Authentication service
```

## License

This project is licensed under the MIT License.