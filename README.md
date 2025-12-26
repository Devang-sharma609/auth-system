# JWT-Based Authentication Platform (Auth Server + Resource Server)

This repository contains an **industry-grade JWT authentication system** designed according to real-world enterprise standards. The system is split into **two independent services**:

- **Auth Server** (Authorization Server)
- **Resource Server** (Protected API Server)

The architecture follows OAuth 2.0 principles with JWT access tokens, opaque refresh tokens, token rotation, revocation, and JWKS-based public key distribution.

---

## 🏗️ Architecture Overview

```
jwt-security-platform/
│
├── auth-server/
│   ├── src/main/java
│   ├── src/main/resources
│   └── pom.xml
│
├── resource-server/
│   ├── src/main/java
│   ├── src/main/resources
│   └── pom.xml
│
└── docker-compose.yml
```

### Separation of Concerns

**Auth Server**
- Authenticates users
- Issues JWT access tokens
- Issues opaque refresh tokens
- Handles refresh token rotation
- Handles logout and revocation
- Publishes JWKS public keys

**Resource Server**
- Protects APIs
- Validates JWTs using JWKS
- Performs authorization (roles/scopes)
- Never issues or refreshes tokens

---

## 🔐 Token Strategy

### Access Token (JWT)
- Format: JWT (RS256)
- Lifetime: 5–15 minutes
- Stateless
- Signed using Auth Server private key

**Claims:**
- `sub` – user identifier
- `iss` – token issuer (Auth Server)
- `aud` – intended audience (Resource Server)
- `exp`, `iat`
- `scope` / `roles`
- `jti` – unique token ID

### Refresh Token (Opaque)
- Format: Random opaque string
- Lifetime: 7–30 days
- Stored server-side (hashed)
- Sent via HttpOnly Secure cookie
- Supports rotation and revocation

---

## 🔑 Key Management & JWKS

- JWTs are signed using **asymmetric keys (RSA)**
- Private key is stored only in Auth Server
- Public keys are exposed via:

```
GET /.well-known/jwks.json
```

- Each JWT contains a `kid` (Key ID)
- Multiple keys are supported for rotation
- Resource Server fetches keys automatically

---

## 🔁 Refresh Token Flow (Rotation)

1. Client calls `/oauth/refresh`
2. Refresh token sent automatically via cookie
3. Auth Server validates token
4. Old refresh token is revoked
5. New access + refresh tokens issued

### Reuse Detection
If a revoked refresh token is reused:
- All refresh tokens for the user are revoked
- User is forced to re-authenticate

---

## 🚪 Logout & Revocation

### Logout
```
POST /oauth/logout
```
- Revokes refresh token
- Clears refresh token cookie
- Access token expires naturally

### Password Change
- All refresh tokens for the user are revoked
- Existing access tokens expire by TTL

---

## 🗄️ Database Schema (Auth Server)

### users
```
id (UUID, PK)
username (unique)
password_hash
enabled
created_at
```

### refresh_tokens
```
id (UUID, PK)
user_id (FK)
token_hash
expires_at
revoked (boolean)
created_at
```

> Raw refresh tokens are **never stored**, only hashed values.

---

## 🔒 Security Best Practices

- HTTPS enforced
- HttpOnly + Secure cookies
- Short-lived access tokens
- Refresh token rotation
- Key rotation support
- No shared secrets between services
- Rate limiting on login/refresh endpoints
- No token values logged

---

## ⚙️ Tech Stack

- Java 17+
- Spring Boot 4.x
- Spring Security
- OAuth2 Authorization Server
- OAuth2 Resource Server
- PostgreSQL
- Optional Redis
- Docker & Docker Compose

---

## 🚀 Getting Started (High Level)

1. Start infrastructure using Docker Compose
2. Run Auth Server
3. Run Resource Server
4. Authenticate via Auth Server
5. Access protected APIs via Resource Server

---

## 📌 Why This Design?

This project mirrors how **real enterprise IAM systems** are built:
- Clear trust boundaries
- Stateless access tokens
- Revocable sessions
- Horizontal scalability
- Zero shared secrets

Completing and understanding this system prepares you for **mid-to-senior backend interviews** and real-world security design discussions.

---

## 📜 License

For learning and educational purposes.

