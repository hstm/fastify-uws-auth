# Project Overview

## Secure Authentication System
### Fastify REST API + uWebSockets.js + PostgreSQL + Nginx

---

## Project Goals

Build a production-ready authentication system that demonstrates:

1. **Short-lived access tokens** (15 minutes) for security
2. **Refresh token rotation** to prevent replay attacks
3. **Seamless WebSocket reauth** without reconnection
4. **RS256 JWT signing** with public/private key pair
5. **Modern TypeScript** architecture
6. **Docker containerization** for easy deployment

---

## Architecture

### Service Breakdown

```
┌─────────────────────────────────────────────────────────┐
│                    Nginx (Port 80)                      │
│                  Reverse Proxy + TLS                    │
│        Rate Limiting + WebSocket Upgrade                │
└─────┬──────────────────────────────────────┬───────────┘
      │                                      │
      │ /api/*                              │ /ws
      │                                      │
┌─────▼──────────────┐              ┌───────▼────────────┐
│   Fastify API      │              │   uWebSockets.js   │
│   (Port 3000)      │              │   (Port 3001)      │
│                    │              │                    │
│ • User Auth        │              │ • WebSocket Server │
│ • JWT Signing      │              │ • JWT Verification │
│ • Token Rotation   │              │ • Live Reauth      │
│ • REST Endpoints   │              │ • Ultra-fast       │
└─────┬──────────────┘              └────────────────────┘
      │
      │ Connection Pool
      │
┌─────▼──────────────┐
│   PostgreSQL       │
│   (Port 5432)      │
│                    │
│ • User Storage     │
│ • Token Rotation   │
│ • Token Families   │
└────────────────────┘
```

---

## Authentication Flow

### 1. Initial Login

```
Client                  Fastify API              PostgreSQL
  │                         │                        │
  │─────POST /login────────▶│                        │
  │  {user, pass}           │                        │
  │                         │──────Get User─────────▶│
  │                         │◀──────User Data────────│
  │                         │                        │
  │                         │ Verify Password        │
  │                         │ Generate Tokens        │
  │                         │                        │
  │                         │───Store Refresh Token─▶│
  │                         │◀────────OK─────────────│
  │                         │                        │
  │◀──Access Token + Cookie─│                        │
  │  (HttpOnly Refresh)     │                        │
```

### 2. WebSocket Connection

```
Client                uWebSockets.js
  │                         │
  │───WS /ws?token=jwt─────▶│
  │                         │ Verify JWT
  │                         │ Check Expiry
  │                         │
  │◀────Connected───────────│
  │  {userId, expiresAt}    │
```

### 3. Token Refresh (Without Disconnecting)

```
Client                  Fastify API         uWebSockets.js
  │                         │                     │
  │─────POST /refresh──────▶│                     │
  │  (Cookie: refreshToken) │                     │
  │                         │                     │
  │                         │ Verify Refresh      │
  │                         │ Revoke Old          │
  │                         │ Generate New        │
  │                         │                     │
  │◀──New Access Token─────│                     │
  │  (+ New Refresh Cookie) │                     │
  │                         │                     │
  │──────────REAUTH─────────────────────────────▶│
  │  {type: "reauth",       │                     │
  │   access: "new_jwt"}    │                     │
  │                         │                     │
  │                         │          Verify JWT │
  │                         │          Update User│
  │                         │                     │
  │◀─────Reauth Success─────────────────────────│
```

---

## Project Structure

```
fastify-uws-auth/
├── docker-compose.yml          # Orchestrates all services
├── generate-keys.sh            # Generate RSA keypair
├── start.sh                    # Quick start script
├── README.md                   # Main documentation
├── SECURITY.md                 # Security documentation
├── client-demo.html            # Interactive demo
├── .gitignore                  # Git ignore rules
│
├── keys/                       # RSA keys (gitignored)
│   ├── private.pem            # Private key for signing
│   └── public.pem             # Public key for verification
│
├── nginx/
│   └── nginx.conf             # Reverse proxy config
│
├── postgres-init/
│   └── 01-init.sql            # Database schema
│
├── fastify-api/               # REST API Server
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   └── src/
│       ├── index.ts           # Server entry point
│       ├── routes.ts          # Auth endpoints
│       ├── database.ts        # Database layer
│       └── jwt.ts             # JWT utilities
│
└── uws-server/                # WebSocket Server
    ├── Dockerfile
    ├── package.json
    ├── tsconfig.json
    └── src/
        ├── index.ts           # WebSocket server
        └── jwt.ts             # JWT verification
```

---

## 🚀 Quick Start

### 1. Generate Keys
```bash
./generate-keys.sh
```

### 2. Start Services
```bash
./start.sh
# or manually:
docker compose up --build -d
```

### 3. Test
```bash
# Open browser
open client-demo.html

# Or use curl
curl -X POST http://localhost/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}' \
  -c cookies.txt
```

---

## Key Features

### Security

- ✅ RS256 JWT signing (4096-bit RSA)
- ✅ Short-lived access tokens (15m)
- ✅ Refresh token rotation
- ✅ Token family tracking
- ✅ Replay attack detection
- ✅ HttpOnly secure cookies
- ✅ bcrypt password hashing
- ✅ Rate limiting
- ✅ CORS protection

### Performance

- ⚡ uWebSockets.js for ultra-fast WebSocket
- ⚡ Connection pooling
- ⚡ Minimal dependencies
- ⚡ Efficient token verification
- ⚡ Compressed WebSocket messages

### Developer Experience

- Full TypeScript support
- Docker Compose setup
- Comprehensive documentation
- Interactive demo
- Easy configuration
- Structured logging

---

## Use Cases

### Ideal For

1. **Real-time applications** requiring secure WebSocket connections
2. **Microservices** with separate REST and WebSocket servers
3. **High-performance systems** needing fast WebSocket handling
4. **Security-critical applications** with strict token rotation
5. **Modern web apps** using JWT authentication

### Not Ideal For

1. **Simple CRUD apps** (overkill)
2. **Single-page apps without WebSocket** (use Fastify only)
3. **Legacy browser support** (requires modern WebSocket API)

---

## Token Lifecycle

```
┌─────────────┐
│   Login     │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────┐
│  Access Token: 15m          │  ◀─── Used for API/WS
│  Refresh Token: 7d          │
│  Token Family: abc123       │
└──────┬──────────────────────┘
       │
       │ Every 5-10 minutes
       ▼
┌─────────────┐
│   Refresh   │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────┐
│  New Access Token: 15m      │
│  New Refresh Token: 7d      │
│  Same Family: abc123        │
│  Old Refresh: REVOKED       │
└──────┬──────────────────────┘
       │
       │ After 7 days or logout
       ▼
┌─────────────┐
│  Re-login   │
└─────────────┘
```

---

## Security Model

### What We Protect Against

| Attack Type | Protection Method |
|-------------|-------------------|
| Token Theft | Short expiry + rotation |
| Replay Attack | Token family tracking |
| XSS | HttpOnly cookies |
| CSRF | SameSite cookies |
| Brute Force | Rate limiting + bcrypt |
| Man-in-the-Middle | HTTPS + RS256 |
| SQL Injection | Parameterized queries |

### Defense in Depth

```
Layer 1: Nginx
  ├─ Rate Limiting
  ├─ Connection Limits
  └─ TLS Termination

Layer 2: Application
  ├─ JWT Verification
  ├─ Token Rotation
  └─ Input Validation

Layer 3: Database
  ├─ Hashed Passwords
  ├─ Hashed Tokens
  └─ Access Control
```

---

## Performance Characteristics

### Expected Throughput

- **REST API**: ~10,000 req/sec (single instance)
- **WebSocket**: ~100,000+ concurrent connections
- **Token Verification**: <1ms per token
- **Database Queries**: <5ms for token operations

### Resource Usage

- **Fastify API**: ~50MB RAM
- **uWebSockets.js**: ~30MB RAM
- **PostgreSQL**: ~100MB RAM + data
- **Nginx**: ~10MB RAM

---

## Configuration

### Environment Variables

**Fastify API**:
```env
PORT=3000
DATABASE_URL=postgresql://...
PRIVATE_KEY_PATH=/app/keys/private.pem
PUBLIC_KEY_PATH=/app/keys/public.pem
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
```

**uWebSockets.js**:
```env
PORT=3001
PUBLIC_KEY_PATH=/app/keys/public.pem
ACCESS_TOKEN_MAX_AGE=900
```

### Tuning Parameters

**Token Expiry**:
- Decrease for higher security (more refreshes)
- Increase for better UX (fewer refreshes)

**Rate Limits**:
- Increase for high-traffic scenarios
- Decrease for protection against abuse

**Connection Pool**:
- Increase for concurrent load
- Decrease to save resources

---

## API Reference

### REST Endpoints

```
POST   /api/login      - Authenticate user
POST   /api/refresh    - Refresh access token
POST   /api/logout     - Revoke all tokens
GET    /api/protected  - Example protected endpoint
GET    /api/health     - Health check
```

### WebSocket Messages

**Client → Server**:
```json
{"type": "ping"}
{"type": "reauth", "access": "jwt"}
{"type": "echo", "payload": {...}}
```

**Server → Client**:
```json
{"type": "connected", "payload": {...}}
{"type": "token_expiring", "payload": {...}}
{"type": "reauth_success", "payload": {...}}
{"type": "error", "payload": {...}}
```

---

## Testing

### Manual Testing

```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}' \
  -c /tmp/cookies.txt | jq -r '.accessToken')

# 2. Call protected API
curl http://localhost/api/protected \
  -H "Authorization: Bearer $TOKEN"

# 3. Refresh token
curl -s -X POST http://localhost/api/refresh \
  -b /tmp/cookies.txt \
  -c /tmp/cookies.txt | jq '.'

# 4. Test WebSocket
wscat -c "ws://localhost/ws?token=$TOKEN"
```

### Load Testing

```bash
# Install k6
brew install k6

# Run load test (create load-test.js)
k6 run load-test.js
```

---

## Further Reading

- [README.md](README.md) - Setup and usage
- [SECURITY.md](SECURITY.md) - Security deep dive
- [Fastify Documentation](https://fastify.dev/)
- [uWebSockets.js Documentation](https://github.com/uNetworking/uWebSockets.js)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)

---

## Contributing

Contributions welcome! Areas for improvement:

1. **Additional authentication methods** (OAuth, SAML)
2. **Multi-factor authentication** (TOTP, SMS)
3. **Session management** (device tracking)
4. **Advanced monitoring** (metrics, tracing)
5. **Load balancing** (Redis for token storage)

---

## 📄 License

MIT License - See LICENSE file for details