# Security Documentation

## Overview

This document details the security measures implemented in the authentication system and explains how they protect against common attacks.

## Table of Contents

1. [Token Strategy](#token-strategy)
2. [Replay Attack Prevention](#replay-attack-prevention)
3. [Token Rotation](#token-rotation)
4. [WebSocket Security](#websocket-security)
5. [Password Security](#password-security)
6. [Rate Limiting](#rate-limiting)
7. [HTTPS Recommendations](#https-recommendations)
8. [Threat Model](#threat-model)

---

## Token Strategy

### Access Tokens

**Type**: JWT (JSON Web Token)  
**Algorithm**: RS256 (RSA with SHA-256)  
**Expiry**: 15 minutes  
**Storage**: Client-side memory (never localStorage or cookies)  

**Structure**:
```json
{
  "userId": 1,
  "username": "testuser",
  "type": "access",
  "iat": 1699264800,
  "exp": 1699265700,
  "iss": "fastify-api",
  "aud": "client-app"
}
```

**Security Properties**:
- Short-lived (15 minutes) minimizes window of attack
- RS256 prevents tampering (requires private key to forge)
- Type field prevents token confusion attacks
- Issuer and audience claims prevent token reuse across services

### Refresh Tokens

**Type**: JWT with opaque token as JTI  
**Algorithm**: RS256  
**Expiry**: 7 days  
**Storage**: HttpOnly, Secure, SameSite cookies  

**Structure**:
```json
{
  "userId": 1,
  "username": "testuser",
  "type": "refresh",
  "tokenFamily": "abc123...",
  "jti": "sha256_hash_of_opaque_token",
  "iat": 1699264800,
  "exp": 1699869600,
  "iss": "fastify-api",
  "aud": "client-app"
}
```

**Security Properties**:
- HttpOnly prevents XSS attacks from stealing tokens
- Secure flag ensures transmission only over HTTPS
- SameSite=strict prevents CSRF attacks
- Token family enables detection of replay attacks
- SHA-256 hashed in database (not reversible)
- Single-use with rotation on every refresh

---

## Replay Attack Prevention

### Token Family Tracking

Each login session creates a unique **token family**. All refresh tokens in the same session share this family identifier.

**Normal Flow**:
```
Login → Token A (family: abc123)
Refresh → Revoke A, Issue Token B (family: abc123)
Refresh → Revoke B, Issue Token C (family: abc123)
```

**Attack Scenario**:
```
User: Login → Token A (family: abc123)
User: Refresh → Revoke A, Issue Token B (family: abc123)

Attacker: Tries to use Token A (already revoked)
          ↓
System: Detects reuse of revoked token in family abc123
        → Revokes entire family abc123
        → User forced to re-login
```

### Detection Logic

```typescript
// Check if token exists in database
const storedToken = await db.getRefreshToken(tokenHash);

if (!storedToken) {
  // Token not found - possible reuse after rotation
  await db.revokeTokenFamily(tokenFamily);
  return error('Token reuse detected');
}

if (storedToken.is_revoked) {
  // Explicitly revoked - definite attack
  await db.revokeTokenFamily(tokenFamily);
  return error('Revoked token used');
}
```

### Why This Works

1. **Legitimate users** always use the latest token
2. **Attackers** with stolen tokens use old (revoked) tokens
3. **System** detects the anomaly and revokes all tokens
4. **Attacker** loses access
5. **Legitimate user** gets logged out and must re-authenticate

---

## Token Rotation

### Refresh Token Rotation

Every time a refresh token is used, it's immediately revoked and replaced with a new one.

**Flow**:
```
1. Client sends refresh token RT1
2. Server verifies RT1 is valid
3. Server revokes RT1 in database
4. Server generates new refresh token RT2
5. Server stores RT2 in database
6. Server generates new access token AT2
7. Server sends AT2 + RT2 (in cookie) to client
```

**Benefits**:
- Limits time window for stolen tokens
- Detects replay attacks
- Reduces impact of token theft
- Enables graceful session termination

### Access Token Refresh via WebSocket

Instead of reconnecting the WebSocket with a new token, we use a **reauth** message:

**Advantages**:
- No connection interruption
- No reconnection overhead
- Seamless user experience
- Maintains WebSocket state

**Flow**:
```
1. Access token expires (or about to expire)
2. Client calls /api/refresh to get new access token
3. Client sends reauth message via existing WebSocket:
   {
     "type": "reauth",
     "access": "new_jwt_token"
   }
4. Server verifies new token
5. Server updates WebSocket user context
6. Connection continues uninterrupted
```

---

## WebSocket Security

### Connection Authentication

WebSocket connections are authenticated during the upgrade handshake:

```typescript
upgrade: (res, req, context) => {
  const token = extractToken(req.getQuery());
  
  if (!token) {
    return res.writeStatus('401').end('No token');
  }
  
  try {
    const payload = verifyAccessToken(token);
    res.upgrade(userData, ...);
  } catch {
    return res.writeStatus('401').end('Invalid token');
  }
}
```

**Security Features**:
- Token verified before WebSocket upgrade
- Invalid tokens rejected immediately
- No unauthenticated connections possible

### Token Expiry Monitoring

The server continuously monitors token expiry:

```typescript
// Check every 30 seconds
setInterval(() => {
  activeConnections.forEach((_, ws) => {
    const tokenExp = ws.getUserData().exp * 1000;
    const timeUntilExpiry = tokenExp - Date.now();
    
    // Warn 2 minutes before expiry
    if (timeUntilExpiry < 120000) {
      sendMessage(ws, {
        type: 'token_expiring',
        payload: { expiresIn: timeUntilExpiry / 1000 }
      });
    }
  });
}, 30000);
```

**Benefits**:
- Proactive token refresh
- Prevents sudden disconnections
- Better user experience

### Message Validation

All WebSocket messages are validated:

```typescript
message: (ws, message, isBinary) => {
  // Check token expiry
  if (Date.now() / 1000 >= userData.exp) {
    return sendError(ws, 'TOKEN_EXPIRED');
  }
  
  // Parse and validate JSON
  try {
    const data = JSON.parse(message);
    handleMessage(ws, data);
  } catch {
    return sendError(ws, 'INVALID_MESSAGE');
  }
}
```

### Connection Limits

- Maximum payload: 16KB
- Idle timeout: 120 seconds
- Max backpressure: 1024 bytes
- Compression enabled

---

## Password Security

### Password Hashing

Passwords are hashed using **bcrypt** with a cost factor of 12:

```typescript
const hash = await bcrypt.hash(password, 12);
```

**Properties**:
- Adaptive: Can increase cost factor over time
- Salt included automatically
- Slow: ~250ms to hash (prevents brute force)
- Industry standard

### Password Requirements

**Minimum Requirements** (enforced in schema):
- Length: 6-255 characters
- No maximum to allow passphrases

**Recommended Requirements** (implement client-side):
- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- Not in common password lists
- Not similar to username

### Credential Validation

```typescript
const user = await db.getUserByUsername(username);
if (!user) {
  return reply.code(401).send({ error: 'Invalid credentials' });
}

const isValid = await bcrypt.compare(password, user.password_hash);
if (!isValid) {
  return reply.code(401).send({ error: 'Invalid credentials' });
}
```

**Security Notes**:
- Same error message for user not found / wrong password
- Prevents username enumeration
- Timing attacks mitigated by bcrypt's constant-time comparison

---

## Rate Limiting

### Nginx Rate Limiting

**Authentication Endpoints** (`/api/login`, `/api/refresh`):
```nginx
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=5r/m;

location ~ ^/api/(login|refresh) {
  limit_req zone=auth_limit burst=3 nodelay;
}
```

- **Rate**: 5 requests per minute per IP
- **Burst**: 3 additional requests allowed
- **Action**: Reject with 429 Too Many Requests

**General API Endpoints**:
```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

location /api/ {
  limit_req zone=api_limit burst=20 nodelay;
}
```

- **Rate**: 10 requests per second per IP
- **Burst**: 20 additional requests allowed

### Fastify Rate Limiting

Application-level rate limiting:
```typescript
await fastify.register(rateLimit, {
  max: 100,
  timeWindow: '1 minute'
});
```

### Connection Limiting

Maximum concurrent connections per IP:
```nginx
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

location /api/ {
  limit_conn conn_limit 10;
}

location /ws {
  limit_conn conn_limit 100;
}
```

---

## HTTPS Recommendations

### Production Deployment

**Never run without HTTPS in production!**

Nginx HTTPS configuration:
```nginx
server {
  listen 443 ssl http2;
  
  ssl_certificate /path/to/fullchain.pem;
  ssl_certificate_key /path/to/privkey.pem;
  
  # Modern TLS configuration
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers off;
  
  # HSTS
  add_header Strict-Transport-Security "max-age=63072000" always;
  
  # OCSP Stapling
  ssl_stapling on;
  ssl_stapling_verify on;
}

# Redirect HTTP to HTTPS
server {
  listen 80;
  return 301 https://$host$request_uri;
}
```

### Cookie Security in Production

Update Fastify cookie settings:
```typescript
reply.setCookie('refreshToken', token, {
  httpOnly: true,
  secure: true,        // Require HTTPS
  sameSite: 'strict',
  domain: 'yourdomain.com',
  path: '/api',
  maxAge: 7 * 24 * 60 * 60
});
```

---

## Threat Model

### Threats Mitigated

| Threat | Mitigation |
|--------|-----------|
| **XSS (Cross-Site Scripting)** | HttpOnly cookies, CSP headers |
| **CSRF (Cross-Site Request Forgery)** | SameSite cookies, CORS configuration |
| **Token Theft** | Short-lived access tokens, rotation |
| **Replay Attacks** | Token family tracking, single-use refresh |
| **Brute Force** | Rate limiting, bcrypt slow hashing |
| **SQL Injection** | Parameterized queries |
| **Man-in-the-Middle** | HTTPS (production), RS256 signing |
| **Session Fixation** | New token family on each login |
| **Password Cracking** | Bcrypt with high cost factor |

### Threats NOT Mitigated

| Threat | Why Not | Recommendation |
|--------|---------|----------------|
| **Zero-day vulnerabilities** | Unknown attacks | Keep dependencies updated |
| **Physical access** | Out of scope | Encrypt at rest, secure hardware |
| **Social engineering** | Human factor | User education, 2FA |
| **Compromised dependencies** | Supply chain | Use `npm audit`, review dependencies |
| **Insider threats** | Trusted users | Audit logs, principle of least privilege |

### Assumptions

This security model assumes:

1. **HTTPS in production** - All traffic encrypted
2. **Secure key storage** - Private keys protected
3. **Regular updates** - Dependencies kept current
4. **Database security** - PostgreSQL properly configured
5. **Network security** - Firewalls and network isolation
6. **Monitoring** - Logs reviewed for anomalies

---

## Security Checklist

### Development

- [ ] Never commit private keys to version control
- [ ] Use environment variables for secrets
- [ ] Test with HTTPS proxy (e.g., ngrok, Caddy)
- [ ] Review dependencies regularly (`npm audit`)
- [ ] Keep TypeScript strict mode enabled

### Deployment

- [ ] Enable HTTPS with valid certificates
- [ ] Set `secure: true` for cookies
- [ ] Configure strong TLS ciphers
- [ ] Enable HSTS header
- [ ] Set up proper CORS origins
- [ ] Configure firewall rules
- [ ] Enable database encryption at rest
- [ ] Set up automated backups
- [ ] Configure log aggregation
- [ ] Set up alerting for suspicious activity

### Monitoring

- [ ] Monitor failed login attempts
- [ ] Track token family revocations
- [ ] Alert on unusual refresh patterns
- [ ] Log rate limit violations
- [ ] Monitor WebSocket connection patterns
- [ ] Track database query performance
- [ ] Set up uptime monitoring

### Maintenance

- [ ] Regular dependency updates
- [ ] Security patch management
- [ ] Key rotation schedule
- [ ] Database maintenance (VACUUM, ANALYZE)
- [ ] Log rotation and retention
- [ ] Backup testing
- [ ] Disaster recovery drills

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [bcrypt Documentation](https://github.com/kelektiv/node.bcrypt.js)
- [PostgreSQL Security](https://www.postgresql.org/docs/current/security.html)

---

## Contact

For security issues, please report to: info@hstahlmann.com

Do not disclose security vulnerabilities publicly until they have been addressed.
