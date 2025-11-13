import { FastifyInstance } from 'fastify';
import bcrypt from 'bcrypt';
import {
  db,
  hashToken,
  generateTokenFamily,
  generateSecureToken,
} from './database';
import { jwtService } from './jwt';

interface LoginBody {
  username: string;
  password: string;
}

interface RefreshBody {
  refreshToken?: string;
}

export async function authRoutes(fastify: FastifyInstance) {
  // Login route
  fastify.post<{ Body: LoginBody }>(
    '/api/login',
    {
      schema: {
        body: {
          type: 'object',
          required: ['username', 'password'],
          properties: {
            username: { type: 'string', minLength: 3, maxLength: 255 },
            password: { type: 'string', minLength: 6, maxLength: 255 },
          },
        },
      },
    },
    async (request, reply) => {
      const { username, password } = request.body;

      try {
        // Get user from database
        const user = await db.getUserByUsername(username);
        if (!user) {
          return reply.code(401).send({
            error: 'Invalid credentials',
          });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        if (!isValidPassword) {
          return reply.code(401).send({
            error: 'Invalid credentials',
          });
        }

        // Generate token family for this session
        const tokenFamily = generateTokenFamily();

        // Generate refresh token (opaque string)
        const refreshTokenString = generateSecureToken();
        const refreshTokenHash = hashToken(refreshTokenString);

        // Sign JWT refresh token with the opaque token as JTI
        const refreshTokenJWT = jwtService.signRefreshToken(
          user.id,
          user.username,
          tokenFamily,
          refreshTokenHash
        );

        // Store refresh token hash in database
        const refreshTokenExpiry = jwtService.getRefreshTokenExpiry();
        await db.saveRefreshToken(
          user.id,
          refreshTokenHash,
          tokenFamily,
          refreshTokenExpiry
        );

        // Generate access token
        const accessToken = jwtService.signAccessToken(user.id, user.username);

        // Set refresh token as HttpOnly cookie
        reply.setCookie('refreshToken', refreshTokenJWT, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          path: '/api',
          maxAge: 7 * 24 * 60 * 60, // 7 days in seconds
        });

        return reply.send({
          accessToken,
          user: {
            id: user.id,
            username: user.username,
          },
        });
      } catch (error) {
        request.log.error(error);
        return reply.code(500).send({
          error: 'Internal server error',
        });
      }
    }
  );

  // Refresh token route
  fastify.post<{ Body: RefreshBody }>(
    '/api/refresh',
    async (request, reply) => {
      try {
        // Get refresh token from cookie
        const refreshTokenJWT = request.cookies.refreshToken;

        if (!refreshTokenJWT) {
          return reply.code(401).send({
            error: 'No refresh token provided',
          });
        }

        // Verify and decode refresh token
        let payload;
        try {
          payload = jwtService.verifyRefreshToken(refreshTokenJWT);
        } catch (error) {
          // Clear invalid cookie
          reply.clearCookie('refreshToken', { path: '/api' });
          return reply.code(401).send({
            error: 'Invalid or expired refresh token',
          });
        }

        const { userId, username, tokenFamily, jti } = payload;

        if (!jti || !tokenFamily) {
          return reply.code(401).send({
            error: 'Invalid refresh token structure',
          });
        }

        // Check if token exists and is not revoked
        const storedToken = await db.getRefreshToken(jti);

        if (!storedToken) {
          // Token not found - possible reuse attack
          // Revoke entire token family
          await db.revokeTokenFamily(tokenFamily);
          reply.clearCookie('refreshToken', { path: '/api' });
          return reply.code(401).send({
            error: 'Invalid refresh token',
            requireReauth: true,
          });
        }

        if (storedToken.is_revoked) {
          // Token was revoked - possible reuse attack
          // Revoke entire token family
          await db.revokeTokenFamily(tokenFamily);
          reply.clearCookie('refreshToken', { path: '/api' });
          return reply.code(401).send({
            error: 'Token has been revoked',
            requireReauth: true,
          });
        }

        if (storedToken.token_family !== tokenFamily) {
          // Token family mismatch - security issue
          await db.revokeTokenFamily(tokenFamily);
          reply.clearCookie('refreshToken', { path: '/api' });
          return reply.code(401).send({
            error: 'Token family mismatch',
            requireReauth: true,
          });
        }

        // Check if token is expired
        if (new Date() > storedToken.expires_at) {
          await db.revokeToken(jti);
          reply.clearCookie('refreshToken', { path: '/api' });
          return reply.code(401).send({
            error: 'Refresh token expired',
          });
        }

        // Token rotation: revoke old token
        await db.revokeToken(jti);

        // Generate new refresh token
        const newRefreshTokenString = generateSecureToken();
        const newRefreshTokenHash = hashToken(newRefreshTokenString);

        // Sign new JWT refresh token
        const newRefreshTokenJWT = jwtService.signRefreshToken(
          userId,
          username,
          tokenFamily, // Keep same family for this session
          newRefreshTokenHash
        );

        // Store new refresh token hash
        const refreshTokenExpiry = jwtService.getRefreshTokenExpiry();
        await db.saveRefreshToken(
          userId,
          newRefreshTokenHash,
          tokenFamily,
          refreshTokenExpiry
        );

        // Generate new access token
        const newAccessToken = jwtService.signAccessToken(userId, username);

        // Set new refresh token cookie
        reply.setCookie('refreshToken', newRefreshTokenJWT, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict',
          path: '/api',
          maxAge: 7 * 24 * 60 * 60,
        });

        return reply.send({
          accessToken: newAccessToken,
        });
      } catch (error) {
        request.log.error(error);
        return reply.code(500).send({
          error: 'Internal server error',
        });
      }
    }
  );

  // Logout route
  fastify.post('/api/logout', async (request, reply) => {
    try {
      const refreshTokenJWT = request.cookies.refreshToken;

      if (refreshTokenJWT) {
        try {
          const payload = jwtService.verifyRefreshToken(refreshTokenJWT);
          const { tokenFamily } = payload;

          if (tokenFamily) {
            // Revoke entire token family on logout
            await db.revokeTokenFamily(tokenFamily);
          }
        } catch (error) {
          // Token invalid, just clear cookie
          request.log.warn('Invalid token during logout');
        }
      }

      // Clear refresh token cookie
      reply.clearCookie('refreshToken', { path: '/api' });

      return reply.send({
        message: 'Logged out successfully',
      });
    } catch (error) {
      request.log.error(error);
      return reply.code(500).send({
        error: 'Internal server error',
      });
    }
  });

  // Protected route example
  fastify.get('/api/protected', async (request, reply) => {
    try {
      const authHeader = request.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return reply.code(401).send({
          error: 'No token provided',
        });
      }

      const token = authHeader.substring(7);

      try {
        const payload = jwtService.verifyAccessToken(token);

        return reply.send({
          message: 'Access granted',
          user: {
            id: payload.userId,
            username: payload.username,
          },
        });
      } catch (error) {
        return reply.code(401).send({
          error: 'Invalid or expired token',
        });
      }
    } catch (error) {
      request.log.error(error);
      return reply.code(500).send({
        error: 'Internal server error',
      });
    }
  });
}
