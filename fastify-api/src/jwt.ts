import jwt from 'jsonwebtoken';
import fs from 'fs';

interface TokenPayload {
  userId: number;
  username: string;
  type: 'access' | 'refresh';
  tokenFamily?: string;
  jti?: string;
  iat?: number;
  exp?: number;
}

class JWTService {
  private privateKey: Buffer;
  private publicKey: Buffer;
  private accessTokenExpiry: string;
  private refreshTokenExpiry: string;

  constructor() {
    const privateKeyPath = process.env.PRIVATE_KEY_PATH || '/app/keys/private.pem';
    const publicKeyPath = process.env.PUBLIC_KEY_PATH || '/app/keys/public.pem';

    this.privateKey = fs.readFileSync(privateKeyPath);
    this.publicKey = fs.readFileSync(publicKeyPath);
    this.accessTokenExpiry = process.env.ACCESS_TOKEN_EXPIRY || '15m';
    this.refreshTokenExpiry = process.env.REFRESH_TOKEN_EXPIRY || '7d';
  }

  signAccessToken(userId: number, username: string): string {
    return jwt.sign(
      {
        userId,
        username,
        type: 'access',
      },
      this.privateKey,
      {
        algorithm: 'RS256',
        expiresIn: this.accessTokenExpiry,
        issuer: 'fastify-api',
        audience: 'client-app',
      } as jwt.SignOptions
    );
  }

  signRefreshToken(
    userId: number,
    username: string,
    tokenFamily: string,
    jti: string
  ): string {
    return jwt.sign(
      {
        userId,
        username,
        type: 'refresh',
        tokenFamily,
        jti,
      },
      this.privateKey,
      {
        algorithm: 'RS256',
        expiresIn: this.refreshTokenExpiry,
        issuer: 'fastify-api',
        audience: 'client-app',
      } as jwt.SignOptions
    );
  }

  verifyAccessToken(token: string): TokenPayload {
    try {
      const payload = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
        issuer: 'fastify-api',
        audience: 'client-app',
      }) as TokenPayload;

      if (payload.type !== 'access') {
        throw new Error('Invalid token type');
      }

      return payload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Access token expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid access token');
      }
      throw error;
    }
  }

  verifyRefreshToken(token: string): TokenPayload {
    try {
      const payload = jwt.verify(token, this.publicKey, {
        algorithms: ['RS256'],
        issuer: 'fastify-api',
        audience: 'client-app',
      }) as TokenPayload;

      if (payload.type !== 'refresh') {
        throw new Error('Invalid token type');
      }

      if (!payload.tokenFamily || !payload.jti) {
        throw new Error('Missing token family or jti');
      }

      return payload;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new Error('Refresh token expired');
      } else if (error instanceof jwt.JsonWebTokenError) {
        throw new Error('Invalid refresh token');
      }
      throw error;
    }
  }

  getRefreshTokenExpiry(): Date {
    const match = this.refreshTokenExpiry.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error('Invalid refresh token expiry format');
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];
    const now = new Date();

    switch (unit) {
      case 's':
        return new Date(now.getTime() + value * 1000);
      case 'm':
        return new Date(now.getTime() + value * 60 * 1000);
      case 'h':
        return new Date(now.getTime() + value * 60 * 60 * 1000);
      case 'd':
        return new Date(now.getTime() + value * 24 * 60 * 60 * 1000);
      default:
        throw new Error('Invalid time unit');
    }
  }
}

export const jwtService = new JWTService();