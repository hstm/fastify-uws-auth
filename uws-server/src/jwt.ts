import jwt from 'jsonwebtoken';
import fs from 'fs';

interface TokenPayload {
  userId: number;
  username: string;
  type: 'access' | 'refresh';
  iat: number;
  exp: number;
}

class JWTVerifier {
  private publicKey: Buffer;
  private maxTokenAge: number;

  constructor() {
    const publicKeyPath = process.env.PUBLIC_KEY_PATH || '/app/keys/public.pem';
    this.publicKey = fs.readFileSync(publicKeyPath);
    
    // Maximum age in seconds (default 15 minutes)
    this.maxTokenAge = parseInt(process.env.ACCESS_TOKEN_MAX_AGE || '900', 10);
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

      // Additional check for token age to prevent replay attacks
      const now = Math.floor(Date.now() / 1000);
      const tokenAge = now - payload.iat;

      if (tokenAge > this.maxTokenAge) {
        throw new Error('Token too old');
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

  getTokenExpiry(token: string): number | null {
    try {
      const decoded = jwt.decode(token) as TokenPayload;
      return decoded?.exp || null;
    } catch {
      return null;
    }
  }
}

export const jwtVerifier = new JWTVerifier();
