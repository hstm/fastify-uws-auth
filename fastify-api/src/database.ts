import { Pool } from 'pg';
import * as crypto from 'crypto';

export interface User {
  id: number;
  username: string;
  password_hash: string;
  created_at: Date;
  updated_at: Date;
}

export interface RefreshToken {
  id: number;
  user_id: number;
  token_hash: string;
  token_family: string;
  expires_at: Date;
  is_revoked: boolean;
  created_at: Date;
  revoked_at: Date | null;
  last_used_at: Date | null;
}

class Database {
  private pool: Pool;

  constructor() {
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

    this.pool.on('error', (err) => {
      console.error('Unexpected database error:', err);
    });
  }

  async query<T>(text: string, params?: any[]): Promise<T[]> {
    const client = await this.pool.connect();
    try {
      const result = await client.query(text, params);
      return result.rows as T[];
    } finally {
      client.release();
    }
  }

  async getUserByUsername(username: string): Promise<User | null> {
    const result = await this.query<User>(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );
    return result[0] || null;
  }

  async getUserById(userId: number): Promise<User | null> {
    const result = await this.query<User>(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
    return result[0] || null;
  }

  async saveRefreshToken(
    userId: number,
    tokenHash: string,
    tokenFamily: string,
    expiresAt: Date
  ): Promise<void> {
    await this.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, token_family, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [userId, tokenHash, tokenFamily, expiresAt]
    );
  }

  async getRefreshToken(tokenHash: string): Promise<RefreshToken | null> {
    const result = await this.query<RefreshToken>(
      'SELECT * FROM refresh_tokens WHERE token_hash = $1',
      [tokenHash]
    );
    return result[0] || null;
  }

  async updateLastUsed(tokenId: number): Promise<void> {
    await this.query(
      'UPDATE refresh_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE id = $1',
      [tokenId]
    );
  }

  async revokeTokenFamily(tokenFamily: string): Promise<void> {
    await this.query(
      `UPDATE refresh_tokens 
       SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP 
       WHERE token_family = $1`,
      [tokenFamily]
    );
  }

  async revokeToken(tokenHash: string): Promise<void> {
    await this.query(
      `UPDATE refresh_tokens 
       SET is_revoked = TRUE, revoked_at = CURRENT_TIMESTAMP 
       WHERE token_hash = $1`,
      [tokenHash]
    );
  }

  async deleteExpiredTokens(): Promise<void> {
    await this.query(
      'DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP'
    );
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function generateTokenFamily(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function generateSecureToken(): string {
  return crypto.randomBytes(64).toString('base64url');
}

export const db = new Database();
