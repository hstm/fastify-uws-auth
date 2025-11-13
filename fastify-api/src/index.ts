import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import { authRoutes } from './routes';
import { db } from './database';

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    transport:
      process.env.NODE_ENV !== 'production'
        ? {
            target: 'pino-pretty',
            options: {
              colorize: true,
              translateTime: 'HH:MM:ss Z',
              ignore: 'pid,hostname',
            },
          }
        : undefined,
  },
  trustProxy: true, // Trust nginx proxy
  bodyLimit: 1048576, // 1MB
});

async function start() {
  try {
    // Register security plugins
    await fastify.register(helmet, {
      contentSecurityPolicy: false, // Disable if serving static files
    });

    await fastify.register(cors, {
      origin: process.env.CORS_ORIGIN || true,
      credentials: true,
    });

    await fastify.register(cookie, {
      secret: process.env.COOKIE_SECRET || 'change-this-secret-in-production',
      parseOptions: {},
    });

    // Rate limiting
    await fastify.register(rateLimit, {
      max: 100,
      timeWindow: '1 minute',
      cache: 10000,
      allowList: [],
      redis: undefined,
      skipOnError: false,
    });

    // Register routes
    await fastify.register(authRoutes);

    // Health check
    fastify.get('/api/health', async () => {
      return { status: 'ok', timestamp: new Date().toISOString() };
    });

    // Cleanup expired tokens every hour
    const cleanupInterval = setInterval(async () => {
      try {
        await db.deleteExpiredTokens();
        fastify.log.info('Expired tokens cleaned up');
      } catch (error) {
        fastify.log.error(error, 'Failed to cleanup expired tokens');
      }
    }, 60 * 60 * 1000); // Every hour

    // Graceful shutdown
    const signals = ['SIGINT', 'SIGTERM'] as const;
    for (const signal of signals) {
      process.on(signal, async () => {
        fastify.log.info(`Received ${signal}, closing server...`);
        clearInterval(cleanupInterval);
        await fastify.close();
        await db.close();
        process.exit(0);
      });
    }

    // Start server
    const port = parseInt(process.env.PORT || '3000', 10);
    const host = process.env.HOST || '0.0.0.0';

    await fastify.listen({ port, host });
    fastify.log.info(`Fastify API server listening on ${host}:${port}`);
  } catch (error) {
    fastify.log.error(error);
    process.exit(1);
  }
}

start();
