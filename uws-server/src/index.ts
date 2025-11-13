import uWS from 'uWebSockets.js';
import { jwtVerifier } from './jwt';

interface UserData {
  userId: number;
  username: string;
  exp: number;
  lastActivity: number;
  isAuthenticated: boolean;
}

interface WebSocketMessage {
  type: string;
  access?: string;
  payload?: any;
}

const HEARTBEAT_INTERVAL = 30000; // 30 seconds
const MAX_MESSAGE_SIZE = 16384; // 16KB
const CONNECTION_TIMEOUT = 5000; // 5 seconds for initial auth

class WebSocketServer {
  private app: uWS.TemplatedApp;
  private port: number;
  private activeConnections = new Map<uWS.WebSocket<UserData>, NodeJS.Timeout>();

  constructor() {
    this.port = parseInt(process.env.PORT || '3001', 10);
    this.app = uWS.App();
    this.setupRoutes();
    this.setupHeartbeat();
  }

  private setupRoutes() {
    this.app.ws<UserData>('/ws', {
      compression: uWS.DEDICATED_COMPRESSOR_3KB,
      maxPayloadLength: MAX_MESSAGE_SIZE,
      idleTimeout: 120,
      maxBackpressure: 1024,

      upgrade: (res, req, context) => {
        const query = req.getQuery();
        const secWebSocketKey = req.getHeader('sec-websocket-key');
        const secWebSocketProtocol = req.getHeader('sec-websocket-protocol');
        const secWebSocketExtensions = req.getHeader('sec-websocket-extensions');

        // Extract token from query parameter
        const token = this.extractToken(query);

        if (!token) {
          console.log('Connection rejected: No token provided');
          res.writeStatus('401 Unauthorized').end('No token provided');
          return;
        }

        // Verify token before upgrading connection
        try {
          const payload = jwtVerifier.verifyAccessToken(token);

          // Prepare user data
          const userData: UserData = {
            userId: payload.userId,
            username: payload.username,
            exp: payload.exp,
            lastActivity: Date.now(),
            isAuthenticated: true,
          };

          // Upgrade to WebSocket
          res.upgrade(
            userData,
            secWebSocketKey,
            secWebSocketProtocol,
            secWebSocketExtensions,
            context
          );
        } catch (error) {
          console.error('Token verification failed:', error);
          res.writeStatus('401 Unauthorized').end('Invalid token');
        }
      },

      open: (ws) => {
        const userData = ws.getUserData();
        console.log(
          `WebSocket opened: userId=${userData.userId}, username=${userData.username}`
        );

        // Set up connection timeout
        const timeout = setTimeout(() => {
          console.log(`Connection timeout for user ${userData.userId}`);
          ws.end(1008, 'Connection timeout');
        }, CONNECTION_TIMEOUT);

        this.activeConnections.set(ws, timeout);

        // Send welcome message
        this.sendMessage(ws, {
          type: 'connected',
          payload: {
            message: 'WebSocket connection established',
            userId: userData.userId,
            username: userData.username,
            expiresAt: new Date(userData.exp * 1000).toISOString(),
          },
        });

        // Clear timeout after successful connection
        clearTimeout(timeout);
      },

      message: (ws, message) => {
        const userData = ws.getUserData();

        // Update last activity
        userData.lastActivity = Date.now();

        // Check if token is expired
        const now = Math.floor(Date.now() / 1000);
        if (now >= userData.exp) {
          this.sendMessage(ws, {
            type: 'error',
            payload: {
              code: 'TOKEN_EXPIRED',
              message: 'Access token has expired',
              requireReauth: true,
            },
          });
          return;
        }

        try {
          const messageStr = Buffer.from(message).toString('utf8');
          const data: WebSocketMessage = JSON.parse(messageStr);

          this.handleMessage(ws, data);
        } catch (error) {
          console.error('Failed to parse message:', error);
          this.sendMessage(ws, {
            type: 'error',
            payload: {
              code: 'INVALID_MESSAGE',
              message: 'Invalid message format',
            },
          });
        }
      },

      drain: (ws) => {
        console.log('WebSocket backpressure: ' + ws.getBufferedAmount());
      },

      close: (ws, code) => {
        const userData = ws.getUserData();
        console.log(
          `WebSocket closed: userId=${userData.userId}, code=${code}`
        );

        // Clear any timeouts
        const timeout = this.activeConnections.get(ws);
        if (timeout) {
          clearTimeout(timeout);
          this.activeConnections.delete(ws);
        }
      },
    });

    // Health check endpoint
    this.app.get('/health', (res) => {
      res.writeStatus('200 OK').end('OK');
    });

    // Catch-all for 404
    this.app.any('/*', (res) => {
      res.writeStatus('404 Not Found').end('Not Found');
    });
  }

  private extractToken(query: string): string | null {
    const params = new URLSearchParams(query);
    return params.get('token');
  }

  private handleMessage(ws: uWS.WebSocket<UserData>, data: WebSocketMessage) {
    const userData = ws.getUserData();

    switch (data.type) {
      case 'reauth':
        this.handleReauth(ws, data);
        break;

      case 'ping':
        this.sendMessage(ws, {
          type: 'pong',
          payload: { timestamp: Date.now() },
        });
        break;

      case 'echo':
        this.sendMessage(ws, {
          type: 'echo',
          payload: data.payload,
        });
        break;

      default:
        console.log(
          `Received message from ${userData.username}:`,
          data.type
        );
        this.sendMessage(ws, {
          type: 'ack',
          payload: { messageType: data.type },
        });
    }
  }

  private handleReauth(ws: uWS.WebSocket<UserData>, data: WebSocketMessage) {
    const userData = ws.getUserData();

    if (!data.access) {
      this.sendMessage(ws, {
        type: 'error',
        payload: {
          code: 'MISSING_TOKEN',
          message: 'Access token is required for reauth',
        },
      });
      return;
    }

    try {
      const payload = jwtVerifier.verifyAccessToken(data.access);

      // Verify user identity matches
      if (payload.userId !== userData.userId) {
        console.warn(
          `Reauth user mismatch: expected ${userData.userId}, got ${payload.userId}`
        );
        ws.end(1008, 'User mismatch');
        return;
      }

      // Update user data with new token
      userData.exp = payload.exp;
      userData.lastActivity = Date.now();

      console.log(`Reauth successful for user ${userData.userId}`);

      this.sendMessage(ws, {
        type: 'reauth_success',
        payload: {
          message: 'Token refreshed successfully',
          expiresAt: new Date(userData.exp * 1000).toISOString(),
        },
      });
    } catch (error) {
      console.error('Reauth failed:', error);
      this.sendMessage(ws, {
        type: 'error',
        payload: {
          code: 'REAUTH_FAILED',
          message: 'Failed to refresh token',
          requireReauth: true,
        },
      });
    }
  }

  private sendMessage(ws: uWS.WebSocket<UserData>, message: object) {
    const messageStr = JSON.stringify(message);
    const success = ws.send(messageStr, false);

    if (!success) {
      console.warn('Failed to send message, buffered amount:', ws.getBufferedAmount());
    }
  }

  private setupHeartbeat() {
    setInterval(() => {
      const now = Date.now();

      this.activeConnections.forEach((_, ws) => {
        const userData = ws.getUserData();

        // Check if token is about to expire (within 2 minutes)
        const tokenExp = userData.exp * 1000;
        const timeUntilExpiry = tokenExp - now;

        if (timeUntilExpiry < 120000 && timeUntilExpiry > 0) {
          this.sendMessage(ws, {
            type: 'token_expiring',
            payload: {
              message: 'Access token expiring soon',
              expiresAt: new Date(tokenExp).toISOString(),
              expiresIn: Math.floor(timeUntilExpiry / 1000),
            },
          });
        }
      });
    }, HEARTBEAT_INTERVAL);
  }

  start() {
    this.app.listen(this.port, (token) => {
      if (token) {
        console.log(`uWebSockets.js server listening on port ${this.port}`);
      } else {
        console.error(`Failed to listen on port ${this.port}`);
        process.exit(1);
      }
    });

    // Graceful shutdown
    const signals = ['SIGINT', 'SIGTERM'] as const;
    for (const signal of signals) {
      process.on(signal, () => {
        console.log(`Received ${signal}, closing server...`);
        
        // Close all active connections
        this.activeConnections.forEach((timeout, ws) => {
          clearTimeout(timeout);
          ws.end(1001, 'Server shutting down');
        });

        process.exit(0);
      });
    }
  }
}

const server = new WebSocketServer();
server.start();
