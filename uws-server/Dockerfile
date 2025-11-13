# ==========================
# Base image with build tools (reusable layer)
# ==========================
FROM node:20-bookworm-slim AS base-with-tools

# Install build tools once (this layer will be cached!)
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*


# ==========================
# 1. Build Stage
# ==========================
FROM base-with-tools AS builder

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install ALL dependencies
RUN npm ci && npm cache clean --force

# Copy source code
COPY tsconfig.json ./
COPY src ./src

# Build TypeScript
RUN npm run build


# ==========================
# 2. Production Dependencies Stage
# ==========================
FROM base-with-tools AS deps

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install production dependencies
RUN npm ci --omit=dev && npm cache clean --force


# ==========================
# 3. Final Production Image
# ==========================
FROM node:20-bookworm-slim AS final

WORKDIR /app

# Install dumb-init only (much faster!)
RUN apt-get update && apt-get install -y \
    dumb-init \
    && rm -rf /var/lib/apt/lists/*

# Copy production node_modules
COPY --from=deps /app/node_modules ./node_modules

# Copy compiled JavaScript
COPY --from=builder /app/dist ./dist

# Copy package.json
COPY package.json ./

# Create non-root user
RUN groupadd -g 1001 nodejs && \
    useradd -u 1001 -g nodejs nodejs && \
    chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]