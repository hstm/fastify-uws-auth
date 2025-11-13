#!/bin/bash

set -e

echo "🚀 Starting Secure Authentication System..."
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ───────────────────────────────
# Check prerequisites
# ───────────────────────────────
echo -e "${BLUE}🔍 Checking prerequisites...${NC}"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker is not running!${NC}"
    echo "Please start Docker and try again."
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker is running"

# Check if the new Docker Compose plugin is available
if ! docker compose version > /dev/null 2>&1; then
    echo -e "${RED}❌ Docker Compose plugin not found!${NC}"
    echo "Please install it via:"
    echo "  sudo apt-get install docker-compose-plugin"
    exit 1
fi
echo -e "${GREEN}✓${NC} Docker Compose plugin is installed"
echo ""

# ───────────────────────────────
# Check Node.js lockfiles
# ───────────────────────────────
echo -e "${BLUE}📦 Checking package-lock.json files...${NC}"

if [ ! -f "fastify-api/package-lock.json" ]; then
    echo -e "${YELLOW}⚠️  fastify-api/package-lock.json not found. Generating...${NC}"
    (cd fastify-api && npm install --silent)
    echo -e "${GREEN}✓${NC} fastify-api/package-lock.json created"
else
    echo -e "${GREEN}✓${NC} fastify-api/package-lock.json exists"
fi

if [ ! -f "uws-server/package-lock.json" ]; then
    echo -e "${YELLOW}⚠️  uws-server/package-lock.json not found. Generating...${NC}"
    (cd uws-server && npm install --silent)
    echo -e "${GREEN}✓${NC} uws-server/package-lock.json created"
else
    echo -e "${GREEN}✓${NC} uws-server/package-lock.json exists"
fi
echo ""

# ───────────────────────────────
# Check RSA keys
# ───────────────────────────────
if [ ! -f "./keys/private.pem" ] || [ ! -f "./keys/public.pem" ]; then
    echo -e "${YELLOW}⚠️  RSA keys not found. Generating...${NC}"
    ./generate-keys.sh
    echo ""
fi

# ───────────────────────────────
# Build and start Docker services
# ───────────────────────────────
echo -e "${BLUE}🏗️  Building and starting Docker containers...${NC}"
docker compose up --build -d

# ───────────────────────────────
# Wait and check services
# ───────────────────────────────
echo ""
echo -e "${BLUE}⏳ Waiting for services to be ready...${NC}"
sleep 5

echo ""
echo -e "${BLUE}🏥 Checking service health...${NC}"

check_service() {
    local name=$1
    local url=$2

    if curl -sf "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $name is running"
    else
        echo -e "${YELLOW}⚠${NC} $name may not be ready yet"
    fi
}

check_service "Nginx" "http://localhost/health"
check_service "Fastify API" "http://localhost/api/health"

# ───────────────────────────────
# Show status and info
# ───────────────────────────────
echo ""
echo -e "${BLUE}📋 Service Status:${NC}"
docker compose ps

echo ""
echo -e "${GREEN}✓ All services started!${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}🌐 Service URLs:${NC}"
echo "  • Nginx Reverse Proxy: http://localhost"
echo "  • Fastify API:         http://localhost/api"
echo "  • WebSocket:           ws://localhost/ws"
echo "  • Health Check:        http://localhost/health"
echo ""
echo -e "${BLUE}📝 Test Credentials:${NC}"
echo "  • Username: testuser"
echo "  • Password: password123"
echo ""
echo -e "${BLUE}🧪 Quick Test:${NC}"
echo "  Open client-demo.html in your browser for an interactive demo"
echo ""
echo -e "${BLUE}📖 API Examples:${NC}"
echo ""
echo "  # Login"
echo "  curl -X POST http://localhost/api/login \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"username\":\"testuser\",\"password\":\"password123\"}' \\"
echo "    -c cookies.txt"
echo ""
echo "  # Call protected endpoint"
echo "  curl http://localhost/api/protected \\"
echo "    -H 'Authorization: Bearer <ACCESS_TOKEN>'"
echo ""
echo "  # Refresh token"
echo "  curl -X POST http://localhost/api/refresh \\"
echo "    -b cookies.txt -c cookies.txt"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}📊 View Logs:${NC}"
echo "  docker compose logs -f"
echo ""
echo -e "${BLUE}🛑 Stop Services:${NC}"
echo "  docker compose down"
echo ""
