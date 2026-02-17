FROM node:20-slim AS builder

WORKDIR /app

# Install backend dependencies
COPY package.json package-lock.json* ./
RUN npm install

# Install frontend dependencies
COPY frontend/package.json frontend/package-lock.json* ./frontend/
RUN cd frontend && npm install

# Copy source code
COPY . .

# Build backend
RUN npm run build

# Build frontend
RUN cd frontend && npm run build

# Production stage
FROM node:20-slim

WORKDIR /app

# Install only production dependencies
COPY package.json package-lock.json* ./
RUN npm install --production

# Copy built backend
COPY --from=builder /app/dist ./dist

# Copy built frontend
COPY --from=builder /app/frontend/dist ./frontend/dist

# Copy patterns library
COPY patterns ./patterns

EXPOSE 8000

# Health check for TEE monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8000/health', (r) => { process.exit(r.statusCode === 200 ? 0 : 1) })"

CMD ["node", "dist/index.js"]
