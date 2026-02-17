#!/bin/bash
set -e

echo "=== Private Code Reviewer — Local Development ==="
echo ""

# Install dependencies
echo "Installing backend dependencies..."
npm install

echo "Installing frontend dependencies..."
cd frontend && npm install && cd ..

# Copy env if needed
if [ ! -f .env ]; then
  echo "Creating .env from .env.example..."
  cp .env.example .env
  echo "  >> Edit .env and add your EIGENAI_API_KEY"
fi

# Create required directories
mkdir -p uploads reports

# Run both servers
echo ""
echo "Starting dev servers..."
echo "  Backend:  http://localhost:8000"
echo "  Frontend: http://localhost:3000"
echo ""
npm run dev:all
