#!/bin/bash
# Shortcut to run both FastAPI backend and React frontend together

echo "Starting FastAPI Backend (port 8000)..."
source .venv/bin/activate 2>/dev/null || true
python -m uvicorn api:app --port 8000 &
API_PID=$!

echo "Starting React Frontend (port 5173)..."
npm run dev --prefix frontend &
FRONT_PID=$!

trap "kill $API_PID $FRONT_PID 2>/dev/null" EXIT INT TERM

wait
