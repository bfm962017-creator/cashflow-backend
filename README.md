# Cashflow backend (API)

Node + Express + Postgres. Endpoints under /api, health check at /health.

Env vars: DATABASE_URL, JWT_SECRET, FRONTEND_URL (comma separated allowed origins).

Local: npm install && DATABASE_URL=... JWT_SECRET=... FRONTEND_URL=http://localhost:8080 npm start
