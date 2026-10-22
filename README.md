# Cashflow backend (API)

Node + Express + Postgres. Endpoints under /api, health check at /health.

Env vars: DATABASE_URL, JWT_SECRET, FRONTEND_URL (comma separated allowed origins).

Local: npm install && DATABASE_URL=... JWT_SECRET=... FRONTEND_URL=http://localhost:8080 npm start

## Deploying on Vercel + Supabase

The same code runs on Render (`npm start`) and on Vercel (`api/index.js` + `vercel.json`).

1. Supabase: create a project and copy the **Transaction pooler** connection string (port 6543). It works from Vercel, which has no IPv6.
2. Vercel: import this repo (no build settings needed) and set these environment variables:
   - `DATABASE_URL`: the Supabase pooler string
   - `JWT_SECRET`: a long random string
   - `FRONTEND_URL`: the app's address, e.g. `https://cashflow-app.vercel.app` (several can be listed with commas)
   - `CRON_SECRET`: a long random string. Vercel Cron sends it to `/api/cron/daily` every night at 11 PM India time, which replaces cron-job.org.
3. The database tables are created automatically on the first request.
