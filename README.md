# GitHub OAuth login demo

A small Node.js/Express learning project showing GitHub OAuth and a signed local session cookie.

## Run

1. Register a GitHub OAuth App and set its callback URL to `http://localhost:3000/github-callback`.
2. Run `npm install`.
3. Copy `.env.example` to `.env` and set `CLIENT_ID`, `CLIENT_SECRET` and a strong random `JWT_SECRET`. Never commit `.env`.
4. Run `npm run dev` and open `http://localhost:3000`.

The callback validates a random OAuth `state` cookie before exchanging the authorization code. The GitHub access token is never printed or included in the redirect URL. The demo session is stored in an HttpOnly cookie. On HTTPS deployments, set `NODE_ENV=production` to use Secure cookies.

**Scope:** learning project, not a production-ready login service. A production implementation also needs persistent sessions, CSRF protection for all state-changing routes, logout, proper rate limits, and stricter deployment configuration.
