const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('node:crypto');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const secureCookie = process.env.NODE_ENV === 'production' ? '; Secure' : '';

for (const key of ['CLIENT_ID', 'CLIENT_SECRET', 'JWT_SECRET']) {
  if (!process.env[key] || process.env[key].startsWith('replace-')) {
    throw new Error(`Missing or invalid environment variable: ${key}`);
  }
}

function cookie(req, name) {
  const pair = (req.headers.cookie || '').split('; ').find(part => part.startsWith(name + '='));
  return pair ? pair.slice(name.length + 1) : '';
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

app.get('/', (req, res) => {
  let username = null;
  try {
    const token = cookie(req, 'demo_session');
    if (token) username = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }).userName;
  } catch {
    // Invalid/expired session: show login again.
  }
  res.type('html').send(username
    ? `<h1>OAuth demo</h1><p>Välkommen ${escapeHtml(username)}!</p>`
    : '<h1>OAuth demo</h1><a href="/auth">Sign in with GitHub</a>');
});

app.get('/auth', (req, res) => {
  const state = crypto.randomBytes(32).toString('hex');
  res.setHeader('Set-Cookie',
    `oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600${secureCookie}`);
  const params = new URLSearchParams({ client_id: process.env.CLIENT_ID, state, scope: 'read:user' });
  res.redirect('https://github.com/login/oauth/authorize?' + params.toString());
});

app.get('/github-callback', async (req, res) => {
  const expected = cookie(req, 'oauth_state');
  const received = typeof req.query.state === 'string' ? req.query.state : '';
  res.setHeader('Set-Cookie',
    `oauth_state=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0${secureCookie}`);

  if (!expected || !received || !/^[a-f0-9]{64}$/.test(expected) ||
      !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received))) {
    return res.status(400).send('Invalid OAuth state');
  }
  if (typeof req.query.code !== 'string' || !req.query.code) {
    return res.status(400).send('Missing authorization code');
  }

  try {
    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        code: req.query.code
      })
    });
    if (!response.ok) throw new Error('Token exchange failed');
    const tokenData = await response.json();
    if (!tokenData.access_token) throw new Error('No access token returned');

    const userResponse = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${tokenData.access_token}`, Accept: 'application/vnd.github+json' }
    });
    if (!userResponse.ok) throw new Error('Could not fetch GitHub user');
    const user = await userResponse.json();
    if (!user.id || !user.login) throw new Error('Invalid GitHub user');

    const session = jwt.sign({ sub: user.id, userName: user.login },
      process.env.JWT_SECRET, { algorithm: 'HS256', expiresIn: '1h' });
    res.setHeader('Set-Cookie',
      `demo_session=${session}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600${secureCookie}`);
    res.redirect('/');
  } catch (error) {
    console.error('OAuth callback failed:', error.message);
    res.status(502).send('GitHub login failed');
  }
});

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));
