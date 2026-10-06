const crypto = require('crypto');
const express = require('express');
const { db, hashPassword, verifyPassword } = require('./db');
const { badRequest, unauthorized, wrap } = require('./errors');

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 天

const router = express.Router();

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_TTL_MS).toISOString();
  db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').run(token, userId, expires);
  return { token, expires };
}

function publicUser(u) {
  return { id: u.id, username: u.username, role: u.role, displayName: u.display_name };
}

/**
 * 会话中间件：支持 Cookie 与 Authorization: Bearer 两种方式。
 * 双凭证判定规则：请求显式携带 Bearer 时，只按该令牌认证，
 * 令牌无效即 401，不回退 Cookie；未携带 Bearer 时才沿用 Cookie。
 */
function authRequired(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.toLowerCase().startsWith('bearer')) {
    // 显式 Bearer：令牌缺失/为空同样视为无效，不回退 Cookie
    const token = header.slice(6).trim();
    if (!token) return next(unauthorized());
    return authenticate(req, next, token, 'bearer');
  }
  if (req.cookies && req.cookies.session) {
    return authenticate(req, next, req.cookies.session, 'cookie');
  }
  return next(unauthorized());
}

function authenticate(req, next, token, via) {
  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session || new Date(session.expires_at).getTime() < Date.now()) return next(unauthorized());
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return next(unauthorized());
  req.user = user;
  req.sessionToken = token;
  req.authVia = via; // 本次实际认证方式：'bearer' | 'cookie'
  next();
}

function requireDirector(req, res, next) {
  if (!req.user) return next(unauthorized());
  if (req.user.role !== 'director') return next(forbiddenDirect());
  next();
}

function forbiddenDirect() {
  const e = new Error('无权访问该资源');
  e.status = 403;
  e.code = 'FORBIDDEN';
  return e;
}

router.post(
  '/login',
  wrap((req, res) => {
    const { username, password } = req.body || {};
    if (!username || !password) throw badRequest('用户名和密码不能为空');
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!user || !verifyPassword(password, user.password_hash)) {
      throw Object.assign(new Error('用户名或密码错误'), { status: 401, code: 'INVALID_CREDENTIALS' });
    }
    const { token, expires } = createSession(user.id);
    res.cookie('session', token, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: SESSION_TTL_MS,
    });
    res.json({ token, expiresAt: expires, user: publicUser(user) });
  })
);

router.post('/logout', authRequired, (req, res) => {
  // 仅撤销本次实际认证所用的令牌：
  // Bearer 退出不动 Cookie 会话，Cookie 退出才清除浏览器 Cookie。
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.sessionToken);
  if (req.authVia === 'cookie') res.clearCookie('session');
  res.json({ ok: true });
});

router.get('/me', authRequired, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

module.exports = { router, authRequired, requireDirector, publicUser };
