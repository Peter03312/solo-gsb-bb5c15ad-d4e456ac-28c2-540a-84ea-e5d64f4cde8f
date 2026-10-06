/**
 * 双凭证（Cookie + Bearer）判定专项验证。
 * 用法: BASE=http://127.0.0.1:3399 node scripts/verify-dual-cred.cjs
 */
const BASE = process.env.BASE || 'http://127.0.0.1:3399';

let failures = 0;
function check(name, cond, extra = '') {
  if (cond) console.log(`  ✅ ${name}`);
  else {
    failures++;
    console.error(`  ❌ ${name} ${extra}`);
  }
}

async function call(method, path, { token, cookie, body } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (cookie) headers['Cookie'] = cookie;
  const res = await fetch(BASE + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* */ }
  return { status: res.status, json, setCookie: res.headers.getSetCookie() };
}

async function login(username, password) {
  const res = await call('POST', '/api/login', { body: { username, password } });
  const raw = res.setCookie.find((c) => c.startsWith('session='));
  return { token: res.json.token, cookie: raw.split(';')[0] };
}

async function main() {
  console.log('— 准备：导演与演员各登录一次 —');
  const director = await login('director', 'director123');
  const lin = await login('lin', 'actor123');

  console.log('— 浏览器持导演 Cookie，同时带演员 Bearer —');
  const both = await call('GET', '/api/me', { token: lin.token, cookie: director.cookie });
  check('/api/me 按 Bearer 返回演员身份',
    both.status === 200 && both.json.user.username === 'lin',
    `status=${both.status} user=${both.json && both.json.user && both.json.user.username}`);
  // 演员 Bearer 访问仅导演接口仍 403（权限隔离）
  const actorsAsLin = await call('GET', '/api/actors', { token: lin.token, cookie: director.cookie });
  check('演员 Bearer 不借导演 Cookie 越权（403）', actorsAsLin.status === 403, `status=${actorsAsLin.status}`);

  console.log('— 无效 Bearer 不得借有效 Cookie 通过 —');
  const invalidBearer = await call('GET', '/api/me', { token: 'deadbeef', cookie: director.cookie });
  check('无效 Bearer + 导演 Cookie -> 401', invalidBearer.status === 401, `status=${invalidBearer.status}`);
  const garbageBearer = await call('GET', '/api/me', { token: '   ', cookie: director.cookie });
  check('空白 Bearer + 导演 Cookie -> 401', garbageBearer.status === 401, `status=${garbageBearer.status}`);
  const invalidPrivate = await call('GET', '/api/actors', { token: 'nope', cookie: director.cookie });
  check('无效 Bearer 访问导演私有接口 -> 401（非 200/403）', invalidPrivate.status === 401, `status=${invalidPrivate.status}`);
  // Cookie 本身仍有效（未被连带撤销）
  const cookieStillAlive = await call('GET', '/api/me', { cookie: director.cookie });
  check('失败的 Bearer 调用后导演 Cookie 仍然有效',
    cookieStillAlive.status === 200 && cookieStillAlive.json.user.username === 'director');

  console.log('— 以 Bearer 退出：只撤销该令牌，不动 Cookie —');
  const logoutBearer = await call('POST', '/api/logout', { token: lin.token, cookie: director.cookie });
  check('Bearer 退出 200', logoutBearer.status === 200, `status=${logoutBearer.status}`);
  const clearsCookie = logoutBearer.setCookie.some((c) => /^session=;|^session=$|Expires=Thu, 01 Jan 1970/.test(c));
  check('Bearer 退出响应不清除 Cookie', !clearsCookie, JSON.stringify(logoutBearer.setCookie));
  const linTokenDead = await call('GET', '/api/me', { token: lin.token });
  check('演员 Bearer 已被撤销（401）', linTokenDead.status === 401, `status=${linTokenDead.status}`);
  const directorCookieAlive = await call('GET', '/api/me', { cookie: director.cookie });
  check('导演 Cookie 会话不受影响',
    directorCookieAlive.status === 200 && directorCookieAlive.json.user.username === 'director');
  // 已失效 Bearer + 仍有效 Cookie 仍判 401（不回退）
  const deadBearerAliveCookie = await call('GET', '/api/me', { token: lin.token, cookie: director.cookie });
  check('已撤销 Bearer + 有效 Cookie 仍 401', deadBearerAliveCookie.status === 401, `status=${deadBearerAliveCookie.status}`);

  console.log('— 以 Cookie 退出：撤销会话并清除 Cookie —');
  // 导演同时有 Cookie 与另一张 Bearer（同会话之外的独立令牌）
  const director2 = await login('director', 'director123');
  const logoutCookie = await call('POST', '/api/logout', { cookie: director2.cookie });
  check('Cookie 退出 200', logoutCookie.status === 200, `status=${logoutCookie.status}`);
  const cleared = logoutCookie.setCookie.some((c) => /Expires=Thu, 01 Jan 1970/.test(c));
  check('Cookie 退出响应清除 session Cookie', cleared, JSON.stringify(logoutCookie.setCookie));
  const cookieDead = await call('GET', '/api/me', { cookie: director2.cookie });
  check('退出后该 Cookie 已失效（401）', cookieDead.status === 401, `status=${cookieDead.status}`);

  console.log('— 单凭证调用 —');
  const chen = await login('chen', 'actor123');
  const bearerOnly = await call('GET', '/api/me', { token: chen.token });
  check('仅 Bearer 正常', bearerOnly.status === 200 && bearerOnly.json.user.username === 'chen');
  const cookieOnly = await call('GET', '/api/me', { cookie: director.cookie });
  check('仅 Cookie 正常', cookieOnly.status === 200 && cookieOnly.json.user.username === 'director');
  const nothing = await call('GET', '/api/me');
  check('无凭证 401', nothing.status === 401, `status=${nothing.status}`);

  if (failures) {
    console.error(`\n${failures} 项失败`);
    process.exit(1);
  }
  console.log('\n双凭证专项全部通过 🎉');
}

main().catch((e) => { console.error(e); process.exit(1); });
