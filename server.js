#!/usr/bin/env node
/**
 * AWS Lightsail 控制面板 —— 本地代理服务器（安全加固版）
 *
 * 核心功能零依赖（仅 Node.js 内置模块）；「在线 SSH」功能需要项目内
 * node_modules（ssh2 + ws），已随项目一起安装，无需手动 npm install。
 *
 * 作用：
 *   1. 托管前端页面 index.html（访问 http://localhost:8080）
 *   2. 提供 POST /api/proxy 接口，服务端完成 SigV4 签名后转发到 AWS Lightsail API
 *   3. 提供 GET/POST /api/config 接口，保存 / 查询本机 AWS 凭证
 *   4. 提供 /ws WebSocket 端点，为「在线 SSH」建立到实例 22 端口的终端通道
 *
 * 安全设计（加固点）：
 *   - AWS 凭证（AK/SK）只保存在本机文件 aws-credentials.json 中，
 *     浏览器端不再持有、也不再做签名；签名由本服务端完成。
 *   - /api/proxy 与 /api/config 仅接受本机回环来源（127.0.0.1 / ::1），
 *     即使误开端口转发，外部请求也会被拒绝。
 *   - 代理只允许转发到 lightsail.*.amazonaws.com 的端点，防止被滥用。
 *
 * 启动：node server.js   （默认端口 8080，可用 PORT 环境变量修改，如 PORT=9000 node server.js）
 */

'use strict';

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { spawn } = require('child_process');

// 在线 SSH 依赖（可选加载；未安装时 /ws 功能不可用，其余功能不受影响）
let WebSocketServer = null;
let SSHClient = null;
try {
  WebSocketServer = require('ws');
  SSHClient = require('ssh2').Client;
} catch (e) {
  /* 依赖缺失时在线 SSH 降级不可用 */
}

const PORT = Number(process.env.PORT) || 8080;
const ROOT = __dirname;
// 旧全局凭证路径（迁移来源：注册第一个账号时自动继承，避免重新配置）
const LEGACY_CREDS_FILE = process.env.CREDS_FILE || path.join(ROOT, 'aws-credentials.json');
const LEGACY_OCI_FILE = process.env.OCI_CREDS_FILE || path.join(ROOT, 'oci-credentials.json');
// 数据目录：账号库 / 会话 / 按账号隔离的凭证都存这里（容器部署时挂 /data）
const APP_VERSION = '202609100329'; // 每次发布更新：YYYYMMDDHHMM
const DATA_DIR = process.env.DATA_DIR || (process.env.CREDS_FILE ? path.dirname(process.env.CREDS_FILE) : ROOT);
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const ociBackend = require('./oci');
const tgNotify = require('./telegram');
tgNotify.setDataDir(DATA_DIR);

/* ---------------- Telegram 通知辅助 ---------------- */
function getClientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (fwd) return fwd;
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}
const NOTIFY_AWS_ACTIONS = {
  StartInstance: '开机',
  StopInstance: '关机',
  RebootInstance: '重启',
  OpenInstancePublicPorts: '开放端口',
  DeleteInstance: '删除实例',
};

/* ---------------- 操作日志（内存环形，重启清空） ---------------- */
const OP_LOG_MAX = 300;
const opLogs = [];
function opLog(user, msg) {
  opLogs.push({ t: Date.now(), u: String(user || ''), m: String(msg).slice(0, 300) });
  if (opLogs.length > OP_LOG_MAX) opLogs.splice(0, opLogs.length - OP_LOG_MAX);
}

/* ---------------- 账号系统（注册 / 登录 / 会话） ---------------- */
const SESSION_TTL_MS = 30 * 24 * 3600 * 1000; // 会话 30 天

function readJsonFile(p, def) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (e) { return def; }
}
function writeJsonFile(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), { encoding: 'utf8', mode: 0o600 });
}
function loadUsers() { return readJsonFile(USERS_FILE, {}); }
function saveUsers(u) { writeJsonFile(USERS_FILE, u); }
function loadSessions() { return readJsonFile(SESSIONS_FILE, {}); }
function saveSessions(s) { writeJsonFile(SESSIONS_FILE, s); }

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, 64).toString('hex');
}
function verifyPassword(password, salt, expectedHash) {
  const h = Buffer.from(hashPassword(password, salt), 'hex');
  const e = Buffer.from(expectedHash, 'hex');
  return h.length === e.length && crypto.timingSafeEqual(h, e);
}
function isValidUsername(u) { return /^[a-zA-Z0-9_-]{3,32}$/.test(u); }

function userDir(user) { return path.join(DATA_DIR, 'users', user); }
function userAwsFile(user) { return path.join(userDir(user), 'aws-credentials.json'); }
function userOciFile(user) { return path.join(userDir(user), 'oci-credentials.json'); }

/** 注册新账号时自动继承旧版全局凭证（AWS / OCI），避免重新配置一遍。
 *  迁移成功后把旧文件重命名为 .migrated，只允许首个账号继承一次。 */
function migrateLegacyCreds(user) {
  try {
    fs.mkdirSync(userDir(user), { recursive: true });
    if (fs.existsSync(LEGACY_CREDS_FILE) && !fs.existsSync(userAwsFile(user))) {
      fs.copyFileSync(LEGACY_CREDS_FILE, userAwsFile(user));
      try { fs.renameSync(LEGACY_CREDS_FILE, LEGACY_CREDS_FILE + '.migrated'); } catch (e) { /* 重命名失败不阻塞 */ }
    }
    if (fs.existsSync(LEGACY_OCI_FILE) && !fs.existsSync(userOciFile(user))) {
      fs.copyFileSync(LEGACY_OCI_FILE, userOciFile(user));
      try { fs.renameSync(LEGACY_OCI_FILE, LEGACY_OCI_FILE + '.migrated'); } catch (e) { /* 重命名失败不阻塞 */ }
    }
  } catch (e) { /* 迁移失败不阻塞注册 */ }
}

/* ---------------- 登录暴力破解防护（账号 + 来源 IP 双维度） ----------------
 * 账号维度：同一账号连续失败 BF_ACCOUNT_LIMIT 次 → 锁该账号（防换 IP 爆破）
 * IP 维度：同一来源 IP 对任意账号累计失败 BF_IP_LIMIT 次 → 锁该 IP（防批量扫号）
 * 锁定时间：1 分钟 × 10^轮次 递增（1 分钟 → 10 分钟 → 100 分钟 → 1000 分钟封顶）
 * 成功登录会同时重置账号与来源 IP 的计数，避免误伤正常使用。
 */
const BF_ACCOUNT_LIMIT = (function () { const v = parseInt(process.env.BF_ACCOUNT_LIMIT || '', 10); return isFinite(v) && v > 0 ? v : 5; })();
const BF_IP_LIMIT = (function () { const v = parseInt(process.env.BF_IP_LIMIT || '', 10); return isFinite(v) && v > 0 ? v : 10; })();
const BF_BASE_MS = (function () { const v = parseInt(process.env.BF_BASE_MS || '', 10); return isFinite(v) && v > 0 ? v : 60000; })();
const BF_MAX_STRIKES = 4; // 1 分钟 → 10 分钟 → 100 分钟 → 1000 分钟（约 16.6 小时封顶档）
const BF_FILE = path.join(DATA_DIR, 'bruteforce.json');
const bfUsers = new Map();
const bfIps = new Map();
function bfSave() {
  try {
    const u = {}, i = {};
    for (const [k, v] of bfUsers.entries()) u[k] = { fails: v.fails, lockUntil: v.lockUntil, strikes: v.strikes };
    for (const [k, v] of bfIps.entries()) i[k] = { fails: v.fails, lockUntil: v.lockUntil, strikes: v.strikes };
    fs.writeFileSync(BF_FILE, JSON.stringify({ users: u, ips: i }), { encoding: 'utf8', mode: 0o600 });
  } catch (e) { /* noop */ }
}
function bfLoad() {
  try {
    const j = JSON.parse(fs.readFileSync(BF_FILE, 'utf8'));
    if (j && typeof j === 'object') {
      // 兼容旧版（直接是 {账号: 记录} 的账号维度格式）
      const users = (j.users && typeof j.users === 'object') ? j.users : (j.ips ? {} : j);
      const ips = (j.ips && typeof j.ips === 'object') ? j.ips : {};
      for (const k of Object.keys(users)) {
        const v = users[k] || {};
        bfUsers.set(k, { fails: v.fails || 0, lockUntil: v.lockUntil || 0, strikes: v.strikes || 0 });
      }
      for (const k of Object.keys(ips)) {
        const v = ips[k] || {};
        bfIps.set(k, { fails: v.fails || 0, lockUntil: v.lockUntil || 0, strikes: v.strikes || 0 });
      }
    }
  } catch (e) { /* noop */ }
}
/** 来源 IP（用真实 TCP 地址，防 X-Forwarded-For 伪造绕过） */
function bfClientIp(req) {
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '') || 'unknown';
}
/** 返回锁定状态；锁定期满自动解除并重置连续失败计数 */
function bfCheckMap(map, key) {
  const r = map.get(key);
  if (!r) return { locked: false };
  if (r.lockUntil && Date.now() < r.lockUntil) {
    const sec = Math.ceil((r.lockUntil - Date.now()) / 1000);
    return { locked: true, waitSec: sec, waitMin: Math.max(1, Math.ceil(sec / 60)) };
  }
  if (r.lockUntil && Date.now() >= r.lockUntil) {
    r.lockUntil = 0;
    r.fails = 0;
    bfSave();
  }
  return { locked: false };
}
/** 记录一次失败；达到阈值触发锁定（时长 = 1 分钟 × 10^轮次） */
function bfFailMap(map, key, limit) {
  let r = map.get(key);
  if (!r) { r = { fails: 0, lockUntil: 0, strikes: 0 }; map.set(key, r); }
  r.fails = (r.fails || 0) + 1;
  if (r.fails >= limit) {
    const mult = Math.pow(10, Math.min(r.strikes || 0, BF_MAX_STRIKES));
    r.lockUntil = Date.now() + BF_BASE_MS * mult;
    r.strikes = (r.strikes || 0) + 1;
    r.fails = 0;
  }
  bfSave();
  return r;
}
function bfResetMap(map, key) { map.delete(key); bfSave(); }

/* ---------------- 二次登录验证码（2FA，2 分钟有效） ---------------- */
const OTP_TTL_MS = 2 * 60 * 1000;
const otpStore = new Map();
function issueOtp(user) {
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  const rec = { user, code, expiresAt: Date.now() + OTP_TTL_MS };
  otpStore.set(user, rec);
  try {
    fs.mkdirSync(path.dirname(path.join(userDir(user), 'otp-state.json')), { recursive: true });
    fs.writeFileSync(path.join(userDir(user), 'otp-state.json'), JSON.stringify(rec), { encoding: 'utf8', mode: 0o600 });
  } catch (e) { /* noop */ }
  return rec;
}
function checkOtp(user, code) {
  const rec = otpStore.get(user) || null;
  if (!rec) return { ok: false, error: '验证码不存在或已失效，请重新登录获取' };
  if (Date.now() > rec.expiresAt) { otpStore.delete(user); return { ok: false, error: '验证码已过期（2 分钟有效），请重新登录获取' }; }
  if (String(code).trim() !== rec.code) return { ok: false, error: '验证码不正确' };
  otpStore.delete(user);
  try { fs.rmSync(path.join(userDir(user), 'otp-state.json'), { force: true }); } catch (e) { /* noop */ }
  return { ok: true };
}
/** 首次部署自动创建默认账号（admin / admin123）；已有账号则不干预 */
function ensureDefaultAdmin() {
  bfLoad();
  const users = loadUsers();
  if (Object.keys(users).length === 0) {
    const salt = crypto.randomBytes(16).toString('hex');
    users.admin = { salt, hash: hashPassword('admin123', salt), created: Date.now() };
    saveUsers(users);
    console.log('  已创建默认账号 admin（密码 admin123），请登录后立即在「账号」设置中修改！');
  }
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  const sessions = loadSessions();
  const now = Date.now();
  for (const k of Object.keys(sessions)) {
    if (sessions[k].exp < now) delete sessions[k];
  }
  sessions[token] = { user, exp: now + SESSION_TTL_MS };
  saveSessions(sessions);
  return token;
}
function destroySession(token) {
  const sessions = loadSessions();
  if (sessions[token]) { delete sessions[token]; saveSessions(sessions); }
}
function getUserFromReq(req) {
  const m = /(?:^|;\s*)session=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const token = m[1];
  const sessions = loadSessions();
  const s = sessions[token];
  if (!s) return null;
  if (s.exp < Date.now()) { delete sessions[token]; saveSessions(sessions); return null; }
  return s.user;
}
function setSessionCookie(res, token) {
  res.setHeader('Set-Cookie', 'session=' + token + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000));
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

/** 除 /api/auth/* 外，所有 /api/* 与 /ws 都需要登录 */
function isPublicApi(urlPath) {
  return urlPath === '/api/auth/register' || urlPath === '/api/auth/login' || urlPath === '/api/auth/verify-otp' || urlPath === '/api/auth/me';
}

/* ---------------- 账号凭证存储（按账号隔离，支持多凭证组） ----------------
 * 文件格式：{ "active": "组名", "accounts": { "组名": {accessKeyId, secretAccessKey, region} } }
 * 兼容旧版单组格式：读到时自动升级为新格式（组名 default） */
function loadCredStore(user) {
  try {
    const c = JSON.parse(fs.readFileSync(userAwsFile(user), 'utf8'));
    if (c && c.accounts && typeof c.accounts === 'object') {
      if (!c.active) c.active = Object.keys(c.accounts)[0] || '';
      return c;
    }
    if (c && c.accessKeyId && c.secretAccessKey) {
      const n = { active: 'default', accounts: { default: { accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey, region: c.region } } };
      try { fs.writeFileSync(userAwsFile(user), JSON.stringify(n, null, 2), { encoding: 'utf8', mode: 0o600 }); } catch (e) { /* noop */ }
      return n;
    }
    return null;
  } catch (e) { return null; }
}
function saveCredStore(user, store) {
  fs.mkdirSync(path.dirname(userAwsFile(user)), { recursive: true });
  fs.writeFileSync(userAwsFile(user), JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 });
}
/** 当前生效的凭证（active 组；active 无效时回退到第一组） */
function loadCredentials(user) {
  const s = loadCredStore(user);
  if (!s) return null;
  const c = s.accounts[s.active] || s.accounts[Object.keys(s.accounts)[0]] || null;
  if (!c || !(c.accessKeyId && c.secretAccessKey)) return null;
  return Object.assign({ name: s.active || Object.keys(s.accounts)[0] }, c);
}
/** 按组名取凭证（实例分组用；组不存在则回退 active） */
function loadCredentialsForGroup(user, group) {
  const s = loadCredStore(user);
  if (!s) return null;
  const name = group && s.accounts[group] ? group : (s.accounts[s.active] ? s.active : Object.keys(s.accounts)[0]);
  const c = s.accounts[name] || null;
  if (!c || !(c.accessKeyId && c.secretAccessKey)) return null;
  return Object.assign({ name }, c);
}
/** 凭证组列表（不回显 SK，AK 只回尾号） */
function listCredentials(user) {
  const s = loadCredStore(user);
  if (!s) return { active: '', accounts: [] };
  const accounts = Object.keys(s.accounts).map((name) => {
    const c = s.accounts[name] || {};
    return { name, region: c.region || '', accessKeyIdTail: String(c.accessKeyId || '').slice(-4), hasSecret: !!c.secretAccessKey };
  });
  return { active: s.active || (accounts[0] ? accounts[0].name : ''), accounts };
}
function saveCredential(user, opts) {
  const s = loadCredStore(user) || { active: '', accounts: {} };
  const name = String(opts.name || '').trim();
  if (!name) throw new Error('凭证组名称不能为空');
  const prev = s.accounts[name] || {};
  const merged = {
    accessKeyId: opts.accessKeyId !== undefined && String(opts.accessKeyId).trim() ? String(opts.accessKeyId).trim() : (prev.accessKeyId || ''),
    secretAccessKey: opts.secretAccessKey !== undefined && String(opts.secretAccessKey).trim() ? String(opts.secretAccessKey).trim() : (prev.secretAccessKey || ''),
    region: opts.region !== undefined && String(opts.region).trim() ? String(opts.region).trim() : (prev.region || '')
  };
  if (!s.accounts[name]) { if (!s.active) s.active = name; }
  s.accounts[name] = merged;
  if (opts.makeActive) s.active = name;
  saveCredStore(user, s);
}
function setActiveCredential(user, name) {
  const s = loadCredStore(user);
  if (!s || !s.accounts[name]) throw new Error('凭证组不存在：' + name);
  s.active = name;
  saveCredStore(user, s);
}
function deleteCredential(user, name) {
  const s = loadCredStore(user);
  if (!s) return;
  delete s.accounts[name];
  if (s.active === name) s.active = Object.keys(s.accounts)[0] || '';
  if (Object.keys(s.accounts).length === 0) {
    try { fs.rmSync(userAwsFile(user), { force: true }); } catch (e) { /* noop */ }
  } else {
    saveCredStore(user, s);
  }
}
function clearCredentials(user) {
  try { fs.rmSync(userAwsFile(user), { force: true }); } catch (e) { /* noop */ }
}

/* ---------------- 服务端 SigV4 签名（AWS JSON 1.1 协议） ---------------- */
function hmacSha256(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}
function sha256Hex(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}
function signAwsJson(action, params, creds, region) {
  const service = 'lightsail';
  const host = 'lightsail.' + region + '.amazonaws.com';
  const body = JSON.stringify(params || {});
  const payloadHash = sha256Hex(body);
  const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const dateStamp = amzDate.slice(0, 8);
  const target = 'Lightsail_20161128.' + action;

  const headers = {
    'content-type': 'application/x-amz-json-1.1',
    'host': host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    'x-amz-target': target
  };
  const signedHeaderNames = Object.keys(headers).sort();
  const canonicalHeaders = signedHeaderNames.map(k => k + ':' + headers[k]).join('\n');
  const signedHeaders = signedHeaderNames.join(';');
  const canonicalRequest = ['POST', '/', '', canonicalHeaders, '', signedHeaders, payloadHash].join('\n');
  const scope = dateStamp + '/' + region + '/' + service + '/aws4_request';
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256Hex(canonicalRequest)].join('\n');

  const kDate = hmacSha256('AWS4' + creds.secretAccessKey, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  const kSigning = hmacSha256(kService, 'aws4_request');
  const signature = hmacSha256(kSigning, stringToSign).toString('hex');
  const authorization = 'AWS4-HMAC-SHA256 Credential=' + creds.accessKeyId + '/' + scope +
    ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;

  return {
    host,
    headers: {
      'Content-Type': 'application/x-amz-json-1.1',
      'X-Amz-Date': amzDate,
      'X-Amz-Target': target,
      'X-Amz-Content-Sha256': payloadHash,
      'Authorization': authorization
    },
    body
  };
}

/* 仅允许本机回环来源（防止端口转发后外部滥用代理与配置接口） */
function isLoopback(addr) {
  if (!addr) return false;
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

/* 容器/路由器部署时可用 ALLOW_LAN=1 放开局域网访问（默认保持仅本机） */
function isAllowedHost(addr) {
  if (process.env.ALLOW_LAN === '1') return true;
  return isLoopback(addr);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/plain; charset=utf-8'
};

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

/* 兼容带 BOM 的请求体（某些工具会写 UTF-8 BOM） */
function parseJsonBody(raw) {
  try { return JSON.parse(raw); } catch (e) {
    try { return JSON.parse(String(raw).replace(/^\uFEFF/, '')); } catch (e2) { return null; }
  }
}

const server = http.createServer((req, res) => {
  // 同源访问（页面与 API 都由本服务提供）；不使用 CORS 通配，配合 HttpOnly Cookie 鉴权
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const urlPath0 = req.url.split('?')[0];

  // ---- 版本号 ----
  if (req.method === 'GET' && urlPath0 === '/api/version') {
    return sendJson(res, 200, { version: APP_VERSION });
  }

  // ---- 账号：注册（已关闭，使用内置默认账号 admin）----
  if (req.method === 'POST' && urlPath0 === '/api/auth/register') {
    return sendJson(res, 403, { error: '注册已关闭：首次部署自带默认账号 admin（密码 admin123），请直接登录后在「账号」设置中修改' });
  }

  // ---- 账号：登录 ----
  if (req.method === 'POST' && urlPath0 === '/api/auth/login') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const payload = parseJsonBody(raw);
      if (!payload) return sendJson(res, 400, { error: '请求体不是合法 JSON' });
      const username = String(payload.username || '').trim();
      const password = String(payload.password || '');
      const users = loadUsers();
      const u = users[username];
      // ---- 暴力破解防护（IP 维度 + 账号维度）----
      const bfIp = bfCheckMap(bfIps, bfClientIp(req));
      if (bfIp.locked) {
        opLog(username, '登录被拒绝（来源 IP 已锁定，剩余约 ' + bfIp.waitMin + ' 分钟）');
        return sendJson(res, 429, { error: '该来源 IP 因登录失败次数过多已临时锁定，请约 ' + bfIp.waitMin + ' 分钟后重试' });
      }
      const bfUser = bfCheckMap(bfUsers, username);
      if (bfUser.locked) {
        opLog(username, '登录被拒绝（账号已锁定，剩余约 ' + bfUser.waitMin + ' 分钟）');
        return sendJson(res, 429, { error: '该账号因密码错误次数过多已临时锁定，请约 ' + bfUser.waitMin + ' 分钟后重试' });
      }
      if (!u || !verifyPassword(password, u.salt, u.hash)) {
        bfFailMap(bfUsers, username, BF_ACCOUNT_LIMIT);
        bfFailMap(bfIps, bfClientIp(req), BF_IP_LIMIT);
        return sendJson(res, 401, { error: '账号或密码不正确' });
      }
      bfResetMap(bfUsers, username);
      bfResetMap(bfIps, bfClientIp(req));
      // ---- 二次登录验证码（2FA）：已开启则先发码，验证通过后才建立会话 ----
      if (tgNotify.load(username).otp_enabled) {
        const otp = issueOtp(username);
        const sent = tgNotify.notify(username,
          '🔐 登录面板需二次验证\n账号：' + username + '\n验证码：' + otp.code + '\n（2 分钟内有效；如非本人操作请忽略并尽快修改密码）',
          null, true);
        if (!sent) {
          return sendJson(res, 400, { error: '已开启二次验证码，但电报机器人未配置完整，无法发送验证码，请先在电报机器人设置中检查' });
        }
        opLog(username, '登录（等待二次验证码）');
        return sendJson(res, 200, { ok: true, otp_required: true, user: username, message: '验证码已发送到您的电报，请查收（2 分钟内有效）' });
      }
      const token = createSession(username);
      setSessionCookie(res, token);
      opLog(username, '登录');
      const loginIp = String(payload.clientIp || '').trim() || getClientIp(req);
      tgNotify.notify(username,
        '🔐 面板登录提醒\n账号：' + username + '\n来源 IP：' + loginIp + '\n设备：' + String(req.headers['user-agent'] || '').slice(0, 80) + '\n时间：' + tgNotify.fmtNow() + '\n\n⚠️ 如非本人操作，请立即修改密码并检查端口转发！',
        null, true);
      return sendJson(res, 200, { ok: true, user: username });
    });
    return;
  }

  // ---- 账号：退出 ----
  if (req.method === 'POST' && urlPath0 === '/api/auth/logout') {
    const m = /(?:^|;\s*)session=([^;]+)/.exec(req.headers.cookie || '');
    let logoutUser = '';
    if (m) {
      const sessions = loadSessions();
      if (sessions[m[1]]) logoutUser = sessions[m[1]].user;
      destroySession(m[1]);
    }
    opLog(logoutUser, '退出登录');
    clearSessionCookie(res);
    return sendJson(res, 200, { ok: true });
  }

  // ---- 账号：二次验证码校验（2FA 第二步）----
  if (req.method === 'POST' && urlPath0 === '/api/auth/verify-otp') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const payload = parseJsonBody(raw);
      if (!payload) return sendJson(res, 400, { error: '请求体不是合法 JSON' });
      const username = String(payload.username || '').trim();
      const users = loadUsers();
      if (!users[username]) return sendJson(res, 401, { error: '账号不存在' });
      const bfIp2 = bfCheckMap(bfIps, bfClientIp(req));
      if (bfIp2.locked) {
        return sendJson(res, 429, { error: '该来源 IP 因登录失败次数过多已临时锁定，请约 ' + bfIp2.waitMin + ' 分钟后重试' });
      }
      const bfUser2 = bfCheckMap(bfUsers, username);
      if (bfUser2.locked) {
        return sendJson(res, 429, { error: '该账号因密码错误次数过多已临时锁定，请约 ' + bfUser2.waitMin + ' 分钟后重试' });
      }
      const r = checkOtp(username, String(payload.code || ''));
      if (!r.ok) { bfFailMap(bfUsers, username, BF_ACCOUNT_LIMIT); return sendJson(res, 401, { error: r.error }); }
      bfResetMap(bfUsers, username);
      bfResetMap(bfIps, bfClientIp(req));
      const token = createSession(username);
      setSessionCookie(res, token);
      opLog(username, '登录（二次验证通过）');
      const loginIp = String(payload.clientIp || '').trim() || getClientIp(req);
      tgNotify.notify(username,
        '✅ 二次验证通过，登录成功\n账号：' + username + '\n来源 IP：' + loginIp + '\n设备：' + String(req.headers['user-agent'] || '').slice(0, 80) + '\n时间：' + tgNotify.fmtNow() + '\n\n⚠️ 如非本人操作，请立即修改密码！',
        null, true);
      return sendJson(res, 200, { ok: true, user: username });
    });
    return;
  }

  // ---- 账号：当前登录用户 ----
  if (req.method === 'GET' && urlPath0 === '/api/auth/me') {
    const user = getUserFromReq(req);
    if (!user) return sendJson(res, 401, { error: '未登录' });
    return sendJson(res, 200, { user });
  }

  // ---- 其余 /api/* 均需登录 ----
  const isApi = urlPath0.startsWith('/api/');
  if (isApi) {
    if (!isAllowedHost(req.socket.remoteAddress)) return sendJson(res, 403, { error: '仅允许本机访问' });
    const user = getUserFromReq(req);
    if (!user) return sendJson(res, 401, { error: '未登录，请先登录账号' });
    req.user = user;
  }

  // ---- 账号：修改账号名 / 密码（登录后）----
  if (req.method === 'POST' && urlPath0 === '/api/auth/change') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const payload = parseJsonBody(raw);
      if (!payload) return sendJson(res, 400, { error: '请求体不是合法 JSON' });
      const oldUser = req.user;
      if (!oldUser) return sendJson(res, 401, { error: '未登录' });
      const users = loadUsers();
      if (!users[oldUser]) return sendJson(res, 401, { error: '当前账号不存在' });
      const newName = payload.username !== undefined ? String(payload.username).trim() : '';
      const newPass = payload.password !== undefined ? String(payload.password) : '';
      if (!newName && !newPass) return sendJson(res, 400, { error: '请填写要修改的账号名或密码（留空表示不变）' });
      let target = oldUser;
      if (newName && newName !== oldUser) {
        if (!isValidUsername(newName)) return sendJson(res, 400, { error: '账号需为 3-32 位字母、数字、下划线或中划线' });
        if (users[newName]) return sendJson(res, 409, { error: '该账号名已被使用' });
        if (fs.existsSync(userDir(newName))) return sendJson(res, 409, { error: '目标账号数据目录已存在，无法改名' });
        target = newName;
      }
      try {
        const base = Object.assign({}, users[oldUser]);
        if (newPass) {
          if (String(newPass).length < 6) return sendJson(res, 400, { error: '密码至少 6 位' });
          const salt = crypto.randomBytes(16).toString('hex');
          base.salt = salt;
          base.hash = hashPassword(newPass, salt);
        }
        base.updated = Date.now();
        users[target] = base;
        if (target !== oldUser) {
          delete users[oldUser];
          const oldDir = userDir(oldUser);
          const newDir = userDir(target);
          if (fs.existsSync(oldDir)) {
            fs.mkdirSync(path.dirname(newDir), { recursive: true });
            fs.renameSync(oldDir, newDir);
          }
          const sessions = loadSessions();
          let changed = false;
          for (const k of Object.keys(sessions)) {
            if (sessions[k].user === oldUser) { sessions[k].user = target; changed = true; }
          }
          if (changed) saveSessions(sessions);
        }
        saveUsers(users);
        opLog(oldUser, '修改账号/密码 → ' + target + (newName ? '' : '（仅改密码）'));
        return sendJson(res, 200, { ok: true, user: target, message: '修改成功' + (target !== oldUser ? '，账号名已更新' : '') });
      } catch (e) {
        return sendJson(res, 500, { error: '修改失败：' + e.message });
      }
    });
    return;
  }

  // ---- 操作日志 ----
  if (req.method === 'GET' && urlPath0 === '/api/telegram') {
    const tc = tgNotify.load(req.user);
    return sendJson(res, 200, {
      enabled: tc.enabled,
      bot_token_tail: tgNotify.safeTail(tc.bot_token),
      chat_id: tc.chat_id,
      api_base: tc.api_base,
      otp_enabled: !!tc.otp_enabled,
      configured: !!(tc.bot_token && tc.chat_id),
    });
  }

  if (req.method === 'POST' && urlPath0 === '/api/telegram') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const payload = parseJsonBody(raw);
      if (!payload) return sendJson(res, 400, { error: '请求体不是合法 JSON' });
      if (payload.otp_enabled) {
        const _tc = tgNotify.load(req.user);
        if (!(_tc.bot_token && _tc.chat_id)) {
          return sendJson(res, 400, { error: '开启二次登录验证码需要先配置电报机器人的 Token 和 Chat ID' });
        }
      }
      try {
        tgNotify.save(req.user, payload);
      } catch (e) {
        return sendJson(res, 400, { error: e.message });
      }
      opLog(req.user, '保存电报通知配置' + (payload.otp_enabled ? '（二次登录验证码已开启）' : ''));
      if (payload.test) {
        tgNotify.notify(req.user,
          '✅ 电报通知测试成功\n账号：' + req.user + '\n时间：' + tgNotify.fmtNow() + '\n\n今后实例操作与面板登录提醒都会发送到这里。',
          (err, code, body) => {
            if (err) return sendJson(res, 200, { ok: true, saved: true, test: false, message: '已保存，但测试消息发送失败：' + err.message + '（请检查 Token / Chat ID / 网络能否访问 Telegram）' });
            if (code !== 200) return sendJson(res, 200, { ok: true, saved: true, test: false, message: '已保存，但 Telegram 拒绝了测试消息（HTTP ' + code + '）：' + String(body || '').slice(0, 220) });
            return sendJson(res, 200, { ok: true, saved: true, test: true, message: '已保存，测试消息发送成功 ✓' });
          }, true);
        return;
      }
      return sendJson(res, 200, { ok: true, saved: true, message: '电报通知配置已保存' });
    });
    return;
  }

  // ---- 数据备份：仅导出当前账号自己的配置（AWS 光帆 / 甲骨文 / 电报）----
  if (req.method === 'GET' && urlPath0 === '/api/backup') {
    const users = loadUsers();
    const u = req.user;
    const dir = userDir(u);
    const acc = {};
    const awsFile = path.join(dir, 'aws-credentials.json');
    const ociFile = path.join(dir, 'oci-credentials.json');
    const tgFile = path.join(dir, 'telegram.json');
    if (fs.existsSync(awsFile)) { try { acc.aws = readJsonFile(awsFile, null); } catch (e) { acc.aws = null; } }
    if (fs.existsSync(ociFile)) { try { acc.oci = readJsonFile(ociFile, null); } catch (e) { acc.oci = null; } }
    if (fs.existsSync(tgFile)) { try { acc.telegram = readJsonFile(tgFile, null); } catch (e) { acc.telegram = null; } }
    opLog(req.user, '导出数据备份（当前账号）');
    return sendJson(res, 200, {
      app: 'cloud-console',
      version: 1,
      exportedAt: new Date().toISOString(),
      user: u,
      users: users[u] ? { [u]: users[u] } : {},
      accounts: { [u]: acc }
    });
  }

  // ---- 数据恢复：仅恢复当前账号自己的配置，校验备份归属 ----
  if (req.method === 'POST' && urlPath0 === '/api/backup/restore') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      let body = null;
      try { body = JSON.parse(raw); } catch (e) { body = null; }
      if (!body || body.app !== 'cloud-console' || !body.accounts || typeof body.accounts !== 'object') {
        return sendJson(res, 400, { error: '不是有效的云服务器控制台备份文件（缺少 app / accounts 字段）' });
      }
      const u = req.user;
      if (body.user && body.user !== u) {
        return sendJson(res, 403, { error: '该备份属于账号「' + body.user + '」，当前登录的是「' + u + '」，不能导入' });
      }
      const acc = body.accounts[u];
      if (!acc) {
        return sendJson(res, 403, { error: '该备份中不包含当前账号「' + u + '」的配置，不能导入' });
      }
      try {
        const dir = userDir(u);
        fs.mkdirSync(dir, { recursive: true });
        let n = 0;
        if (acc.aws != null) { writeJsonFile(path.join(dir, 'aws-credentials.json'), acc.aws); n++; }
        if (acc.oci != null) { writeJsonFile(path.join(dir, 'oci-credentials.json'), acc.oci); n++; }
        if (acc.telegram != null) { writeJsonFile(path.join(dir, 'telegram.json'), acc.telegram); n++; }
        opLog(req.user, '恢复数据备份（当前账号）：' + n + ' 组配置');
        return sendJson(res, 200, { ok: true, message: '恢复成功：当前账号 ' + n + ' 组配置（AWS/甲骨文/电报）' });
      } catch (e) {
        return sendJson(res, 500, { error: '恢复失败：' + e.message });
      }
    });
    return;
  }

  if (req.method === 'GET' && urlPath0 === '/api/logs') {
    return sendJson(res, 200, { logs: opLogs.slice(-OP_LOG_MAX) });
  }

  // ---- 查询账号凭证状态（凭证组列表，不回显密钥）----
  if (req.method === 'GET' && urlPath0 === '/api/config') {
    const info = listCredentials(req.user);
    if (info.accounts.length) {
      const cur = loadCredentials(req.user) || {};
      return sendJson(res, 200, { configured: true, active: info.active, accounts: info.accounts, accessKeyIdTail: cur.accessKeyId ? String(cur.accessKeyId).slice(-4) : '', region: cur.region || '' });
    }
    return sendJson(res, 200, { configured: false, active: '', accounts: [] });
  }

  // ---- 保存 / 删除 / 切换凭证组 ----
  if (req.method === 'POST' && urlPath0 === '/api/config') {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const payload = parseJsonBody(raw);
      if (!payload) return sendJson(res, 400, { error: '请求体不是合法 JSON' });
      if (payload.clear) {
        clearCredentials(req.user);
        opLog(req.user, '清除全部 AWS 凭证');
        return sendJson(res, 200, { ok: true });
      }
      if (payload.action === 'set-active') {
        try {
          const name = String(payload.name || '').trim();
          setActiveCredential(req.user, name);
          opLog(req.user, '切换 AWS 当前凭证 → ' + name);
          return sendJson(res, 200, { ok: true, active: name });
        } catch (e) { return sendJson(res, 400, { error: e.message }); }
      }
      if (payload.action === 'delete') {
        const delName = String(payload.name || '').trim();
        deleteCredential(req.user, delName);
        opLog(req.user, '删除 AWS 凭证：' + delName);
        return sendJson(res, 200, { ok: true });
      }
      if (payload.action === 'save') {
        const name = String(payload.name || '').trim();
        if (!name) return sendJson(res, 400, { error: '凭证组名称不能为空' });
        const store = loadCredStore(req.user) || { active: '', accounts: {} };
        const isNew = !store.accounts[name];
        const prev = store.accounts[name] || {};
        const ak = payload.accessKeyId !== undefined && String(payload.accessKeyId).trim() ? String(payload.accessKeyId).trim() : (prev.accessKeyId || '');
        const sk = payload.secretAccessKey !== undefined && String(payload.secretAccessKey).trim() ? String(payload.secretAccessKey).trim() : (prev.secretAccessKey || '');
        const region = payload.region !== undefined && String(payload.region).trim() ? String(payload.region).trim() : (prev.region || '');
        if (isNew && (!ak || !sk)) return sendJson(res, 400, { error: '新凭证组必须填写 Access Key 和 Secret Key' });
        if (ak && !/^[A-Z0-9]{16,32}$/i.test(ak)) return sendJson(res, 400, { error: 'Access Key ID 格式不正确' });
        if (region && !/^[a-z]{2}(-[a-z]+)+-\d+$/.test(region)) return sendJson(res, 400, { error: '区域格式不正确' });
        saveCredential(req.user, { name, accessKeyId: ak, secretAccessKey: sk, region, makeActive: payload.makeActive !== false });
        opLog(req.user, (isNew ? '新建 AWS 凭证：' : '更新 AWS 凭证：') + name + (region ? '（' + region + '）' : ''));
        return sendJson(res, 200, { ok: true, active: name, accessKeyIdTail: ak ? ak.slice(-4) : (prev.accessKeyId ? String(prev.accessKeyId).slice(-4) : ''), region });
      }
      const ak = String(payload.accessKeyId || '').trim();
      const sk = String(payload.secretAccessKey || '').trim();
      const region = String(payload.region || '').trim();
      if (!ak || !sk) return sendJson(res, 400, { error: 'Access Key / Secret Key 不能为空' });
      if (!/^[A-Z0-9]{16,32}$/i.test(ak)) return sendJson(res, 400, { error: 'Access Key ID 格式不正确' });
      if (region && !/^[a-z]{2}(-[a-z]+)+-\d+$/.test(region)) return sendJson(res, 400, { error: '区域格式不正确' });
      let name;
      try {
        // 兼容旧前端（无 action）：保存到当前生效组
        const cur = loadCredentials(req.user);
        name = cur && cur.name ? cur.name : 'default';
        saveCredential(req.user, { name, accessKeyId: ak, secretAccessKey: sk, region, makeActive: true });
        return sendJson(res, 200, { ok: true, active: name, accessKeyIdTail: ak.slice(-4), region });
      } catch (e) { return sendJson(res, 400, { error: e.message }); }
    });
    return;
  }

  // ---- 转发代理（服务端签名，使用当前账号的凭证）----
  if (req.method === 'POST' && req.url.split('?')[0] === '/api/proxy') {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 4 * 1024 * 1024) req.destroy();
    });
    req.on('end', () => {
      const payload = parseJsonBody(raw);
      if (!payload) {
        return sendJson(res, 400, { error: '请求体不是合法 JSON' });
      }
      if (!payload.action) {
        return sendJson(res, 400, { error: '前端版本过旧，请按 Ctrl+F5 强制刷新浏览器后重试' });
      }
      const creds = payload.group ? loadCredentialsForGroup(req.user, String(payload.group)) : loadCredentials(req.user);
      if (!creds) {
        return sendJson(res, 409, { error: '尚未配置 AWS 凭证：请先在「设置」页填写并保存' });
      }
      const region = payload.region || creds.region || '';
      if (!region) {
        return sendJson(res, 400, { error: '缺少区域参数，请按 Ctrl+F5 强制刷新页面后重试' });
      }
      if (!/^[a-z]{2}(-[a-z]+)+-\d+$/.test(region)) {
        return sendJson(res, 400, { error: '区域格式不正确' });
      }
      opLog(req.user, 'AWS ' + payload.action + ' region=' + region + ' 账号=' + (payload.group || creds.name));
      let signed;
      try {
        signed = signAwsJson(payload.action, payload.params || {}, creds, region);
      } catch (e) {
        return sendJson(res, 500, { error: '签名失败：' + e.message });
      }

      const upstream = https.request({
        hostname: signed.host,
        port: 443,
        path: '/',
        method: 'POST',
        headers: signed.headers
      }, (upRes) => {
        let data = '';
        upRes.on('data', (chunk) => { data += chunk; });
        upRes.on('end', () => {
          if (NOTIFY_AWS_ACTIONS[payload.action] && (upRes.statusCode || 500) === 200) {
            const inst = (payload.params && payload.params.instanceName) || '';
            tgNotify.notify(req.user,
              '🖥️ AWS 光帆 · ' + NOTIFY_AWS_ACTIONS[payload.action] + '通知\n账号：' + (payload.group || creds.name) + '\n区域：' + region + '\n实例：' + inst + '\n结果：成功\n时间：' + tgNotify.fmtNow());
          }
          sendJson(res, 200, {
            status: upRes.statusCode || 500,
            headers: upRes.headers,
            body: data
          });
        });
      });

      upstream.setTimeout(30000, () => {
        upstream.destroy();
        sendJson(res, 504, { error: 'AWS 请求超时（30 秒）' });
      });
      upstream.on('error', (e) => {
        sendJson(res, 502, { error: '无法连接 AWS：' + e.message });
      });
      upstream.write(signed.body);
      upstream.end();
    });
    return;
  }

  // ---- 静态文件 ----
  let urlPath;
  try {
    urlPath = decodeURIComponent(req.url.split('?')[0]);
  } catch (e) {
    urlPath = '/';
  }

  // ---- OCI 面板 API（甲骨文，纯 Node 实现；使用当前账号的凭证文件）----
  if (urlPath.startsWith('/api/oci')) {
    ociBackend.setCredsFile(userOciFile(req.user));
    opLog(req.user, 'OCI ' + req.method + ' ' + urlPath);
    return ociBackend.handle(req, res, urlPath, req.method, sendJson, isAllowedHost);
  }

  let filePath = urlPath === '/' ? path.join(ROOT, 'index.html') : path.join(ROOT, urlPath);
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }
  fs.stat(filePath, (err, stat) => {
    if (!err && stat.isDirectory()) filePath = path.join(filePath, 'index.html');
    fs.readFile(filePath, (readErr, buf) => {
      if (readErr) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('404 Not Found');
        return;
      }
      const ext = path.extname(filePath).toLowerCase();
      const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream' };
      // 页面不缓存，避免浏览器加载到旧版前端（凭证处理逻辑变更时尤为重要）
      if (ext === '.html') headers['Cache-Control'] = 'no-cache, no-store, must-revalidate';
      res.writeHead(200, headers);
      res.end(buf);
    });
  });
});

server.listen(PORT, () => {
  console.log('');
  console.log('  云服务器控制台（AWS 光帆 + 甲骨文 OCI）已启动');
  console.log('  请在浏览器打开: http://localhost:' + PORT);
  ensureDefaultAdmin();
  const userCount = Object.keys(loadUsers()).length;
  console.log('  账号系统：' + (userCount ? '已注册 ' + userCount + ' 个账号，打开页面用账号登录' : '无账号'));
  console.log('  凭证目录：' + DATA_DIR);
  console.log('  接口限制：/api 需登录；仅允许本机/局域网访问（防端口转发滥用）');
  if (WebSocketServer && SSHClient) {
    console.log('  在线 SSH：已启用');
  } else {
    console.log('  在线 SSH：未启用（缺少 ssh2/ws 依赖，请保留 node_modules 目录）');
  }
  console.log('  （Ctrl+C 停止）');
  console.log('');
});

/* ============================================================
   在线 SSH —— WebSocket 终端通道（仅本机访问）
   ============================================================ */
// 兜底：任何未捕获异常只记录、不退出，避免面板服务整体挂掉
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err && err.stack ? err.stack : String(err));
});

/**
 * 清洗私钥字符串，修复常见传输损坏：
 *  - 首尾空白 / BOM
 *  - 字面 "\n"（双重转义）还原为真实换行
 *  - CRLF 统一为 LF（ssh2 两种都支持，统一更稳）
 */
function sanitizePrivateKey(key) {
  if (!key) return key;
  let k = String(key);
  if (k.includes('\\n')) k = k.replace(/\\n/g, '\n');
  k = k.replace(/^\uFEFF/, '');
  k = k.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return k.trim();
}

/**
 * 私钥类型映射：无论头部怎么粘连/缺空格，都归一为标准 PEM 类型名
 */
const PRIVATE_KEY_TYPES = {
  'OPENSSHPRIVATEKEY': 'OPENSSH PRIVATE KEY',
  'RSAPRIVATEKEY': 'RSA PRIVATE KEY',
  'PRIVATEKEY': 'PRIVATE KEY',
  'ECPRIVATEKEY': 'EC PRIVATE KEY',
  'DSAPRIVATEKEY': 'DSA PRIVATE KEY',
  'ENCRYPTEDPRIVATEKEY': 'ENCRYPTED PRIVATE KEY'
};

/**
 * 重建私钥为标准 PEM 格式：提取 BEGIN/END 之间的 base64，
 * 去掉所有空白（含被破坏的换行），再按 64 字符一行重新排版。
 * 用于修复私钥在 JSON 传输中换行丢失/被空格替换导致的解析失败。
 * 无法识别时返回 null（交给 ssh2 原样尝试）。
 */
function rebuildPrivateKey(key) {
  const s = String(key).trim();
  const m = s.match(/-----BEGIN\s*([A-Za-z0-9 ]+?)-----/);
  if (!m) return null;
  const type = PRIVATE_KEY_TYPES[m[1].replace(/\s+/g, '').toUpperCase()];
  if (!type) return null;
  const b64m = s.match(/-----BEGIN[^-]+-----([\s\S]*?)-----END/);
  if (!b64m) return null;
  const b64 = b64m[1].replace(/\s+/g, '');
  if (!b64) return null;
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${type}-----\n` + lines.join('\n') + '\n-----END ' + type + '-----';
}

function normalizePrivateKey(key) {
  const cleaned = sanitizePrivateKey(key);
  if (!cleaned) return cleaned;
  const rebuilt = rebuildPrivateKey(cleaned);
  const candidate = rebuilt || cleaned;
  // AWS Lightsail 的 ED25519 新实例私钥是 PKCS#8（-----BEGIN PRIVATE KEY-----），
  // ssh2 1.17 无法直接解析该格式，需要转成 ssh2 认识的老格式。
  if (/^-----BEGIN PRIVATE KEY-----/.test(candidate)) {
    const converted = convertPkcs8ToSsh2Friendly(candidate);
    if (converted) return converted;
  }
  return candidate;
}

function be32(n) { const b = Buffer.alloc(4); b.writeUInt32BE(n >>> 0); return b; }
function sshString(buf) { return Buffer.concat([be32(buf.length), buf]); }

/**
 * 将 PKCS#8 格式私钥（-----BEGIN PRIVATE KEY-----）转换为 ssh2 1.17 能解析的格式：
 *  - Ed25519 -> OpenSSH（openssh-key-v1，手工构造，ssh2 不支持 PKCS#8 的 Ed25519）
 *  - RSA     -> PKCS#1（-----BEGIN RSA PRIVATE KEY-----）
 *  - EC      -> SEC1 （-----BEGIN EC PRIVATE KEY-----）
 * 解析失败或未知类型返回 null（交给 ssh2 原样尝试）。
 */
function convertPkcs8ToSsh2Friendly(pem) {
  try {
    const pk = crypto.createPrivateKey({ key: pem, format: 'pem' });
    const jwk = pk.export({ format: 'jwk' });
    if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
      const pubBytes = Buffer.from(jwk.x, 'base64url');
      const seed = Buffer.from(jwk.d, 'base64url');
      if (pubBytes.length !== 32 || seed.length !== 32) return null;
      const type = Buffer.from('ssh-ed25519');
      const pubBlob = Buffer.concat([sshString(type), sshString(pubBytes)]);
      const checkint = crypto.randomBytes(4);
      const privBlobOuter = Buffer.concat([
        checkint,
        checkint,
        sshString(type),
        sshString(pubBytes),
        sshString(Buffer.concat([seed, pubBytes])),
        sshString(Buffer.alloc(0)),
        Buffer.from([1])
      ]);
      const opensshBlob = Buffer.concat([
        Buffer.from('openssh-key-v1\0'),
        sshString(Buffer.from('none')),
        sshString(Buffer.from('none')),
        sshString(Buffer.alloc(0)),
        be32(1),
        sshString(pubBlob),
        sshString(privBlobOuter)
      ]);
      const b64 = opensshBlob.toString('base64').match(/.{1,64}/g).join('\n');
      return `-----BEGIN OPENSSH PRIVATE KEY-----\n${b64}\n-----END OPENSSH PRIVATE KEY-----`;
    }
    if (jwk.kty === 'RSA') {
      const rsaPem = crypto.createPrivateKey({ key: pem, format: 'pem' }).export({ type: 'pkcs1', format: 'pem' });
      return String(rsaPem).trim();
    }
    if (jwk.kty === 'EC') {
      const ecPem = crypto.createPrivateKey({ key: pem, format: 'pem' }).export({ type: 'sec1', format: 'pem' });
      return String(ecPem).trim();
    }
    return null;
  } catch (e) {
    return null;
  }
}

/* ============================================================
   在线 SSH：系统 OpenSSH 客户端通道（支持 AWS 证书认证 certKey）
   Lightsail 的浏览器 SSH 使用 SSH 证书机制：GetInstanceAccessDetails
   返回的 privateKey 必须配合 certKey（AWS CA 短期签发的证书）一起使用，
   ssh2 库不支持证书认证，因此改用系统自带的 OpenSSH 客户端（Win10 内置）。
   ============================================================ */
function findSshExe() {
  const candidates = [
    process.env.SSH_PATH,
    'C:\\Windows\\System32\\OpenSSH\\ssh.exe',
    'C:\\Program Files\\Git\\usr\\bin\\ssh.exe',
    '/usr/bin/ssh',
    '/usr/local/bin/ssh'
  ].filter(Boolean);
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return p; } catch (e) { /* noop */ }
  }
  return 'ssh';
}

function startSshViaExe({ host, port, username, privateKey, certKey, cols, rows }, send) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ls-ssh-'));
  const keyFile = path.join(tmpDir, 'id');
  const certFile = path.join(tmpDir, 'id-cert.pub');
  const knownHosts = path.join(tmpDir, 'known_hosts');
  fs.writeFileSync(keyFile, privateKey + '\n');
  try { fs.chmodSync(keyFile, 0o600); } catch (e) { /* Windows 不支持权限位时忽略 */ }
  fs.writeFileSync(certFile, certKey + '\n');
  try { fs.chmodSync(certFile, 0o600); } catch (e) { /* noop */ }
  fs.writeFileSync(knownHosts, '');

  const sshPath = findSshExe();
  const args = [
    '-tt',
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=' + knownHosts,
    '-o', 'LogLevel=ERROR',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=3',
    '-i', keyFile,
    '-o', 'CertificateFile=' + certFile,
    '-p', String(port || 22),
    '-l', username,
    host
  ];
  let proc = null;
  try {
    proc = spawn(sshPath, args, { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e2) { /* noop */ }
    send({ type: 'error', message: '无法启动系统 SSH 客户端：' + e.message });
    return null;
  }

  let stderrBuf = '';
  let readySent = false;
  let exited = false;
  const cleanupTmp = () => { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { /* noop */ } };
  const markReady = () => {
    if (!readySent) { readySent = true; send({ type: 'connected' }); send({ type: 'shell-ready' }); }
  };
  proc.stdout.on('data', (d) => { markReady(); send({ type: 'data', data: d.toString('utf8') }); });
  proc.stderr.on('data', (d) => { stderrBuf += d.toString('utf8'); });
  const timer = setTimeout(() => markReady(), 2000);
  proc.on('error', (err) => {
    clearTimeout(timer); cleanupTmp(); exited = true;
    send({ type: 'error', message: '无法启动系统 SSH 客户端：' + err.message });
  });
  proc.on('close', (code) => {
    clearTimeout(timer); cleanupTmp();
    if (exited) return;
    exited = true;
    const stderr = stderrBuf.trim();
    if (code !== 0 || !readySent) {
      let msg = 'SSH 连接失败（exit ' + code + '）';
      if (/Permission denied/i.test(stderr)) msg = 'SSH 认证失败：用户名或证书不被服务器接受（Permission denied）';
      else if (/Could not resolve hostname/i.test(stderr)) msg = '无法解析主机名（Could not resolve hostname）';
      else if (/timed out|Operation timed out/i.test(stderr)) msg = '连接超时，请检查实例公网 IP 是否可达、22 端口是否在防火墙放行';
      else if (/Connection refused/i.test(stderr)) msg = '连接被拒绝（Connection refused），请确认实例已开机且 22 端口已开放';
      else if (stderr) msg += '：' + stderr.split('\n')[0];
      send({ type: 'error', message: msg });
    } else {
      send({ type: 'exit' });
    }
  });

  return {
    write(d) { try { proc.stdin.write(d); } catch (e) { /* noop */ } },
    resize(c, r) {
      try { proc.stdin.write('stty rows ' + r + ' cols ' + c + '\n'); } catch (e) { /* noop */ }
    },
    close() {
      try { proc.stdin.end(); } catch (e) { /* noop */ }
      try { proc.kill(); } catch (e) { /* noop */ }
    }
  };
}

if (WebSocketServer && SSHClient) {
  const wss = new WebSocketServer.Server({ noServer: true });

  // 在线 SSH 通道同样要求登录：upgrade 时校验会话 Cookie，未登录直接拒绝
  server.on('upgrade', (req, socket, head) => {
    const p = (req.url || '').split('?')[0];
    if (p !== '/ws') { socket.destroy(); return; }
    if (!isAllowedHost(req.socket ? req.socket.remoteAddress : req.connection.remoteAddress)) {
      socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      socket.destroy();
      return;
    }
    if (!getUserFromReq(req)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  });

  wss.on('connection', (socket) => {
    let conn = null;
    let stream = null;
    let sshProc = null;
    let closed = false;

    const cleanup = () => {
      if (sshProc) { try { sshProc.close(); } catch (e) { /* noop */ } sshProc = null; }
      if (stream) { try { stream.end(); } catch (e) { /* noop */ } stream = null; }
      if (conn) { try { conn.end(); } catch (e) { /* noop */ } conn = null; }
    };
    const send = (obj) => {
      if (socket.readyState === WebSocketServer.OPEN) {
        socket.send(JSON.stringify(obj));
      }
    };

    socket.on('message', (raw) => {
      let msg;
      try { msg = JSON.parse(raw); } catch (e) { return; }

      if (msg.type === 'connect') {
        if (conn || sshProc) return;
        const { host, port, username, privateKey: rawKey, certKey: rawCert, term, cols, rows } = msg;
        const privateKey = normalizePrivateKey(rawKey);
        if (!host || !username || !privateKey) {
          return send({ type: 'error', message: '缺少连接参数（host/username/privateKey）' });
        }
        // AWS Lightsail 返回 certKey 时走系统 OpenSSH 客户端（支持 SSH 证书认证，
        // 与光帆控制台同机制）；没有 certKey 才退回 ssh2 普通密钥认证。
        if (rawCert) {
          sshProc = startSshViaExe({
            host,
            port: port || 22,
            username,
            privateKey,
            certKey: String(rawCert).trim(),
            cols: cols || 80,
            rows: rows || 24
          }, send);
          if (sshProc) return;
        }
        conn = new SSHClient();
        conn.on('ready', () => {
          send({ type: 'connected' });
          conn.shell({ term: term || 'xterm-256color', cols: cols || 80, rows: rows || 24 }, (err, str) => {
            if (err) return send({ type: 'error', message: '启动 shell 失败：' + err.message });
            stream = str;
            stream.on('data', (d) => {
              if (socket.readyState === WebSocketServer.OPEN) {
                socket.send(JSON.stringify({ type: 'data', data: d.toString('utf8') }));
              }
            });
            stream.on('close', () => {
              if (!closed) { closed = true; send({ type: 'exit' }); }
              cleanup();
            });
            stream.on('error', () => { /* 由 close 处理 */ });
            send({ type: 'shell-ready' });
          });
        });
        conn.on('error', (err) => {
          if (!closed) { closed = true; send({ type: 'error', message: 'SSH 连接失败：' + err.message }); }
          cleanup();
        });
        conn.on('close', () => {
          if (!closed) { closed = true; send({ type: 'exit' }); }
          cleanup();
        });
        try {
          conn.connect({
            host,
            port: port || 22,
            username,
            privateKey,
            readyTimeout: 20000,
            keepaliveInterval: 15000
          });
        } catch (err) {
          if (!closed) { closed = true; send({ type: 'error', message: 'SSH 参数无效：' + err.message }); }
          cleanup();
        }
      } else if (msg.type === 'data') {
        if (sshProc) sshProc.write(msg.data);
        else if (stream) stream.write(msg.data);
      } else if (msg.type === 'resize') {
        if (sshProc) sshProc.resize(msg.cols, msg.rows);
        else if (stream && msg.rows && msg.cols) {
          try { stream.setWindow(msg.rows, msg.cols); } catch (e) { /* noop */ }
        }
      } else if (msg.type === 'disconnect') {
        cleanup();
        try { socket.close(); } catch (e) { /* noop */ }
      }
    });

    socket.on('close', () => cleanup());
    socket.on('error', () => cleanup());
  });
}
