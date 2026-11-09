/**
 * Google Cloud（GCP）后端模块 —— 纯 Node 实现，无外部依赖
 *
 * 功能：
 *   - 凭证读写（gcp-credentials.json，支持多凭证组，Service Account JSON）
 *   - Service Account JWT(RS256) → OAuth2 access_token（缓存复用）
 *   - 实例列表（aggregatedList 一次拉取全部区域实例）
 *   - 开机(start) / 停止(stop) / 硬重启(reset)
 *   - 更换外部 IPv4：deleteAccessConfig + addAccessConfig（拿到新的临时 IP，免费）
 *     ★ 关键安全设计：如果旧 IP 是「静态（预留）IP」，deleteAccessConfig 并不会
 *       释放它，它会留在项目地址池里继续按小时计费。因此换 IP 前先检测，
 *       是静态地址就一并 DELETE 释放，确保不产生残留费用。
 *   - 读取 IPv4 / IPv6 地址（ipv6AccessConfigs.externalIpv6）
 *   - 在线 SSH 信息（外部 IPv4 + 用户名 + 用户配置的私钥）
 *
 * 认证说明：GCP 用 Service Account JSON（client_email + private_key）签 JWT，
 *   到 oauth2.googleapis.com 换取 access_token（有效期 1 小时，带缓存）。
 */

'use strict';

const tgNotify = require('./telegram');

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let GCP_CREDS_FILE = process.env.GCP_CREDS_FILE || path.join(__dirname, 'gcp-credentials.json');

/** 切换当前账号的凭证文件路径（由 server.js 在 /api/gcp 请求时调用） */
function setCredsFile(p) {
  if (p) GCP_CREDS_FILE = p;
}

/* ---------------- 凭证读写（支持多凭证组） ----------------
 * 文件格式：{ "active": "组名", "accounts": { "组名": {project_id, service_json, ssh_user, ssh_key} } } */
function loadGcpStore() {
  try {
    const raw = fs.readFileSync(GCP_CREDS_FILE, 'utf8');
    const c = JSON.parse(raw) || {};
    if (c.accounts && typeof c.accounts === 'object') {
      if (!c.active) c.active = Object.keys(c.accounts)[0] || '';
      return c;
    }
    // 兼容旧版单组格式
    if (c.project_id || c.service_json) {
      const n = { active: 'default', accounts: { default: c } };
      try { fs.writeFileSync(GCP_CREDS_FILE, JSON.stringify(n, null, 2), { encoding: 'utf8', mode: 0o600 }); } catch (e) { /* noop */ }
      return n;
    }
    return null;
  } catch (e) {
    return null;
  }
}
function saveGcpStore(store) {
  fs.mkdirSync(path.dirname(GCP_CREDS_FILE), { recursive: true });
  fs.writeFileSync(GCP_CREDS_FILE, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 });
}
/** 按组名取 GCP 配置（实例分组用；组不存在回退 active） */
function loadGcpConfigForGroup(group) {
  const s = loadGcpStore();
  if (!s) return {};
  const keys = Object.keys(s.accounts);
  let name = (group && s.accounts[group]) ? group : s.active;
  if (!name || !s.accounts[name]) name = keys[0];
  if (!name) return {};
  return Object.assign({ name: name }, s.accounts[name] || {});
}
function loadGcpConfig() {
  const s = loadGcpStore();
  if (!s) return {};
  const name = s.active || Object.keys(s.accounts)[0] || '';
  return Object.assign({ name: name }, (s.accounts[name] || {}));
}
function listGcpAccounts() {
  const s = loadGcpStore();
  if (!s) return { active: '', accounts: [] };
  return {
    active: s.active || '',
    accounts: Object.keys(s.accounts).map(function (k) {
      const a = s.accounts[k] || {};
      let pid = a.project_id || '';
      if (!pid && a.service_json) { try { pid = (JSON.parse(a.service_json) || {}).project_id || ''; } catch (e) { /* noop */ } }
      return { name: k, project_id: pid, has_service_json: !!String(a.service_json || '').trim(), has_ssh_key: !!String(a.ssh_key || '').trim(), ssh_user: a.ssh_user || '' };
    })
  };
}
function saveGcpAccount(name, cfg, makeActive) {
  const s = loadGcpStore() || { active: '', accounts: {} };
  s.accounts[name] = cfg;
  if (makeActive || !s.active) s.active = name;
  saveGcpStore(s);
  return s;
}
function setActiveGcpAccount(name) {
  const s = loadGcpStore();
  if (!s || !s.accounts[name]) throw new Error('凭证组不存在：' + name);
  s.active = name;
  saveGcpStore(s);
}
function deleteGcpAccount(name) {
  const s = loadGcpStore();
  if (!s || !s.accounts[name]) return;
  delete s.accounts[name];
  const keys = Object.keys(s.accounts);
  if (s.active === name) s.active = keys[0] || '';
  saveGcpStore(s);
}
function clearGcpCreds() {
  try { fs.unlinkSync(GCP_CREDS_FILE); } catch (e) { /* noop */ }
}

/** 解析 Service Account JSON，校验必需字段 */
function parseServiceAccount(cfg) {
  const raw = String((cfg && cfg.service_json) || '').trim();
  if (!raw) throw new Error('尚未配置 Service Account JSON');
  let sa;
  try { sa = JSON.parse(raw); } catch (e) { throw new Error('Service Account JSON 不是合法 JSON：' + e.message); }
  if (!sa.client_email || !sa.private_key) throw new Error('Service Account JSON 缺少 client_email 或 private_key 字段');
  return sa;
}
/** 项目 ID：优先 cfg.project_id，否则从 Service Account JSON 取 */
function projectId(cfg) {
  if (cfg && cfg.project_id) return String(cfg.project_id).trim();
  const sa = parseServiceAccount(cfg);
  return (sa.project_id || '').trim();
}

/* ---------------- OAuth2：JWT → access_token（缓存） ---------------- */
const tokenCache = Object.create(null); // key = client_email，value = {token, expMs}

function b64url(input) {
  const b = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return b.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function httpPostForm(host, pathName, bodyStr, headers) {
  return new Promise(function (resolve, reject) {
    const req = https.request({
      host: host, port: 443, path: pathName, method: 'POST',
      headers: Object.assign({
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(bodyStr)
      }, headers || {}),
      timeout: 20000
    }, function (res) {
      let buf = '';
      res.on('data', function (d) { buf += d; });
      res.on('end', function () {
        let json = null;
        try { json = buf ? JSON.parse(buf) : null; } catch (e) { /* noop */ }
        if (res.statusCode >= 400) {
          const msg = (json && (json.error_description || (json.error && json.error.message) || json.error)) || ('HTTP ' + res.statusCode);
          return reject(new Error('Google 认证失败（HTTP ' + res.statusCode + '）：' + msg));
        }
        resolve(json || {});
      });
    });
    req.on('timeout', function () { req.destroy(new Error('Google 认证请求超时')); });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

async function getAccessToken(cfg) {
  const sa = parseServiceAccount(cfg);
  const ck = sa.client_email + '|' + (cfg.project_id || sa.project_id || '');
  const hit = tokenCache[ck];
  if (hit && Date.now() < hit.expMs - 5 * 60 * 1000) return hit.token;

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/compute',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };
  const signingInput = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));
  let jwt;
  try {
    const sig = crypto.createSign('RSA-SHA256').update(signingInput).sign(sa.private_key);
    jwt = signingInput + '.' + b64url(sig);
  } catch (e) {
    throw new Error('Service Account 私钥签名失败（请确认 JSON 中 private_key 完整且未加密）：' + e.message);
  }
  const body = 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + encodeURIComponent(jwt);
  const r = await httpPostForm('oauth2.googleapis.com', '/token', body);
  if (!r.access_token) throw new Error('Google 未返回 access_token（请检查 Service Account 是否有效/项目是否启用 Compute API）');
  tokenCache[ck] = { token: r.access_token, expMs: Date.now() + ((Number(r.expires_in) || 3600) * 1000) };
  return r.access_token;
}

/* ---------------- Compute API 请求 ---------------- */
function enc(s) { return encodeURIComponent(String(s)); }

async function gcpRequest(cfg, opts) {
  const token = await getAccessToken(cfg);
  const apiPath = '/compute/v1' + opts.path + (opts.query ? ('?' + opts.query) : '');
  const body = opts.body ? JSON.stringify(opts.body) : null;
  return new Promise(function (resolve, reject) {
    const req = https.request({
      host: 'compute.googleapis.com', port: 443, path: apiPath, method: opts.method || 'GET',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
        'Content-Length': body ? Buffer.byteLength(body) : 0
      },
      timeout: 35000
    }, function (res) {
      let buf = '';
      res.on('data', function (d) { buf += d; });
      res.on('end', function () {
        let json = null;
        try { json = buf ? JSON.parse(buf) : null; } catch (e) { /* noop */ }
        if (res.statusCode >= 400) {
          const gerr = (json && json.error) || {};
          const msg = gerr.message || (json && json.message) || ('HTTP ' + res.statusCode);
          const err = new Error(msg);
          err.statusCode = res.statusCode;
          err.gcode = gerr.code || '';
          err.gstatus = gerr.status || '';
          return reject(err);
        }
        resolve({ statusCode: res.statusCode, json: json || {} });
      });
    });
    req.on('timeout', function () { req.destroy(new Error('Google Compute API 请求超时（35s）')); });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

/* ---------------- 实例 ---------------- */
function simplifyInstance(inst) {
  const zoneFull = String(inst.zone || '');          // projects/x/zones/ap-northeast-2-a
  const zone = zoneFull.split('/').pop();            // ap-northeast-2-a
  const region = zone.split('-').slice(0, -1).join('-'); // ap-northeast-2
  const ni = (inst.networkInterfaces || [])[0] || {};
  let externalIp = '';
  let ipv6 = '';
  for (const ac of (ni.accessConfigs || [])) {
    if (ac && ac.natIP) { externalIp = ac.natIP; break; }
  }
  if (!externalIp && ni.externalIp) externalIp = ni.externalIp;
  for (const a6 of (ni.ipv6AccessConfigs || [])) {
    if (a6 && a6.externalIpv6) { ipv6 = a6.externalIpv6; break; }
  }
  // 有些实例 IPv6 在 networkInterfaces 的 ipv6 字段
  if (!ipv6 && Array.isArray(ni.ipv6Addresses) && ni.ipv6Addresses.length) ipv6 = ni.ipv6Addresses[0];
  return {
    name: inst.name || '',
    id: inst.id || '',
    zone: zone,
    region: region,
    status: inst.status || '?',
    machine_type: String(inst.machineType || '').split('/').pop(),
    external_ip: externalIp,
    internal_ip: ni.networkIP || '',
    ipv6: ipv6,
    creation: inst.creationTimestamp || ''
  };
}

async function listInstances(cfg) {
  const pid = projectId(cfg);
  const r = await gcpRequest(cfg, {
    method: 'GET',
    path: '/projects/' + enc(pid) + '/aggregated/instances',
    query: 'maxResults=100'
  });
  const items = (r.json && r.json.items) || {};
  const out = [];
  for (const k of Object.keys(items)) {
    const group = items[k] || {};
    for (const inst of (group.instances || [])) out.push(simplifyInstance(inst));
  }
  out.sort(function (a, b) { return (a.region + a.name).localeCompare(b.region + b.name); });
  return { project: pid, instances: out };
}

async function getInstance(cfg, zone, name) {
  const pid = projectId(cfg);
  const r = await gcpRequest(cfg, {
    method: 'GET',
    path: '/projects/' + enc(pid) + '/zones/' + enc(zone) + '/instances/' + enc(name)
  });
  return r.json || {};
}

function instBase(cfg, zone, name) {
  return '/projects/' + enc(projectId(cfg)) + '/zones/' + enc(zone) + '/instances/' + enc(name);
}

/** 开机 / 停止 / 硬重启 */
async function instanceAction(cfg, zone, name, action) {
  const act = String(action || '').toLowerCase();
  if (!['start', 'stop', 'reset'].includes(act)) throw new Error('不支持的 action：' + action);
  await gcpRequest(cfg, { method: 'POST', path: instBase(cfg, zone, name) + '/' + act });
  // 操作是异步的，回读一次状态
  let state = '';
  try {
    const inst = await getInstance(cfg, zone, name);
    state = inst.status || '';
  } catch (e) { /* noop */ }
  return { ok: true, action: act, state: state };
}

/** 查旧 IP 是否属于项目里的静态（预留）地址；返回可释放的信息或 null */
async function findStaticAddress(cfg, region, ip) {
  const pid = projectId(cfg);
  // 区域地址
  try {
    const ra = await gcpRequest(cfg, { method: 'GET', path: '/projects/' + enc(pid) + '/regions/' + enc(region) + '/addresses' });
    for (const a of ((ra.json && ra.json.items) || [])) {
      if (a && a.address === ip) {
        return {
          name: a.name, kind: 'region', status: a.status || '',
          deletePath: '/projects/' + enc(pid) + '/regions/' + enc(region) + '/addresses/' + enc(a.name)
        };
      }
    }
  } catch (e) { /* 区域地址列表失败不阻塞换 IP */ }
  // 全局地址
  try {
    const ga = await gcpRequest(cfg, { method: 'GET', path: '/projects/' + enc(pid) + '/globalAddresses' });
    for (const a of ((ga.json && ga.json.items) || [])) {
      if (a && a.address === ip) {
        return {
          name: a.name, kind: 'global', status: a.status || '',
          deletePath: '/projects/' + enc(pid) + '/globalAddresses/' + enc(a.name)
        };
      }
    }
  } catch (e) { /* noop */ }
  return null;
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

/**
 * 更换外部 IPv4。
 * 流程：解绑旧 accessConfig → 若旧 IP 是静态地址则释放（防继续扣费）→
 *       重新添加 accessConfig 拿新临时 IP → 轮询回读新 IP。
 */
async function switchIp(cfg, zone, name) {
  const inst = await getInstance(cfg, zone, name);
  const nic0 = ((inst.networkInterfaces || [])[0]) || {};
  const ac = ((nic0.accessConfigs || [])[0]) || {};
  const oldIp = ac.natIP || nic0.externalIp || '';
  if (!oldIp) throw new Error('该实例当前没有外部 IPv4 地址（可能未绑定外部 IP），无需更换');
  const acName = ac.name || 'External NAT';
  const region = String(zone).split('-').slice(0, -1).join('-');

  const staticAddr = await findStaticAddress(cfg, region, oldIp);

  // 1) 解绑
  await gcpRequest(cfg, {
    method: 'POST',
    path: instBase(cfg, zone, name) + '/deleteAccessConfig',
    query: 'accessConfig=' + enc(acName) + '&networkInterface=nic0'
  });

  // 2) 静态地址必须显式释放，否则会继续计费
  let released = null;
  if (staticAddr) {
    try {
      await gcpRequest(cfg, { method: 'DELETE', path: staticAddr.deletePath });
      released = staticAddr.name;
    } catch (e) {
      throw new Error('旧静态 IP 释放失败（如果不处理会继续计费，请到 GCP 控制台手动删除地址 ' + staticAddr.name + '）：' + e.message);
    }
  }

  // 3) 添加新的外部访问配置（临时 IP，免费）
  await gcpRequest(cfg, {
    method: 'POST',
    path: instBase(cfg, zone, name) + '/addAccessConfig',
    query: 'networkInterface=nic0',
    body: { name: 'External NAT', type: 'ONE_TO_ONE_NAT' }
  });

  // 4) 轮询回读新 IP
  let newIp = '';
  for (let i = 0; i < 12; i++) {
    await sleep(1500);
    try {
      const ni2 = await getInstance(cfg, zone, name);
      const acs2 = (((ni2.networkInterfaces || [])[0] || {}).accessConfigs) || [];
      if (acs2[0] && acs2[0].natIP) { newIp = acs2[0].natIP; break; }
    } catch (e) { /* noop */ }
  }

  return {
    ok: true,
    old_ip: oldIp,
    new_ip: newIp,
    released_static: !!released,
    released_name: released || '',
    was_static: !!staticAddr,
    message: released
      ? '已更换 IP，并释放了旧静态地址 ' + released + '（不再继续计费）'
      : '已更换 IP（旧地址为临时 IP，已自动回收，不产生费用）'
  };
}

/** 在线 SSH 连接信息 */
function sshInfo(cfg, inst) {
  if (!inst || !inst.external_ip) throw new Error('该实例没有外部 IPv4 地址，无法通过公网 SSH');
  const key = String((cfg && cfg.ssh_key) || '').trim();
  if (!key) throw new Error('尚未配置 SSH 私钥：请到「谷歌云设置」填写与实例 authorized_keys 对应的私钥');
  return {
    host: inst.external_ip,
    port: 22,
    username: String((cfg && cfg.ssh_user) || 'ubuntu').trim() || 'ubuntu',
    privateKey: key
  };
}

function tgActionLabel(action) {
  if (action === 'start') return '开机';
  if (action === 'stop') return '关机';
  if (action === 'reset') return '重启（硬重启）';
  return action;
}

/* ---------------- HTTP 路由 ---------------- */
function handle(req, res, urlPath, method, sendJson, isAllowedHost) {
  const segs = urlPath.split('/').filter(Boolean); // ['api','gcp', ...]
  const sub = segs.slice(2).join('/');

  // ---------- 凭证 ----------
  if (sub === 'config' && method === 'GET') {
    const info = listGcpAccounts();
    if (info.accounts.length) {
      const cur = loadGcpConfig();
      return sendJson(res, 200, {
        configured: true, active: info.active, accounts: info.accounts,
        project_id: cur.project_id || '', ssh_user: cur.ssh_user || '',
        has_service_json: !!String(cur.service_json || '').trim(),
        has_ssh_key: !!String(cur.ssh_key || '').trim()
      });
    }
    return sendJson(res, 200, { configured: false, active: '', accounts: [] });
  }

  if (sub === 'config' && method === 'POST') {
    if (!isAllowedHost(req.socket.remoteAddress)) return sendJson(res, 403, { error: '仅允许本机访问' });
    let raw = '';
    req.on('data', function (chunk) { raw += chunk; if (raw.length > 4 * 1024 * 1024) req.destroy(); });
    req.on('end', function () {
      let payload;
      try { payload = JSON.parse(raw); } catch (e) { return sendJson(res, 400, { error: '请求体不是合法 JSON' }); }
      if (payload.clear) {
        clearGcpCreds();
        return sendJson(res, 200, { ok: true });
      }
      if (payload.action === 'set-active') {
        try {
          const name = String(payload.name || '').trim();
          setActiveGcpAccount(name);
          return sendJson(res, 200, { ok: true, active: name });
        } catch (e) { return sendJson(res, 400, { error: e.message }); }
      }
      if (payload.action === 'delete') {
        deleteGcpAccount(String(payload.name || '').trim());
        return sendJson(res, 200, { ok: true });
      }
      try {
        const name = String(payload.name || '').trim();
        if (payload.action === 'save') {
          if (!name) return sendJson(res, 400, { error: '凭证名称不能为空' });
          const existing = loadGcpStore() || { active: '', accounts: {} };
          const prev = existing.accounts[name] || {};
          const sj = payload.service_json !== undefined ? String(payload.service_json || '').trim() : (prev.service_json || '');
          if (sj) { try { JSON.parse(sj); } catch (e) { return sendJson(res, 400, { error: 'Service Account JSON 不是合法 JSON' }); } }
          const cfg = {
            project_id: payload.project_id !== undefined ? String(payload.project_id || '').trim() : (prev.project_id || ''),
            service_json: sj,
            ssh_user: payload.ssh_user !== undefined ? String(payload.ssh_user || '').trim() : (prev.ssh_user || ''),
            ssh_key: payload.ssh_key !== undefined && String(payload.ssh_key).trim() ? String(payload.ssh_key).trim() : (prev.ssh_key || '')
          };
          saveGcpAccount(name, cfg, payload.makeActive !== false);
          return sendJson(res, 200, { ok: true, active: name, message: '设置已保存' });
        }
        // 兼容旧前端：保存到当前组
        const cur = loadGcpConfig();
        const gname = cur.name || 'default';
        const cfg2 = {
          project_id: payload.project_id !== undefined ? String(payload.project_id || '').trim() : (cur.project_id || ''),
          service_json: payload.service_json !== undefined ? String(payload.service_json || '').trim() : (cur.service_json || ''),
          ssh_user: payload.ssh_user !== undefined ? String(payload.ssh_user || '').trim() : (cur.ssh_user || ''),
          ssh_key: payload.ssh_key !== undefined && String(payload.ssh_key).trim() ? String(payload.ssh_key).trim() : (cur.ssh_key || '')
        };
        saveGcpAccount(gname, cfg2, true);
        return sendJson(res, 200, { ok: true, active: gname, message: '设置已保存' });
      } catch (e) { return sendJson(res, 400, { error: e.message }); }
    });
    return;
  }

  // 以下接口需要凭证
  const urlObj = new URL(req.url, 'http://localhost');
  const groupParam = urlObj.searchParams.get('group') || '';
  const cfg = loadGcpConfigForGroup(groupParam);
  if (!cfg || !cfg.name) {
    return sendJson(res, 409, { ok: false, message: '尚未配置谷歌云凭证：请到「谷歌云设置」填写 Service Account JSON' });
  }

  // ---------- 测试连接 ----------
  if (sub === 'test' && method === 'POST') {
    listInstances(cfg).then(function (r) {
      return sendJson(res, 200, { ok: true, message: '连接成功，项目 ' + r.project + ' 共 ' + r.instances.length + ' 台实例' });
    }).catch(function (e) {
      return sendJson(res, 200, { ok: false, message: '连接失败：' + e.message });
    });
    return;
  }

  // ---------- 实例列表 ----------
  if (sub === 'instances' && method === 'GET') {
    listInstances(cfg).then(function (r) {
      return sendJson(res, 200, { ok: true, project: r.project, instances: r.instances });
    }).catch(function (e) {
      return sendJson(res, 200, { ok: false, message: '获取实例失败：' + e.message });
    });
    return;
  }

  // ---------- 实例操作 / 换 IP / SSH 信息 ----------
  const instMatch = sub.match(/^instances\/([^/]+)\/(action|switch-ip|ssh-info)$/);
  if (instMatch) {
    const instName = decodeURIComponent(instMatch[1]);
    const op = instMatch[2];
    const zoneFromQuery = urlObj.searchParams.get('zone') || '';

    if (op === 'action' && method === 'POST') {
      let raw = '';
      req.on('data', function (chunk) { raw += chunk; });
      req.on('end', function () {
        let payload = {};
        try { payload = JSON.parse(raw) || {}; } catch (e) { /* ignore */ }
        const zone = String(payload.zone || zoneFromQuery || '').trim();
        const action = String(payload.action || '').toLowerCase();
        if (!zone) return sendJson(res, 400, { ok: false, message: '缺少 zone 参数' });
        if (!['start', 'stop', 'reset'].includes(action)) return sendJson(res, 400, { ok: false, message: '不支持的 action：' + action });
        instanceAction(cfg, zone, instName, action).then(function (r) {
          tgNotify.notify(req.user,
            '☁️ 谷歌云 GCP · ' + tgActionLabel(action) + '通知\n项目：' + projectId(cfg) + '\n区域：' + zone + '\n实例：' + instName + '\n结果：已提交（' + (r.state || '处理中') + '）\n时间：' + tgNotify.fmtNow(), null, true);
          return sendJson(res, 200, r);
        }).catch(function (e) {
          return sendJson(res, 200, { ok: false, message: tgActionLabel(action) + '失败：' + e.message });
        });
      });
      return;
    }

    if (op === 'switch-ip' && method === 'POST') {
      let raw = '';
      req.on('data', function (chunk) { raw += chunk; });
      req.on('end', function () {
        let payload = {};
        try { payload = JSON.parse(raw) || {}; } catch (e) { /* ignore */ }
        const zone = String(payload.zone || zoneFromQuery || '').trim();
        if (!zone) return sendJson(res, 400, { ok: false, message: '缺少 zone 参数' });
        switchIp(cfg, zone, instName).then(function (r) {
          tgNotify.notify(req.user,
            '🔄 谷歌云 GCP · 更换外部 IPv4 通知\n项目：' + projectId(cfg) + '\n区域：' + zone + '\n实例：' + instName +
            '\n旧 IP：' + (r.old_ip || '无') + '\n新 IP：' + (r.new_ip || '?') +
            (r.released_static ? '\n已释放静态地址：' + r.released_name + '（不再计费）' : '') +
            '\n时间：' + tgNotify.fmtNow(), null, true);
          return sendJson(res, 200, r);
        }).catch(function (e) {
          return sendJson(res, 200, { ok: false, message: '更换 IP 失败：' + e.message });
        });
      });
      return;
    }

    if (op === 'ssh-info' && method === 'GET') {
      const zone = zoneFromQuery;
      if (!zone) return sendJson(res, 400, { ok: false, message: '缺少 zone 参数' });
      getInstance(cfg, zone, instName).then(function (inst) {
        const simple = simplifyInstance(inst);
        try {
          const info = sshInfo(cfg, simple);
          return sendJson(res, 200, { ok: true, host: info.host, port: info.port, username: info.username, privateKey: info.privateKey, ipv6: simple.ipv6 || '' });
        } catch (e) {
          return sendJson(res, 200, { ok: false, message: e.message });
        }
      }).catch(function (e) {
        return sendJson(res, 200, { ok: false, message: '获取实例信息失败：' + e.message });
      });
      return;
    }
  }

  sendJson(res, 404, { ok: false, message: '未知接口：' + urlPath });
}

module.exports = {
  handle: handle,
  setCredsFile: setCredsFile,
  loadGcpConfig: loadGcpConfig,
  loadGcpConfigForGroup: loadGcpConfigForGroup,
  listGcpAccounts: listGcpAccounts,
  clearGcpCreds: clearGcpCreds
};
