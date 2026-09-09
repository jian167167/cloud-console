/**
 * OCI（Oracle Cloud）后端模块 —— 纯 Node 实现，无 Python 依赖
 *
 * 功能（与旧 Flask 版 1:1 对齐）：
 *   - 凭证读写（oci-credentials.json，支持 OCI_CREDS_FILE 环境变量）
 *   - OCI SigV4-RSA 请求签名（RSA 私钥 + (request-target)/host/date/x-content-sha256 等）
 *   - 实例列表 / 开机 / 关机 / 重启 / 切换公网 IP / 开放端口 / 查看规则
 *   - 测试连接 / 分区列表
 *
 * 说明：OCI REST API 与 AWS 同为 SigV4 家族，但 OCI 用 RSA 私钥做
 *   SHA256withRSA 签名（keyId = tenancy/user/fingerprint），且强制要求
 *   x-content-sha256 头参与签名。
 */

'use strict';

const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let OCI_CREDS_FILE = process.env.OCI_CREDS_FILE || path.join(__dirname, 'oci-credentials.json');

/** 切换当前账号的凭证文件路径（由 server.js 在 /api/oci 请求时调用） */
function setCredsFile(p) {
  if (p) OCI_CREDS_FILE = p;
}

/* ---------------- 凭证读写（支持多凭证组） ----------------
 * 文件格式：{ "active": "组名", "accounts": { "组名": {tenancy_ocid,...} } }
 * 兼容旧版单组格式：读到时自动升级（组名 default） */
function loadOciStore() {
  try {
    const raw = fs.readFileSync(OCI_CREDS_FILE, 'utf8');
    const c = JSON.parse(raw) || {};
    if (c.accounts && typeof c.accounts === 'object') {
      if (!c.active) c.active = Object.keys(c.accounts)[0] || '';
      return c;
    }
    if (c.tenancy_ocid || c.user_ocid || c.fingerprint) {
      const n = { active: 'default', accounts: { default: c } };
      try { fs.writeFileSync(OCI_CREDS_FILE, JSON.stringify(n, null, 2), { encoding: 'utf8', mode: 0o600 }); } catch (e) { /* noop */ }
      return n;
    }
    return null;
  } catch (e) {
    return null;
  }
}
function saveOciStore(store) {
  fs.mkdirSync(path.dirname(OCI_CREDS_FILE), { recursive: true });
  fs.writeFileSync(OCI_CREDS_FILE, JSON.stringify(store, null, 2), { encoding: 'utf8', mode: 0o600 });
}
/** 按组名取 OCI 配置（实例分组用；组不存在回退 active） */
function loadOciConfigForGroup(group) {
  const s = loadOciStore();
  if (!s) return {};
  const keys = Object.keys(s.accounts);
  const name = group && s.accounts[group] ? group : (s.accounts[s.active] ? s.active : keys[0]);
  return s.accounts[name] || {};
}
/** 当前生效的 OCI 配置（active 组） */
function loadOciConfig() {
  return loadOciConfigForGroup('');
}
/** 凭证组列表（key_content 原文不回显，只回显是否有） */
function listOciAccounts() {
  const s = loadOciStore();
  if (!s) return { active: '', accounts: [] };
  const accounts = Object.keys(s.accounts).map((name) => {
    const c = s.accounts[name] || {};
    const safe = {};
    for (const k of ['tenancy_ocid', 'user_ocid', 'fingerprint', 'region', 'compartment_ocid', 'key_file']) {
      if (c[k]) safe[k] = c[k];
    }
    safe.name = name;
    safe.has_key_content = !!String(c.key_content || '').trim();
    return safe;
  });
  return { active: s.active || (accounts[0] ? accounts[0].name : ''), accounts };
}
function saveOciAccount(name, cfg, makeActive) {
  const s = loadOciStore() || { active: '', accounts: {} };
  if (!s.accounts[name]) { if (!s.active) s.active = name; }
  s.accounts[name] = cfg;
  if (makeActive) s.active = name;
  saveOciStore(s);
}
function setActiveOciAccount(name) {
  const s = loadOciStore();
  if (!s || !s.accounts[name]) throw new Error('凭证组不存在：' + name);
  s.active = name;
  saveOciStore(s);
}
function deleteOciAccount(name) {
  const s = loadOciStore();
  if (!s) return;
  delete s.accounts[name];
  if (s.active === name) s.active = Object.keys(s.accounts)[0] || '';
  if (Object.keys(s.accounts).length === 0) {
    try { fs.rmSync(OCI_CREDS_FILE, { force: true }); } catch (e) { /* noop */ }
  } else {
    saveOciStore(s);
  }
}
function clearOciCreds() {
  try { fs.rmSync(OCI_CREDS_FILE, { force: true }); } catch (e) { /* noop */ }
}

/** 把保存的配置组装成可用配置（校验必填 + 解析私钥）。返回 {ok, cfg|error} */
function buildOciConfig(saved) {
  const cfg = {
    tenancy: String(saved.tenancy_ocid || '').trim(),
    user: String(saved.user_ocid || '').trim(),
    fingerprint: String(saved.fingerprint || '').trim(),
    region: String(saved.region || '').trim(),
    compartment: String(saved.compartment_ocid || '').trim() || String(saved.tenancy_ocid || '').trim(),
  };
  let privateKey = '';
  const keyContent = String(saved.key_content || '').trim();
  const keyFile = String(saved.key_file || '').trim();
  if (keyContent) {
    privateKey = keyContent;
  } else if (keyFile) {
    try {
      privateKey = fs.readFileSync(keyFile, 'utf8');
    } catch (e) {
      return { ok: false, error: '无法读取私钥文件：' + keyFile + '（' + e.message + '）' };
    }
  } else {
    return { ok: false, error: '缺少 API 私钥：请在设置中粘贴私钥内容，或填写私钥文件路径' };
  }
  const missing = [];
  if (!cfg.tenancy) missing.push('租户 OCID');
  if (!cfg.user) missing.push('用户 OCID');
  if (!cfg.fingerprint) missing.push('指纹');
  if (!cfg.region) missing.push('区域');
  if (missing.length) return { ok: false, error: '缺少配置项：' + missing.join('、') };
  cfg.privateKey = privateKey;
  return { ok: true, cfg };
}

/* ---------------- OCI 签名 ---------------- */

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
/** OCI 要求 x-content-sha256 为 BASE64 编码的 SHA-256 摘要 */
function sha256B64(buf) {
  return crypto.createHash('sha256').update(buf).digest('base64');
}

/** 执行一次带签名的 OCI REST 请求 */
function ociRequest({ service, region, method, urlPath, body }, cfg, timeoutMs) {
  return new Promise((resolve, reject) => {
    const host = (service === 'identity' ? 'identity' : 'iaas') + '.' + region + '.oraclecloud.com';
    const bodyBuf = body ? Buffer.from(body, 'utf8') : Buffer.alloc(0);
    const sha = sha256B64(bodyBuf);
    const hasBody = bodyBuf.length > 0;
    const date = new Date().toUTCString();

    const signLines = [
      'date: ' + date,
      '(request-target): ' + method.toLowerCase() + ' ' + urlPath,
      'host: ' + host,
    ];
    const headerNames = ['date', '(request-target)', 'host'];
    if (hasBody) {
      signLines.push('content-length: ' + bodyBuf.length);
      signLines.push('content-type: application/json');
      signLines.push('x-content-sha256: ' + sha);
      headerNames.push('content-length', 'content-type', 'x-content-sha256');
    }
    const signingString = signLines.join('\n');

    let signature;
    try {
      const signer = crypto.createSign('RSA-SHA256');
      signer.update(signingString);
      signature = signer.sign(cfg.privateKey, 'base64');
    } catch (e) {
      reject(new Error('私钥签名失败（请确认私钥内容完整且未加密）：' + e.message));
      return;
    }

    const keyId = cfg.tenancy + '/' + cfg.user + '/' + cfg.fingerprint;
    const authorization = 'Signature algorithm="rsa-sha256",headers="' +
      headerNames.join(' ') + '",keyId="' + keyId + '",signature="' + signature + '",version="1"';

    const headers = {
      'host': host,
      'date': date,
      'authorization': authorization,
    };
    if (hasBody) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(bodyBuf.length);
      headers['x-content-sha256'] = sha;
    }

    const req = https.request({ hostname: host, port: 443, path: urlPath, method, headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) { /* 非 JSON 响应 */ }
        if (res.statusCode >= 400) {
          const msg = (json && (json.message || json.code)) ? (json.message || json.code) : data.slice(0, 300);
          const err = new Error('HTTP ' + res.statusCode + ': ' + msg);
          err.status = res.statusCode;
          err.ociCode = json && json.code;
          reject(err);
        } else {
          resolve({ status: res.statusCode, json, raw: data });
        }
      });
    });
    req.setTimeout(timeoutMs || 30000, () => { req.destroy(new Error('OCI 请求超时（30 秒）')); });
    req.on('error', (e) => reject(e));
    if (hasBody) req.write(bodyBuf);
    req.end();
  });
}

/* ---------------- 规则辅助（与旧版逻辑等价） ---------------- */

/** OCI REST 列表类响应可能是裸数组，也可能是 {data:[]} 包装 */
function respList(json) {
  if (Array.isArray(json)) return json;
  if (json && Array.isArray(json.data)) return json.data;
  return [];
}

const PROTO_NAMES = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6', all: 'ALL' };

function protoName(p) {
  const n = PROTO_NAMES[p];
  return n === undefined ? String(p) : n;
}

function rulePorts(r) {
  const pr = (r.tcpOptions && r.tcpOptions.destinationPortRange) || (r.udpOptions && r.udpOptions.destinationPortRange);
  if (pr && pr.min !== undefined) {
    return pr.min === pr.max ? String(pr.min) : pr.min + '-' + pr.max;
  }
  return '';
}

function simplifyRule(r, direction) {
  return {
    direction: direction,
    protocol: protoName(r.protocol),
    source: r.source || null,
    destination: r.destination || null,
    ports: rulePorts(r),
    stateless: !!r.isStateless,
    description: r.description || '',
  };
}

function parsePorts(text) {
  const ranges = [];
  for (let part of String(text || '').split(',')) {
    part = part.trim();
    if (!part) continue;
    let lo, hi;
    if (part.indexOf('-') >= 0) {
      const p = part.split('-', 2);
      lo = parseInt(p[0].trim(), 10);
      hi = parseInt(p[1].trim(), 10);
    } else {
      lo = hi = parseInt(part, 10);
    }
    if (isNaN(lo) || isNaN(hi) || lo < 1 || hi > 65535 || lo > hi) {
      throw new Error('端口格式无效（1-65535）：' + part);
    }
    ranges.push([lo, hi]);
  }
  if (!ranges.length) throw new Error('请填写要开放的端口，例如 22,443,8000-9000');
  return ranges;
}

function ruleMatchesPort(rule, pr) {
  if (pr === null || pr === undefined) return true;
  for (const key of ['tcpOptions', 'udpOptions']) {
    const rng = rule[key] && rule[key].destinationPortRange;
    if (rng && rng.min === pr[0] && rng.max === pr[1]) return true;
  }
  return false;
}

/** 安全列表规则去重判断。spec=[protoNum, prOrNull, cidr] */
function slHas(rules, direction, spec) {
  const [protoNum, pr, cidr] = spec;
  for (const r of rules || []) {
    if (String(r.protocol) !== String(protoNum)) continue;
    if (direction === 'INGRESS') {
      if (r.source !== cidr) continue;
    } else {
      if (r.destination !== cidr) continue;
    }
    if (ruleMatchesPort(r, pr)) return true;
  }
  return false;
}

/** NSG 规则去重判断 */
function nsgHas(rules, direction, spec) {
  const [protoNum, pr, cidr] = spec;
  for (const r of rules || []) {
    if (r.direction !== direction) continue;
    if (String(r.protocol) !== String(protoNum)) continue;
    if (direction === 'INGRESS') {
      if (r.source !== cidr) continue;
    } else {
      if (r.destination !== cidr) continue;
    }
    if (ruleMatchesPort(r, pr)) return true;
  }
  return false;
}

/** 构造安全列表规则 JSON（OCI API camelCase） */
function buildSlRule(direction, spec) {
  const [protoNum, pr, cidr] = spec;
  const kw = {
    protocol: protoNum,
    isStateless: false,
    description: 'open-ports (web tool)',
  };
  if (pr) {
    const port = { min: pr[0], max: pr[1] };
    if (protoNum === '6') kw.tcpOptions = { destinationPortRange: port };
    else if (protoNum === '17') kw.udpOptions = { destinationPortRange: port };
  }
  if (direction === 'INGRESS') kw.source = cidr;
  else kw.destination = cidr;
  return kw;
}

/** 构造 NSG 规则 JSON */
function buildNsgRule(direction, spec) {
  const [protoNum, pr, cidr] = spec;
  const kw = {
    direction: direction,
    protocol: protoNum,
    isStateless: false,
    description: 'open-ports (web tool)',
  };
  if (pr) {
    const port = { min: pr[0], max: pr[1] };
    if (protoNum === '6') kw.tcpOptions = { destinationPortRange: port };
    else if (protoNum === '17') kw.udpOptions = { destinationPortRange: port };
  }
  if (direction === 'INGRESS') kw.source = cidr;
  else kw.destination = cidr;
  return kw;
}

/* ---------------- 实例辅助 ---------------- */

async function getPrimaryVnic(computeHost, cfg, instId) {
  const comp = cfg.compartment;
  const vaRes = await ociRequest({
    service: 'iaas', region: cfg.region, method: 'GET',
    urlPath: '/20160918/vnicAttachments?compartmentId=' + encodeURIComponent(comp) + '&instanceId=' + encodeURIComponent(instId),
  }, cfg);
  for (const va of respList(vaRes.json)) {
    const vRes = await ociRequest({
      service: 'iaas', region: cfg.region, method: 'GET',
      urlPath: '/20160918/vnics/' + encodeURIComponent(va.vnicId),
    }, cfg);
    const v = vRes.json;
    if (v && v.isPrimary) return v;
  }
  return null;
}

async function getPrimaryPrivateIpId(computeHost, cfg, vnicId) {
  const pRes = await ociRequest({
    service: 'iaas', region: cfg.region, method: 'GET',
    urlPath: '/20160918/privateIps?vnicId=' + encodeURIComponent(vnicId),
  }, cfg);
  const pips = respList(pRes.json);
  const prim = pips.find((p) => p.isPrimary);
  return prim ? prim.id : null;
}

/* ---------------- 路由处理 ---------------- */

/** 统一入口：由 server.js 调用。urlPath 不含 query。 */
function handle(req, res, urlPath, method, sendJson, isAllowedHost) {
  // 解析路径段：/api/oci/... 
  const segs = urlPath.split('/').filter(Boolean); // ['api','oci', ...]
  const sub = segs.slice(2).join('/'); // 'config' | 'test' | 'compartments' | 'instances' | 'instances/<id>/action' ...

  // ---------- 凭证 ----------
  if (sub === 'config' && method === 'GET') {
    const info = listOciAccounts();
    if (info.accounts.length) {
      const cur = loadOciConfig();
      const safe = { configured: true, active: info.active, accounts: info.accounts };
      for (const k of ['tenancy_ocid', 'user_ocid', 'fingerprint', 'region', 'compartment_ocid', 'key_file']) {
        if (cur[k]) safe[k] = cur[k];
      }
      safe.has_key_content = !!String(cur.key_content || '').trim();
      return sendJson(res, 200, safe);
    }
    return sendJson(res, 200, { configured: false, active: '', accounts: [] });
  }

  if (sub === 'config' && method === 'POST') {
    if (!isAllowedHost(req.socket.remoteAddress)) return sendJson(res, 403, { error: '仅允许本机访问' });
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; if (raw.length > 4 * 1024 * 1024) req.destroy(); });
    req.on('end', () => {
      let payload;
      try { payload = JSON.parse(raw); } catch (e) { return sendJson(res, 400, { error: '请求体不是合法 JSON' }); }
      if (payload.clear) {
        clearOciCreds();
        return sendJson(res, 200, { ok: true });
      }
      if (payload.action === 'set-active') {
        try {
          const name = String(payload.name || '').trim();
          setActiveOciAccount(name);
          return sendJson(res, 200, { ok: true, active: name });
        } catch (e) { return sendJson(res, 400, { error: e.message }); }
      }
      if (payload.action === 'delete') {
        deleteOciAccount(String(payload.name || '').trim());
        return sendJson(res, 200, { ok: true });
      }
      let name;
      try {
        if (payload.action === 'save') {
          name = String(payload.name || '').trim();
          if (!name) return sendJson(res, 400, { error: '凭证名称不能为空' });
          const existing = loadOciStore() || { active: '', accounts: {} };
          const prev = existing.accounts[name] || {};
          const cfg = {
            tenancy_ocid: payload.tenancy_ocid !== undefined ? String(payload.tenancy_ocid || '').trim() : (prev.tenancy_ocid || ''),
            user_ocid: payload.user_ocid !== undefined ? String(payload.user_ocid || '').trim() : (prev.user_ocid || ''),
            fingerprint: payload.fingerprint !== undefined ? String(payload.fingerprint || '').trim() : (prev.fingerprint || ''),
            region: payload.region !== undefined ? String(payload.region || '').trim() : (prev.region || ''),
            compartment_ocid: payload.compartment_ocid !== undefined ? String(payload.compartment_ocid || '').trim() : (prev.compartment_ocid || ''),
            key_file: payload.key_file !== undefined ? String(payload.key_file || '').trim() : (prev.key_file || ''),
            key_content: payload.key_content !== undefined && String(payload.key_content).trim() ? String(payload.key_content).trim() : (prev.key_content || '')
          };
          saveOciAccount(name, cfg, payload.makeActive !== false);
          return sendJson(res, 200, { ok: true, active: name, message: '设置已保存' });
        }
        // 兼容旧前端（无 action）：保存到当前生效组
        const cur = loadOciConfig();
        name = cur.name || 'default';
        const cfg2 = {};
        for (const k of ['tenancy_ocid', 'user_ocid', 'fingerprint', 'key_content', 'key_file', 'region', 'compartment_ocid']) {
          if (payload[k] !== undefined) cfg2[k] = String(payload[k] || '').trim();
        }
        saveOciAccount(name, Object.assign({}, cur, cfg2), true);
        return sendJson(res, 200, { ok: true, active: name, message: '设置已保存' });
      } catch (e) { return sendJson(res, 400, { error: e.message }); }
    });
    return;
  }

  // 以下接口需要已配置凭证（支持 ?group=xxx 指定凭证组，实例分组用）
  const urlObj = new URL(req.url, 'http://localhost');
  const groupParam = urlObj.searchParams.get('group') || '';
  const built = buildOciConfig(loadOciConfigForGroup(groupParam));
  if (!built.ok) {
    return sendJson(res, 409, { ok: false, message: '尚未配置 OCI 凭证：' + built.error });
  }
  const cfg = built.cfg;

  // ---------- 测试连接 ----------
  if (sub === 'test' && method === 'POST') {
    ociRequest({
      service: 'identity', region: cfg.region, method: 'GET',
      urlPath: '/20160918/availabilityDomains?compartmentId=' + encodeURIComponent(cfg.tenancy),
    }, cfg).then((r) => {
      const ads = respList(r.json).map((a) => a.name);
      return sendJson(res, 200, { ok: true, message: '连接成功，可用域：' + (ads.join('、') || '（无）') });
    }).catch((e) => sendJson(res, 200, { ok: false, message: '连接失败：' + e.message }));
    return;
  }

  // ---------- 分区列表 ----------
  if (sub === 'compartments' && method === 'GET') {
    ociRequest({
      service: 'identity', region: cfg.region, method: 'GET',
      urlPath: '/20160918/compartments?compartmentId=' + encodeURIComponent(cfg.tenancy) +
        '&compartmentIdInSubtree=true&accessLevel=ACCESSIBLE&lifecycleState=ACTIVE',
    }, cfg).then((r) => {
      const comps = [{ id: cfg.tenancy, name: '根分区 (tenancy)' }];
      for (const c of respList(r.json)) {
        comps.push({ id: c.id, name: c.name });
      }
      return sendJson(res, 200, { ok: true, compartments: comps });
    }).catch((e) => sendJson(res, 200, { ok: false, message: '获取分区失败：' + e.message }));
    return;
  }

  // ---------- 实例列表 ----------
  if (sub === 'instances' && method === 'GET') {
    listInstances(cfg).then((result) => sendJson(res, 200, { ok: true, instances: result }))
      .catch((e) => sendJson(res, 200, { ok: false, message: '获取实例失败：' + e.message }));
    return;
  }

  // ---------- 实例操作 / 换 IP / 开放端口 / 规则 ----------
  const instMatch = sub.match(/^instances\/([^/]+)\/(action|switch-ip|open-ports|rules)$/);
  if (instMatch) {
    const instId = decodeURIComponent(instMatch[1]);
    const op = instMatch[2];

    if (op === 'action' && method === 'POST') {
      let raw = '';
      req.on('data', (chunk) => { raw += chunk; });
      req.on('end', () => {
        let payload = {};
        try { payload = JSON.parse(raw) || {}; } catch (e) { /* ignore */ }
        const action = String(payload.action || '').toUpperCase();
        if (!['START', 'STOP', 'SOFTSTOP', 'SOFTRESET', 'RESET'].includes(action)) {
          return sendJson(res, 200, { ok: false, message: '不支持的 action：' + action });
        }
        ociRequest({
          service: 'iaas', region: cfg.region, method: 'POST',
          urlPath: '/20160918/instances/' + encodeURIComponent(instId) + '?action=' + action,
        }, cfg).then((r) => {
          const st = (r.json && r.json.lifecycleState) || '?';
          return sendJson(res, 200, { ok: true, action: action, state: st });
        }).catch((e) => sendJson(res, 200, { ok: false, message: '操作失败：' + e.message }));
      });
      return;
    }

    if (op === 'switch-ip' && method === 'POST') {
      switchIp(cfg, instId).then((r) => sendJson(res, 200, r))
        .catch((e) => sendJson(res, 200, { ok: false, message: '更换 IP 失败：' + e.message }));
      return;
    }

    if (op === 'open-ports' && method === 'POST') {
      let raw = '';
      req.on('data', (chunk) => { raw += chunk; });
      req.on('end', () => {
        let data = {};
        try { data = JSON.parse(raw) || {}; } catch (e) { /* ignore */ }
        openPorts(cfg, instId, data).then((r) => sendJson(res, 200, r))
          .catch((e) => sendJson(res, 200, { ok: false, message: (e.kind === 'param' ? '参数错误：' : '开放端口失败：') + e.message }));
      });
      return;
    }

    if (op === 'rules' && method === 'GET') {
      getRules(cfg, instId).then((r) => sendJson(res, 200, { ok: true, ...r }))
        .catch((e) => sendJson(res, 200, { ok: false, message: '获取规则失败：' + e.message }));
      return;
    }
  }

  sendJson(res, 404, { ok: false, message: '未知接口：' + urlPath });
}

/* ---------------- 实例列表 ---------------- */

async function listInstances(cfg) {
  const comp = cfg.compartment;
  const instRes = await ociRequest({
    service: 'iaas', region: cfg.region, method: 'GET',
    urlPath: '/20160918/instances?compartmentId=' + encodeURIComponent(comp),
  }, cfg);
  const insts = respList(instRes.json);
  const result = [];
  for (const inst of insts) {
    const sc = inst.shapeConfig || {};
    const item = {
      id: inst.id,
      display_name: inst.displayName || inst.id,
      state: inst.lifecycleState,
      shape: inst.shape,
      ocpus: sc.ocpus !== undefined ? sc.ocpus : null,
      memory_in_gbs: sc.memoryInGBs !== undefined ? sc.memoryInGBs : null,
      availability_domain: inst.availabilityDomain,
      time_created: inst.timeCreated || null,
      private_ip: null,
      public_ip: null,
      ipv6: [],
      private_ip_id: null,
      vnic_id: null,
      subnet_id: null,
      nsg_ids: [],
    };
    try {
      const vaRes = await ociRequest({
        service: 'iaas', region: cfg.region, method: 'GET',
        urlPath: '/20160918/vnicAttachments?compartmentId=' + encodeURIComponent(comp) + '&instanceId=' + encodeURIComponent(inst.id),
      }, cfg);
      for (const va of respList(vaRes.json)) {
        const vRes = await ociRequest({
          service: 'iaas', region: cfg.region, method: 'GET',
          urlPath: '/20160918/vnics/' + encodeURIComponent(va.vnicId),
        }, cfg);
        const v = vRes.json;
        if (!v || !v.isPrimary) continue;
        item.private_ip = v.privateIp || null;
        item.public_ip = v.publicIp || null;
        item.ipv6 = (v.ipv6Addresses || []).slice();
        item.vnic_id = v.id;
        item.subnet_id = v.subnetId || null;
        item.nsg_ids = (v.nsgIds || []).slice();
        try {
          item.private_ip_id = await getPrimaryPrivateIpId(cfg, v.id);
        } catch (e) { /* 忽略 */ }
      }
    } catch (e) {
      /* 单个实例网络信息失败不阻断列表 */
    }
    result.push(item);
  }
  result.sort((a, b) => String(b.time_created || '').localeCompare(String(a.time_created || '')));
  return result;
}

/* ---------------- 切换公网 IP ---------------- */

async function switchIp(cfg, instId) {
  const primary = await getPrimaryVnic(cfg, instId);
  if (!primary) throw new Error('未找到实例的主 VNIC');

  const privateIpId = await getPrimaryPrivateIpId(cfg, primary.id);
  if (!privateIpId) throw new Error('实例没有可分配公网 IP 的私网 IP');

  let oldIp = null;
  if (primary.publicIp) {
    let pub = null;
    try {
      const r = await ociRequest({
        service: 'iaas', region: cfg.region, method: 'POST',
        urlPath: '/20160918/publicIps/actions/getByIpAddress',
        body: JSON.stringify({ ipAddress: primary.publicIp }),
      }, cfg);
      pub = r.json;
    } catch (e) {
      if (e.status !== 404) throw e;
    }
    if (pub) {
      if (pub.lifetime === 'RESERVED') {
        throw new Error('该实例绑定的是保留公网 IP（Reserved），无法自动更换。请先在 OCI 控制台解绑保留 IP，或改用临时公网 IP。');
      }
      oldIp = pub.ipAddress;
      await ociRequest({
        service: 'iaas', region: cfg.region, method: 'DELETE',
        urlPath: '/20160918/publicIps/' + encodeURIComponent(pub.id),
      }, cfg);
      for (let i = 0; i < 15; i++) {
        try {
          await ociRequest({
            service: 'iaas', region: cfg.region, method: 'GET',
            urlPath: '/20160918/publicIps/' + encodeURIComponent(pub.id),
          }, cfg);
          await new Promise((r) => setTimeout(r, 2000));
        } catch (e) {
          break;
        }
      }
    }
  }

  let newIp = null;
  let lastErr = null;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      const r = await ociRequest({
        service: 'iaas', region: cfg.region, method: 'POST',
        urlPath: '/20160918/publicIps',
        body: JSON.stringify({
          compartmentId: cfg.compartment,
          lifetime: 'EPHEMERAL',
          privateIpId: privateIpId,
          displayName: 'web-manager-' + Date.now().toString().slice(-10),
        }),
      }, cfg);
      newIp = r.json && r.json.ipAddress;
      break;
    } catch (e) {
      lastErr = e;
      if (attempt < 5) await new Promise((r) => setTimeout(r, 4000));
    }
  }
  if (!newIp) throw lastErr || new Error('分配新公网 IP 失败');

  return {
    ok: true,
    old_ip: oldIp,
    new_ip: newIp,
    message: '更换成功：' + (oldIp || '无') + ' → ' + newIp,
  };
}

/* ---------------- 开放端口 ---------------- */

async function openPorts(cfg, instId, data) {
  const mode = String(data.mode || 'all').toLowerCase();
  const protocol = String(data.protocol || 'TCP').toUpperCase();
  const source = String(data.source || '0.0.0.0/0').trim() || '0.0.0.0/0';
  const direction = String(data.direction || 'INGRESS').toUpperCase();
  if (!['INGRESS', 'EGRESS'].includes(direction)) throw { kind: 'param', message: 'direction 只支持 INGRESS / EGRESS' };

  let rulesSpec;
  if (mode === 'all') {
    rulesSpec = [['all', null, '0.0.0.0/0'], ['all', null, '::/0']];
  } else {
    if (!['TCP', 'UDP', 'ICMP', 'ALL'].includes(protocol)) throw { kind: 'param', message: 'protocol 只支持 TCP / UDP / ICMP / ALL' };
    if (protocol === 'ALL') rulesSpec = [['all', null, source]];
    else if (protocol === 'ICMP') rulesSpec = [['1', null, source]];
    else {
      const protoNum = protocol === 'TCP' ? '6' : '17';
      let ranges;
      try { ranges = parsePorts(data.ports); } catch (e) { throw { kind: 'param', message: e.message }; }
      rulesSpec = ranges.map((pr) => [protoNum, pr, source]);
    }
  }

  const comp = cfg.compartment;
  const vaRes = await ociRequest({
    service: 'iaas', region: cfg.region, method: 'GET',
    urlPath: '/20160918/vnicAttachments?compartmentId=' + encodeURIComponent(comp) + '&instanceId=' + encodeURIComponent(instId),
  }, cfg);
  const vas = respList(vaRes.json);
  const changedSl = [];
  const changedNsg = [];
  const skipped = [];

  for (const va of vas) {
    const vRes = await ociRequest({
      service: 'iaas', region: cfg.region, method: 'GET',
      urlPath: '/20160918/vnics/' + encodeURIComponent(va.vnicId),
    }, cfg);
    const vnic = vRes.json;
    if (!vnic) continue;

    // 1) NSG
    for (const nsgId of (vnic.nsgIds || [])) {
      const rulesRes = await ociRequest({
        service: 'iaas', region: cfg.region, method: 'GET',
        urlPath: '/20160918/networkSecurityGroups/' + encodeURIComponent(nsgId) + '/securityRules',
      }, cfg);
      const existing = respList(rulesRes.json);
      const toAdd = rulesSpec.filter((s) => !nsgHas(existing, direction, s));
      if (!toAdd.length) { skipped.push('NSG ' + nsgId); continue; }
      await ociRequest({
        service: 'iaas', region: cfg.region, method: 'POST',
        urlPath: '/20160918/networkSecurityGroups/' + encodeURIComponent(nsgId) + '/securityRules',
        body: JSON.stringify({ securityRules: toAdd.map((s) => buildNsgRule(direction, s)) }),
      }, cfg);
      changedNsg.push(nsgId);
    }

    // 2) 子网安全列表
    if (!vnic.subnetId) continue;
    const subRes = await ociRequest({
      service: 'iaas', region: cfg.region, method: 'GET',
      urlPath: '/20160918/subnets/' + encodeURIComponent(vnic.subnetId),
    }, cfg);
    const subnet = subRes.json;
    for (const slId of (subnet && subnet.securityListIds) || []) {
      const slRes = await ociRequest({
        service: 'iaas', region: cfg.region, method: 'GET',
        urlPath: '/20160918/securityLists/' + encodeURIComponent(slId),
      }, cfg);
      const sl = slRes.json;
      const ingress = respList(sl && sl.ingressSecurityRules).slice();
      const egress = respList(sl && sl.egressSecurityRules).slice();
      const target = direction === 'INGRESS' ? ingress : egress;
      const toAdd = rulesSpec.filter((s) => !slHas(target, direction, s));
      if (!toAdd.length) { skipped.push('安全列表 ' + slId); continue; }
      target.push(...toAdd.map((s) => buildSlRule(direction, s)));
      await ociRequest({
        service: 'iaas', region: cfg.region, method: 'PUT',
        urlPath: '/20160918/securityLists/' + encodeURIComponent(slId),
        body: JSON.stringify({ ingressSecurityRules: ingress, egressSecurityRules: egress }),
      }, cfg);
      changedSl.push(slId);
    }
  }

  if (!changedSl.length && !changedNsg.length) {
    return { ok: true, message: '未发现需要修改的规则（目标规则可能已全部存在）', skipped: skipped };
  }
  return {
    ok: true,
    message: '已开放：安全列表 ' + changedSl.length + ' 个、NSG ' + changedNsg.length + ' 个',
    security_lists: changedSl,
    nsgs: changedNsg,
    skipped: skipped,
  };
}

/* ---------------- 查看规则 ---------------- */

async function getRules(cfg, instId) {
  const comp = cfg.compartment;
  const vaRes = await ociRequest({
    service: 'iaas', region: cfg.region, method: 'GET',
    urlPath: '/20160918/vnicAttachments?compartmentId=' + encodeURIComponent(comp) + '&instanceId=' + encodeURIComponent(instId),
  }, cfg);
  const vas = respList(vaRes.json);
  const result = { security_lists: [], nsgs: [] };
  const seenSl = new Set();
  const seenNsg = new Set();

  for (const va of vas) {
    const vRes = await ociRequest({
      service: 'iaas', region: cfg.region, method: 'GET',
      urlPath: '/20160918/vnics/' + encodeURIComponent(va.vnicId),
    }, cfg);
    const vnic = vRes.json;
    if (!vnic) continue;

    if (vnic.subnetId) {
      const subRes = await ociRequest({
        service: 'iaas', region: cfg.region, method: 'GET',
        urlPath: '/20160918/subnets/' + encodeURIComponent(vnic.subnetId),
      }, cfg);
      const subnet = subRes.json;
      for (const slId of (subnet && subnet.securityListIds) || []) {
        if (seenSl.has(slId)) continue;
        seenSl.add(slId);
        const slRes = await ociRequest({
          service: 'iaas', region: cfg.region, method: 'GET',
          urlPath: '/20160918/securityLists/' + encodeURIComponent(slId),
        }, cfg);
        const sl = slRes.json;
        result.security_lists.push({
          id: slId,
          display_name: (sl && sl.displayName) || slId,
          subnet: subnet.displayName || null,
          ingress: respList(sl && sl.ingressSecurityRules).map((r) => simplifyRule(r, 'INGRESS')),
          egress: respList(sl && sl.egressSecurityRules).map((r) => simplifyRule(r, 'EGRESS')),
        });
      }
    }

    for (const nsgId of (vnic.nsgIds || [])) {
      if (seenNsg.has(nsgId)) continue;
      seenNsg.add(nsgId);
      const rulesRes = await ociRequest({
        service: 'iaas', region: cfg.region, method: 'GET',
        urlPath: '/20160918/networkSecurityGroups/' + encodeURIComponent(nsgId) + '/securityRules',
      }, cfg);
      const rules = respList(rulesRes.json);
      result.nsgs.push({
        id: nsgId,
        rules: rules.map((r) => simplifyRule(r, r.direction || '?')),
      });
    }
  }
  return result;
}

module.exports = { handle: handle, loadOciConfig: loadOciConfig, setCredsFile: setCredsFile };
