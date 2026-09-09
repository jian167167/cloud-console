#!/usr/bin/env node
/**
 * Telegram 操作通知模块（零依赖，仅 Node.js 内置模块）
 *
 * 配置按账号隔离存储：<DATA_DIR>/users/<用户名>/telegram.json
 *   { enabled: bool, bot_token: string, chat_id: string, api_base: string }
 *
 * api_base 默认 api.telegram.org；如果运行环境无法直连 Telegram，
 * 可填自己的反代域名（如 tg.example.com，服务端会访问 https://<api_base>/bot<token>/sendMessage）。
 *
 * notify() 静默失败：通知发送失败绝不影响面板操作本身。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const https = require('https');

let DATA_DIR = process.cwd();

function setDataDir(d) {
  if (d) DATA_DIR = d;
}

function tgFile(user) {
  return path.join(DATA_DIR, 'users', user, 'telegram.json');
}

/** 读取配置；文件缺失或损坏时返回默认值 */
function load(user) {
  const def = { enabled: false, bot_token: '', chat_id: '', api_base: 'api.telegram.org' };
  try {
    const c = JSON.parse(fs.readFileSync(tgFile(user), 'utf8'));
    return {
      enabled: !!c.enabled,
      bot_token: String(c.bot_token || ''),
      chat_id: String(c.chat_id || ''),
      api_base: String(c.api_base || '').trim() || 'api.telegram.org',
    };
  } catch (e) {
    return def;
  }
}

/** 保存配置；token 留空表示保持不变 */
function save(user, cfg) {
  fs.mkdirSync(path.dirname(tgFile(user)), { recursive: true });
  const prev = load(user);
  const next = {
    enabled: !!cfg.enabled,
    bot_token: cfg.bot_token !== undefined && String(cfg.bot_token).trim() !== '' ? String(cfg.bot_token).trim() : prev.bot_token,
    chat_id: cfg.chat_id !== undefined && String(cfg.chat_id).trim() !== '' ? String(cfg.chat_id).trim() : prev.chat_id,
    api_base: cfg.api_base !== undefined && String(cfg.api_base).trim() !== '' ? String(cfg.api_base).trim().replace(/^https?:\/\//, '') : prev.api_base,
  };
  try {
    fs.writeFileSync(tgFile(user), JSON.stringify(next, null, 2), { encoding: 'utf8', mode: 0o600 });
  } catch (e) {
    throw new Error('写入电报配置失败：' + e.message);
  }
  return next;
}

/** 实际发送（不校验 enabled；由 notify 控制开关） */
function sendHttp(apiBase, token, chatId, text, cb) {
  const payload = JSON.stringify({ chat_id: chatId, text: text, disable_web_page_preview: true });
  const req = https.request({
    hostname: apiBase,
    port: 443,
    method: 'POST',
    path: '/bot' + token + '/sendMessage',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
    },
  }, (res) => {
    let d = '';
    res.on('data', (chunk) => { d += chunk; });
    res.on('end', () => { try { cb(null, res.statusCode || 500, d); } catch (e) { /* noop */ } });
  });
  req.setTimeout(15000, () => { req.destroy(new Error('Telegram 请求超时（15 秒）')); });
  req.on('error', (e) => { try { cb(e); } catch (err) { /* noop */ } });
  req.write(payload);
  req.end();
}

/**
 * 发送通知。
 * force=true 时忽略 enabled 开关（用于“测试发送”），但 token / chat_id 必须已配置。
 * 未配置或未启用时不会发送，也不抛错。
 */
function notify(user, text, cb, force) {
  const c = load(user);
  const done = cb || function () {};
  if (!c.bot_token || !c.chat_id) {
    try { done(new Error('未配置机器人 Token 或 Chat ID')); } catch (e) { /* noop */ }
    return false;
  }
  if (!force && !c.enabled) {
    try { done(null, null); } catch (e) { /* noop */ }
    return false;
  }
  sendHttp(c.api_base, c.bot_token, c.chat_id, String(text || ''), done);
  return true;
}

/** Token 脱敏：AK…XYZ */
function safeTail(t) {
  const s = String(t || '');
  if (!s) return '';
  return s.length > 8 ? s.slice(0, 3) + '…' + s.slice(-3) : '***';
}

/** 北京时间（UTC+8）格式化 */
function fmtNow() {
  const d = new Date(Date.now() + 8 * 3600 * 1000);
  return d.toISOString().replace('T', ' ').slice(0, 19);
}

module.exports = { setDataDir, load, save, notify, sendHttp, safeTail, fmtNow };
