#!/usr/bin/env node
// Only GETs allowlisted local endpoints. Never launches apps or sends test traffic.
'use strict';
const fs = require('node:fs');
const http = require('node:http');

function args(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith('--') || !argv[i + 1] || argv[i + 1].startsWith('--')) throw Error('Invalid arguments');
    const key = argv[i].slice(2);
    if (!['plan', 'controller', 'socket', 'token-file', 'duration', 'output', 'snapshot'].includes(key) || key in out) throw Error('Invalid arguments');
    out[key] = argv[i + 1];
  }
  return out;
}
function loadJSON(file) {
  if (fs.statSync(file).size > 16 * 1024 * 1024) throw Error('Input too large');
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}
function validatePlan(plan, live = false) {
  if (plan.schema_version !== 1 || !['global', 'rule', 'direct'].includes(plan.mode) || !Array.isArray(plan.test_targets) || !plan.test_targets.length || plan.test_targets.length > 32) throw Error('Invalid plan');
  if (!plan.test_targets.every(h => typeof h === 'string' && h.length <= 253 && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(h))) throw Error('Invalid test targets');
  if (plan.claude?.session_policy !== 'do-not-touch-existing' || !['private-or-isolated', 'none'].includes(plan.claude?.web_test_context)) throw Error('Unsafe session policy');
  if (typeof plan.claude?.group !== 'string' || !plan.claude.group || typeof plan.claude.allow_failover !== 'boolean' || plan.claude.failure_action !== 'reject') throw Error('Invalid route intent');
  if (plan.claude.listener != null && typeof plan.claude.listener !== 'string') throw Error('Invalid listener intent');
  if (live && (plan.status !== 'ready' || plan.authorization?.local_read !== true)) throw Error('Record local-read authorization first');
  return plan;
}
function transport(options) {
  if (Boolean(options.controller) === Boolean(options.socket)) throw Error('Choose one local transport');
  if (options.socket) {
    if (!(options.socket.startsWith('\\\\.\\pipe\\') || options.socket.startsWith('/'))) throw Error('Explicit local socket required');
    return { socketPath: options.socket };
  }
  const url = new URL(options.controller);
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw Error('Literal loopback HTTP controller required');
  return { hostname: url.hostname.replace(/[\[\]]/g, ''), port: url.port || 80 };
}
function makeGet(options, token = '') {
  const destination = transport(options);
  return endpoint => new Promise((resolve, reject) => {
    if (!['/version', '/configs', '/proxies', '/connections'].includes(endpoint)) return reject(Error('Endpoint not allowed'));
    const request = http.request({ ...destination, path: endpoint, method: 'GET', agent: false,
      headers: token ? { Authorization: 'Bearer ' + token } : {} }, response => {
      let size = 0; const chunks = [];
      response.on('data', chunk => { size += chunk.length; if (size > 16 * 1024 * 1024) request.destroy(Error('Response too large')); else chunks.push(chunk); });
      response.on('error', () => reject(Error('Local response failed')));
      response.on('end', () => {
        if (response.statusCode !== 200) return reject(Error('Local API HTTP ' + response.statusCode));
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(Error('Invalid local JSON')); }
      });
    });
    const deadline = setTimeout(() => request.destroy(Error('Local API deadline')), 5000);
    request.on('close', () => clearTimeout(deadline));
    request.on('error', () => reject(Error('Local API unavailable')));
    request.end();
  });
}
function summarize(raw, plan, startedAt, scope = 'offline-fixture') {
  const proxies = raw.proxies?.proxies || {};
  const entries = Object.entries(proxies);
  const ids = new Map(entries.map(([name, p], i) => [name, ['DIRECT', 'REJECT', 'REJECT-DROP', 'GLOBAL'].includes(name) ? name : (p.all ? 'group-' : 'node-') + (i + 1)]));
  const ref = name => ids.get(name) || (['DIRECT', 'REJECT', 'REJECT-DROP', 'GLOBAL'].includes(name) ? name : 'UNRESOLVED');
  const allowedTypes = new Set(['Selector', 'Fallback', 'URLTest', 'LoadBalance', 'Relay', 'Direct', 'Reject']);
  const groups = entries.filter(([, p]) => Array.isArray(p.all)).map(([name, p]) => ({
    id: ref(name), type: allowedTypes.has(p.type) ? p.type : 'other', selected: ref(p.now),
    members: p.all.map(ref), is_expected: name === plan.claude.group,
  }));
  const targets = new Set(plan.test_targets.map(h => h.toLowerCase()));
  const inboundIDs = new Map();
  const rows = [];
  for (const connection of raw.connections?.connections || []) {
    const m = connection.metadata || {}, host = typeof m.host === 'string' ? m.host.toLowerCase() : '';
    if (!targets.has(host)) continue;
    const inbound = m.inboundName;
    if (typeof inbound === 'string' && !inboundIDs.has(inbound)) inboundIDs.set(inbound, 'inbound-' + (inboundIDs.size + 1));
    const date = typeof connection.start === 'string' && /^\d{4}-\d\d-\d\dT/.test(connection.start) ? Date.parse(connection.start) : NaN;
    rows.push({ target: host, network: ['tcp', 'udp'].includes(m.network) ? m.network : 'unknown',
      inbound_type: ['Tun', 'HTTP', 'HTTPS', 'Socks5', 'Inner'].includes(m.type) ? m.type : 'other',
      inbound_id: inboundIDs.get(inbound) || null,
      expected_inbound: plan.claude.listener == null ? null : (typeof inbound === 'string' ? inbound === plan.claude.listener : null),
      chains: Array.isArray(connection.chains) ? connection.chains.map(ref) : [],
      lifetime: Number.isFinite(date) && date <= Date.now() + 1000 ? (date >= Date.parse(startedAt) ? 'started_after_capture' : 'preexisting') : 'start_unknown' });
  }
  const cfg = raw.configs || {}, tun = cfg.tun || {};
  const flag = v => typeof v === 'boolean' ? v : null;
  const hijack = Array.isArray(tun['dns-hijack']) ? tun['dns-hijack'] : [];
  const version = raw.version?.version;
  return { schema_version: 1, source: scope, observed_at: new Date().toISOString(), capture_started_at: startedAt,
    core_version: typeof version === 'string' && /^v?\d+\.\d+\.\d+(?:[-+][a-z0-9.-]{1,64})?$/i.test(version) ? version : null,
    ipv6: flag(cfg.ipv6), allow_lan: flag(cfg['allow-lan']),
    mode: ['global', 'rule', 'direct'].includes(cfg.mode) ? cfg.mode : 'unknown',
    tun: Object.fromEntries(['enable', 'auto-route', 'strict-route'].map(k => [k, flag(tun[k])])),
    dns_hijack: { udp53: hijack.includes('any:53') || hijack.includes('udp://any:53'), tcp53: hijack.includes('tcp://any:53') },
    groups, expected_group_id: ids.get(plan.claude.group) || null,
    connections: rows, limits: ['No requests generated; no apps or logged-in sessions opened.', 'No remote reachability, account, DNS-leak or kill-switch claim.'] };
}
async function collect(options, plan) {
  const duration = options.duration == null ? 5 : Number(options.duration);
  if (!Number.isFinite(duration) || duration < 0 || duration > 60) throw Error('Duration must be 0..60 seconds');
  if (options.snapshot) {
    if (options.controller || options.socket || options['token-file']) throw Error('Offline snapshot cannot use a controller');
    return summarize(loadJSON(options.snapshot), plan, new Date().toISOString());
  }
  validatePlan(plan, true);
  let token = '';
  if (options['token-file']) {
    if (fs.statSync(options['token-file']).size > 8192) throw Error('Token file too large');
    token = fs.readFileSync(options['token-file'], 'utf8').trim();
    if (/[\r\n]/.test(token)) throw Error('Invalid token');
  }
  const get = makeGet(options, token), start = new Date().toISOString(), stop = Date.now() + duration * 1000;
  const version = await get('/version');
  const raw = { version, configs: await get('/configs'), proxies: await get('/proxies'), connections: { connections: [] } };
  const initialShape = JSON.stringify({ configs: raw.configs, proxies: Object.entries(raw.proxies.proxies || {}).map(([n,p]) => [n,p.type,p.now,p.all]) });
  const samples = new Map();
  do {
    const current = await get('/connections');
    const summary = summarize({ ...raw, connections: current }, plan, start, 'local-api');
    for (const row of summary.connections) samples.set(JSON.stringify(row), row);
    if (Date.now() < stop) await new Promise(r => setTimeout(r, 250));
  } while (Date.now() < stop);
  // Read current state at the end, so a mode change during sampling is not hidden.
  raw.configs = await get('/configs'); raw.proxies = await get('/proxies');
  const result = summarize(raw, plan, start, 'local-api');
  result.state_changed_during_capture = initialShape !== JSON.stringify({ configs: raw.configs, proxies: Object.entries(raw.proxies.proxies || {}).map(([n,p]) => [n,p.type,p.now,p.all]) });
  result.connections = [...samples.values()];
  return result;
}
module.exports = { args, validatePlan, transport, makeGet, summarize, collect };
if (require.main === module) (async () => {
  const options = args(process.argv.slice(2));
  if (!options.plan) throw Error('Plan required');
  const plan = validatePlan(loadJSON(options.plan));
  const result = await collect(options, plan);
  const encoded = JSON.stringify(result, null, 2) + '\n';
  if (options.output) fs.writeFileSync(options.output, encoded, { flag: 'wx' }); else process.stdout.write(encoded);
})().catch(() => { process.stderr.write('Runtime collection failed; no credentials or raw API data were printed.\n'); process.exitCode = 1; });
