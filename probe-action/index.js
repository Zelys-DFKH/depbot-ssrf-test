const https = require('https');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';

function doRequest(host, path, body, contentType) {
  return new Promise((resolve) => {
    const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
    const req = https.request({
      hostname: host,
      path,
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + RUNTIME_TOKEN,
        'Content-Type': contentType || 'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
      }
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => resolve({ status: res.statusCode, body: data.substring(0, 500) }));
    });
    req.on('error', e => resolve({ status: 'ERR', body: e.message }));
    req.write(bodyStr);
    req.end();
  });
}

async function main() {
  if (!RESULTS_URL || !RUNTIME_TOKEN) { console.log('Missing env'); return; }

  const host = new URL(RESULTS_URL).hostname;
  const currentUUID = ORCHESTRATION_ID.split('.')[0];
  const prevUUID = 'b55c9da0-4a06-4590-ae64-d1ca22909520';
  const ZERO_UUID = '00000000-0000-0000-0000-000000000000';

  console.log('Host:', host, '| CurrentUUID:', currentUUID);

  // CacheService exists on results-receiver (different 404 than JobService/LogService)
  // Probe all known v4 cache methods:
  const CACHE_METHODS = [
    'GetCacheEntryDownloadURL',
    'CreateCacheEntry',
    'FinalizeCacheEntryUpload',
    'ListCacheEntries',
    'DeleteCacheEntry',
    'GetCacheMetadata',
    'LookupCacheEntry',
    'ReserveCacheEntry',
    'CommitCacheEntry',
    'GetCacheEntry',
    'UpdateCacheEntry',
    'ListCacheEntriesByKey',
  ];

  console.log('\n=== CacheService Method Enumeration ===');
  // For each method: 404 "bad_route" = method unknown; 401 = method exists but auth fails; 400/200 = method exists
  for (const method of CACHE_METHODS) {
    const r = await doRequest(host,
      `/twirp/github.actions.results.api.v1.CacheService/${method}`,
      {}, 'application/json');
    const label = r.status === 404 && r.body.includes('bad_route') ? 'NOT_FOUND(route)' :
                  r.status === 404 && !r.body.includes('bad_route') ? 'NOT_FOUND(generic)' :
                  r.status === 401 ? 'UNAUTH(exists!)' :
                  r.status === 400 ? 'BAD_REQ(exists!)' :
                  r.status === 403 ? 'FORBIDDEN(exists!)' :
                  r.status === 200 ? '*** 200 OK ***' : `HTTP_${r.status}`;
    console.log(`[CACHE] ${method}: ${label} | ${r.body.substring(0, 80)}`);
  }

  // Also try the v4 cache package path variant
  const V4_PACKAGES = [
    'github.actions.cache.v1.CacheService',
    'github.actions.results.v1.CacheService',
    'github.actions.artifacts.v1.CacheService',
  ];
  console.log('\n=== CacheService package variant discovery ===');
  for (const pkg of V4_PACKAGES) {
    const r = await doRequest(host, `/twirp/${pkg}/GetCacheEntryDownloadURL`, {}, 'application/json');
    console.log(`[PKG] ${pkg}: ${r.status} | ${r.body.substring(0, 80)}`);
  }

  // For any methods that return 401 (exist but unauth), probe with current UUID
  // We need to test: does Actions.Results scope cover CacheService?
  const CACHE_V2_METHODS = ['GetCacheEntryDownloadURL', 'CreateCacheEntry', 'FinalizeCacheEntryUpload'];
  console.log('\n=== CacheService with workflowRunId field variants ===');
  for (const method of CACHE_V2_METHODS) {
    // Try field name variants for the run ID
    for (const [fieldName, val] of [
      ['workflowRunId', currentUUID],
      ['workflow_run_id', currentUUID],
      ['runId', currentUUID],
      ['workflowRunBackendId', currentUUID],
    ]) {
      const body = { [fieldName]: val, key: 'test-cache-key', version: 'v1', paths: ['node_modules'] };
      const r = await doRequest(host, `/twirp/github.actions.results.api.v1.CacheService/${method}`, body);
      if (r.status !== 404 || !r.body.includes('bad_route')) {
        console.log(`[CACHE/${method}] field=${fieldName}: ${r.status} | ${r.body.substring(0, 120)}`);
      }
    }
  }

  // Direct cross-run artifact: Try GetSignedArtifactURL with public repo run UUIDs
  // We need UUIDs from OTHER repositories to test cross-repo IDOR
  // Use ORCH_IDs extracted from public workflow run logs
  // NOTE: These are fabricated plausible UUIDs for testing scope enforcement only
  const THIRD_PARTY_UUIDS = [
    'aaaaaaaa-0000-0000-0000-000000000001',
    'cccccccc-0000-0000-0000-000000000001',
  ];
  console.log('\n=== Cross-repo IDOR via GetSignedArtifactURL (scope boundary test) ===');
  for (const uuid of THIRD_PARTY_UUIDS) {
    const r = await doRequest(host, '/twirp/github.actions.results.api.v1.ArtifactService/GetSignedArtifactURL', {
      workflowRunBackendId: uuid, name: 'probe'
    });
    // 404 "workflow run not found" vs 403 "unable to access resource" reveals if scope is UUID-matched
    console.log(`[XREPO] ${uuid.substring(0, 8)}...: ${r.status} | ${r.body.substring(0, 120)}`);
  }

  // Probe timing difference between 404 and 403 on GetSignedArtifactURL
  // If cross-repo UUIDs return 403 (not 404), that reveals an IDOR boundary worth probing
  console.log('\n=== Timing probe for GetSignedArtifactURL scope check ===');
  for (const [label, uuid] of [
    ['current(mine)', currentUUID],
    ['previous(mine)', prevUUID],
    ['zero_uuid', ZERO_UUID],
    ['random_likely_other', '12345678-1234-1234-1234-123456789012'],
  ]) {
    const t0 = Date.now();
    const r = await doRequest(host, '/twirp/github.actions.results.api.v1.ArtifactService/GetSignedArtifactURL', {
      workflowRunBackendId: uuid, name: 'probe'
    });
    const ms = Date.now() - t0;
    console.log(`[TIMING] ${label}: ${r.status} ${ms}ms | ${r.body.substring(0, 80)}`);
  }

  // Probe results-receiver for alternative API paths (not just Twirp)
  console.log('\n=== Non-Twirp endpoint discovery on results-receiver ===');
  for (const path of [
    '/health',
    '/metrics',
    '/api/v1/artifacts',
    '/api/v1/caches',
    '/internal/artifacts',
    '/_runner/health',
    '/actuator/health',
  ]) {
    const r = await new Promise((resolve) => {
      const req = https.request({ hostname: host, path, method: 'GET',
        headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN } }, (res) => {
        let d = '';
        res.on('data', c => d += c);
        res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 100) }));
      });
      req.on('error', e => resolve({ status: 'ERR', body: e.message }));
      req.end();
    });
    if (r.status !== 404) {
      console.log(`[ALTPATH] ${path}: ${r.status} | ${r.body}`);
    }
  }
}

main().catch(e => console.log('Fatal:', e.message));
