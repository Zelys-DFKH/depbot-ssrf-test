const https = require('https');

// v21: Probe github.authentication.v0.CredentialManager Twirp service
// Discovered: GITHUB_TOKEN JWT has aud="/twirp/github.authentication.v0.CredentialManager/"
// and sub="integration/15368" — this is an internal GitHub Twirp service
// We have a valid JWT intended for this service — can we call it?

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_RUN_ID = process.env.GITHUB_RUN_ID || '';
const GITHUB_ACTOR = process.env.GITHUB_ACTOR || '';
const GITHUB_REPOSITORY_ID = process.env.GITHUB_REPOSITORY_ID || '';

function req(hostname, path, method, auth, body, extraHeaders) {
  return new Promise((resolve) => {
    let data = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;
    const hdrs = {
      'Authorization': 'Bearer ' + auth,
      'Accept': 'application/json',
      'User-Agent': 'probe',
      ...(extraHeaders || {})
    };
    if (data) {
      hdrs['Content-Type'] = 'application/json';
      hdrs['Content-Length'] = Buffer.byteLength(data);
    }
    const r = https.request({ hostname, path, method: method || 'GET', headers: hdrs },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    if (data) r.write(data);
    r.end();
  });
}

function twirpReq(hostname, method, token, body) {
  const path = '/twirp/github.authentication.v0.CredentialManager/' + method;
  return new Promise((resolve) => {
    const data = JSON.stringify(body || {});
    const r = https.request({ hostname, path, method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        'User-Agent': 'probe'
      }
    }, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 500) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(data); r.end();
  });
}

async function main() {
  console.log('=== V21: CredentialManager Twirp Probe ===');
  console.log('Repo:', GITHUB_REPOSITORY, '| Run:', GITHUB_RUN_ID);

  // Extract the JWT part of GITHUB_TOKEN for analysis
  const tokenMatch = GITHUB_TOKEN.match(/^ghs_(\d+)_(.+)$/);
  const tokenId = tokenMatch ? tokenMatch[1] : null;
  console.log('GITHUB_TOKEN format: ghs_' + (tokenId || '?') + '_<JWT416chars>');
  console.log('Token aud: /twirp/github.authentication.v0.CredentialManager/');
  console.log('Token sub: integration/15368');

  // The OIDC host varies; get it
  const oidcHost = OIDC_URL ? new URL(OIDC_URL).hostname : null;
  const poolId = OIDC_URL ? new URL(OIDC_URL).pathname.split('/')[1] : null;
  console.log('OIDC host:', oidcHost, '| Pool:', poolId);

  // === PART 1: Try CredentialManager on the runner host ===
  console.log('\n=== PART 1: CredentialManager on runner host ===');
  if (oidcHost) {
    // Methods we hypothesize exist (based on gRPC/Twirp naming conventions for credential managers)
    const methods = [
      'GetToken',
      'IssueToken',
      'GetCredentials',
      'RefreshToken',
      'ValidateToken',
      'GetInstallationToken',
      'ListTokens',
      'GetJobToken',
      'GetActionToken',
      'GetRepoToken',
      'GetOrgToken',
    ];
    for (const method of methods) {
      const r = await twirpReq(oidcHost, method, GITHUB_TOKEN, {
        repository: GITHUB_REPOSITORY,
        repository_id: GITHUB_REPOSITORY_ID,
        run_id: GITHUB_RUN_ID,
      });
      const status = r.status;
      // 404 bad_route = method doesn't exist
      // 401/403 = method exists but we're not authorized
      // 400 = method exists, wrong params
      // 200 = !!!
      if (status !== 'ERR') {
        const label = r.body.includes('bad_route') ? '404(no-route)' : String(status);
        console.log('[CRED_RUNNER] ' + method + ': ' + label + ' | ' + r.body.substring(0, 150));
      }
    }
  }

  // === PART 2: Try CredentialManager on api.github.com ===
  console.log('\n=== PART 2: CredentialManager on api.github.com ===');
  const apiMethods = ['GetToken', 'IssueToken', 'GetInstallationToken', 'GetCredentials'];
  for (const method of apiMethods) {
    const r = await twirpReq('api.github.com', method, GITHUB_TOKEN, {});
    console.log('[CRED_API] ' + method + ': ' + r.status + ' | ' + r.body.substring(0, 150));
  }

  // === PART 3: Try CredentialManager on github.com ===
  console.log('\n=== PART 3: CredentialManager on github.com ===');
  const ghMethods = ['GetToken', 'IssueToken', 'GetInstallationToken'];
  for (const method of ghMethods) {
    const r = await twirpReq('github.com', method, GITHUB_TOKEN, {});
    console.log('[CRED_GH] ' + method + ': ' + r.status + ' | ' + r.body.substring(0, 150));
  }

  // === PART 4: Try OIDC token against CredentialManager ===
  // Maybe OIDC_TOKEN (not GITHUB_TOKEN) is what CredentialManager expects
  console.log('\n=== PART 4: CredentialManager with OIDC_TOKEN ===');
  if (oidcHost && OIDC_TOKEN) {
    for (const method of ['GetToken', 'IssueToken', 'GetInstallationToken']) {
      const r = await twirpReq(oidcHost, method, OIDC_TOKEN, {});
      const label = r.body.includes('bad_route') ? '404(no-route)' : String(r.status);
      console.log('[CRED_OIDC] ' + method + ': ' + label + ' | ' + r.body.substring(0, 150));
    }
  }

  // === PART 5: Check if the runner-service pool accepts arbitrary method names ===
  // At /{poolId}// we know: /secrets → HMAC, /health → 200
  // Does /credentials exist without HMAC? Does /token?
  console.log('\n=== PART 5: Runner service credential/token endpoints ===');
  if (oidcHost && poolId) {
    const basePath = '/' + poolId + '//';
    const credPaths = [
      'credentials',
      'token',
      'tokens',
      'actions-token',
      'installation-token',
      'access-token',
      'oauth-token',
    ];
    for (const p of credPaths) {
      const r = await req(oidcHost, basePath + p, 'GET', GITHUB_TOKEN);
      const hmacRequired = r.body.includes('hmac is missing');
      const label = hmacRequired ? 'HMAC_REQUIRED' : String(r.status);
      if (!hmacRequired || r.status !== 400) {
        console.log('[RUNNER_CRED] ' + p + ': ' + label + ' | ' + r.body.substring(0, 150));
      } else {
        console.log('[RUNNER_CRED] ' + p + ': HMAC_REQUIRED(400)');
      }
    }
  }

  // === PART 6: What is azc claim "site/19454198618"? ===
  // Hypothesis: 19454198618 is the GitHub Actions app installation ID on github.com
  // Let's verify by checking GitHub API for installation info
  console.log('\n=== PART 6: Integration/installation ID analysis ===');
  const integrationId = 15368;  // from aid/sub in JWT
  const siteId = 19454198618;   // from azc claim

  // Check if integration 15368 is a GitHub App
  const appR = await req('api.github.com', '/apps/' + integrationId, 'GET', GITHUB_TOKEN);
  console.log('[APP] /apps/' + integrationId + ':', appR.status, '|', appR.body.substring(0, 200));

  // Check the GitHub Actions app specifically
  const actionsAppR = await req('api.github.com', '/apps/github-actions', 'GET', GITHUB_TOKEN);
  console.log('[APP] /apps/github-actions:', actionsAppR.status, '|', actionsAppR.body.substring(0, 200));

  // Check installation
  const installR = await req('api.github.com', '/app/installations/' + siteId, 'GET', GITHUB_TOKEN);
  console.log('[INSTALL] /app/installations/' + siteId + ':', installR.status, '|', installR.body.substring(0, 200));

  // === PART 7: Can GITHUB_TOKEN JWT authenticate to any Actions service we know about? ===
  console.log('\n=== PART 7: GITHUB_TOKEN on known Twirp services ===');
  if (oidcHost) {
    // Test known Twirp services on the runner host with GITHUB_TOKEN
    const services = [
      'github.actions.results.api.v1.ArtifactService/ListArtifacts',
      'github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',
      'github.actions.results.api.v1.LogService/GetStepSummary',
    ];
    for (const svc of services) {
      const r = await new Promise((resolve) => {
        const data = JSON.stringify({});
        const p = '/' + poolId + '//' + svc;  // Use the pool prefix
        const r2 = https.request({ hostname: oidcHost, path: p, method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + GITHUB_TOKEN,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(data)
          }
        }, (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 200) })); });
        r2.on('error', e => resolve({ status: 'ERR', body: e.message }));
        r2.write(data); r2.end();
      });
      console.log('[TWIRP_GHT] ' + svc.split('/').pop() + ': ' + r.status + ' | ' + r.body.substring(0, 100));
    }
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message));
