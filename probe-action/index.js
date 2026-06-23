const https = require('https');

// First: dump all ACTIONS_* and GITHUB_* env vars to find what's available
console.log('=== V15b: Environment Variable Discovery ===');
const envKeys = Object.keys(process.env).sort();
for (const k of envKeys) {
  if (/^(ACTIONS|GITHUB|RUNNER)/.test(k)) {
    const v = process.env[k] || '';
    const preview = v.length > 80 ? v.substring(0, 80) + '...(len=' + v.length + ')' : v;
    console.log('[ENV] ' + k + '=' + preview);
  }
}

// Try various possible names for the results/runtime token
const RESULTS_URL = process.env.ACTIONS_RESULTS_URL 
                 || process.env.ACTIONS_RUNTIME_URL
                 || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN 
                   || process.env.ACTIONS_RESULTS_TOKEN
                   || '';

console.log('\nResults URL candidate:', RESULTS_URL ? RESULTS_URL.substring(0, 80) : 'NOT FOUND');
console.log('Runtime token present:', RUNTIME_TOKEN ? 'YES len=' + RUNTIME_TOKEN.length : 'NOT FOUND');

if (!RESULTS_URL || !RUNTIME_TOKEN) {
  console.log('Missing critical env vars. Check [ENV] lines above.');
  process.exit(0);
}

// Try a basic CacheService call
const host = new URL(RESULTS_URL).hostname;
console.log('\nHost:', host);
const s = JSON.stringify({ key: 'test', version: 'v1' });
const req = https.request({
  hostname: host,
  path: '/twirp/github.actions.results.api.v1.CacheService/GetCacheEntryDownloadURL',
  method: 'POST',
  headers: { 'Authorization': 'Bearer ' + RUNTIME_TOKEN, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(s) }
}, (res) => { let d=''; res.on('data', c=>d+=c); res.on('end', () => console.log('[TEST] CacheService:', res.statusCode, d.substring(0, 200))); });
req.on('error', e => console.log('[TEST] Error:', e.message));
req.write(s); req.end();
