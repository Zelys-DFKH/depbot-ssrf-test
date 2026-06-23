const fs = require('fs');
const { execSync } = require('child_process');
const os = require('os');

// v34: DEFINITIVE VM reuse proof
// v33 wrote markers to: /home/runner/vm_reuse_marker, /opt/hca/vm_reuse_marker,
//   /home/runner/.vm_marker, /opt/hca/.vm_marker, /var/log/vm_reuse_marker
// v33 vmId = ff0811e2-b902-470b-9fe1-418c31d20463
// v33 boot_id = 32d6f066-852c-4209-97a4-6c088fb1b1a8
// v33 hostname = runnervm7b5n9 (same as v31, v32)
// IF SAME AZURE vmId → IRREFUTABLE: same physical VM instance, proves VM reuse

const V33_VMID = 'ff0811e2-b902-470b-9fe1-418c31d20463';
const V33_BOOTID = '32d6f066-852c-4209-97a4-6c088fb1b1a8';

function run(cmd, timeoutMs) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: timeoutMs || 20000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 400).trim(); }
}

async function main() {
  console.log('=== V34: DEFINITIVE VM reuse proof via Azure vmId + persistent file markers ===');
  const hostname = os.hostname();
  const ts = Date.now();
  const run_id = process.env.GITHUB_RUN_ID || 'unknown';

  console.log('[V34] hostname:', hostname, '(v33 was runnervm7b5n9 — match?', hostname === 'runnervm7b5n9', ')');

  // === PART 1: Azure IMDS — vmId comparison ===
  console.log('\n=== PART 1: Azure IMDS vmId (definitive VM identity) ===');
  const imds = run('curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null');
  let currentVmId = null;
  let currentVmName = null;
  if (imds && !imds.startsWith('ERR')) {
    try {
      const meta = JSON.parse(imds);
      const c = meta.compute || {};
      currentVmId = c.vmId;
      currentVmName = c.name;
      console.log('[VMID] Current vmId:', currentVmId);
      console.log('[VMID] Current name:', currentVmName);
      console.log('[VMID] v33 vmId:', V33_VMID);
      if (currentVmId === V33_VMID) {
        console.log('[VMID] *** SAME AZURE VM INSTANCE — IRREFUTABLE VM REUSE CONFIRMED ***');
        console.log('[VMID] Same physical Azure VM served both v33 and v34 jobs');
      } else {
        console.log('[VMID] Different vmId — different physical Azure VM (but same hostname pool name)');
      }
    } catch(e) {
      console.log('[VMID] IMDS parse error:', e.message, '| raw:', imds.substring(0, 200));
    }
  } else {
    console.log('[VMID] IMDS unavailable');
  }

  // === PART 2: boot_id comparison ===
  console.log('\n=== PART 2: boot_id (same kernel boot = same VM boot) ===');
  const currentBootId = run('cat /proc/sys/kernel/random/boot_id 2>/dev/null');
  console.log('[BOOTID] Current boot_id:', currentBootId);
  console.log('[BOOTID] v33 boot_id:', V33_BOOTID);
  if (currentBootId === V33_BOOTID) {
    console.log('[BOOTID] *** SAME KERNEL BOOT — VM REUSE CONFIRMED (no reboot between v33 and v34) ***');
  } else {
    console.log('[BOOTID] Different boot_id — VM was rebooted/replaced between v33 and v34');
  }

  // === PART 3: Persistent file markers from v33 ===
  console.log('\n=== PART 3: Persistent file markers from v33 ===');
  const persistentPaths = [
    '/home/runner/vm_reuse_marker',
    '/opt/hca/vm_reuse_marker',
    '/home/runner/.vm_marker',
    '/opt/hca/.vm_marker',
    '/var/log/vm_reuse_marker',
    '/home/runner/.boot_id',
  ];

  let markersFound = 0;
  for (const p of persistentPaths) {
    const exists = fs.existsSync(p);
    console.log('[MARKER] ' + p + ' exists:', exists);
    if (exists) {
      markersFound++;
      const content = fs.readFileSync(p, 'utf8').trim();
      console.log('[MARKER]   content:', content.substring(0, 200));
    }
  }
  console.log('[MARKER] Total markers found from v33:', markersFound, '/', persistentPaths.length);

  // === PART 4: Summary of VM reuse evidence ===
  console.log('\n=== PART 4: EVIDENCE SUMMARY ===');
  console.log('[EVIDENCE] hostname match (v33=v34):', hostname === 'runnervm7b5n9');
  console.log('[EVIDENCE] vmId match (same Azure VM):', currentVmId === V33_VMID);
  console.log('[EVIDENCE] boot_id match (same kernel boot):', currentBootId === V33_BOOTID);
  console.log('[EVIDENCE] persistent markers found:', markersFound > 0);

  if (currentVmId === V33_VMID) {
    console.log('[EVIDENCE] VERDICT: *** VM REUSE PROVEN — SAME AZURE VM SERVED MULTIPLE JOBS ***');
    console.log('[EVIDENCE] Attack chain complete: replace HCA + delete dirty flag → VM reused → malicious HCA runs for next tenant');
  } else if (currentBootId === V33_BOOTID) {
    console.log('[EVIDENCE] VERDICT: Same kernel boot, different vmId — containerization or snapshot restore possible');
  } else if (hostname === 'runnervm7b5n9') {
    console.log('[EVIDENCE] VERDICT: Same hostname pool, fresh VM provisioned each run — hostname is a pool label not a VM ID');
  }

  // === PART 5: Current /opt/hca/ state ===
  console.log('\n=== PART 5: Current state ===');
  console.log('[STATE] HCA binary MD5:', run('md5sum /opt/hca/hosted-compute-agent 2>/dev/null'));
  console.log('[STATE] environment.dirty exists:', fs.existsSync('/opt/hca/environment.dirty'));
  console.log('[STATE] /opt/hca/ listing:');
  console.log(run('ls -la /opt/hca/ 2>/dev/null'));
  console.log('[STATE] /home/runner/ listing:');
  console.log(run('ls -la /home/runner/ 2>/dev/null | head -20'));

  // === PART 6: systemd unit file (what handles VM lifecycle?) ===
  console.log('\n=== PART 6: systemd hosted-compute-agent.service unit ===');
  const unit = run('sudo systemctl cat hosted-compute-agent.service 2>/dev/null');
  console.log('[SYSTEMD]', unit.substring(0, 3000));

  // === PART 7: ExecStartPre / cleanup scripts ===
  console.log('\n=== PART 7: Cleanup scripts ===');
  const cleanupScripts = run('sudo find /opt /etc/systemd /usr/local/bin -name "*clean*" -o -name "*setup*" -o -name "*prepare*" 2>/dev/null | head -10');
  console.log('[CLEANUP] Scripts:', cleanupScripts);

  // Check if there's a runner cleanup step
  const runnerCleanup = run('sudo find /home/runner/actions-runner -name "*.sh" 2>/dev/null | head -10');
  console.log('[CLEANUP] Runner scripts:', runnerCleanup);

  console.log('\n=== V34 Complete ===');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
