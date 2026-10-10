import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { watch } from 'node:fs';
import { mkdtemp, readFile, writeFile, readdir, rm, utimes } from 'node:fs/promises';
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { createServer, connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { bls12_381 } from '@noble/curves/bls12-381.js';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dst = 'LEIOS_ARTIFACT_UPLOAD_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';
const bls = bls12_381.shortSignatures;
const secret = Buffer.alloc(32);
secret[31] = 1; // Public test scalar, never an operational key.
const hex = bytes => Buffer.from(bytes).toString('hex');
const key = hex(bls.getPublicKey(secret).toBytes());
const pool = 'ab'.repeat(28);
const freshId = () => randomBytes(16).toString('hex');

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required; start nix run .#floci-dev first`);
  return value;
}

const endpoint = requiredEnv('INBOX_S3_ENDPOINT');
assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(endpoint).hostname), 'smoke writes only to a loopback S3 emulator endpoint');
const bucket = requiredEnv('INBOX_S3_BUCKET');
const region = requiredEnv('INBOX_S3_REGION');
requiredEnv('AWS_ACCESS_KEY_ID');
requiredEnv('AWS_SECRET_ACCESS_KEY');
const serverCommand = process.env.INBOX_SERVER_COMMAND
  ? process.env.INBOX_SERVER_COMMAND.trim().split(/\s+/)
  : ['mix', 'run', '--no-halt']; // Developer launcher; packaged smoke selects the release explicitly.
const signer = requiredEnv('UKETSUKE_SIGN');
const awsEnv = { ...process.env, AWS_DEFAULT_REGION: region, AWS_EC2_METADATA_DISABLED: 'true' };

function aws(...args) {
  return execFileSync('aws', ['--endpoint-url', endpoint, '--region', region, 's3api', ...args], {
    env: awsEnv, encoding: 'utf8', timeout: 30000,
  });
}

function authentication(manifest, signingKey = secret, domain = dst) {
  const bytes = Buffer.isBuffer(manifest) ? manifest : Buffer.from(JSON.stringify(manifest));
  return {
    'x-upload-manifest': bytes.toString('base64'),
    'x-upload-key': hex(bls.getPublicKey(signingKey).toBytes()),
    'x-upload-signature': hex(bls.sign(bls.hash(bytes, domain), signingKey).toBytes()),
  };
}

async function freePort() {
  const socket = createServer();
  socket.listen(0, '127.0.0.1');
  await once(socket, 'listening');
  const port = socket.address().port;
  await new Promise((resolve, reject) => socket.close(error => error ? reject(error) : resolve()));
  return port;
}

async function awaitStagingRemoval(path, id) {
  return new Promise((resolve, reject) => {
    const watcher = watch(path, () => void check());
    const timer = setTimeout(() => finish(new Error(`staging leaked for ${id}`)), 5000);
    function finish(error) {
      clearTimeout(timer);
      watcher.close();
      error ? reject(error) : resolve();
    }
    async function check() {
      try {
        if (!(await readdir(path)).some(name => name.startsWith(id))) finish();
      } catch (error) { finish(error); }
    }
    void check();
  });
}

// Forwards requests to the S3 emulator verbatim (SigV4 signs the proxy's Host),
// answering 503 instead for requests matching `fail`.
async function faultProxy(fail) {
  const upstream = new URL(endpoint);
  let failures = 0;
  const proxy = createHttpServer((req, res) => {
    if (fail(req)) {
      failures += 1;
      req.resume();
      req.on('end', () => { res.writeHead(503, { 'content-length': 0 }); res.end(); });
      return;
    }
    const forward = httpRequest({
      host: upstream.hostname, port: upstream.port, method: req.method, path: req.url, headers: req.headers,
    }, answer => {
      res.writeHead(answer.statusCode, answer.headers);
      answer.pipe(res);
    });
    forward.on('error', error => res.destroy(error));
    req.pipe(forward);
  });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  return {
    endpoint: `http://127.0.0.1:${proxy.address().port}`,
    failures: () => failures,
    close: () => new Promise((resolve, reject) => {
      proxy.closeAllConnections();
      proxy.close(error => error ? reject(error) : resolve());
    }),
  };
}

await test('real signed uploads: Zig signer, curl, Elixir/blst, and S3 Archive', { timeout: 240000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'uketsuke-smoke-'));
  let server;
  let output = '';
  t.after(async () => {
    await stop();
    await rm(dir, { recursive: true, force: true });
  });
  t.afterEach(subtest => { if (!subtest.passed) console.error(output); });
  const port = await freePort();
  const service = `http://127.0.0.1:${port}`;
  const staging = join(dir, 'staging');
  const rosterPath = join(dir, 'roster.json');
  const configPath = join(dir, 'server.json');
  const reportPath = join(dir, 'report[2024]{a,b}.zip');
  const campaign = { service, network: 'smoke-network', campaign: 'glue', lifetime_secs: 900 };
  const fixtureText = 'Real report fixture; the inbox never extracts this ZIP.\n'.repeat(2048);
  await writeFile(join(dir, 'run.json'), fixtureText);
  execFileSync('zip', ['-q', '-0', reportPath, 'run.json'], { cwd: dir });
  const report = await readFile(reportPath);
  const digest = createHash('sha256').update(report).digest('hex');
  const roster = JSON.stringify({ epoch: 42, slot: 1000, pools: { [pool]: [key] } });
  await writeFile(rosterPath, roster);
  await writeFile(join(dir, 'bls.skey'), JSON.stringify({
    type: 'BlsSigningKey_bls12-381-BLS-Signature-Minimal-Signature-Size', cborHex: `5820${hex(secret)}`,
  }), { mode: 0o600 });
  await writeFile(join(dir, 'campaign.json'), JSON.stringify(campaign));
  const config = {
    port, service, network: campaign.network, campaign: campaign.campaign,
    staging_dir: staging, roster_path: rosterPath,
    max_file_bytes: report.length * 2, max_total_bytes: report.length * 4,
    max_inflight: 2, max_manifest_bytes: 4096, max_lifetime_secs: 3600,
    upload_timeout_ms: 2000, roster_max_age_secs: 3600,
    s3_bucket: bucket, s3_region: region, s3_endpoint: endpoint,
    s3_prefix: `uketsuke/v1/smoke-${freshId()}/`, s3_timeout_ms: 10000,
  };
  await writeFile(configPath, JSON.stringify(config));

  const objectKey = (id, cfg = config) => `${cfg.s3_prefix}submissions/${id}.tar`;
  function keys(cfg = config) {
    const page = JSON.parse(aws('list-objects-v2', '--bucket', cfg.s3_bucket, '--prefix', `${cfg.s3_prefix}submissions/`));
    if (page.KeyCount === 0) return [];
    assert.ok(Array.isArray(page.Contents), 'nonempty listing must supply Contents');
    return page.Contents.map(item => item.Key).sort();
  }
  function archiveEntry(id, cfg = config) {
    const path = join(dir, `${id}.tar`);
    aws('get-object', '--bucket', cfg.s3_bucket, '--key', objectKey(id, cfg), path);
    const names = execFileSync('tar', ['-tf', path], { encoding: 'utf8' }).trim().split('\n').sort();
    assert.deepEqual(names, ['attestation.json', 'manifest.json', 'receipt.json', 'report.zip']);
    const member = name => execFileSync('tar', ['-xOf', path, name]);
    return {
      report: member('report.zip'), manifestBytes: member('manifest.json'),
      attestation: JSON.parse(member('attestation.json')), receipt: JSON.parse(member('receipt.json')),
    };
  }
  async function ledger() {
    const path = join(dir, 'quota.json');
    aws('get-object', '--bucket', config.s3_bucket, '--key', `${config.s3_prefix}quota.json`, path);
    return JSON.parse(await readFile(path, 'utf8'));
  }
  async function start() {
    output = '';
    server = spawn(serverCommand[0], serverCommand.slice(1), {
      cwd: root, env: { ...process.env, INBOX_CONFIG: configPath }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`server startup timed out\n${output}`)), 30000);
      const exited = code => { clearTimeout(timer); reject(new Error(`server exited ${code}\n${output}`)); };
      server.once('exit', exited);
      server.once('error', reject);
      function capture(chunk) {
        output += chunk;
        if (output.includes(`UKETSUKE_READY ${service}`)) {
          clearTimeout(timer);
          server.removeListener('exit', exited);
          resolve();
        }
      }
      server.stdout.on('data', capture);
      server.stderr.on('data', capture);
    });
  }
  async function stop() {
    if (!server || server.pid === undefined || server.exitCode !== null || server.signalCode !== null) return;
    const exited = once(server, 'exit');
    const timer = setTimeout(() => server.kill('SIGKILL'), 5000);
    server.kill('SIGTERM');
    await exited;
    clearTimeout(timer);
  }
  function manifest(changes = {}) {
    return {
      protocol: 'leios-artifact-upload/v1', service, network: campaign.network, campaign: campaign.campaign,
      pool_id: pool, submission_id: freshId(), file_hash: digest, file_size: report.length,
      filename: 'report.zip', expires_at: Math.floor(Date.now() / 1000) + 900, ...changes,
    };
  }
  async function put(m, body = report, headers = authentication(m)) {
    return fetch(`${service}/v1/uploads/${m.submission_id}`, { method: 'PUT', headers, body });
  }
  async function rejected(m, expected, body = report, headers = authentication(m)) {
    const response = await put(m, body, headers);
    assert.equal(response.status, expected, await response.text());
    assert.ok(!keys().includes(objectKey(m.submission_id)), 'rejected submission was published');
  }
  async function incomplete(m) {
    const socket = connect(port, '127.0.0.1');
    await once(socket, 'connect');
    const accepted = new Promise((resolve, reject) => {
      let response = '';
      socket.on('error', reject);
      socket.on('data', chunk => {
        response += chunk;
        if (response.includes('100 Continue')) resolve();
        else if (/HTTP\/1\.1 [45]/.test(response)) reject(new Error(response));
      });
    });
    socket.write(`PUT /v1/uploads/${m.submission_id} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: ${report.length}\r\nExpect: 100-continue\r\n${Object.entries(authentication(m)).map(([k,v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n`);
    await accepted;
    socket.write(report.subarray(0, 16));
    return socket;
  }
  await start();
  const sign = out => JSON.parse(execFileSync(signer, ['--key', join(dir, 'bls.skey'),
    '--file', reportPath, '--pool', pool, '--campaign', join(dir, 'campaign.json'), '--out', join(dir, out)], { encoding: 'utf8' }));
  const curl = (out, config) => spawnSync('curl', ['-K', join(dir, out, config)], { encoding: 'utf8' });
  const receiptOf = (out, config) => {
    const result = curl(out, config);
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  };

  await t.test('signer and curl publish one self-verifiable Bundle in S3', async () => {
    const signed = sign('request');
    assert.equal(signed.public_key, key);
    assert.equal(signed.file_hash, digest);
    const receipt = receiptOf('request', 'upload.curl');
    assert.equal(receipt.submission_id, signed.submission_id);
    assert.equal(receipt.file_hash, digest);
    assert.equal(receipt.file_size, report.length);
    assert.equal(receipt.durability, 's3');
    const entry = archiveEntry(receipt.submission_id);
    assert.deepEqual(entry.report, report);
    assert.deepEqual([entry.attestation.roster_epoch, entry.attestation.roster_slot], [42, 1000]);
    assert.deepEqual(entry.receipt, receipt);
    assert.deepEqual(entry.manifestBytes, await readFile(join(dir, 'request/manifest.json')));
    assert.ok(bls.verify(Buffer.from(entry.attestation.signature, 'hex'), bls.hash(entry.manifestBytes, dst), Buffer.from(entry.attestation.public_key, 'hex')));
  });
  const original = JSON.parse(await readFile(join(dir, 'request/manifest.json'), 'utf8'));
  await t.test('retries and refreshed GET return the original Receipt without another object', async () => {
    assert.deepEqual(receiptOf('request', 'upload.curl'), receiptOf('request', 'receipt.curl'));
    sign('unsent');
    const missing = curl('unsent', 'receipt.curl');
    assert.equal(missing.status, 22, missing.stdout);
    assert.match(missing.stderr, /404/);
    assert.match(missing.stdout, /receipt_not_found/);
    assert.deepEqual(keys(), [objectKey(original.submission_id)]);
    const refreshed = { ...original, expires_at: original.expires_at + 1 };
    const response = await fetch(`${service}/v1/receipts/${original.submission_id}`, { headers: authentication(refreshed) });
    assert.equal(response.status, 200, await response.text());
  });
  await t.test('same Submission ID cannot replace different content', async () => {
    const response = await put({ ...original, file_hash: '00'.repeat(32) });
    assert.equal(response.status, 409, await response.text());
    assert.deepEqual(archiveEntry(original.submission_id).report, report);
  });
  await t.test('unsigned, tampered and duplicate-field Manifests are rejected', async () => {
    await rejected(manifest(), 400, report, {});
    const m = manifest();
    const headers = authentication(m);
    headers['x-upload-manifest'] = Buffer.from(JSON.stringify({ ...m, filename: 'changed.zip' })).toString('base64');
    await rejected(m, 401, report, headers);
    const duplicated = manifest({ pool_id: 'cd'.repeat(28) });
    const bytes = Buffer.from(JSON.stringify(duplicated).replace('{', `{"pool_id":"${pool}",`));
    await rejected(duplicated, 400, report, authentication(bytes));
  });
  await t.test('Key Roster association and artifact-specific signing domain are enforced', async () => {
    await rejected(manifest({ pool_id: 'cd'.repeat(28) }), 403);
    const m = manifest();
    await rejected(m, 401, report, authentication(m, secret, 'METSUKE_SUBMISSION_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_'));
  });
  await t.test('malformed signature encoding remains a protocol error, not an authentication failure', async () => {
    const m = manifest();
    const response = await put(m, report, { ...authentication(m), 'x-upload-signature': 'not-hex' });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, 'invalid_signature');
    assert.ok(!keys().includes(objectKey(m.submission_id)));
  });
  await t.test('destination, Campaign, network and expiry are enforced', async () => {
    for (const changes of [{ service: 'https://elsewhere.example' }, { network: 'other-network' }, { campaign: 'other-campaign' }]) {
      await rejected(manifest(changes), 403);
    }
    await rejected(manifest({ expires_at: Math.floor(Date.now() / 1000) - 1 }), 401);
  });
  await t.test('digest and declared-size mismatches never publish', async () => {
    const corrupted = Buffer.from(report);
    corrupted[0] ^= 1;
    await rejected(manifest(), 422, corrupted);
    await rejected(manifest({ file_size: report.length + 1 }), 422);
  });
  await t.test('oversized reports are refused before publication', async () => {
    await rejected(manifest({ file_size: config.max_file_bytes + 1 }), 413);
  });
  await t.test('transport rejects oversized Manifest headers', async () => {
    const large = manifest({ filename: 'x'.repeat(config.max_manifest_bytes) });
    const response = await put(large);
    assert.ok(response.status >= 400 && response.status < 500, await response.text());
    assert.ok(!keys().includes(objectKey(large.submission_id)));
  });
  await t.test('disconnect removes staging and releases the Submission ID', async () => {
    const m = manifest();
    const socket = await incomplete(m);
    const cleaned = awaitStagingRemoval(staging, m.submission_id);
    socket.destroy();
    await cleaned;
    assert.ok(!keys().includes(objectKey(m.submission_id)));
  });
  await t.test('concurrency is bounded and stalled uploads are killed', async () => {
    const a = manifest(); const b = manifest();
    const sa = await incomplete(a); const sb = await incomplete(b);
    try { await rejected(manifest(), 429); }
    finally { sa.destroy(); sb.destroy(); }
    await Promise.all([a,b].map(m => awaitStagingRemoval(staging, m.submission_id)));
    const stalled = manifest();
    const socket = await incomplete(stalled);
    const closed = once(socket, 'close');
    socket.resume();
    await closed;
    await awaitStagingRemoval(staging, stalled.submission_id);
    assert.ok(!keys().includes(objectKey(stalled.submission_id)));
  });
  await t.test('stale Key Roster refuses admission', async () => {
    const old = new Date(Date.now() - (config.roster_max_age_secs + 60) * 1000);
    await utimes(rosterPath, old, old);
    try { await rejected(manifest(), 503); }
    finally { await writeFile(rosterPath, roster); }
  });
  await t.test('unusable roster key is an operator fault', async () => {
    const infinity = `c0${'00'.repeat(95)}`;
    await writeFile(rosterPath, JSON.stringify({ epoch: 42, slot: 1000, pools: { [pool]: [infinity] } }));
    const m = manifest();
    const headers = { ...authentication(m), 'x-upload-key': infinity };
    try { await rejected(m, 503, report, headers); }
    finally { await writeFile(rosterPath, roster); }
  });
  const retried = manifest();
  await t.test('failed Bundle PUT keeps its reservation and the retry returns the reserved Receipt', async () => {
    const proxy = await faultProxy(req => req.method === 'PUT' && req.url.includes('/submissions/'));
    try {
      await stop();
      await writeFile(configPath, JSON.stringify({ ...config, s3_endpoint: proxy.endpoint }));
      await start();
      const response = await put(retried);
      assert.equal(response.status, 500);
      assert.equal((await response.json()).error.code, 'storage_failed');
      assert.equal(proxy.failures(), 1, 'only the Bundle PUT was failed');
    } finally {
      await stop();
      await proxy.close();
      await writeFile(configPath, JSON.stringify(config));
      await start();
    }
    assert.ok(!keys().includes(objectKey(retried.submission_id)));
    const reserved = (await ledger()).reservations[retried.submission_id];
    assert.ok(reserved, 'failed publication released its quota reservation');
    const lookup = await fetch(`${service}/v1/receipts/${retried.submission_id}`, { headers: authentication(retried) });
    assert.equal(lookup.status, 404, await lookup.text());
    const response = await put(retried);
    assert.equal(response.status, 201);
    const receipt = await response.json();
    assert.deepEqual(receipt, reserved.receipt);
    assert.deepEqual(archiveEntry(retried.submission_id).receipt, reserved.receipt);
  });
  await t.test('quota and Receipt recovery survive restart with an empty staging directory', async () => {
    const second = manifest();
    const response = await put(second);
    assert.equal(response.status, 201, await response.text());
    const third = manifest();
    const discarded = await put(third);
    assert.equal(discarded.status, 201);
    await discarded.body.cancel(); // The caller saves no Receipt from this accepted upload.
    await rejected(manifest(), 507);
    await stop();
    await rm(staging, { recursive: true });
    await start();
    await rejected(manifest(), 507);
    const recovered = await fetch(`${service}/v1/receipts/${original.submission_id}`, { headers: authentication(original) });
    assert.equal(recovered.status, 200, await recovered.text());
    const lost = await fetch(`${service}/v1/receipts/${third.submission_id}`, { headers: authentication(third) });
    assert.equal(lost.status, 200);
    assert.deepEqual(await lost.json(), archiveEntry(third.submission_id).receipt);
    assert.deepEqual(archiveEntry(second.submission_id).report, report);
    assert.deepEqual(keys(), [original, retried, second, third].map(m => objectKey(m.submission_id)).sort());
  });
});
