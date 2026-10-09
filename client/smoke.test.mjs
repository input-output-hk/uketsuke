import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { watch } from 'node:fs';
import { mkdtemp, readFile, writeFile, readdir, rm, rename, utimes } from 'node:fs/promises';
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

await test('real signed uploads: Node signer and uploader, Elixir and blst', { timeout: 90000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'leios-inbox-smoke-'));
  let server;
  let output = '';
  t.after(async () => {
    await stop();
    await rm(dir, { recursive: true, force: true });
  });
  t.afterEach(subtest => { if (!subtest.passed) console.error(output); });
  const port = await freePort();
  const service = `http://127.0.0.1:${port}`;
  const storage = join(dir, 'store');
  const rosterPath = join(dir, 'roster.json');
  const configPath = join(dir, 'server.json');
  // Brackets and braces stay literal: the uploader opens the path, nothing globs it.
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
    type: 'BlsSigningKey_bls12-381-BLS-Signature-Minimal-Signature-Size',
    cborHex: `5820${hex(secret)}`,
  }), { mode: 0o600 });
  await writeFile(join(dir, 'campaign.json'), JSON.stringify(campaign));
  const config = {
    port, service, network: campaign.network, campaign: campaign.campaign,
    storage_dir: storage, roster_path: rosterPath,
    max_file_bytes: report.length * 2, max_total_bytes: report.length * 3,
    max_inflight: 2, max_manifest_bytes: 4096, max_lifetime_secs: 3600,
    upload_timeout_ms: 2000, roster_max_age_secs: 3600,
  };
  await writeFile(configPath, JSON.stringify(config));
  async function start() {
    server = spawn('mix', ['run', '--no-halt'], {
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
    const text = await response.text();
    assert.equal(response.status, expected, text);
    assert.ok(!(await readdir(join(storage, 'archive'))).includes(m.submission_id), 'rejected submission was published');
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
  const sign = out => JSON.parse(execFileSync(process.execPath, [join(root, 'client/sign.mjs'), '--key', join(dir, 'bls.skey'),
    '--file', reportPath, '--pool', pool, '--campaign', join(dir, 'campaign.json'), '--out', join(dir, out)], { encoding: 'utf8' }));
  const send = (...args) => spawnSync(process.execPath, [join(root, 'client/upload.mjs'), ...args], { encoding: 'utf8' });
  const receiptOf = (...args) => {
    const result = send(...args);
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  };
  await t.test('local signer and uploader store a genuine blst-verifiable submission', async () => {
    const signed = sign('request');
    assert.equal(signed.public_key, key);
    assert.equal(signed.file_hash, digest);
    const receipt = receiptOf(join(dir, 'request'));
    assert.deepEqual(JSON.parse(await readFile(join(dir, 'request/receipt.json'), 'utf8')), receipt);
    assert.equal(receipt.submission_id, signed.submission_id);
    assert.equal(receipt.file_hash, digest);
    assert.equal(receipt.file_size, report.length);
    assert.equal(receipt.durability, 'local-fsync');
    const archive = join(storage, 'archive', receipt.submission_id);
    assert.deepEqual(await readFile(join(archive, 'report.zip')), report);
    assert.equal(await readFile(join(archive, 'roster.json'), 'utf8'), roster);
    const raw = await readFile(join(archive, 'manifest.json'));
    const auth = JSON.parse(await readFile(join(archive, 'attestation.json'), 'utf8'));
    assert.ok(bls.verify(Buffer.from(auth.signature, 'hex'), bls.hash(raw, dst), Buffer.from(auth.public_key, 'hex')));
  });
  const original = JSON.parse(await readFile(join(dir, 'request/manifest.json'), 'utf8'));
  await t.test('retries and GET recover the identical receipt without another stored upload', async () => {
    assert.deepEqual(receiptOf(join(dir, 'request')), receiptOf('--receipt', join(dir, 'request')));
    sign('unsent');
    const missing = send('--receipt', join(dir, 'unsent'));
    assert.equal(missing.status, 1, missing.stdout);
    assert.match(missing.stderr, /answered 404: .*receipt_not_found/);
    await assert.rejects(readFile(join(dir, 'unsent/receipt.json')), { code: 'ENOENT' });
    assert.equal((await readdir(join(storage, 'archive'))).length, 1);
    const refreshed = { ...original, expires_at: original.expires_at + 1 };
    const response = await fetch(`${service}/v1/receipts/${original.submission_id}`, { headers: authentication(refreshed) });
    assert.equal(response.status, 200, await response.text());
  });
  await t.test('same submission ID cannot replace different content', async () => {
    const response = await put({ ...original, file_hash: '00'.repeat(32) });
    assert.equal(response.status, 409, await response.text());
    assert.deepEqual(await readFile(join(storage, 'archive', original.submission_id, 'report.zip')), report);
  });
  await t.test('unsigned and tampered manifests are rejected', async () => {
    await rejected(manifest(), 400, report, {});
    const m = manifest();
    const headers = authentication(m);
    headers['x-upload-manifest'] = Buffer.from(JSON.stringify({ ...m, filename: 'changed.zip' })).toString('base64');
    await rejected(m, 401, report, headers);
    // Jason keeps the first duplicate: lead with the registered pool, then sign for another.
    const duplicated = manifest({ pool_id: 'cd'.repeat(28) });
    const bytes = Buffer.from(JSON.stringify(duplicated).replace('{', `{"pool_id":"${pool}",`));
    await rejected(duplicated, 400, report, authentication(bytes));
  });
  await t.test('roster association and artifact-specific signing domain are enforced', async () => {
    await rejected(manifest({ pool_id: 'cd'.repeat(28) }), 403);
    const m = manifest();
    await rejected(m, 401, report, authentication(m, secret, 'METSUKE_SUBMISSION_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_'));
  });
  await t.test('service, network, campaign and expiry are bound by the signature', async () => {
    for (const changes of [{ service: 'https://elsewhere.example' }, { network: 'other-network' },
      { campaign: 'other-campaign' }]) {
      await rejected(manifest(changes), 403);
    }
    await rejected(manifest({ expires_at: Math.floor(Date.now() / 1000) - 1 }), 401);
  });
  await t.test('digest mismatch and declared size mismatch never publish', async () => {
    const corrupted = Buffer.from(report);
    corrupted[0] ^= 1;
    await rejected(manifest(), 422, corrupted);
    await rejected(manifest({ file_size: report.length + 1 }), 422);
  });
  await t.test('oversized files are refused before publication', async () => {
    await rejected(manifest({ file_size: config.max_file_bytes + 1 }), 413);
  });
  await t.test('transport rejects an oversized manifest header without publishing', async () => {
    const large = manifest({ filename: 'x'.repeat(config.max_manifest_bytes) });
    const response = await put(large);
    assert.ok(response.status >= 400 && response.status < 500, await response.text());
    assert.ok(!(await readdir(join(storage, 'archive'))).includes(large.submission_id));
  });
  await t.test('disconnect removes staging and releases the submission ID', async () => {
    const m = manifest();
    const socket = await incomplete(m);
    const cleaned = awaitStagingRemoval(join(storage, 'staging'), m.submission_id);
    socket.destroy();
    await cleaned;
    assert.ok(!(await readdir(join(storage, 'archive'))).includes(m.submission_id));
  });
  await t.test('concurrency is bounded and stalled upload is terminated', async () => {
    const a = manifest(); const b = manifest();
    const sa = await incomplete(a);
    const sb = await incomplete(b);
    try { await rejected(manifest(), 429); }
    finally { sa.destroy(); sb.destroy(); }
    await Promise.all([a,b].map(m => awaitStagingRemoval(join(storage, 'staging'), m.submission_id)));
    const stalled = manifest();
    const socket = await incomplete(stalled);
    const closed = once(socket, 'close');
    socket.resume();
    await closed;
    await awaitStagingRemoval(join(storage, 'staging'), stalled.submission_id);
    assert.ok(!(await readdir(join(storage, 'archive'))).includes(stalled.submission_id));
  });
  await t.test('stale roster refuses admission without consulting rewards', async () => {
    const old = new Date(Date.now() - (config.roster_max_age_secs + 60) * 1000);
    await utimes(rosterPath, old, old);
    try { await rejected(manifest(), 503); }
    finally { await writeFile(rosterPath, roster); }
  });
  await t.test('an invalid roster key is an operator fault, not a client rejection', async () => {
    const infinity = `c0${'00'.repeat(95)}`;
    await writeFile(rosterPath, JSON.stringify({ epoch: 42, slot: 1000, pools: { [pool]: [infinity] } }));
    const m = manifest();
    const headers = { ...authentication(m), 'x-upload-key': infinity };
    try { await rejected(m, 503, report, headers); }
    finally { await writeFile(rosterPath, roster); }
  });
  await t.test('storage failure cannot produce a receipt', async () => {
    const archive = join(storage, 'archive');
    await rename(archive, `${archive}.held`);
    await writeFile(archive, 'not a directory');
    const m = manifest();
    try {
      const response = await put(m);
      assert.equal(response.status, 500, await response.text());
    } finally {
      await rm(archive);
      await rename(`${archive}.held`, archive);
    }
    const response = await fetch(`${service}/v1/receipts/${m.submission_id}`, { headers: authentication(m) });
    assert.equal(response.status, 404, await response.text());
  });
  await t.test('storage quota survives restart and receipts remain recoverable', async () => {
    const second = manifest();
    const response = await put(second);
    assert.equal(response.status, 201, await response.text());
    const third = await put(manifest());
    assert.equal(third.status, 201, await third.text());
    await rejected(manifest(), 507);
    await stop();
    output = '';
    await start();
    await rejected(manifest(), 507);
    const recovered = await fetch(`${service}/v1/receipts/${original.submission_id}`, { headers: authentication(original) });
    assert.equal(recovered.status, 200, await recovered.text());
    assert.deepEqual(await readFile(join(storage, 'archive', second.submission_id, 'report.zip')), report);
  });
});
