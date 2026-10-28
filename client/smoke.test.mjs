import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFile, execFileSync, spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { watch } from 'node:fs';
import { mkdtemp, readFile, writeFile, readdir, rm, utimes } from 'node:fs/promises';
import { createServer as createHttpServer, request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createServer, connect } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';
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
const ukc = requiredEnv('UKC');
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

const literal = text => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const json = (value, status = 200) => ({ status, headers: { 'content-type': 'application/json' }, body: JSON.stringify(value) });

// A throwaway CA and a localhost certificate it signed, valid for a day.
async function testCertificates(dir) {
  const openssl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
  openssl('req', '-x509', ...ec, '-days', '1', '-subj', '/CN=ukc smoke CA', '-keyout', 'ca.key', '-out', 'ca.pem');
  openssl('req', ...ec, '-subj', '/CN=localhost', '-keyout', 'tls.key', '-out', 'tls.csr');
  await writeFile(join(dir, 'tls.ext'), 'subjectAltName=DNS:localhost\n');
  openssl('x509', '-req', '-in', 'tls.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
    '-days', '1', '-extfile', 'tls.ext', '-out', 'tls.pem');
  return { ca: join(dir, 'ca.pem'), key: await readFile(join(dir, 'tls.key')), cert: await readFile(join(dir, 'tls.pem')) };
}

// Answers at its own loopback origin with `answerFor(origin, path)`: an
// { status, headers, body } record, or a function of (request, body) giving
// one. Unanswered /v1/ paths go to `service`. With `tls` ({ key, cert }) the
// origin is https://localhost.
async function campaignHost(service, answerFor, tls) {
  const upstream = new URL(service);
  const handler = (req, res) => {
    const answer = answerFor(origin, req.url.replace(/^\/v1\/uploads\/[0-9a-f]+$/, '/v1/uploads/ID'));
    if (answer || !req.url.startsWith('/v1/')) {
      const chunks = [];
      req.on('data', chunk => chunks.push(chunk));
      req.on('end', () => {
        const record = typeof answer === 'function' ? answer(req, Buffer.concat(chunks)) : answer;
        const { status, headers, body } = record ?? { status: 404, headers: {}, body: '' };
        res.writeHead(status, headers);
        res.end(body);
      });
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
  };
  const host = tls ? createHttpsServer(tls, handler) : createHttpServer(handler);
  // Dual-stack, since localhost may resolve to ::1 or 127.0.0.1.
  host.listen(0, tls ? '::' : '127.0.0.1');
  await once(host, 'listening');
  const origin = tls ? `https://localhost:${host.address().port}` : `http://127.0.0.1:${host.address().port}`;
  return {
    origin,
    close: () => new Promise((resolve, reject) => {
      host.closeAllConnections();
      host.close(error => error ? reject(error) : resolve());
    }),
  };
}

await test('real signed uploads: ukc, curl, Elixir/blst, and S3 Archive', { timeout: 240000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'uketsuke-smoke-'));
  let server;
  let output = '';
  let metricsUrl;
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
  const rosterMaxAgeSecs = 3600;
  const config = {
    port, metrics_port: 0, service, network: campaign.network, campaign: campaign.campaign,
    staging_dir: staging, roster_path: rosterPath,
    max_file_bytes: report.length * 2, max_total_bytes: report.length * 5,
    max_inflight: 2, max_manifest_bytes: 4096, campaign_lifetime: '55m', clock_skew: '5m',
    upload_timeout: '2s', roster_max_age: `${rosterMaxAgeSecs}s`,
    s3_bucket: bucket, s3_region: region, s3_endpoint: endpoint,
    s3_prefix: `uketsuke/v1/smoke-${freshId()}/`, s3_timeout: '10s', progress_interval: '15s',
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
        const ready = output.match(/UKETSUKE_READY (\S+) metrics=(\S+)\n/);
        if (ready) {
          assert.equal(ready[1], service);
          metricsUrl = ready[2];
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
  const sign = out => JSON.parse(execFileSync(ukc, ['sign', '--key', join(dir, 'bls.skey'),
    '--file', reportPath, '--pool', pool, '--campaign', join(dir, 'campaign.json'), '--out', join(dir, out)], { encoding: 'utf8' }));
  // Asynchronous, so campaignHost in this process can answer ukc.
  const sendWith = (env, ...args) => new Promise(resolve => execFile(ukc,
    ['send', '--key', join(dir, 'bls.skey'), '--file', reportPath, ...args], { encoding: 'utf8', timeout: 30000, env },
    (error, stdout, stderr) => resolve({ status: error ? error.code ?? error.signal : 0, stdout, stderr })));
  const send = (...args) => sendWith(process.env, ...args);
  const curl = (out, config) => spawnSync('curl', ['-q', '-K', join(dir, out, config)], { encoding: 'utf8' });
  const receiptOf = (out, config) => {
    const result = curl(out, config);
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  };

  await t.test('ukc sign and curl publish one self-verifiable Bundle in S3', async () => {
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
  let sent;
  await t.test('ukc send uploads, prints the Receipt, and recovers it with --id', async () => {
    const result = await send('--pool', pool, '--campaign', join(dir, 'campaign.json'));
    assert.equal(result.status, 0, result.stderr);
    sent = JSON.parse(result.stdout);
    assert.equal(sent.durability, 's3');
    assert.equal(sent.file_hash, digest);
    assert.match(result.stderr, new RegExp(`^submission ${sent.submission_id}: uploading ${report.length} bytes to ${literal(service)}\n$`));
    assert.deepEqual(archiveEntry(sent.submission_id).receipt, sent);
    // The retry fetches the Campaign the server serves for itself.
    const retry = await send('--pool', pool, '--campaign', `${service}/campaigns/glue.json`, '--id', sent.submission_id);
    assert.equal(retry.status, 0, retry.stderr);
    assert.deepEqual(JSON.parse(retry.stdout), sent);
  });
  await t.test('ukc send fetches campaign URLs only from the service they name, without redirects', async () => {
    const host = await campaignHost(service, (origin, path) => ({
      '/own.json': json({ ...campaign, service: origin }),
      '/foreign.json': json(campaign),
      '/moved.json': { status: 302, headers: { location: '/own.json' }, body: '' },
    })[path]);
    try {
      const own = await send('--pool', pool, '--campaign', `${host.origin}/own.json`);
      assert.equal(own.status, 1);
      assert.match(own.stderr, /upload rejected with HTTP 403: .*"wrong_service"/);
      const foreign = await send('--pool', pool, '--campaign', `${host.origin}/foreign.json`);
      assert.equal(foreign.status, 1);
      assert.match(foreign.stderr, /names service http:\/\/127\.0\.0\.1:\d+; a fetched campaign must name its own origin/);
      const moved = await send('--pool', pool, '--campaign', `${host.origin}/moved.json`);
      assert.equal(moved.status, 1);
      assert.match(moved.stderr, /moved\.json answered HTTP 302/);
    } finally { await host.close(); }
  });
  await t.test('ukc send fetches and uploads over HTTPS, trusting SSL_CERT_FILE in place of the system CAs', async () => {
    const certs = await testCertificates(dir);
    let uploaded;
    const host = await campaignHost(service, (origin, path) => ({
      '/tls.json': json({ ...campaign, service: origin }),
      '/v1/uploads/ID': (req, body) => {
        const signed = JSON.parse(Buffer.from(req.headers['x-upload-manifest'], 'base64'));
        uploaded = { service: signed.service, hash: createHash('sha256').update(body).digest('hex'), size: body.length };
        return json({ submission_id: signed.submission_id, file_hash: uploaded.hash, file_size: body.length }, 201);
      },
    })[path], { key: certs.key, cert: certs.cert });
    try {
      const { SSL_CERT_FILE, ...systemCas } = process.env;
      const untrusted = await sendWith(systemCas, '--pool', pool, '--campaign', `${host.origin}/tls.json`);
      assert.equal(untrusted.status, 1);
      assert.match(untrusted.stderr, new RegExp(`cannot connect to ${literal(host.origin)}/tls\\.json: `));
      assert.equal(uploaded, undefined);
      const trusted = await sendWith({ ...systemCas, SSL_CERT_FILE: certs.ca }, '--pool', pool, '--campaign', `${host.origin}/tls.json`);
      assert.equal(trusted.status, 0, trusted.stderr);
      assert.equal(JSON.parse(trusted.stdout).file_hash, digest);
      assert.deepEqual(uploaded, { service: host.origin, hash: digest, size: report.length });
    } finally { await host.close(); }
  });
  await t.test('ukc send accepts only a receipt for its submission, and classifies rejections', async () => {
    const host = await campaignHost(service, (origin, path) => ({
      '/portal.json': json({ ...campaign, service: origin }),
      '/v1/uploads/ID': { status: 200, headers: { 'content-type': 'text/html' }, body: '<html>Sign in to Wi-Fi</html>' },
    })[path]);
    try {
      const portal = await send('--pool', pool, '--campaign', `${host.origin}/portal.json`);
      assert.equal(portal.status, 1);
      assert.equal(portal.stdout, '');
      assert.match(portal.stderr, /HTTP 200 answer is not a receipt for this submission: <html>Sign in to Wi-Fi<\/html>; retry with --id [0-9a-f]{32}/);
    } finally { await host.close(); }
    const unavailable = JSON.stringify({ error: { code: 'storage_failed' } });
    const busy = await campaignHost(service, (origin, path) => ({
      '/busy.json': json({ ...campaign, service: origin }),
      '/v1/uploads/ID': { status: 503, headers: {}, body: unavailable },
    })[path]);
    try {
      const failed = await send('--pool', pool, '--campaign', `${busy.origin}/busy.json`);
      assert.equal(failed.status, 1);
      assert.match(failed.stderr, new RegExp(`upload failed with HTTP 503: ${literal(unavailable)}; retry with --id [0-9a-f]{32}\n$`));
    } finally { await busy.close(); }
    const error = JSON.stringify({ error: { code: 'key_not_registered' } });
    const gzipped = await campaignHost(service, (origin, path) => ({
      '/gzip.json': json({ ...campaign, service: origin }),
      '/v1/uploads/ID': { status: 403, headers: { 'content-encoding': 'gzip' }, body: gzipSync(error) },
    })[path]);
    try {
      const rejected = await send('--pool', pool, '--campaign', `${gzipped.origin}/gzip.json`);
      assert.equal(rejected.status, 1);
      assert.match(rejected.stderr, new RegExp(`upload rejected with HTTP 403: ${literal(error)}\n$`));
    } finally { await gzipped.close(); }
  });
  await t.test('ukc send reports a rejected upload with the server error and a failing exit', async () => {
    const result = await send('--pool', 'cd'.repeat(28), '--campaign', join(dir, 'campaign.json'));
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /upload rejected with HTTP 403: .*"key_not_registered"/);
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
    const old = new Date(Date.now() - (rosterMaxAgeSecs + 60) * 1000);
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
    assert.ok(sent, 'the ukc send upload subtest failed earlier');
    assert.deepEqual(keys(), [original, sent, retried, second, third].map(m => objectKey(m.submission_id)).sort());
  });
  await t.test('healthz, loopback metrics and request log lines observe the restarted server', async () => {
    const health = await fetch(`${service}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).status, 'ready');
    assert.equal((await fetch(`${service}/metrics`)).status, 404);
    assert.notEqual(new URL(metricsUrl).port, String(port));
    const metrics = await (await fetch(metricsUrl)).text();
    for (const series of [
      'uketsuke_requests_total{route="upload",outcome="rejected",code="storage_quota"} 1',
      'uketsuke_requests_total{route="receipt",outcome="recovered"} 2',
      `uketsuke_quota_reserved_bytes ${config.max_total_bytes}`,
      `uketsuke_quota_max_bytes ${config.max_total_bytes}`,
      'uketsuke_s3_requests_total{op="head",status="200"} 2',
      'uketsuke_roster_ok 1',
      'uketsuke_inflight 0',
    ]) assert.ok(metrics.includes(`${series}\n`), `missing ${series}\n${metrics}`);
    const lines = output.split('\n').filter(line => line.startsWith('{')).map(line => JSON.parse(line));
    const requests = lines.filter(line => line.message?.event === 'request').map(line => line.message);
    const timed = ({ duration_ms, ...rest }) => { assert.ok(Number.isInteger(duration_ms)); return rest; };
    assert.deepEqual(timed(requests.find(r => r.submission_id === original.submission_id)), {
      event: 'request', route: 'receipt', outcome: 'recovered', status: 200,
      pool_id: pool, submission_id: original.submission_id, file_size: report.length,
    });
    const refused = requests.find(r => r.code === 'storage_quota');
    assert.deepEqual(timed(refused), {
      event: 'request', route: 'upload', outcome: 'rejected', code: 'storage_quota', status: 507,
      pool_id: pool, submission_id: refused.submission_id, file_size: report.length,
    });
    assert.ok(!output.includes(key), 'a public key reached the log');
  });
});
