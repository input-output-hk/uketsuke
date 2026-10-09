import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { bls12_381 } from '@noble/curves/bls12-381.js';

const DST = 'LEIOS_ARTIFACT_UPLOAD_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';
const FIELDS = ['protocol', 'service', 'network', 'campaign', 'pool_id', 'submission_id', 'file_hash', 'file_size', 'filename', 'expires_at'];
const leaks = (text, secret) => [...Array(secret.length - 7).keys()].some(i => text.includes(secret.slice(i, i + 8)));

await test('signer accepts Cardano BLS envelopes, never cold keys or invalid scalars', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'leios-signer-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'test.skey');
  const report = join(dir, 'report.zip');
  const campaign = join(dir, 'campaign.json');
  await writeFile(report, 'opaque archive bytes');
  await writeFile(campaign, JSON.stringify({ service: 'http://127.0.0.1:4100', network: 'test', campaign: 'glue', lifetime_secs: 900 }));
  let attempt = 0;
  const run = () => spawnSync(process.execPath, [join(dirname(fileURLToPath(import.meta.url)), 'sign.mjs'),
    '--key', keyPath, '--file', report, '--pool', 'ab'.repeat(28), '--campaign', campaign,
    '--out', join(dir, `request-${attempt++}`)], { encoding: 'utf8' });
  // Public golden fixture at IntersectMBO/cardano-cli b788cd365e3dd6246d9099018f093ba351779f9c,
  // cardano-cli/test/cardano-cli-golden/files/input/shelley/keys/bls_keys/.
  const scalar = '6f4b2375c689e6ef27cd3fc2cce9ae8d221386c3641746ec4e8eb3d32ebd2b7c';
  const publicKey = '8f25d696f778b68ceca228315b9366423029d781a36c4353a9ccfc7b4e879b5827324000c1c0748d19f11ea92857d7ce004c3c11ef18949e6df8cfced42c25764ff95c3603973af54e38b7d760a2a9921959498ef895d66d8ba2266dcb69659b';
  for (const spelling of ['Minimal', 'Mininimal']) {
    await writeFile(keyPath, JSON.stringify({ type: `BlsSigningKey_bls12-381-BLS-Signature-${spelling}-Signature-Size`, cborHex: `5820${scalar}` }));
    const result = run();
    assert.equal(result.status, 0, result.stderr);
    const signed = JSON.parse(result.stdout);
    assert.equal(signed.public_key, publicKey);
    const manifest = await readFile(join(signed.request_directory, 'manifest.json'));
    const request = JSON.parse(await readFile(join(signed.request_directory, 'request.json'), 'utf8'));
    assert.deepEqual(request, { file: report, public_key: publicKey, signature: request.signature });
    const fields = JSON.parse(manifest);
    assert.deepEqual(Object.keys(fields).sort(), [...FIELDS].sort());
    assert.equal(fields.file_size, 20);
    const bls = bls12_381.shortSignatures;
    assert.ok(bls.verify(Buffer.from(request.signature, 'hex'), bls.hash(manifest, DST),
      Buffer.from(publicKey, 'hex')), 'emitted signature does not verify over the emitted manifest');
  }
  const blsType = 'BlsSigningKey_bls12-381-BLS-Signature-Minimal-Signature-Size';
  for (const [text, secret] of [
    [JSON.stringify({ type: 'StakePoolSigningKey_ed25519', cborHex: `5820${scalar}` }), scalar],
    [JSON.stringify({ type: blsType, cborHex: `5820${'00'.repeat(32)}` }), '00'.repeat(32)],
    [JSON.stringify({ type: blsType, cborHex: `5820${'ff'.repeat(32)}` }), 'ff'.repeat(32)],
    [`{"type":"${blsType}","cborHex":x${scalar}}`, scalar],
  ]) {
    await writeFile(keyPath, text);
    const result = run();
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stderr, /signing failed:/);
    assert.equal(result.stdout, '');
    assert.ok(!leaks(result.stderr, secret), `private material appeared in an error: ${result.stderr}`);
  }
});
