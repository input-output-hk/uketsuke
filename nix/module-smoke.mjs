import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { bls12_381 } from '@noble/curves/bls12-381.js';

// Public scalar and bucket credentials are fixtures, not operator secrets.
const secret = Buffer.alloc(32); secret[31] = 1;
const bls = bls12_381.shortSignatures;
const hex = bytes => Buffer.from(bytes).toString('hex');
const key = hex(bls.getPublicKey(secret).toBytes());
const pool = 'ab'.repeat(28);
const id = '10'.repeat(16);
const service = 'http://127.0.0.1:4000';
const dst = 'LEIOS_ARTIFACT_UPLOAD_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';
const phase = process.argv[2];
const aws = args => execFileSync('aws', ['--endpoint-url', process.env.INBOX_S3_ENDPOINT, '--region', process.env.INBOX_S3_REGION, 's3api', ...args]);
function headers(bytes) {
  return {
    'x-upload-manifest': bytes.toString('base64'),
    'x-upload-key': key,
    'x-upload-signature': hex(bls.sign(bls.hash(bytes, dst), secret).toBytes()),
  };
}
if (phase === 'prepare') {
  writeFileSync('/var/lib/uketsuke-roster.json', JSON.stringify({ epoch: 42, slot: 1000, pools: { [pool]: [key] } }));
  writeFileSync('/tmp/run.json', 'module report\n'.repeat(160));
  execFileSync('zip', ['-q', '-0', '/tmp/module.zip', 'run.json'], { cwd: '/tmp' });
  const report = readFileSync('/tmp/module.zip');
  assert.ok(report.length < 3000 && report.length * 2 > 3000);
  writeFileSync('/tmp/module-manifest.json', JSON.stringify({
    protocol: 'leios-artifact-upload/v1', service, network: 'smoke-network', campaign: 'module',
    pool_id: pool, submission_id: id, file_hash: createHash('sha256').update(report).digest('hex'),
    file_size: report.length, filename: 'report.zip', expires_at: Math.floor(Date.now() / 1000) + 900,
  }));
} else {
  const bytes = readFileSync('/tmp/module-manifest.json');
  const report = readFileSync('/tmp/module.zip');
  const manifest = JSON.parse(bytes);
  if (phase === 'upload' || phase === 'restart') {
    const response = await fetch(`${service}/v1/uploads/${id}`, { method: 'PUT', headers: headers(bytes), body: report });
    assert.ok(response.ok, `${response.status}: ${await response.clone().text()}`);
    const receipt = await response.json();
    assert.equal(receipt.durability, 's3');
    if (phase === 'upload') writeFileSync('/tmp/module-receipt.json', JSON.stringify(receipt));
    else assert.deepEqual(receipt, JSON.parse(readFileSync('/tmp/module-receipt.json')));
    const object = 'uketsuke/v1/module/submissions/' + id + '.tar';
    const archive = JSON.parse(aws(['get-object', '--bucket', 'uketsuke', '--key', object, '/tmp/module-bundle.tar']).toString());
    if (phase === 'upload') writeFileSync('/tmp/module-archive-etag', archive.ETag);
    else assert.equal(archive.ETag, readFileSync('/tmp/module-archive-etag', 'utf8'));
    const names = execFileSync('tar', ['-tf', '/tmp/module-bundle.tar'], { encoding: 'utf8' }).trim().split('\n').sort();
    assert.deepEqual(names, ['attestation.json', 'manifest.json', 'receipt.json', 'report.zip']);
    assert.deepEqual(execFileSync('tar', ['-xOf', '/tmp/module-bundle.tar', 'report.zip']), report);
    assert.deepEqual(execFileSync('tar', ['-xOf', '/tmp/module-bundle.tar', 'manifest.json']), bytes);
    aws(['get-object', '--bucket', 'uketsuke', '--key', 'uketsuke/v1/module/quota.json', '/tmp/module-quota.json']);
    const reservations = JSON.parse(readFileSync('/tmp/module-quota.json')).reservations;
    assert.deepEqual(Object.keys(reservations), [id]);
    assert.equal(reservations[id].immutable.file_size, report.length);
    assert.deepEqual(reservations[id].receipt, receipt);
  } else if (phase === 'quota') {
    manifest.submission_id = '20'.repeat(16);
    const changed = Buffer.from(JSON.stringify(manifest));
    const response = await fetch(`${service}/v1/uploads/${manifest.submission_id}`, { method: 'PUT', headers: headers(changed), body: report });
    assert.equal(response.status, 507, await response.clone().text());
    assert.equal((await response.json()).error.code, 'storage_quota');
  } else throw new Error(`Unknown phase ${phase}`);
}
console.log(`module smoke ${phase}: passed`);
