import { createHash, randomBytes } from 'node:crypto';
import { mkdir, open, readFile, writeFile } from 'node:fs/promises';
import { basename, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { bls12_381 } from '@noble/curves/bls12-381.js';

const DST = 'LEIOS_ARTIFACT_UPLOAD_V1_BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';
const KEY_TYPES = new Set([
  'BlsSigningKey_bls12-381-BLS-Signature-Minimal-Signature-Size',
  'BlsSigningKey_bls12-381-BLS-Signature-Mininimal-Signature-Size',
]);

function requireValue(values, name) {
  if (!values[name]) throw new Error(`missing --${name}; use --help`);
  return values[name];
}

async function main() {
  const { values } = parseArgs({
    options: {
      key: { type: 'string' }, file: { type: 'string' }, pool: { type: 'string' },
      campaign: { type: 'string' }, out: { type: 'string' }, id: { type: 'string' },
      help: { type: 'boolean' },
    },
    strict: true,
    allowPositionals: false,
  });
  if (values.help) {
    console.log(`Sign locally; this program makes no network requests.
Usage: node client/sign.mjs --key bls.skey --file report.zip --pool POOL_HEX \\
  --campaign campaign.json --out request [--id PREVIOUS_SUBMISSION_ID]

The campaign JSON requires service, network, campaign, lifetime_secs.
A fresh random submission ID is used unless --id is supplied for recovery.
Output: manifest.json (the exact signed bytes) and request.json (report path,
public key, signature).
Upload: node client/upload.mjs request
Recover receipt: node client/upload.mjs --receipt request
Never use a cold key. No private key is included in the generated files.`);
    return;
  }
  const keyPath = requireValue(values, 'key');
  const filePath = resolve(requireValue(values, 'file'));
  const pool = requireValue(values, 'pool');
  const campaignPath = requireValue(values, 'campaign');
  const out = resolve(requireValue(values, 'out'));
  if (!/^[0-9a-f]{56}$/.test(pool)) throw new Error('--pool must be a 28-byte lowercase hex pool ID');
  const id = values.id ?? randomBytes(16).toString('hex');
  if (!/^[0-9a-f]{32}$/.test(id)) throw new Error('--id must be 16-byte lowercase hex');

  const campaign = JSON.parse(await readFile(campaignPath, 'utf8'));
  if (Object.keys(campaign).sort().join(',') !== 'campaign,lifetime_secs,network,service') {
    throw new Error('campaign JSON must contain exactly service, network, campaign, lifetime_secs');
  }
  for (const field of ['service', 'network', 'campaign']) {
    if (typeof campaign[field] !== 'string' || !campaign[field].trim()) {
      throw new Error(`campaign ${field} must be a nonempty string`);
    }
  }
  if (!Number.isSafeInteger(campaign.lifetime_secs) || campaign.lifetime_secs <= 0) {
    throw new Error('campaign lifetime_secs must be a positive safe integer');
  }
  const service = new URL(campaign.service);
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(service.hostname);
  if (service.origin !== campaign.service || service.username || service.password ||
      !(service.protocol === 'https:' || (service.protocol === 'http:' && loopback))) {
    throw new Error('service must be an HTTPS origin without a trailing slash; HTTP is allowed only on loopback');
  }
  const file = await open(filePath, 'r');
  let digest;
  let size = 0;
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size <= 0n || before.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error('--file must be a nonempty regular file with a safely representable size');
    }
    const hash = createHash('sha256');
    for await (const chunk of file.createReadStream({ autoClose: false })) {
      size += chunk.length;
      hash.update(chunk);
    }
    const after = await file.stat({ bigint: true });
    if (before.size !== after.size || before.mtimeNs !== after.mtimeNs || BigInt(size) !== before.size) {
      throw new Error('report changed while hashing; retry with a stable file');
    }
    digest = hash.digest('hex');
  } finally {
    await file.close();
  }

  const expires = Math.floor(Date.now() / 1000) + campaign.lifetime_secs;
  if (!Number.isSafeInteger(expires)) throw new Error('campaign expiry is outside safe integer range');
  const manifest = {
    protocol: 'leios-artifact-upload/v1',
    service: campaign.service,
    network: campaign.network,
    campaign: campaign.campaign,
    pool_id: pool,
    submission_id: id,
    file_hash: digest,
    file_size: size,
    filename: basename(filePath),
    expires_at: expires,
  };
  const bytes = Buffer.from(JSON.stringify(manifest));
  let envelope;
  try {
    envelope = JSON.parse(await readFile(keyPath, 'utf8'));
  } catch (error) {
    // V8 parse errors quote the input around the failure, which here is key material.
    if (error instanceof SyntaxError) throw new Error('--key is not valid JSON');
    throw error;
  }
  if (!KEY_TYPES.has(envelope.type) || typeof envelope.cborHex !== 'string' ||
      !/^5820[0-9a-fA-F]{64}$/.test(envelope.cborHex)) {
    throw new Error('--key must be a Leios BLS signing-key TextEnvelope containing a 32-byte scalar');
  }
  const secret = Buffer.from(envelope.cborHex.slice(4), 'hex');
  // bls12_381 Fr reduces out-of-range scalars instead of rejecting them.
  const scalar = BigInt(`0x${secret.toString('hex')}`);
  if (scalar <= 0n || scalar >= bls12_381.fields.Fr.ORDER) throw new Error('invalid BLS secret scalar');
  const bls = bls12_381.shortSignatures;
  const publicKey = Buffer.from(bls.getPublicKey(secret).toBytes()).toString('hex');
  const signature = Buffer.from(bls.sign(bls.hash(bytes, DST), secret).toBytes()).toString('hex');
  await mkdir(out, { mode: 0o700 });
  for (const [name, content] of [
    ['manifest.json', bytes],
    ['request.json', `${JSON.stringify({ file: filePath, public_key: publicKey, signature }, null, 2)}\n`],
  ]) {
    await writeFile(resolve(out, name), content, { mode: 0o600, flag: 'wx' });
  }
  console.log(JSON.stringify({ submission_id: id, file_hash: digest, file_size: size, public_key: publicKey, request_directory: out }, null, 2));
}

main().catch(error => {
  console.error(`signing failed: ${error.message}`);
  process.exitCode = 1;
});
