import { createHash } from 'node:crypto';
import { open, readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { join, resolve } from 'node:path';
import { isDeepStrictEqual, parseArgs } from 'node:util';

// Resolves with the first complete response. The server answers some requests
// (stored receipts, rejections) and closes before reading the body, so a write
// error after the response has started is expected and ignored.
function exchange(url, method, headers, body) {
  return new Promise((settle, fail) => {
    const transport = url.protocol === 'https:' ? https : http;
    let answered = false;
    const request = transport.request(url, { method, headers }, response => {
      answered = true;
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => settle({ status: response.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', fail);
    });
    request.on('error', error => { if (!answered) fail(error); });
    if (body) {
      request.strictContentLength = true;
      body.on('error', error => request.destroy(error));
      body.pipe(request);
    } else {
      request.end();
    }
  });
}

async function upload(url, manifest, path, headers) {
  const file = await open(path, 'r');
  let body;
  try {
    const stat = await file.stat({ bigint: true });
    if (!stat.isFile() || stat.size !== BigInt(manifest.file_size)) {
      throw new Error(`${path} is no longer the ${manifest.file_size}-byte file that was signed`);
    }
    const hash = createHash('sha256');
    for await (const chunk of file.createReadStream({ autoClose: false, start: 0 })) hash.update(chunk);
    if (hash.digest('hex') !== manifest.file_hash) throw new Error(`${path} changed since it was signed`);
    body = file.createReadStream({ autoClose: false, start: 0, end: manifest.file_size - 1 });
    return await exchange(url, 'PUT', {
      ...headers,
      'content-type': 'application/zip',
      'content-length': String(manifest.file_size),
    }, body);
  } finally {
    body?.destroy();
    await file.close();
  }
}

// A submission has exactly one receipt, so an existing copy must match.
async function keep(path, receipt) {
  try {
    await writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    if (!isDeepStrictEqual(JSON.parse(await readFile(path, 'utf8')), receipt)) {
      throw new Error(`${path} already holds a different receipt`);
    }
  }
}

async function main() {
  const { values, positionals } = parseArgs({
    options: { receipt: { type: 'boolean' }, help: { type: 'boolean' } },
    strict: true,
    allowPositionals: true,
  });
  if (values.help) {
    console.log(`Send a request directory written by client/sign.mjs.
Usage: node client/upload.mjs [--receipt] request

Uploads the signed report, or with --receipt only fetches the receipt of an
earlier upload. Retrying an upload that already succeeded returns the same
receipt without sending the report again. The receipt is printed and saved
as request/receipt.json.`);
    return;
  }
  if (positionals.length !== 1) throw new Error('expected exactly one request directory; use --help');
  const dir = resolve(positionals[0]);
  const bytes = await readFile(join(dir, 'manifest.json'));
  const manifest = JSON.parse(bytes);
  const request = JSON.parse(await readFile(join(dir, 'request.json'), 'utf8'));
  const headers = {
    'x-upload-manifest': bytes.toString('base64'),
    'x-upload-key': request.public_key,
    'x-upload-signature': request.signature,
  };
  const route = values.receipt ? 'receipts' : 'uploads';
  const url = new URL(`/v1/${route}/${manifest.submission_id}`, manifest.service);
  const response = values.receipt
    ? await exchange(url, 'GET', headers)
    : await upload(url, manifest, request.file, headers);
  if (response.status !== 200 && response.status !== 201) {
    throw new Error(`${url} answered ${response.status}: ${response.text}`);
  }
  const receipt = JSON.parse(response.text);
  for (const field of ['submission_id', 'file_hash', 'file_size']) {
    if (receipt[field] !== manifest[field]) throw new Error(`receipt ${field} differs from the signed manifest`);
  }
  await keep(join(dir, 'receipt.json'), receipt);
  console.log(JSON.stringify(receipt, null, 2));
}

main().catch(error => {
  console.error(`upload failed: ${error.message}`);
  process.exitCode = 1;
});
