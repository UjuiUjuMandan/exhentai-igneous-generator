import { connect } from 'cloudflare:sockets';
import { startTls } from '../vendor/subtls/src/tls/startTls.ts';
import { ReadQueue } from '../vendor/subtls/src/util/readQueue.ts';

// subtls uses a bare `chatty` global (normally stripped by esbuild --define at
// build time) to gate verbose debug logging. We just want it off.
globalThis.chatty = false;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: false });

// Buffers chunks pulled from a ReadableStreamDefaultReader into the
// `(bytes) => Promise<Uint8Array | undefined>` shape startTls expects.
class StreamReadQueue extends ReadQueue {
  constructor(reader) {
    super();
    this.closed = false;
    this._pump(reader);
  }

  async _pump(reader) {
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.length) this.enqueue(value);
      }
    } catch {
      // socket errored or was reset; treat like a clean EOF
    } finally {
      this.closed = true;
      this.dequeue();
    }
  }

  moreDataMayFollow() {
    return !this.closed;
  }
}

let rootCertsPromise;

function getRootCerts(origin) {
  rootCertsPromise ??= (async () => {
    const [indexRes, dataRes] = await Promise.all([
      fetch(new URL('/certs.index.json', origin)),
      fetch(new URL('/certs.binary.txt', origin)),
    ]);
    if (!indexRes.ok || !dataRes.ok) throw new Error('Failed to load root certificate database');
    const [index, data] = await Promise.all([indexRes.json(), dataRes.arrayBuffer()]);
    return { index, data: new Uint8Array(data) };
  })();
  return rootCertsPromise;
}

function concatUint8(chunks, totalLength) {
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}

// Buffers a TLS record read function so HTTP/1.1 parsing can pull exact byte
// counts or read a line at a time, and leaves any bytes read past the current
// response sitting ready for the next request on the same connection.
class ByteReader {
  constructor(read) {
    this._read = read;
    this._buf = new Uint8Array(0);
  }

  async _fill() {
    const chunk = await this._read();
    if (chunk === undefined) return false;
    if (chunk.length === 0) return true;
    this._buf = concatUint8([this._buf, chunk], this._buf.length + chunk.length);
    return true;
  }

  async readLine() {
    for (;;) {
      for (let i = 0; i < this._buf.length - 1; i++) {
        if (this._buf[i] === 0x0d && this._buf[i + 1] === 0x0a) {
          const line = textDecoder.decode(this._buf.subarray(0, i));
          this._buf = this._buf.subarray(i + 2);
          return line;
        }
      }
      if (!(await this._fill())) {
        const line = textDecoder.decode(this._buf);
        this._buf = new Uint8Array(0);
        return line || undefined;
      }
    }
  }

  async readExact(n) {
    while (this._buf.length < n) {
      if (!(await this._fill())) break;
    }
    const got = Math.min(n, this._buf.length);
    const out = this._buf.subarray(0, got);
    this._buf = this._buf.subarray(got);
    return out;
  }

  async readUntilClose() {
    const chunks = [this._buf];
    let total = this._buf.length;
    this._buf = new Uint8Array(0);
    let chunk;
    while ((chunk = await this._read()) !== undefined) {
      chunks.push(chunk);
      total += chunk.length;
    }
    return concatUint8(chunks, total);
  }
}

async function readHttpResponse(byteReader) {
  const statusLine = await byteReader.readLine();
  const statusMatch = statusLine && statusLine.match(/^HTTP\/\d\.\d\s+(\d+)/);
  const status = statusMatch ? Number(statusMatch[1]) : 0;

  const headers = {};
  const setCookies = [];
  for (;;) {
    const line = await byteReader.readLine();
    if (!line) break;
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === 'set-cookie') setCookies.push(value);
    else headers[key] = value;
  }
  if (setCookies.length) headers['set-cookie'] = setCookies.join(', ');

  let bodyBytes;
  const transferEncoding = headers['transfer-encoding'];
  if (transferEncoding && transferEncoding.toLowerCase().includes('chunked')) {
    const chunks = [];
    let total = 0;
    for (;;) {
      const sizeLine = await byteReader.readLine();
      const size = parseInt((sizeLine || '0').split(';')[0], 16);
      if (!size) { await byteReader.readLine(); break; } // trailing CRLF after the 0-size chunk (trailers unsupported)
      const data = await byteReader.readExact(size);
      chunks.push(data);
      total += data.length;
      await byteReader.readLine(); // CRLF after each chunk's data
    }
    bodyBytes = concatUint8(chunks, total);
  } else if (headers['content-length'] !== undefined) {
    bodyBytes = await byteReader.readExact(parseInt(headers['content-length'], 10));
  } else {
    bodyBytes = await byteReader.readUntilClose();
  }

  return { status, headers, body: textDecoder.decode(bodyBytes) };
}

// Opens a raw TLS 1.3 connection to `connectHost` (e.g. a direct origin
// IP/hostname) while presenting `hostHeader` as the HTTP virtual host - like
// curl's --connect-to. `origin` must be this Worker's own origin, used to
// load the root cert database from static assets (`/certs.index.json` +
// `/certs.binary.txt`). Returns a `request()` you can call more than once to
// send several HTTP/1.1 requests over the one TLS connection, and a
// `close()` to call when done.
export async function openDirectHttpsSession({ origin, connectHost, hostHeader, port = 443 }) {
  const rootCerts = await getRootCerts(origin);

  const socket = connect({ hostname: connectHost, port }, { secureTransport: 'off', allowHalfOpen: false });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const queue = new StreamReadQueue(reader);

  const networkRead = (n, readMode) => queue.read(n, readMode);
  const networkWrite = (data) => { writer.write(data); };

  const { read, write } = await startTls(connectHost, rootCerts, networkRead, networkWrite, {
    protocolsForALPN: ['http/1.1'],
  });
  const byteReader = new ByteReader(read);

  async function request({ method = 'GET', path = '/', headers = {} } = {}) {
    const reqHeaders = { Host: hostHeader, ...headers };
    const lines = [`${method} ${path} HTTP/1.1\r\n`];
    for (const [k, v] of Object.entries(reqHeaders)) lines.push(`${k}: ${v}\r\n`);
    lines.push('\r\n');
    await write(textEncoder.encode(lines.join('')));
    return readHttpResponse(byteReader);
  }

  async function close() {
    try { writer.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
  }

  return { request, close };
}
