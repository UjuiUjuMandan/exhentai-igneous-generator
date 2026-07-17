import { connect } from 'cloudflare:sockets';
import { startTls } from '../vendor/subtls/src/tls/startTls.ts';
import { ReadQueue } from '../vendor/subtls/src/util/readQueue.ts';

// subtls uses a bare `chatty` global (normally stripped by esbuild --define at
// build time) to gate verbose debug logging. We just want it off.
globalThis.chatty = false;

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

function parseRawHttpResponse(bytes) {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  const headerEnd = text.indexOf('\r\n\r\n');
  const headerBlock = headerEnd === -1 ? text : text.slice(0, headerEnd);
  const body = headerEnd === -1 ? '' : text.slice(headerEnd + 4);

  const headerLines = headerBlock.split('\r\n');
  const statusLine = headerLines.shift() || '';
  const statusMatch = statusLine.match(/^HTTP\/\d\.\d\s+(\d+)/);
  const status = statusMatch ? Number(statusMatch[1]) : 0;

  const headers = {};
  const setCookies = [];
  for (const line of headerLines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === 'set-cookie') setCookies.push(value);
    else headers[key] = value;
  }
  if (setCookies.length) headers['set-cookie'] = setCookies.join(', ');

  return { status, headers, body };
}

// Speaks raw TLS 1.3 + HTTP/1.0 directly over a `connect()`ed TCP socket, so
// the TCP/TLS endpoint (`connectHost`, e.g. a direct origin IP/hostname) can
// differ from the virtual host the request is actually for (`hostHeader`).
// `origin` must be this Worker's own origin, used to load the root cert
// database from static assets (`/certs.index.json` + `/certs.binary.txt`).
export async function directHttpsRequest({
  origin,
  connectHost,
  hostHeader,
  port = 443,
  method = 'GET',
  path = '/',
  headers = {},
}) {
  const rootCerts = await getRootCerts(origin);

  const socket = connect({ hostname: connectHost, port }, { secureTransport: 'off', allowHalfOpen: false });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const queue = new StreamReadQueue(reader);

  const networkRead = (n, readMode) => queue.read(n, readMode);
  const networkWrite = (data) => { writer.write(data); };

  try {
    const { read, write } = await startTls(connectHost, rootCerts, networkRead, networkWrite, {
      protocolsForALPN: ['http/1.1'],
    });

    const reqHeaders = { Host: hostHeader, Connection: 'close', ...headers };
    const lines = [`${method} ${path} HTTP/1.0\r\n`];
    for (const [k, v] of Object.entries(reqHeaders)) lines.push(`${k}: ${v}\r\n`);
    lines.push('\r\n');
    await write(new TextEncoder().encode(lines.join('')));

    const chunks = [];
    let total = 0;
    let chunk;
    while ((chunk = await read()) !== undefined) {
      chunks.push(chunk);
      total += chunk.length;
    }
    const all = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { all.set(c, offset); offset += c.length; }

    return parseRawHttpResponse(all);
  } finally {
    try { writer.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
  }
}
