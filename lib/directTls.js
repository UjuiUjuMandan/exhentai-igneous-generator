import { connect } from 'cloudflare:sockets';
import { startTls } from '../vendor/subtls/src/tls/startTls.ts';
import { ReadQueue, LazyReadFunctionReadQueue } from '../vendor/subtls/src/util/readQueue.ts';
import { HPACKBytes } from '../vendor/subtls/src/util/hpackBytes.ts';
import { HPACKStaticTable, HTTP2FrameType, writeFrame, readFrame } from '../vendor/subtls/src/h2.ts';

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

// Reads one HTTP/2 header block (HEADERS + any CONTINUATION frames) into a
// plain headers object, decoding HPACK fields. Only static-table indexing is
// supported for decoding (matching upstream subtls's own https.ts client) -
// none of the origins this talks to send dynamic-table-indexed responses for
// the handful of headers we care about (status, set-cookie, location).
async function readHPACKHeaders(hpackBytes, length) {
  const headers = {};
  const setCookies = [];
  const end = hpackBytes.offset + length;
  while (hpackBytes.offset < end) {
    const byte = await hpackBytes.readUint8();
    hpackBytes.offset--;

    let key, value;
    if (byte & 0x80) { // indexed field
      const { i: tableIndex } = await hpackBytes.readHPACKInt(1);
      if (tableIndex === 0) throw new Error('Illegal zero index for header');
      const entry = HPACKStaticTable[tableIndex];
      if (!entry) throw new Error(`Unsupported dynamic-table index ${tableIndex}`);
      [key, value] = entry;
    } else {
      const indexed = byte & 0x40;
      const { i: tableIndex } = await hpackBytes.readHPACKInt(indexed ? 2 : 4);
      if (tableIndex === 0) {
        key = await hpackBytes.readHPACKString();
      } else {
        const entry = HPACKStaticTable[tableIndex];
        if (!entry) throw new Error(`Unsupported dynamic-table index ${tableIndex}`);
        key = entry[0];
      }
      value = await hpackBytes.readHPACKString();
    }

    key = key.toLowerCase();
    if (key === ':status') headers.status = Number(value);
    else if (key === 'set-cookie') setCookies.push(value);
    else headers[key] = value;
  }
  if (setCookies.length) headers['set-cookie'] = setCookies.join(', ');
  return headers;
}

// Demultiplexes HTTP/2 frames off one TLS connection into per-stream
// promises. Supports opening multiple concurrent streams over the one
// connection instead of needing a fresh TCP+TLS handshake per request.
class H2Connection {
  constructor(read, write) {
    // `read` yields one whole decrypted TLS record per call, which may be
    // smaller or larger than the byte count Bytes.ensureReadAvailable asks
    // for. LazyReadFunctionReadQueue adapts that into an exact-byte-count
    // reader and buffers leftover bytes between frames, same as upstream
    // subtls's own http/2 client (https.ts) does.
    const readQueue = new LazyReadFunctionReadQueue(read);
    this._readFn = readQueue.read.bind(readQueue);
    this._write = write;
    this._streams = new Map(); // streamId -> { headers, bodyChunks, bodyLength, resolve, reject, headersDone }
    this._nextStreamId = 1;
    this._writeQueue = Promise.resolve();
    this._pumpError = null;
    this._pumpDone = this._pump();
  }

  _send(bytes) {
    this._writeQueue = this._writeQueue.then(() => this._write(bytes));
    return this._writeQueue;
  }

  async _pump() {
    try {
      for (;;) {
        const frame = new HPACKBytes(this._readFn);
        const { payloadEnd, payloadRemaining, frameType, flags, streamId } = await readFrame(frame);

        switch (frameType) {
          case HTTP2FrameType.SETTINGS: {
            const ack = Boolean(flags & 0x01);
            if (!ack) {
              await frame.readBytes(payloadRemaining()); // we don't act on server settings
              const ackFrame = new HPACKBytes();
              writeFrame(ackFrame, HTTP2FrameType.SETTINGS, 0x0, 0x01);
              this._send(ackFrame.array());
            }
            break;
          }

          case HTTP2FrameType.WINDOW_UPDATE: {
            await frame.readUint32();
            break;
          }

          case HTTP2FrameType.PING: {
            const pingData = await frame.readBytes(payloadRemaining());
            const ack = Boolean(flags & 0x01);
            if (!ack) {
              const pong = new HPACKBytes();
              const endPing = writeFrame(pong, HTTP2FrameType.PING, 0x0, 0x01);
              pong.writeBytes(pingData);
              endPing();
              this._send(pong.array());
            }
            break;
          }

          case HTTP2FrameType.GOAWAY: {
            await frame.readBytes(payloadRemaining());
            break;
          }

          case HTTP2FrameType.RST_STREAM: {
            const errorCode = await frame.readUint32();
            const stream = this._streams.get(streamId);
            if (stream) {
              this._streams.delete(streamId);
              stream.reject(new Error(`Stream ${streamId} reset by server (error ${errorCode})`));
            }
            break;
          }

          case HTTP2FrameType.HEADERS:
          case HTTP2FrameType.CONTINUATION:
          case HTTP2FrameType.DATA: {
            const stream = this._streams.get(streamId);

            const flagPadded = Boolean(flags & 0x08);
            const flagPriority = Boolean(flags & 0x20);
            const flagEndHeaders = Boolean(flags & 0x04);
            const flagEndStream = Boolean(flags & 0x01);

            let paddingBytes = 0;
            if (flagPadded) paddingBytes = await frame.readUint8();
            if (flagPriority) {
              await frame.readUint32();
              await frame.readUint8();
            }

            if (frameType === HTTP2FrameType.HEADERS || frameType === HTTP2FrameType.CONTINUATION) {
              const headerBlockLength = payloadRemaining() - paddingBytes;
              const headers = await readHPACKHeaders(frame, headerBlockLength);
              if (stream) Object.assign(stream.headers, headers);
              if (stream && flagEndHeaders) stream.headersDone = true;
            } else { // DATA
              const dataLength = payloadRemaining() - paddingBytes;
              const data = await frame.readBytes(dataLength);
              if (stream) {
                stream.bodyChunks.push(data);
                stream.bodyLength += data.length;
              }
            }

            if (paddingBytes > 0) await frame.skipRead(paddingBytes);

            if (flagEndStream && stream) {
              this._streams.delete(streamId);
              stream.resolve(stream);
            }
            break;
          }

          default: {
            await frame.readBytes(payloadRemaining());
          }
        }

        payloadEnd();
      }
    } catch (e) {
      this._pumpError = e;
      for (const stream of this._streams.values()) stream.reject(e);
      this._streams.clear();
    }
  }

  // Opens a new client-initiated stream (odd stream IDs, per RFC 9113 §5.1.1)
  // and sends a HEADERS frame built from HPACK-encoded pseudo-headers plus
  // regular headers. Resolves once END_STREAM is seen for that stream.
  async request({ method = 'GET', path = '/', authority, headers = {} }) {
    if (this._pumpError) throw this._pumpError;

    const streamId = this._nextStreamId;
    this._nextStreamId += 2;

    const streamPromise = new Promise((resolve, reject) => {
      this._streams.set(streamId, { headers: {}, bodyChunks: [], bodyLength: 0, resolve, reject, headersDone: false });
    });

    const headerFrame = new HPACKBytes();
    const endHeadersFrame = writeFrame(headerFrame, HTTP2FrameType.HEADERS, streamId, 0x04 | 0x01, '= END_HEADERS | END_STREAM');

    headerFrame.writeHPACKInt(7, 1, 1); // :scheme: https (indexed)

    if (method === 'GET') {
      headerFrame.writeHPACKInt(2, 1, 1); // :method: GET (indexed)
    } else {
      headerFrame.writeHPACKInt(2, 4, 0);
      headerFrame.writeHPACKString(method);
    }

    if (path === '/') {
      headerFrame.writeHPACKInt(4, 1, 1); // :path: / (indexed)
    } else {
      headerFrame.writeHPACKInt(4, 4, 0);
      headerFrame.writeHPACKString(path);
    }

    headerFrame.writeHPACKInt(1, 4, 0); // :authority (literal, not indexed)
    headerFrame.writeHPACKString(authority);

    for (const [key, value] of Object.entries(headers)) {
      headerFrame.writeHPACKInt(0, 4, 0); // literal header, name not indexed
      headerFrame.writeHPACKString(key.toLowerCase());
      headerFrame.writeHPACKString(String(value));
    }

    endHeadersFrame();
    await this._send(headerFrame.array());

    const stream = await streamPromise;
    return {
      status: stream.headers.status ?? 0,
      headers: stream.headers,
      body: textDecoder.decode(concatChunks(stream.bodyChunks, stream.bodyLength)),
    };
  }
}

function concatChunks(chunks, totalLength) {
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}

// Opens a raw TLS 1.3 connection to `connectHost` (e.g. a direct origin
// IP/hostname), presenting `sniHost` (defaults to `hostHeader`) as the TLS
// SNI name and `hostHeader` as the HTTP/2 :authority - like curl's
// --connect-to combined with --resolve. Pass `sniHost` explicitly whenever
// `connectHost` is a bare IP, since SNI must be a hostname, not the IP being
// connected to. Pass `useSNI: false` to omit the SNI extension entirely (the
// server still needs to have only one cert on that IP, since there's no
// hostname left to pick one by). `origin` must be this Worker's own origin,
// used to load the root cert database from static assets
// (`/certs.index.json` + `/certs.binary.txt`). Speaks HTTP/2 exclusively
// (ALPN offers only 'h2'; all origins this talks to support it). Returns a
// `request()` you can call more than once - including concurrently - to send
// several requests as multiplexed streams over the one TLS connection, and a
// `close()` to call when done.
export async function openDirectHttpsSession({ origin, connectHost, hostHeader, sniHost = hostHeader, useSNI = true, port = 443 }) {
  const rootCerts = await getRootCerts(origin);

  const socket = connect({ hostname: connectHost, port }, { secureTransport: 'off', allowHalfOpen: false });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const queue = new StreamReadQueue(reader);

  const networkRead = (n, readMode) => queue.read(n, readMode);
  const networkWrite = (data) => { writer.write(data); };

  const { read, write, protocolFromALPN } = await startTls(sniHost, rootCerts, networkRead, networkWrite, {
    useSNI,
    protocolsForALPN: ['h2'],
  });
  if (protocolFromALPN !== 'h2') throw new Error(`Server did not negotiate h2 (got ${protocolFromALPN ?? 'nothing'})`);

  const preface = new HPACKBytes();
  preface.writeUTF8String('PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n');
  const endSettingsFrame = writeFrame(preface, HTTP2FrameType.SETTINGS, 0x0);
  preface.writeUint16(0x0002); // SETTINGS_ENABLE_PUSH
  preface.writeUint32(0x00000000); // disabled
  endSettingsFrame();
  await write(preface.array());

  const connection = new H2Connection(read, write);

  async function request({ method = 'GET', path = '/', headers = {} } = {}) {
    return connection.request({ method, path, authority: hostHeader, headers });
  }

  async function close() {
    try { writer.releaseLock(); } catch {}
    try { await socket.close(); } catch {}
  }

  return { request, close };
}
