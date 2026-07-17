// Minimal drop-in replacement for the two `hextreme` functions subtls
// actually calls at runtime, so the Cloudflare Pages build doesn't depend on
// an `npm install` step (Pages CI here has no build command configured, so
// node_modules is never populated).

export function toHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

export function fromBase64(str: string, opts: { alphabet?: 'base64' | 'base64url' } = {}): Uint8Array {
  const normalized = opts.alphabet === 'base64url'
    ? str.replace(/-/g, '+').replace(/_/g, '/')
    : str;
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
