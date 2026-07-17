// Workers/browser only: always has global crypto.subtle, so no Node < 19 fallback needed
// (that fallback did a dynamic import('crypto'), which esbuild can't resolve for this platform)
const subtleCrypto = Promise.resolve(crypto.subtle);

function subtleCryptoMethod(method: string, args: any[]) {
  return subtleCrypto.then((cs: any) => cs[method](...args));
}

export default new Proxy({}, {
  get(target, property: string) {
    return (...args: any[]) => subtleCryptoMethod(property, args);
  }
}) as SubtleCrypto;
