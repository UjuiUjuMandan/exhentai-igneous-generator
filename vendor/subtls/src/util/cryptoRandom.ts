// Workers/browser only: always has global crypto, so no Node < 19 fallback needed
// (that fallback did a dynamic import('crypto'), which esbuild can't resolve for this platform)
const cryptoPromise = Promise.resolve(crypto);

export async function getRandomValues(...args: Parameters<typeof crypto.getRandomValues>) {
  const c: any = await cryptoPromise;
  return c.getRandomValues(...args);
}
