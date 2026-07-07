/** Monotonic millisecond clock for measuring durations. */
export function monotonicMs(): number {
  // process.hrtime.bigint is monotonic and unaffected by wall-clock changes.
  const ns = process.hrtime.bigint();
  return Number(ns / 1_000_000n);
}

/** Race a promise against a timeout; rejects with a labelled error on expiry. */
export async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  label: string,
): Promise<T> {
  if (!Number.isFinite(ms) || ms <= 0) {
    throw new Error(`withTimeout: invalid timeout (${ms}) for ${label}`);
  }
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`timeout after ${ms}ms: ${label}`));
    }, ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
