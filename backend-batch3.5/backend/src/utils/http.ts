export class TimeoutError extends Error {
  constructor(message = "Request timed out.") {
    super(message);
    this.name = "TimeoutError";
  }
}

/**
 * fetch() with an AbortController timeout. Does not log request bodies
 * or authorization headers.
 */
export async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs: number,
  fetchImpl: typeof fetch = fetch
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal });
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new TimeoutError(`Request timed out after ${timeoutMs}ms.`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
